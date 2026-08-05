#!/usr/bin/env python3
"""
orion_devices.py

Lists the devices SolarWinds Orion is monitoring, with the fields this
repo needs to drive an Ansible inventory:

    Polling IP address  -> Orion.Nodes.IPAddress
    Machine Type        -> Orion.Nodes.MachineType
    System Name         -> Orion.Nodes.SysName
    DNS Name            -> Orion.Nodes.DNS

plus Caption (Orion's display name) and NodeID (the key everything else
in Orion joins on).

READ-ONLY. This script, and the client underneath it, can only issue
SWQL queries -- there is no code path here that writes to Orion.

Requires: requests. PyYAML is used for --format inventory if present,
and a hand-rolled emitter is used if it isn't.

## Quick start

    # prompts for the password, doesn't echo it
    python3 orion_devices.py --host orion.example.com \\
        --username ansible --insecure

    # password from the environment (keeps it out of `ps` and history)
    read -rs ORION_PASSWORD && export ORION_PASSWORD
    python3 orion_devices.py --host orion.example.com \\
        --username ansible --password-env ORION_PASSWORD --insecure

`--insecure` is usually needed: a stock Orion install serves SWIS with a
self-signed certificate. The connection stays TLS either way.

## Before trusting the output -- confirm the schema

Every property name above comes from SolarWinds documentation, not from
your instance. Ask the instance what it actually has:

    python3 orion_devices.py --host ... --username ... --insecure \\
        --list-columns

    python3 orion_devices.py --host ... --username ... --insecure \\
        --list-custom-properties

If `--list-columns` doesn't show one of the four fields, the query will
fail with a SWIS error naming the bad property -- that error is the
fastest route to the real name. For a full first-contact capture of a
new instance, run orion_probe.py instead; it records all of this to
files you can carry back across the airgap.

## Output

    --format table       aligned columns, for reading (default)
    --format csv         for a spreadsheet, or carrying across the airgap
    --format json        raw rows, for anything programmatic
    --format inventory   an Ansible YAML inventory skeleton

    --output FILE        write there instead of stdout

## Filtering

    # one vendor's kit only
    --where "Vendor = @v" --param v=Cisco

    # skip nodes Orion isn't currently managing
    --where "Unmanaged = @u" --param u=int:0

Values always go through --param, never inline in --where: SWQL is a
query language and interpolating values into it is the same class of
mistake as SQL injection. Parameters are sent as strings unless
prefixed with `int:`.

## Extra fields

    --columns NodeID,Caption,IPAddress,MachineType,SysName,DNS
    --extra-columns Vendor,Status,IOSVersion
    --extra-columns CustomProperties.Site

Custom properties (site, role, owner -- whatever this Orion defines)
are reachable through the navigable CustomProperties relation; run
--list-custom-properties to see which exist here.
"""

import argparse
import csv
import getpass
import io
import json
import sys
from pathlib import Path

# PyYAML is used for --format inventory when it's importable, and a
# hand-rolled emitter is used when it isn't. Unlike requests, which is
# confirmed present on the airgapped box, PyYAML there is only
# "probably available" -- and probably is not the same as available. A
# script that dies on an import at the far end of an airgap costs a
# whole round trip to find out. Both paths emit the same structure --
# see render_inventory().
try:
    import yaml
    HAVE_PYYAML = True
except ImportError:  # pragma: no cover - depends on the host
    HAVE_PYYAML = False

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_client import (  # noqa: E402
    COMMON_EXTRA_COLUMNS,
    DEFAULT_NODE_COLUMNS,
    DEFAULT_SWIS_PORT,
    LEGACY_SWIS_PORT,
    OrionClient,
    OrionError,
    format_status,
)


# -- Output formatting -------------------------------------------------

def _cell(value):
    """Renders one value for text output. None becomes an empty string
    rather than the literal "None" -- Orion leaves DNS and SysName
    genuinely empty on plenty of nodes (ICMP-only ones especially), and
    "None" in a CSV column reads as data."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def render_table(rows, columns):
    if not rows:
        return "(no nodes matched)\n"

    display = [[_cell(r.get(c)) for c in columns] for r in rows]
    widths = [len(c) for c in columns]
    for row in display:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    out = io.StringIO()
    out.write("  ".join(h.ljust(widths[i]) for i, h in enumerate(columns)).rstrip())
    out.write("\n")
    out.write("  ".join("-" * w for w in widths).rstrip())
    out.write("\n")
    for row in display:
        out.write("  ".join(c.ljust(widths[i]) for i, c in enumerate(row)).rstrip())
        out.write("\n")
    out.write(f"\n{len(rows)} node(s)\n")
    return out.getvalue()


def render_csv(rows, columns):
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(columns)
    for r in rows:
        writer.writerow([_cell(r.get(c)) for c in columns])
    return out.getvalue()


def render_json(rows, columns):
    # Projected to the selected columns and ordered, rather than dumping
    # whatever SWIS returned -- so the JSON matches the table/CSV for the
    # same invocation instead of quietly carrying extra fields.
    return json.dumps(
        [{c: r.get(c) for c in columns} for r in rows], indent=2
    ) + "\n"


def _yaml_scalar(value):
    """Renders a scalar for the hand-rolled YAML path.

    Dispatch is on the Python type, so the emitted document round-trips
    to the same types PyYAML would produce -- the two paths have to
    agree, or an inventory built on the airgapped side would carry
    differently-typed variables from one built here, and a playbook
    comparing them would behave differently in the two places.

    Numbers and booleans go out bare; everything else is double-quoted
    unconditionally. That is heavier than PyYAML's output, but it is
    what keeps the fallback correct without reimplementing YAML's
    "when does this need quoting" rules: unquoted Orion *strings* would
    otherwise be reinterpreted on load -- a MachineType of "Yes" would
    become a boolean, a SysName of "2621" an integer, and anything
    containing ": " would break the document outright.
    """
    if value is None:
        return '""'
    if isinstance(value, bool):
        # Checked before int: bool is a subclass of int in Python, so
        # the numeric branch below would render True as "1".
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _inventory_hostname(row):
    """Picks the inventory key for a node, preferring the name a human
    would recognise. Caption is Orion's display name and is what the
    Orion UI shows, so it's first; SysName and DNS are the device's own
    names; NodeID is the last resort so a node can never be dropped for
    want of a name.

    Characters Ansible dislikes in a host key (whitespace, brackets,
    colons) are replaced with underscores.
    """
    for key in ("Caption", "SysName", "DNS"):
        value = row.get(key)
        if value:
            name = str(value).strip()
            if name:
                break
    else:
        name = f"node_{row.get('NodeID')}"

    for ch in " \t\n[]:,'\"":
        name = name.replace(ch, "_")
    return name


INVENTORY_HEADER = (
    "# Generated by orion/orion_devices.py from SolarWinds Orion.\n"
    "# Skeleton only: no credentials, connection vars or grouping.\n"
)


def build_inventory(rows, columns, group="orion_nodes"):
    """Builds the inventory as a plain dict -- shared by both emitters
    below, so the PyYAML and fallback paths cannot drift apart.
    orion_inventory_sync.py reuses this with its own group name, so the
    hosts it adds are shaped identically to the ones --format inventory
    emits.

    Deliberately a *skeleton*, not a drop-in replacement for this repo's
    inventory.yml: it carries no credentials, no connection settings and
    no group structure beyond a single flat group, because those are
    decisions about how to reach a device and Orion has no opinion on
    them. Grouping by site/role belongs on Orion custom properties; pull
    one in with --extra-columns CustomProperties.<Name> and group on it
    once the real property names are known.

    A node with no polling IP gets `orion_polling_ip_missing: true`
    rather than being skipped, and rather than a YAML comment -- a
    device missing from an inventory is much harder to notice than one
    that is present and obviously incomplete, and a key can be grepped
    or asserted on by a playbook where a comment cannot.
    """
    hosts = {}
    for row in rows:
        name = _inventory_hostname(row)
        # Orion Captions are not guaranteed unique; two hosts with the
        # same key would silently collapse into one in YAML, so
        # duplicates get their NodeID appended instead of being lost.
        if name in hosts:
            name = f"{name}_{row.get('NodeID')}"

        host_vars = {}
        ip = row.get("IPAddress")
        if ip:
            host_vars["ansible_host"] = str(ip)
        else:
            host_vars["orion_polling_ip_missing"] = True
        for col in columns:
            if col in ("Caption", "IPAddress"):
                continue
            value = row.get(col)
            host_vars[f"orion_{col.replace('.', '_').lower()}"] = (
                "" if value is None else value
            )
        hosts[name] = host_vars

    return {"all": {"children": {group: {"hosts": hosts}}}}


def render_inventory(rows, columns, group="orion_nodes"):
    """Emits an Ansible YAML inventory skeleton: each node becomes a host
    with ansible_host set to its polling IP.

    Uses PyYAML when available and a hand-rolled emitter otherwise (see
    the import at the top of this file for why). The hand-rolled path
    double-quotes every string unconditionally -- heavier than PyYAML's
    output, but that is what keeps it correct without a real emitter's
    knowledge of when quoting is needed: unquoted Orion values would
    otherwise be reinterpreted by YAML, so a MachineType of "Yes" would
    become a boolean, a SysName of "2621" an integer, and anything
    containing ": " would break the document outright.
    """
    inventory = build_inventory(rows, columns, group=group)

    if HAVE_PYYAML:
        return INVENTORY_HEADER + yaml.safe_dump(
            inventory, default_flow_style=False, sort_keys=False,
            allow_unicode=True,
        )

    out = io.StringIO()
    out.write(INVENTORY_HEADER)
    out.write(f"all:\n  children:\n    {group}:\n      hosts:\n")
    hosts = inventory["all"]["children"][group]["hosts"]
    if not hosts:
        out.write("        {}\n")
        return out.getvalue()
    for name, host_vars in hosts.items():
        out.write(f"        {_yaml_scalar(name)}:\n")
        for key, value in host_vars.items():
            out.write(f"          {key}: {_yaml_scalar(value)}\n")
    return out.getvalue()


RENDERERS = {
    "table": render_table,
    "csv": render_csv,
    "json": render_json,
    "inventory": render_inventory,
}


# -- Argument handling -------------------------------------------------

def parse_params(pairs):
    """Turns --param k=v arguments into a SWQL parameter dict. Values
    are strings unless prefixed `int:`, since SWQL comparisons are typed
    and a quoted "0" will not match an integer column."""
    params = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise SystemExit(
                f"--param expects key=value, got {pair!r}"
            )
        key, value = pair.split("=", 1)
        if value.startswith("int:"):
            try:
                params[key] = int(value[4:])
            except ValueError:
                raise SystemExit(
                    f"--param {key}: {value[4:]!r} is not an integer"
                )
        else:
            params[key] = value
    return params


def build_client(args):
    if args.use_vault_secret:
        return OrionClient.from_vault_secret(
            host=args.host,
            username=args.username,
            secret_path=args.secret_path,
            vault_password_file=args.vault_password_file,
            # getattr rather than direct access: orion_inventory_sync.py
            # shares this function, and a caller that has not defined
            # these should get the defaults rather than an AttributeError.
            username_key=getattr(args, "username_key", "username"),
            password_key=getattr(args, "password_key", "password"),
            port=args.port,
            verify_ssl=not args.insecure,
            timeout=args.timeout,
        )

    if not args.username:
        raise SystemExit("--username is required unless --use-vault-secret is given")

    password = None
    if not args.password_env:
        password = getpass.getpass(f"Orion password for {args.username}: ")

    return OrionClient(
        host=args.host,
        username=args.username,
        password=password,
        password_env=args.password_env,
        port=args.port,
        verify_ssl=not args.insecure,
        timeout=args.timeout,
    )


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    conn = parser.add_argument_group("connection")
    conn.add_argument("--host", required=True,
                      help="Orion server hostname (a full https:// URL is "
                           "also accepted)")
    conn.add_argument("--username",
                      help="Orion individual account. AD accounts take the "
                           "DOMAIN\\user form -- quote it on the shell.")
    conn.add_argument("--password-env", default=None,
                      help="Environment variable holding the password. "
                           "Without this (and without --use-vault-secret) "
                           "you are prompted, and the password is not "
                           "echoed.")
    conn.add_argument("--use-vault-secret", action="store_true",
                      help="Take credentials from an ansible-vault-encrypted "
                           "orion_secret.yml. Needs ansible-core, so this is "
                           "the path for this side of the airgap, not the "
                           "Orion side.")
    conn.add_argument("--secret-path", default="orion_secret.yml",
                      help="Vault-encrypted YAML holding the credentials "
                           "(default: orion_secret.yml). Can be an existing "
                           "vars file -- see --username-key/--password-key.")
    conn.add_argument("--username-key", default="username",
                      help="Which variable in the vault file holds the "
                           "username (default: username). Dotted paths work "
                           "for nested values, e.g. orion.api.username.")
    conn.add_argument("--password-key", default="password",
                      help="Which variable in the vault file holds the "
                           "password (default: password). Dotted paths work.")
    conn.add_argument("--vault-password-file", default=None)
    conn.add_argument("--port", type=int, default=DEFAULT_SWIS_PORT,
                      help=f"SWIS SSL port (default: {DEFAULT_SWIS_PORT}). "
                           f"Orion 2022.4.1 and earlier used "
                           f"{LEGACY_SWIS_PORT}.")
    conn.add_argument("--insecure", action="store_true",
                      help="Skip TLS certificate validation. Usually needed "
                           "-- a stock Orion install has a self-signed "
                           "certificate. The connection is still TLS.")
    conn.add_argument("--timeout", type=int, default=60)

    query = parser.add_argument_group("query")
    query.add_argument("--columns", default=None,
                       help="Comma-separated Orion.Nodes properties, "
                            "replacing the default set "
                            f"({','.join(DEFAULT_NODE_COLUMNS)})")
    query.add_argument("--extra-columns", default=None,
                       help="Comma-separated properties to add to the "
                            "default set. Commonly useful: "
                            f"{','.join(COMMON_EXTRA_COLUMNS)}")
    query.add_argument("--where", default=None,
                       help="SWQL WHERE clause without the WHERE keyword, "
                            "e.g. \"Vendor = @v\". Put values in --param, "
                            "never inline.")
    query.add_argument("--param", action="append", default=[], metavar="K=V",
                       help="Bind value for --where. Repeatable. String "
                            "unless prefixed int: (e.g. --param u=int:0).")
    query.add_argument("--page-size", type=int, default=500,
                       help="Rows per SWQL request (default: 500)")
    query.add_argument("--no-paging", action="store_true",
                       help="Fetch everything in one query instead of paging.")

    out = parser.add_argument_group("output")
    out.add_argument("--format", choices=sorted(RENDERERS), default="table")
    out.add_argument("--output", default=None,
                     help="Write to this file instead of stdout")

    schema = parser.add_argument_group("schema discovery")
    schema.add_argument("--list-columns", action="store_true",
                        help="List the properties this Orion instance really "
                             "has on Orion.Nodes, then exit. Run this before "
                             "trusting the field names.")
    schema.add_argument("--list-custom-properties", action="store_true",
                        help="List the node custom properties defined on this "
                             "instance, then exit.")

    args = parser.parse_args()

    try:
        client = build_client(args)

        if args.list_columns or args.list_custom_properties:
            entity = ("Orion.NodesCustomProperties" if args.list_custom_properties
                      else "Orion.Nodes")
            props = (client.discover_custom_properties()
                     if args.list_custom_properties
                     else client.discover_properties())
            if not props:
                print(f"No properties returned for {entity}. Either the "
                      f"entity name is wrong on this Orion version, or the "
                      f"account cannot read Metadata.Property.",
                      file=sys.stderr)
                return 1
            text = render_table(props, ["Name", "Type", "IsNavigable"])
            print(f"Properties of {entity} on {args.host}:\n")
            sys.stdout.write(text)
            return 0

        if args.columns:
            columns = [c.strip() for c in args.columns.split(",") if c.strip()]
        else:
            columns = list(DEFAULT_NODE_COLUMNS)
        if args.extra_columns:
            for col in args.extra_columns.split(","):
                col = col.strip()
                if col and col not in columns:
                    columns.append(col)
        if "NodeID" not in columns:
            columns.insert(0, "NodeID")

        rows = client.get_nodes(
            columns=columns,
            where=args.where,
            parameters=parse_params(args.param),
            page_size=None if args.no_paging else args.page_size,
        )

        # Status is an integer in Orion; render it as a label wherever it
        # was asked for, since a bare "2" in a device list is not useful.
        if "Status" in columns:
            for row in rows:
                if "Status" in row:
                    row["Status"] = format_status(row["Status"])

        text = RENDERERS[args.format](rows, columns)

        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"Wrote {len(rows)} node(s) to {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(text)
        return 0

    except OrionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if e.exception_type:
            print(f"       SWIS exception type: {e.exception_type}",
                  file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
