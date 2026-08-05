#!/usr/bin/env python3
"""
orion_inventory_sync.py

Compares the devices SolarWinds Orion monitors against the Ansible
inventory, and reports (or adds) the ones that are not in the inventory
yet.

**Additive only. Never removes, never edits an existing host.** A device
that has disappeared from Orion is reported, not deleted -- an inventory
entry may exist for reasons Orion knows nothing about (a device
deliberately not monitored, a host that isn't a network device at all),
and deleting on that basis would be acting on half the picture. Existing
hosts are never rewritten either, so anything hand-tuned in the
inventory stays exactly as it is.

READ-ONLY against Orion. The only thing this writes is a local
inventory file.

## What "already exists" means

The inventory is read through this repo's `inventory_reader.py`, which
uses Ansible's `InventoryManager` -- so what counts as existing is
exactly what Ansible itself sees, including group_vars, host_vars,
vault-encrypted values, and whatever inventory plugins are configured.
Re-implementing a YAML parse here would have been a second, subtly
different opinion about the same question.

A device is considered present if any of these match, checked in this
order (the first hit wins, and the report says which one it was):

  1. **Polling IP == an inventory host's `ansible_host`.** Strongest
     signal: that is literally the address Ansible would connect to.
  2. **Exact name match** against the inventory hostname, comparing
     Caption, SysName and DNS, case-insensitively.
  3. **Short-name match** -- the same three names with the domain
     stripped. `core1.example.com` in Orion matches an inventory host
     called `core1`.

Rule 3 is deliberately last, and can be turned off with
`--no-short-name-match`. It is the one rule that can produce a false
"already exists", because short names collide across domains; the
consequence of a false positive is a device silently *not* added, which
is harder to notice than a duplicate.

Where the rules disagree -- an IP matching one inventory host while a
name matches a different one -- the device is reported as AMBIGUOUS and
is **not** added. That is a real inconsistency between Orion and the
inventory and it wants a human, not a default.

## Usage

Report only (the default -- writes nothing):

    python3 orion_inventory_sync.py --host orion.example.com \\
        --username ansible --password-env ORION_PASSWORD --insecure \\
        --inventory ../inventory.yml

Write just the new devices to their own inventory file:

    ... --write-new orion_discovered.yml

Merge the new devices into an existing inventory file in place:

    ... --merge-into ../inventory.yml

`--merge-into` rewrites the file through a YAML round-trip, so **any
comments and hand-formatting in it are lost**. A timestamped `.bak` is
written first, and the tool refuses if the backup cannot be created.
`--write-new` avoids the problem entirely by never touching the
existing file, and is the safer default habit: add the generated file
as a second inventory source rather than merging into a hand-maintained
one.

## Requires

requests, ansible-core (the inventory is read through Ansible), and
PyYAML for the writing modes.
"""

import argparse
import getpass
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from orion_client import DEFAULT_NODE_COLUMNS, OrionClient, OrionError  # noqa: E402
from orion_devices import (  # noqa: E402
    _inventory_hostname,
    build_client,
    build_inventory,
    parse_params,
    render_table,
)


class Verdict:
    """One Orion device's reconciliation result."""

    EXISTS = "EXISTS"
    NEW = "NEW"
    AMBIGUOUS = "AMBIGUOUS"

    def __init__(self, row, state, matched_host=None, rule=None, detail=None):
        self.row = row
        self.state = state
        self.matched_host = matched_host
        self.rule = rule
        self.detail = detail


def _norm(value):
    """Normalises a name for comparison: lowercased, trimmed, trailing
    dot stripped (a fully-qualified DNS name may carry one)."""
    if value is None:
        return ""
    return str(value).strip().rstrip(".").lower()


def _short(name):
    """The hostname with its domain stripped."""
    return name.split(".", 1)[0] if name else ""


def index_inventory(resolver):
    """Builds the lookup structures for the existing inventory.

    Returns (by_ip, by_name, by_short), each mapping a normalised key to
    a *list* of inventory hostnames. Lists rather than single values
    because the inventory can genuinely contain collisions -- two hosts
    sharing a short name across domains is normal -- and silently
    keeping only the first would make the ambiguity invisible at exactly
    the point it matters.
    """
    by_ip, by_name, by_short = {}, {}, {}

    for hostname in resolver.list_all_hosts():
        name = _norm(hostname)
        by_name.setdefault(name, []).append(hostname)

        short = _short(name)
        if short:
            by_short.setdefault(short, []).append(hostname)

        # get_connection_address() falls back to the hostname itself
        # when ansible_host isn't set, matching Ansible's own behaviour.
        # That fallback is not an address, so it must not go in the IP
        # index -- otherwise a host called "core1" would look like it
        # had the polling IP "core1" and never match anything anyway,
        # but a host whose *name is an IP* would be double-counted.
        address = resolver.get_connection_address(hostname)
        if address and _norm(address) != name:
            by_ip.setdefault(_norm(address), []).append(hostname)

    return by_ip, by_name, by_short


def reconcile(rows, by_ip, by_name, by_short, short_name_match=True):
    """Decides, for each Orion device, whether it is already in the
    inventory. See the module docstring for the rule order and why
    short-name matching is last and optional."""
    verdicts = []

    for row in rows:
        candidate_names = [
            _norm(row.get(field)) for field in ("Caption", "SysName", "DNS")
        ]
        candidate_names = [n for n in candidate_names if n]
        ip = _norm(row.get("IPAddress"))

        matches = []  # (rule, detail, [hostnames])

        if ip and ip in by_ip:
            matches.append(("polling-ip", ip, by_ip[ip]))

        for name in candidate_names:
            if name in by_name:
                matches.append(("name", name, by_name[name]))
                break

        if short_name_match:
            for name in candidate_names:
                short = _short(name)
                if short and short in by_short:
                    matches.append(("short-name", short, by_short[short]))
                    break

        if not matches:
            verdicts.append(Verdict(row, Verdict.NEW))
            continue

        # Every rule that fired must agree on the inventory host, or the
        # inventory and Orion disagree about what this device is.
        hosts = {h for _, _, hostnames in matches for h in hostnames}
        if len(hosts) > 1:
            rules = ", ".join(
                f"{rule}={detail} -> {'/'.join(hostnames)}"
                for rule, detail, hostnames in matches
            )
            verdicts.append(Verdict(row, Verdict.AMBIGUOUS, detail=rules))
            continue

        rule, detail, hostnames = matches[0]
        verdicts.append(Verdict(row, Verdict.EXISTS, matched_host=hostnames[0],
                                rule=rule, detail=detail))

    return verdicts


def render_report(verdicts, columns):
    """The human-readable reconciliation report. Deliberately lists the
    EXISTS rows too, with the rule that matched: a device wrongly judged
    to already exist is the failure mode that would otherwise be silent,
    so the evidence for every such judgement is on screen."""
    rows = []
    for v in verdicts:
        rows.append({
            "Verdict": v.state,
            "Caption": v.row.get("Caption"),
            "IPAddress": v.row.get("IPAddress"),
            "MachineType": v.row.get("MachineType"),
            "Matched": v.matched_host or "",
            "Rule": v.rule or (v.detail or ""),
        })

    order = {Verdict.NEW: 0, Verdict.AMBIGUOUS: 1, Verdict.EXISTS: 2}
    rows.sort(key=lambda r: (order[r["Verdict"]], str(r["Caption"] or "")))

    text = render_table(
        rows, ["Verdict", "Caption", "IPAddress", "MachineType", "Matched", "Rule"]
    )

    counts = {state: 0 for state in order}
    for v in verdicts:
        counts[v.state] += 1
    summary = (
        f"\n{counts[Verdict.NEW]} new, "
        f"{counts[Verdict.EXISTS]} already in inventory, "
        f"{counts[Verdict.AMBIGUOUS]} ambiguous "
        f"(of {len(verdicts)} in Orion)\n"
    )
    if counts[Verdict.AMBIGUOUS]:
        summary += (
            "\nAMBIGUOUS means Orion's IP and name point at different "
            "inventory hosts.\nThose are not added -- the inventory and "
            "Orion disagree and it needs a human.\n"
        )
    return text + summary


def merge_into(existing_path, additions, group):
    """Merges new hosts into an existing inventory file, additively.

    Only ever adds host keys. An existing host of the same name is left
    completely untouched -- reconcile() should already have classified
    it as EXISTS, so reaching here means the name collided by a route
    the matching rules did not cover, and overwriting a hand-maintained
    entry on that basis would be the worst possible outcome.
    """
    import yaml

    with open(existing_path, "r", encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}

    if not isinstance(document, dict):
        raise SystemExit(
            f"{existing_path} does not parse as a YAML mapping -- refusing "
            f"to rewrite it."
        )

    all_section = document.setdefault("all", {})
    children = all_section.setdefault("children", {})
    target = children.setdefault(group, {})
    hosts = target.setdefault("hosts", {})
    if hosts is None:
        hosts = target["hosts"] = {}

    added, skipped = [], []
    for name, host_vars in additions.items():
        if name in hosts:
            skipped.append(name)
            continue
        hosts[name] = host_vars
        added.append(name)

    return document, added, skipped


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    conn = parser.add_argument_group("orion connection")
    conn.add_argument("--host", required=True)
    conn.add_argument("--username")
    conn.add_argument("--password-env", default=None)
    conn.add_argument("--use-vault-secret", action="store_true")
    conn.add_argument("--secret-path", default="orion_secret.yml")
    conn.add_argument("--vault-password-file", default=None)
    conn.add_argument("--port", type=int, default=17778)
    conn.add_argument("--insecure", action="store_true")
    conn.add_argument("--timeout", type=int, default=60)

    query = parser.add_argument_group("orion query")
    query.add_argument("--where", default=None,
                       help="SWQL WHERE clause without the keyword. Use this "
                            "to scope what gets considered, e.g. only managed "
                            "network kit.")
    query.add_argument("--param", action="append", default=[], metavar="K=V")
    query.add_argument("--extra-columns", default=None,
                       help="Extra Orion properties to carry into the new "
                            "inventory entries as orion_* host vars.")

    inv = parser.add_argument_group("inventory")
    inv.add_argument("--inventory", action="append", default=None,
                     metavar="PATH",
                     help="Inventory source. Repeatable. Defaults to "
                          "$ANSIBLE_INVENTORY, then inventory.yml/.yaml/"
                          "inventory in the current or parent directory.")
    inv.add_argument("--group", default="orion_discovered",
                     help="Group new hosts are added to (default: "
                          "orion_discovered). Kept separate from existing "
                          "groups by default so generated entries are "
                          "obvious and easy to reverse.")
    inv.add_argument("--no-short-name-match", action="store_true",
                     help="Disable domain-stripped name matching. Stricter: "
                          "more devices judged new, fewer false 'already "
                          "exists'.")

    out = parser.add_argument_group("output")
    out.add_argument("--write-new", metavar="FILE", default=None,
                     help="Write the new devices to their own inventory "
                          "file. Does not touch the existing inventory.")
    out.add_argument("--merge-into", metavar="FILE", default=None,
                     help="Add the new devices to this existing inventory "
                          "file, in place. Additive only, backs up first, "
                          "and LOSES COMMENTS AND FORMATTING (YAML "
                          "round-trip). Prefer --write-new.")

    args = parser.parse_args()

    if args.write_new and args.merge_into:
        raise SystemExit("--write-new and --merge-into are mutually exclusive")

    try:
        from inventory_reader import InventoryReader, find_default_inventory
    except ImportError as e:
        raise SystemExit(
            f"Could not import inventory_reader ({e}). This script reads the "
            f"inventory through Ansible, so ansible-core is required here "
            f"even though the plain device-list scripts do not need it."
        )

    # find_default_inventory() already returns a list (or None), so it is
    # used directly. Wrapping it in another list builds a nested one,
    # which InventoryManager rejects -- a bug that survived in
    # workbench/ansible because every test passed --inventory explicitly
    # and never exercised the default path.
    sources = args.inventory or find_default_inventory() or []
    sources = [s for s in sources if s]
    if not sources:
        raise SystemExit(
            "No inventory found. Pass --inventory explicitly -- this repo "
            "holds no inventory of its own; it reads whichever one you "
            "point it at (e.g. workbench/ansible's, or a production clone "
            "of it)."
        )

    columns = list(DEFAULT_NODE_COLUMNS)
    if args.extra_columns:
        for col in args.extra_columns.split(","):
            col = col.strip()
            if col and col not in columns:
                columns.append(col)

    try:
        client = build_client(args)
        rows = client.get_nodes(
            columns=columns,
            where=args.where,
            parameters=parse_params(args.param),
        )
    except OrionError as e:
        print(f"ERROR talking to Orion: {e}", file=sys.stderr)
        return 1

    try:
        resolver = InventoryReader(
            sources=sources, vault_password_file=args.vault_password_file
        )
    except Exception as e:
        print(f"ERROR reading inventory {sources}: {e}", file=sys.stderr)
        # A missing vault password file is the most likely cause and the
        # least obvious, because it fails even when the inventory
        # contains nothing encrypted: ansible.cfg names the file, so
        # Ansible insists on it. Same behaviour as ansible-playbook, so
        # it is not worked around here -- just explained, since the
        # message alone does not say where the path came from.
        if "vault password file" in str(e).lower():
            print(
                "\nThat path most likely comes from ansible.cfg's "
                "vault_password_file setting, found by walking up from the "
                "current directory (workbench/ansible's ansible.cfg sets "
                "~/.vault_pass). Ansible requires it once configured, even "
                "if nothing in the inventory is encrypted. Either create it, "
                "or point somewhere else with --vault-password-file / "
                "$ANSIBLE_VAULT_PASSWORD_FILE.",
                file=sys.stderr,
            )
        return 1

    by_ip, by_name, by_short = index_inventory(resolver)
    existing_count = len(resolver.list_all_hosts())

    verdicts = reconcile(
        rows, by_ip, by_name, by_short,
        short_name_match=not args.no_short_name_match,
    )

    print(f"Orion: {len(rows)} device(s).  "
          f"Inventory ({', '.join(str(s) for s in sources)}): "
          f"{existing_count} host(s).\n")
    print(render_report(verdicts, columns))

    new_rows = [v.row for v in verdicts if v.state == Verdict.NEW]
    if not new_rows:
        print("Nothing to add.")
        return 0

    if not (args.write_new or args.merge_into):
        print("Report only. Re-run with --write-new FILE or --merge-into "
              "FILE to add the new devices.")
        return 0

    inventory = build_inventory(new_rows, columns, group=args.group)
    additions = inventory["all"]["children"][args.group]["hosts"]

    import yaml

    if args.write_new:
        target = Path(args.write_new)
        header = (
            "# Generated by orion/orion_inventory_sync.py.\n"
            "# Devices present in SolarWinds Orion but not in the existing\n"
            "# inventory at the time of generation. Add as an additional\n"
            "# inventory source; review before use.\n"
        )
        target.write_text(
            header + yaml.safe_dump(inventory, default_flow_style=False,
                                    sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        print(f"Wrote {len(additions)} new host(s) to {target}")
        print(f"Nothing existing was modified. Use it alongside the current "
              f"inventory, e.g.\n  ansible-playbook -i {sources[0]} "
              f"-i {target} ...")
        return 0

    target = Path(args.merge_into)
    if not target.exists():
        raise SystemExit(f"--merge-into: {target} does not exist")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = target.with_suffix(target.suffix + f".{stamp}.bak")
    try:
        backup.write_bytes(target.read_bytes())
    except OSError as e:
        raise SystemExit(
            f"Refusing to merge: could not write backup {backup}: {e}"
        )

    document, added, skipped = merge_into(target, additions, args.group)
    target.write_text(
        yaml.safe_dump(document, default_flow_style=False, sort_keys=False,
                       allow_unicode=True),
        encoding="utf-8",
    )

    print(f"Backed up {target} -> {backup}")
    print(f"Added {len(added)} host(s) to group '{args.group}' in {target}")
    if skipped:
        print(f"Left {len(skipped)} existing host(s) untouched: "
              f"{', '.join(skipped)}")
    print("NOTE: comments and formatting in the original file are not "
          "preserved by the YAML round-trip -- diff against the backup.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
