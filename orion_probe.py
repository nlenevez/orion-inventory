#!/usr/bin/env python3
"""
orion_probe.py

First-contact capture for a SolarWinds Orion instance. Run this once on
the airgapped side, carry the output directory back, and every
assumption orion_client.py currently makes from documentation becomes
either confirmed or corrected against real data.

READ-ONLY. Every probe is a SWQL SELECT. Nothing here can write to
Orion.

Requires: requests.

## Why this exists

orion_client.py's property names -- IPAddress, MachineType, SysName,
DNS -- come from SolarWinds documentation, not from your Orion. So does
the status-code map, the SWIS port, and the shape of the response
envelope. Documentation is not the instance. This repo already applies
that discipline to YANG models (see discovery/): capture what the real
system says, then build against the capture.

The probes are deliberately **separate queries, one assumption each**.
A single query selecting all four fields would fail as a unit if any
one property name were wrong, and the failure would not say which --
so a wrong `SysName` would cast doubt on `IPAddress` too. Probing each
field on its own means the summary can say exactly which names hold.

## Usage

    read -rs ORION_PASSWORD && export ORION_PASSWORD
    python3 orion_probe.py --host orion.example.com \\
        --username ansible --password-env ORION_PASSWORD --insecure

    # or let it prompt (not echoed)
    python3 orion_probe.py --host orion.example.com \\
        --username ansible --insecure

Writes to ./orion-probe-output/ by default (--output-dir to change).
Start with summary.txt in that directory -- it is the PASS/FAIL table;
the JSON files beside it are the raw evidence.

## What the output contains

Device names, DNS names, machine types and management IP addresses from
the monitored estate, plus the Orion schema. It contains no credentials.
Review it before moving it anywhere, as with any inventory extract.
"""

import argparse
import getpass
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_client import (  # noqa: E402
    DEFAULT_NODE_COLUMNS,
    DEFAULT_SWIS_PORT,
    LEGACY_SWIS_PORT,
    OrionClient,
    OrionError,
)

#: The four fields this module was built to retrieve, probed one at a
#: time so a wrong name is attributed to the right field. Each entry is
#: (what it was asked for, the Orion property assumed to provide it).
TARGET_FIELDS = [
    ("Polling IP address", "IPAddress"),
    ("Machine Type", "MachineType"),
    ("System Name", "SysName"),
    ("DNS Name", "DNS"),
]


class Probe:
    """One assumption, one query, one verdict."""

    def __init__(self, name, expectation, swql, parameters=None,
                 filename=None):
        self.name = name
        #: Written into the output *before* the result is known -- the
        #: point is to state what is expected, so the capture records a
        #: prediction rather than a rationalisation after the fact.
        self.expectation = expectation
        self.swql = swql
        self.parameters = parameters
        self.filename = filename or (name.replace(" ", "_").lower() + ".json")
        self.ok = None
        self.rows = []
        self.error = None

    def run(self, client, max_rows):
        try:
            rows = client.query(self.swql, parameters=self.parameters)
        except OrionError as e:
            self.ok = False
            self.error = str(e)
            return self
        self.ok = True
        self.row_count = len(rows)
        self.rows = rows[:max_rows] if max_rows else rows
        self.truncated = bool(max_rows) and len(rows) > max_rows
        return self

    def to_dict(self):
        payload = {
            "probe": self.name,
            "expectation": self.expectation,
            "swql": self.swql,
            "parameters": self.parameters,
            "result": "ok" if self.ok else "FAILED",
        }
        if self.ok:
            payload["row_count"] = getattr(self, "row_count", len(self.rows))
            payload["rows_shown"] = len(self.rows)
            payload["truncated"] = getattr(self, "truncated", False)
            payload["rows"] = self.rows
        else:
            payload["error"] = self.error
        return payload


def build_probes(sample_rows):
    probes = [
        Probe(
            "connectivity",
            f"SWIS answers on the port given and the account can read "
            "Orion.Nodes. If this fails, nothing below is meaningful.",
            "SELECT TOP 1 NodeID FROM Orion.Nodes",
        ),
        Probe(
            "node count",
            "Returns a single row with the total number of monitored "
            "nodes -- tells us the size of the estate and whether paging "
            "matters.",
            "SELECT COUNT(NodeID) AS NodeCount FROM Orion.Nodes",
        ),
        Probe(
            "orion nodes properties",
            "Metadata.Property lists the real selectable properties of "
            "Orion.Nodes. This is the authoritative answer to 'what "
            "columns exist here' and supersedes anything assumed from "
            "documentation.",
            "SELECT Name, Type, IsNavigable FROM Metadata.Property "
            "WHERE EntityName = @entity ORDER BY Name",
            {"entity": "Orion.Nodes"},
        ),
        Probe(
            "node custom properties",
            "The custom properties this Orion defines on nodes (site, "
            "role, owner and similar are almost always modelled this "
            "way). Per-installation by definition, so this can only be "
            "discovered. May legitimately return zero rows if none are "
            "defined.",
            "SELECT Name, Type, IsNavigable FROM Metadata.Property "
            "WHERE EntityName = @entity ORDER BY Name",
            {"entity": "Orion.NodesCustomProperties"},
        ),
        Probe(
            "node related entities",
            "Which Node-related SWIS entities exist on this version -- "
            "confirms Orion.NodeIPAddresses and friends are really called "
            "that here.",
            "SELECT FullName, BaseType FROM Metadata.Entity "
            "WHERE FullName LIKE @pattern ORDER BY FullName",
            {"pattern": "%Node%"},
        ),
    ]

    # One probe per requested field, so the summary can attribute a
    # failure to the specific property rather than to the set.
    for label, prop in TARGET_FIELDS:
        probes.append(Probe(
            f"field {prop}",
            f"Orion.Nodes.{prop} exists and is the '{label}' asked for. "
            f"A failure here names the bad property in the SWIS error, "
            f"which is the fastest route to the correct name.",
            f"SELECT TOP {sample_rows} NodeID, {prop} FROM Orion.Nodes "
            f"ORDER BY NodeID",
            filename=f"field_{prop.lower()}.json",
        ))

    probes.extend([
        Probe(
            "combined default query",
            "All the default columns together -- the exact shape "
            "orion_devices.py will issue. Should succeed if every "
            "individual field probe above succeeded.",
            f"SELECT TOP {sample_rows} {', '.join(DEFAULT_NODE_COLUMNS)} "
            f"FROM Orion.Nodes ORDER BY NodeID",
        ),
        Probe(
            "status distribution",
            "How many nodes sit at each Status value. Confirms (or "
            "corrects) NODE_STATUS_NAMES in orion_client.py -- any code "
            "appearing here that is missing from that map is one the map "
            "would render as a bare number.",
            "SELECT Status, COUNT(NodeID) AS NodeCount FROM Orion.Nodes "
            "GROUP BY Status ORDER BY Status",
        ),
        Probe(
            "paging cursor",
            "The keyset-paging form get_nodes() uses (TOP n + WHERE "
            "NodeID > @after + ORDER BY). Confirms SWQL accepts TOP and "
            "a bound parameter in a WHERE clause -- the two things paging "
            "depends on.",
            f"SELECT TOP {sample_rows} NodeID, Caption FROM Orion.Nodes "
            f"WHERE NodeID > @__after ORDER BY NodeID",
            {"__after": 0},
        ),
        Probe(
            "node ip addresses",
            "Orion.NodeIPAddresses holds every discovered address on a "
            "node, as distinct from the single polling IP. Confirms the "
            "entity and its column names for any future 'all addresses' "
            "workflow. Not needed for the device list itself.",
            f"SELECT TOP {sample_rows} NodeID, IPAddress, IPAddressType, "
            f"InterfaceIndex FROM Orion.NodeIPAddresses ORDER BY NodeID",
        ),
    ])

    return probes


def write_summary(probes, out_dir, host):
    lines = [
        "SolarWinds Orion probe summary",
        f"host: {host}",
        "",
        "Each probe states what was expected BEFORE it ran; the verdict",
        "is this tool's, not a matter of interpreting raw output. Any",
        "FAILED line is a documented assumption that does not hold on",
        "this instance and must be corrected in orion_client.py.",
        "",
    ]

    width = max(len(p.name) for p in probes)
    passed = failed = 0
    for p in probes:
        if p.ok:
            passed += 1
            count = getattr(p, "row_count", len(p.rows))
            note = f"{count} row(s)"
            if count == 0:
                note += "  <- succeeded but returned nothing; see expectation"
            lines.append(f"  PASS  {p.name.ljust(width)}  {note}")
        else:
            failed += 1
            first_line = (p.error or "").splitlines()[0][:160]
            lines.append(f"  FAIL  {p.name.ljust(width)}  {first_line}")

    lines += [
        "",
        f"{passed} passed, {failed} failed, {len(probes)} total.",
        "",
        "Field probes specifically -- these are the four fields asked for:",
    ]
    for label, prop in TARGET_FIELDS:
        probe = next((p for p in probes if p.name == f"field {prop}"), None)
        verdict = "PASS" if probe and probe.ok else "FAIL"
        lines.append(f"  {verdict}  {label:<20} -> Orion.Nodes.{prop}")

    lines += [
        "",
        "Raw evidence for every probe is in the JSON files beside this",
        "summary. Bring the whole directory back across the airgap.",
        "",
    ]

    text = "\n".join(lines)
    (out_dir / "summary.txt").write_text(text, encoding="utf-8")
    return text


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--username", required=True,
                        help="Orion individual account. AD accounts take the "
                             "DOMAIN\\user form -- quote it on the shell.")
    parser.add_argument("--password-env", default=None,
                        help="Environment variable holding the password. "
                             "Without it you are prompted, not echoed.")
    parser.add_argument("--port", type=int, default=DEFAULT_SWIS_PORT,
                        help=f"SWIS SSL port (default: {DEFAULT_SWIS_PORT}). "
                             f"Orion 2022.4.1 and earlier used "
                             f"{LEGACY_SWIS_PORT}.")
    parser.add_argument("--insecure", action="store_true",
                        help="Skip TLS certificate validation -- usually "
                             "needed against a stock Orion's self-signed "
                             "certificate.")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--output-dir", default="orion-probe-output")
    parser.add_argument("--sample-rows", type=int, default=5,
                        help="Rows to capture per sample probe (default: 5). "
                             "Kept small so the output is easy to carry back "
                             "and review.")

    args = parser.parse_args()

    password = None
    if not args.password_env:
        password = getpass.getpass(f"Orion password for {args.username}: ")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        client = OrionClient(
            host=args.host,
            username=args.username,
            password=password,
            password_env=args.password_env,
            port=args.port,
            verify_ssl=not args.insecure,
            timeout=args.timeout,
        )
    except OrionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    probes = build_probes(args.sample_rows)

    print(f"Probing {client.base_url}\n")
    for probe in probes:
        # Every probe runs even if an earlier one failed: a failure is a
        # result, and stopping at the first would turn one wrong property
        # name into a wasted trip across the airgap.
        probe.run(client, max_rows=args.sample_rows)
        status = "ok" if probe.ok else "FAILED"
        print(f"  [{status:>6}] {probe.name}")
        (out_dir / probe.filename).write_text(
            json.dumps(probe.to_dict(), indent=2, default=str) + "\n",
            encoding="utf-8",
        )

    print()
    print(write_summary(probes, out_dir, args.host))
    print(f"Output written to {out_dir.resolve()}")

    # Non-zero if any probe failed, so this is usable as a gate rather
    # than something whose output has to be read to know if it worked.
    return 0 if all(p.ok for p in probes) else 1


if __name__ == "__main__":
    sys.exit(main())
