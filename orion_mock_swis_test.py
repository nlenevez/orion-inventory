#!/usr/bin/env python3
"""
orion_mock_swis_test.py

Unit tests for orion_client.py and orion_devices.py, run against a mock
SWIS server that speaks the real protocol over real TLS on localhost.

    python3 orion/orion_mock_swis_test.py

## Why a mock server rather than stubbed functions

There is no Orion instance on this side of the airgap, so the choice is
between testing nothing and testing against a stand-in. A stub that
replaces OrionClient.query() would exercise none of what is most likely
to be wrong: the Basic auth header, the POST body shape, TLS against a
self-signed certificate, HTTP error handling, and the paging cursor.
Those are the parts that talk to something foreign, so those are the
parts a test has to cover.

What this therefore does NOT prove: that Orion's real property names
are what this repo assumes. The mock's schema is this repo's assumption
-- a fixture written from the same belief as the code cannot disagree
with it. Only orion_probe.py against the real instance settles that,
which is exactly why that script exists and why its output is the gate
before anything here is trusted.

So: these tests confirm the client is internally correct and speaks the
protocol it thinks it does. They confirm nothing about SolarWinds.
"""

import base64
import json
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from orion_client import OrionClient, OrionError, format_status  # noqa: E402
import orion_devices  # noqa: E402

# Defined here rather than beside the tests that use it: the vault and
# inventory suites both gate on it, and the first of them appears well
# above where this used to live.
try:
    import ansible  # noqa: F401
    HAVE_ANSIBLE = True
except ImportError:  # pragma: no cover - depends on the host
    HAVE_ANSIBLE = False


USERNAME = "ansible"
PASSWORD = "correct-horse"

#: The mock's Orion.Nodes schema. Deliberately the same names the code
#: assumes -- see the module docstring on why that proves nothing about
#: the real Orion, only that the client is self-consistent.
MOCK_SCHEMA = {
    "NodeID", "Caption", "IPAddress", "MachineType", "SysName", "DNS",
    "Vendor", "Status", "Unmanaged",
}

#: Seven nodes, with NodeIDs that are deliberately non-contiguous -- a
#: cursor that assumed "next id = last + 1" would pass on 1..7 and fail
#: here.
MOCK_NODES = [
    {"NodeID": 1, "Caption": "core1", "IPAddress": "10.0.0.1",
     "MachineType": "Cisco ASR9000", "SysName": "core1.example.net",
     "DNS": "core1.example.com", "Vendor": "Cisco", "Status": 1,
     "Unmanaged": False},
    {"NodeID": 4, "Caption": "core2", "IPAddress": "10.0.0.2",
     "MachineType": "Cisco ASR9000", "SysName": "core2.example.net",
     "DNS": "core2.example.com", "Vendor": "Cisco", "Status": 2,
     "Unmanaged": False},
    {"NodeID": 9, "Caption": "edge1", "IPAddress": "10.0.0.3",
     "MachineType": "Juniper MX204", "SysName": "edge1", "DNS": "",
     "Vendor": "Juniper", "Status": 1, "Unmanaged": False},
    # No DNS and no SysName -- ICMP-only nodes really do look like this.
    {"NodeID": 12, "Caption": "ups-a", "IPAddress": "10.0.0.4",
     "MachineType": "APC UPS", "SysName": None, "DNS": None,
     "Vendor": "APC", "Status": 9, "Unmanaged": True},
    # Values that YAML would mangle if emitted unquoted.
    {"NodeID": 15, "Caption": "sw: lab", "IPAddress": "10.0.0.5",
     "MachineType": "Yes", "SysName": "2621", "DNS": "sw.example.com",
     "Vendor": "Cisco", "Status": 3, "Unmanaged": False},
    # Duplicate Caption -- Orion does not enforce uniqueness.
    {"NodeID": 18, "Caption": "core1", "IPAddress": "10.0.0.6",
     "MachineType": "Cisco ASR9000", "SysName": "core1b",
     "DNS": "core1b.example.com", "Vendor": "Cisco", "Status": 1,
     "Unmanaged": False},
    # No polling IP at all.
    {"NodeID": 21, "Caption": "orphan", "IPAddress": None,
     "MachineType": "Unknown", "SysName": "orphan", "DNS": None,
     "Vendor": "", "Status": 0, "Unmanaged": False},
]

MOCK_PROPERTIES = [{"Name": n, "Type": "System.String", "IsNavigable": False}
                   for n in sorted(MOCK_SCHEMA)]


class MockSwisHandler(BaseHTTPRequestHandler):
    """Implements enough of SWIS to exercise the client honestly:
    Basic auth, the JSON POST body, bound parameters, TOP, the paging
    WHERE clause, and SWIS-shaped errors for unknown properties."""

    server_version = "MockSWIS/1.0"

    def log_message(self, *args):
        pass  # keep the test output readable

    def _send_json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.server.request_log.append(self.path)

        if self.path != "/SolarWinds/InformationService/v3/Json/Query":
            self._send_json(404, {"Message": f"No route {self.path}"})
            return

        # Lets a test reproduce a status the mock has no natural way to
        # produce -- a 403 depends on Orion account configuration, not on
        # anything in the request. Checked before auth so a forced status
        # is not masked by the credential check.
        forced = getattr(self.server, "force_status", None)
        if forced:
            self._send_json(forced, {"Message": f"forced status {forced}"})
            return

        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            self._send_json(401, {"Message": "No Basic credentials"})
            return
        decoded = base64.b64decode(auth[6:]).decode("utf-8")
        if decoded != f"{USERNAME}:{PASSWORD}":
            self._send_json(401, {"Message": "Bad credentials"})
            return

        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except ValueError:
            self._send_json(400, {"Message": "Body was not JSON"})
            return

        swql = body.get("query", "")
        params = body.get("parameters", {}) or {}
        self.server.query_log.append((swql, params))

        try:
            results = self._execute(swql, params)
        except _SwqlError as e:
            self._send_json(400, {
                "Message": str(e),
                "ExceptionType": "SolarWinds.Data.SwisException",
            })
            return

        self._send_json(200, {"results": results})

    def _execute(self, swql, params):
        if "Metadata.Property" in swql:
            entity = params.get("entity")
            if entity == "Orion.Nodes":
                return MOCK_PROPERTIES
            if entity == "Orion.NodesCustomProperties":
                return [{"Name": "Site", "Type": "System.String",
                         "IsNavigable": False}]
            return []

        if "Metadata.Entity" in swql:
            return [{"FullName": "Orion.Nodes", "BaseType": "Orion.Node"},
                    {"FullName": "Orion.NodeIPAddresses",
                     "BaseType": "Orion.NodeIPAddress"}]

        if "Orion.NodeIPAddresses" in swql:
            return [{"NodeID": 1, "IPAddress": "10.0.0.1",
                     "IPAddressType": "IPv4", "InterfaceIndex": 1}]

        # GROUP BY is checked before the bare COUNT branch: the status
        # distribution query contains both, and testing COUNT first
        # would collapse it to a single total -- making the mock answer
        # a different question from the one asked.
        if "GROUP BY Status" in swql:
            counts = {}
            for node in MOCK_NODES:
                counts[node["Status"]] = counts.get(node["Status"], 0) + 1
            return [{"Status": s, "NodeCount": c}
                    for s, c in sorted(counts.items())]

        if "COUNT(" in swql.upper():
            return [{"NodeCount": len(MOCK_NODES)}]

        if "FROM Orion.Nodes" not in swql:
            raise _SwqlError(f"Unknown entity in query: {swql}")

        # -- SELECT [TOP n] <cols> FROM Orion.Nodes [WHERE ...] --------
        match = re.search(r"SELECT\s+(?:TOP\s+(\d+)\s+)?(.*?)\s+FROM\s+Orion\.Nodes",
                          swql, re.IGNORECASE | re.DOTALL)
        if not match:
            raise _SwqlError(f"Could not parse: {swql}")
        top = int(match.group(1)) if match.group(1) else None
        columns = [c.strip() for c in match.group(2).split(",")]

        for col in columns:
            if col not in MOCK_SCHEMA:
                # This is the behaviour that matters: a real SWIS
                # rejects an unknown property, it does not silently
                # return null for it.
                raise _SwqlError(
                    f"Entity Orion.Nodes does not contain property {col}"
                )

        rows = list(MOCK_NODES)

        cursor = re.search(r"NodeID\s*>\s*@(\w+)", swql)
        if cursor:
            after = params.get(cursor.group(1))
            if after is None:
                raise _SwqlError(
                    f"Parameter @{cursor.group(1)} referenced but not bound"
                )
            rows = [r for r in rows if r["NodeID"] > after]

        vendor = re.search(r"Vendor\s*=\s*@(\w+)", swql)
        if vendor:
            rows = [r for r in rows if r["Vendor"] == params.get(vendor.group(1))]

        unmanaged = re.search(r"Unmanaged\s*=\s*@(\w+)", swql)
        if unmanaged:
            want = params.get(unmanaged.group(1))
            # SWQL is typed: an integer 0 matches false, the string "0"
            # does not. The client's `int:` prefix exists for this.
            if not isinstance(want, int):
                raise _SwqlError(
                    f"Cannot compare Boolean to String for Unmanaged"
                )
            rows = [r for r in rows if r["Unmanaged"] == bool(want)]

        rows.sort(key=lambda r: r["NodeID"])
        if top is not None:
            rows = rows[:top]
        return [{c: r[c] for c in columns} for r in rows]


class _SwqlError(Exception):
    pass


def _make_cert(directory):
    key = Path(directory) / "key.pem"
    cert = Path(directory) / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return cert, key


class MockSwisServer:
    """Runs the mock over TLS with a self-signed certificate -- so the
    client's --insecure path is exercised for real rather than assumed."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        cert, key = _make_cert(self._tmp.name)

        self.httpd = HTTPServer(("127.0.0.1", 0), MockSwisHandler)
        self.httpd.request_log = []
        self.httpd.query_log = []
        self.httpd.force_status = None

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)

        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
        self.thread.start()

    @property
    def query_log(self):
        return self.httpd.query_log

    @property
    def force_status(self):
        return self.httpd.force_status

    @force_status.setter
    def force_status(self, value):
        self.httpd.force_status = value

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._tmp.cleanup()


class OrionClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = MockSwisServer()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        del self.server.query_log[:]
        self.client = OrionClient(
            host="127.0.0.1", username=USERNAME, password=PASSWORD,
            port=self.server.port, verify_ssl=False, timeout=15,
        )

    # -- transport ----------------------------------------------------

    def test_query_returns_rows_over_tls(self):
        rows = self.client.query("SELECT NodeID, Caption FROM Orion.Nodes")
        self.assertEqual(len(rows), len(MOCK_NODES))
        self.assertEqual(rows[0]["Caption"], "core1")

    def test_bad_password_raises_401(self):
        """Negative control for the auth path: if the mock accepted
        anything, every other test here would pass just as well with a
        wrong password."""
        bad = OrionClient(host="127.0.0.1", username=USERNAME,
                          password="wrong", port=self.server.port,
                          verify_ssl=False, timeout=15)
        with self.assertRaises(OrionError) as ctx:
            bad.query("SELECT NodeID FROM Orion.Nodes")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_tls_verification_actually_verifies(self):
        """Negative control for --insecure: with verification on, the
        self-signed certificate must be rejected. If this passed, the
        insecure flag would be doing nothing and the tests above would
        prove nothing about TLS."""
        strict = OrionClient(host="127.0.0.1", username=USERNAME,
                             password=PASSWORD, port=self.server.port,
                             verify_ssl=True, timeout=15)
        with self.assertRaises(OrionError) as ctx:
            strict.query("SELECT NodeID FROM Orion.Nodes")
        self.assertIn("certificate", str(ctx.exception).lower())

    def test_unknown_property_surfaces_swis_error(self):
        with self.assertRaises(OrionError) as ctx:
            self.client.query("SELECT NoSuchColumn FROM Orion.Nodes")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.exception_type,
                         "SolarWinds.Data.SwisException")
        self.assertIn("NoSuchColumn", str(ctx.exception))

    def test_403_explains_the_ad_group_cause(self):
        """A live instance returned 403 with valid credentials. SWIS
        returns 401 for a bad password, so a 403 is authorisation --
        classically an AD account whose Orion access comes via a Windows
        group, which SWIS cannot authenticate even though the web UI
        can. The message has to say that; "403 Forbidden" alone sends
        the reader back to re-checking the password, which is the one
        thing already excluded."""
        self.server.force_status = 403
        try:
            with self.assertRaises(OrionError) as ctx:
                self.client.query("SELECT NodeID FROM Orion.Nodes")
        finally:
            self.server.force_status = None

        message = str(ctx.exception)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("401 for a bad password", message)
        self.assertIn("GROUP", message)
        self.assertIn("INDIVIDUAL account", message)
        self.assertIn("InformationService", message)

    def test_401_and_403_are_distinguished(self):
        """Negative control: the two must not collapse into one message.
        A 401 is a password problem and a 403 is not, and telling the
        reader to go and reconfigure an AD account when the password is
        simply wrong would be worse than saying nothing."""
        bad = OrionClient(host="127.0.0.1", username=USERNAME,
                          password="wrong", port=self.server.port,
                          verify_ssl=False, timeout=15)
        with self.assertRaises(OrionError) as ctx:
            bad.query("SELECT NodeID FROM Orion.Nodes")
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertNotIn("GROUP", str(ctx.exception))

    def test_404_names_the_port_change(self):
        """A live 2026.2.1 instance returned 404 on port 17778, because
        the REST endpoint moved to 17774 in Orion 2023.1 and something
        else still answers on the old port -- so it presents as a bad
        path, not a dead port. That cost a round trip across the airgap.
        The message must now say so.

        The 404 is produced by pointing the client at a path the mock
        does not route, which is the same thing an out-of-date port does
        in practice: an HTTP server that answers but does not know this
        URL.
        """
        import orion_client
        original = orion_client.SWIS_BASE_PATH
        try:
            orion_client.SWIS_BASE_PATH = "/NotTheSwisPath/v3/Json"
            client = OrionClient(host="127.0.0.1", username=USERNAME,
                                 password=PASSWORD, port=self.server.port,
                                 verify_ssl=False, timeout=15)
            with self.assertRaises(OrionError) as ctx:
                client.query("SELECT NodeID FROM Orion.Nodes")
        finally:
            orion_client.SWIS_BASE_PATH = original

        message = str(ctx.exception)
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("wrong port", message)
        self.assertIn("17778", message)
        self.assertIn("2023.1", message)
        self.assertIn("orion_endpoint_probe.py", message)

    def test_non_404_errors_do_not_mention_the_port(self):
        """Negative control for the hint above: it must be attached to
        404s specifically, not pasted onto every failure. A 400 from a
        bad property is not a port problem, and saying so would send the
        next person down the wrong path."""
        with self.assertRaises(OrionError) as ctx:
            self.client.query("SELECT NoSuchColumn FROM Orion.Nodes")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertNotIn("wrong port", str(ctx.exception))

    def test_default_port_is_the_current_one(self):
        """Orion 2023.1 moved REST from 17778 to 17774."""
        from orion_client import DEFAULT_SWIS_PORT, LEGACY_SWIS_PORT
        self.assertEqual(DEFAULT_SWIS_PORT, 17774)
        self.assertEqual(LEGACY_SWIS_PORT, 17778)
        client = OrionClient(host="orion.example.com", username="u",
                             password="p")
        self.assertIn(":17774/", client.base_url)

    def test_connection_refused_is_reported_clearly(self):
        dead = OrionClient(host="127.0.0.1", username=USERNAME,
                           password=PASSWORD, port=1, verify_ssl=False,
                           timeout=5)
        with self.assertRaises(OrionError) as ctx:
            dead.query("SELECT NodeID FROM Orion.Nodes")
        self.assertIn("Connection failed", str(ctx.exception))

    def test_parameters_are_bound_not_interpolated(self):
        rows = self.client.query(
            "SELECT NodeID, Caption FROM Orion.Nodes WHERE Vendor = @v",
            parameters={"v": "Juniper"},
        )
        self.assertEqual([r["Caption"] for r in rows], ["edge1"])
        swql, params = self.server.query_log[-1]
        self.assertIn("@v", swql)
        self.assertEqual(params, {"v": "Juniper"})
        self.assertNotIn("Juniper", swql)

    # -- host normalisation -------------------------------------------

    def test_host_normalisation(self):
        for given in ("orion.example.com", "https://orion.example.com",
                      "https://orion.example.com:17774",
                      "https://orion.example.com/Orion/Login.aspx"):
            client = OrionClient(host=given, username="u", password="p")
            self.assertEqual(client.host, "orion.example.com", given)
            self.assertEqual(
                client.base_url,
                "https://orion.example.com:17774"
                "/SolarWinds/InformationService/v3/Json",
            )

    # -- paging -------------------------------------------------------

    def test_paging_returns_every_node_exactly_once(self):
        rows = self.client.get_nodes(page_size=2)
        ids = [r["NodeID"] for r in rows]
        self.assertEqual(ids, [n["NodeID"] for n in MOCK_NODES])
        self.assertEqual(len(ids), len(set(ids)), "duplicate rows across pages")

    def test_paging_actually_pages(self):
        """Guards against the result above being right by accident --
        with 7 nodes and page_size=2 the client must issue 4 queries
        (2+2+2+1). A client that ignored page_size would return the same
        7 rows in one query and the assertion above would still pass."""
        self.client.get_nodes(page_size=2)
        node_queries = [q for q, _ in self.server.query_log
                        if "FROM Orion.Nodes" in q]
        self.assertEqual(len(node_queries), 4)
        self.assertTrue(all("TOP 2" in q for q in node_queries))

    def test_paging_cursor_advances_past_gaps(self):
        cursors = []
        self.client.get_nodes(page_size=2)
        for _, params in self.server.query_log:
            if "__after" in params:
                cursors.append(params["__after"])
        # NodeIDs are 1,4,9,12,15,18,21 -- a naive last+1 cursor would
        # produce 2,5,... and stall.
        self.assertEqual(cursors, [-1, 4, 12, 18])

    def test_no_paging_issues_single_query(self):
        rows = self.client.get_nodes(page_size=None)
        self.assertEqual(len(rows), len(MOCK_NODES))
        node_queries = [q for q, _ in self.server.query_log
                        if "FROM Orion.Nodes" in q]
        self.assertEqual(len(node_queries), 1)
        self.assertNotIn("TOP", node_queries[0])

    def test_paging_combines_with_where_clause(self):
        rows = self.client.get_nodes(
            page_size=2, where="Vendor = @v", parameters={"v": "Cisco"},
        )
        self.assertEqual([r["Caption"] for r in rows],
                         ["core1", "core2", "sw: lab", "core1"])

    def test_nodeid_is_always_selected(self):
        rows = self.client.get_nodes(columns=["Caption", "IPAddress"])
        self.assertIn("NodeID", rows[0])

    # -- the four requested fields ------------------------------------

    def test_default_columns_are_the_requested_fields(self):
        rows = self.client.get_nodes()
        for field in ("IPAddress", "MachineType", "SysName", "DNS"):
            self.assertIn(field, rows[0], f"{field} missing from default query")

    # -- schema discovery ---------------------------------------------

    def test_discover_properties(self):
        props = self.client.discover_properties()
        self.assertIn("MachineType", [p["Name"] for p in props])

    def test_discover_custom_properties(self):
        props = self.client.discover_custom_properties()
        self.assertEqual([p["Name"] for p in props], ["Site"])

    # -- status rendering ---------------------------------------------

    def test_format_status_known_and_unknown(self):
        self.assertEqual(format_status(1), "Up")
        self.assertEqual(format_status(2), "Down")
        # An undocumented code must show as itself, not be mislabelled.
        self.assertEqual(format_status(99), "99")
        self.assertEqual(format_status(None), "")


class OutputFormatTests(unittest.TestCase):
    """Renderers are pure functions of rows+columns, so they are tested
    directly against the awkward rows in MOCK_NODES."""

    COLUMNS = ["NodeID", "Caption", "IPAddress", "MachineType", "SysName", "DNS"]

    def rows(self):
        return [{c: n.get(c) for c in self.COLUMNS} for n in MOCK_NODES]

    def test_table_renders_none_as_blank(self):
        text = orion_devices.render_table(self.rows(), self.COLUMNS)
        self.assertIn("ups-a", text)
        self.assertNotIn("None", text)
        self.assertIn("7 node(s)", text)

    def test_table_handles_no_rows(self):
        self.assertIn("no nodes matched",
                      orion_devices.render_table([], self.COLUMNS))

    def test_csv_has_header_and_row_per_node(self):
        import csv as csv_module
        import io as io_module
        text = orion_devices.render_csv(self.rows(), self.COLUMNS)
        parsed = list(csv_module.reader(io_module.StringIO(text)))
        self.assertEqual(parsed[0], self.COLUMNS)
        self.assertEqual(len(parsed), len(MOCK_NODES) + 1)
        # Round-trip rather than asserting on quoting: csv quotes only
        # when it must, so checking for literal quotes would test the
        # stdlib's formatting choices instead of our correctness.
        captions = [row[self.COLUMNS.index("Caption")] for row in parsed[1:]]
        self.assertIn("sw: lab", captions)
        # A None must land as an empty field, not the string "None".
        orphan = parsed[1 + [n["NodeID"] for n in MOCK_NODES].index(21)]
        self.assertEqual(orphan[self.COLUMNS.index("DNS")], "")

    def test_json_is_projected_to_selected_columns(self):
        parsed = json.loads(orion_devices.render_json(self.rows(), self.COLUMNS))
        self.assertEqual(len(parsed), len(MOCK_NODES))
        self.assertEqual(set(parsed[0]), set(self.COLUMNS))

    def test_inventory_is_valid_yaml_and_preserves_types(self):
        import yaml
        text = orion_devices.render_inventory(self.rows(), self.COLUMNS)
        parsed = yaml.safe_load(text)
        hosts = parsed["all"]["children"]["orion_nodes"]["hosts"]

        self.assertEqual(len(hosts), len(MOCK_NODES))
        self.assertEqual(hosts["core1"]["ansible_host"], "10.0.0.1")

        # The values chosen to break naive YAML emission.
        lab = hosts["sw__lab"]
        self.assertEqual(lab["orion_machinetype"], "Yes")
        self.assertIsInstance(lab["orion_machinetype"], str)
        self.assertEqual(lab["orion_sysname"], "2621")
        self.assertIsInstance(lab["orion_sysname"], str)

        # Duplicate Caption must not collapse two nodes into one.
        self.assertIn("core1_18", hosts)

        # A node with no polling IP is present and flagged, not dropped.
        self.assertNotIn("ansible_host", hosts["orphan"])
        self.assertTrue(hosts["orphan"]["orion_polling_ip_missing"])

    def test_inventory_fallback_matches_pyyaml_output(self):
        """The hand-rolled emitter exists for a box without PyYAML. If
        it drifted from the PyYAML path, that difference would only ever
        show up on the airgapped side, where it is most expensive to
        find."""
        import yaml
        rows, cols = self.rows(), self.COLUMNS

        original = orion_devices.HAVE_PYYAML
        try:
            orion_devices.HAVE_PYYAML = False
            fallback = orion_devices.render_inventory(rows, cols)
        finally:
            orion_devices.HAVE_PYYAML = original
        with_pyyaml = orion_devices.render_inventory(rows, cols)

        self.assertNotEqual(fallback, with_pyyaml, "test is not exercising "
                            "two different code paths")
        self.assertEqual(yaml.safe_load(fallback), yaml.safe_load(with_pyyaml))

    def test_inventory_handles_no_rows(self):
        import yaml
        for flag in (True, False):
            original = orion_devices.HAVE_PYYAML
            try:
                orion_devices.HAVE_PYYAML = flag
                text = orion_devices.render_inventory([], self.COLUMNS)
            finally:
                orion_devices.HAVE_PYYAML = original
            parsed = yaml.safe_load(text)
            hosts = parsed["all"]["children"]["orion_nodes"]["hosts"]
            self.assertIn(hosts, ({}, None), f"HAVE_PYYAML={flag}")


class ParamParsingTests(unittest.TestCase):
    def test_strings_by_default(self):
        self.assertEqual(orion_devices.parse_params(["v=Cisco"]), {"v": "Cisco"})

    def test_int_prefix(self):
        self.assertEqual(orion_devices.parse_params(["u=int:0"]), {"u": 0})

    def test_rejects_missing_equals(self):
        with self.assertRaises(SystemExit):
            orion_devices.parse_params(["novalue"])

    def test_rejects_non_integer_int(self):
        with self.assertRaises(SystemExit):
            orion_devices.parse_params(["u=int:abc"])


@unittest.skipUnless(HAVE_ANSIBLE, "ansible-core not installed")
class VaultSecretTests(unittest.TestCase):
    """--use-vault-secret against a REAL ansible-vault-encrypted file.

    Encrypts with the actual `ansible-vault` binary rather than a
    fixture: the point is that the file this reads is the file
    ansible-vault produces, and a hand-written stand-in would only prove
    the reader agrees with itself. This path shipped untested and is a
    credential path, which is the worst combination to leave uncovered.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = MockSwisServer()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        # ansible-core's vault secrets context is PROCESS-GLOBAL and
        # first-write-wins, with no public reset. Another test class
        # initialises it with a different password, which leaves inline
        # `!vault` scalars here undecryptable -- these tests passed in
        # isolation and failed in the suite until this was added.
        # Reaching for the private attribute is the only way to give each
        # test a clean context; the alternative is a test that only works
        # when run alone, which is worse.
        try:
            from ansible.parsing.vault import VaultSecretsContext
            VaultSecretsContext._current = None
        except ImportError:  # pragma: no cover - older ansible-core
            pass

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)

        self.vault_pass = root / "vault_pass"
        self.vault_pass.write_text("the-vault-password\n", encoding="utf-8")

        self.secret = root / "orion_secret.yml"
        self.secret.write_text(f"username: {USERNAME}\npassword: {PASSWORD}\n",
                               encoding="utf-8")
        result = subprocess.run(
            ["ansible-vault", "encrypt", str(self.secret),
             "--vault-password-file", str(self.vault_pass)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.secret.read_text().startswith("$ANSIBLE_VAULT"),
                        "fixture is not actually encrypted")

    def run_cli(self, *extra):
        import io
        import contextlib
        argv = ["orion_devices.py", "--host", "127.0.0.1",
                "--port", str(self.server.port), "--insecure", *extra]
        out, err = io.StringIO(), io.StringIO()
        old = sys.argv
        sys.argv = argv
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    code = orion_devices.main()
                except SystemExit as e:
                    code = e.code
        finally:
            sys.argv = old
        return code, out.getvalue(), err.getvalue()

    def test_credentials_come_from_the_vault(self):
        """No --username and no --password-env: both must come out of
        the encrypted file."""
        code, out, err = self.run_cli(
            "--use-vault-secret", "--secret-path", str(self.secret),
            "--vault-password-file", str(self.vault_pass), "--format", "json")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(json.loads(out)), len(MOCK_NODES))

    def test_vault_password_from_environment(self):
        import os
        os.environ["ANSIBLE_VAULT_PASSWORD_FILE"] = str(self.vault_pass)
        self.addCleanup(os.environ.pop, "ANSIBLE_VAULT_PASSWORD_FILE", None)
        code, out, err = self.run_cli(
            "--use-vault-secret", "--secret-path", str(self.secret),
            "--format", "json")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(json.loads(out)), len(MOCK_NODES))

    def test_username_argument_overrides_the_file(self):
        """The file carries a username, but an explicit one wins -- so a
        single shared secret can serve more than one account."""
        code, _, err = self.run_cli(
            "--use-vault-secret", "--secret-path", str(self.secret),
            "--vault-password-file", str(self.vault_pass),
            "--username", "someone-else", "--format", "json")
        # Wrong username against the mock's fixed credentials -> 401,
        # which is proof the override reached the wire.
        self.assertEqual(code, 1)
        self.assertIn("401", err)

    def test_wrong_vault_password_fails(self):
        """Negative control: if this passed, the tests above would prove
        nothing about decryption actually happening."""
        bad = Path(self.tmp.name) / "bad_pass"
        bad.write_text("wrong\n", encoding="utf-8")
        code, _, err = self.run_cli(
            "--use-vault-secret", "--secret-path", str(self.secret),
            "--vault-password-file", str(bad), "--format", "json")
        self.assertEqual(code, 1)
        self.assertIn("decrypt", err.lower())

    def _encrypt(self, path):
        result = subprocess.run(
            ["ansible-vault", "encrypt", str(path),
             "--vault-password-file", str(self.vault_pass)],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_existing_vars_file_with_custom_key_names(self):
        """The realistic case: credentials already live in a vars file
        alongside unrelated variables, under names of the estate's own
        choosing. Requiring a purpose-made file would mean maintaining
        the Orion credentials in two places."""
        path = Path(self.tmp.name) / "group_vars_all.yml"
        path.write_text(
            f"---\nntp_servers:\n  - 10.0.0.1\n"
            f"orion_api_user: {USERNAME}\n"
            f"orion_api_password: {PASSWORD}\n"
            f"snmp_community: public\n", encoding="utf-8")
        self._encrypt(path)

        code, out, err = self.run_cli(
            "--use-vault-secret", "--secret-path", str(path),
            "--vault-password-file", str(self.vault_pass),
            "--username-key", "orion_api_user",
            "--password-key", "orion_api_password", "--format", "json")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(json.loads(out)), len(MOCK_NODES))

    def test_nested_values_via_dotted_path(self):
        path = Path(self.tmp.name) / "nested.yml"
        path.write_text(
            f"---\norion:\n  api:\n    username: {USERNAME}\n"
            f"    password: {PASSWORD}\n", encoding="utf-8")
        self._encrypt(path)

        code, out, err = self.run_cli(
            "--use-vault-secret", "--secret-path", str(path),
            "--vault-password-file", str(self.vault_pass),
            "--username-key", "orion.api.username",
            "--password-key", "orion.api.password", "--format", "json")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(json.loads(out)), len(MOCK_NODES))

    def test_inline_encrypt_string_scalar(self):
        """A PLAINTEXT vars file with only the password encrypted, which
        is what `ansible-vault encrypt_string` produces and the most
        common shape for an existing file.

        This one genuinely broke: ansible-core returns a lazy object for
        such scalars that decrypts on access via a process-global secrets
        context, which ansible-playbook establishes during CLI bootstrap
        and an API caller does not. str() on it raised "A required
        VaultSecretsContext context is not active" -- at the point of
        use, far from the load that looked responsible.
        """
        encrypted = subprocess.run(
            ["ansible-vault", "encrypt_string", PASSWORD,
             "--name", "orion_api_password",
             "--vault-password-file", str(self.vault_pass)],
            capture_output=True, text=True, check=True).stdout

        path = Path(self.tmp.name) / "inline.yml"
        path.write_text(f"---\norion_api_user: {USERNAME}\n{encrypted}\n",
                        encoding="utf-8")
        # The file itself must stay readable -- that is the entire point
        # of encrypt_string over encrypting the whole file.
        self.assertFalse(path.read_text().startswith("$ANSIBLE_VAULT"))
        self.assertIn("!vault", path.read_text())

        code, out, err = self.run_cli(
            "--use-vault-secret", "--secret-path", str(path),
            "--vault-password-file", str(self.vault_pass),
            "--username-key", "orion_api_user",
            "--password-key", "orion_api_password", "--format", "json")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(json.loads(out)), len(MOCK_NODES))

    def test_wrong_key_name_names_the_key_and_lists_what_is_there(self):
        """Negative control for the key-name feature, and the error that
        makes it usable: "not found" alone would leave the reader
        guessing at the spelling of their own variable."""
        path = Path(self.tmp.name) / "vars.yml"
        path.write_text(f"---\norion_api_user: {USERNAME}\n"
                        f"orion_api_password: {PASSWORD}\n", encoding="utf-8")
        self._encrypt(path)

        code, _, err = self.run_cli(
            "--use-vault-secret", "--secret-path", str(path),
            "--vault-password-file", str(self.vault_pass),
            "--username-key", "orion_api_user",
            "--password-key", "no_such_var", "--format", "json")
        self.assertEqual(code, 1)
        self.assertIn("no_such_var", err)
        self.assertIn("orion_api_password", err, "should list what IS there")

    def test_missing_secret_file_explains_how_to_create_one(self):
        code, _, err = self.run_cli(
            "--use-vault-secret",
            "--secret-path", str(Path(self.tmp.name) / "nope.yml"),
            "--vault-password-file", str(self.vault_pass), "--format", "json")
        self.assertEqual(code, 1)
        self.assertIn("not found", err)
        self.assertIn("ansible-vault encrypt", err)


class CliEndToEndTests(unittest.TestCase):
    """Drives main() the way an operator does -- argv in, text out."""

    @classmethod
    def setUpClass(cls):
        cls.server = MockSwisServer()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def run_cli(self, *extra):
        import io
        import contextlib
        argv = ["--host", "127.0.0.1", "--username", USERNAME,
                "--password-env", "ORION_TEST_PASSWORD",
                "--port", str(self.server.port), "--insecure", *extra]
        out, err = io.StringIO(), io.StringIO()
        old = sys.argv
        sys.argv = ["orion_devices.py"] + list(argv)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = orion_devices.main()
        finally:
            sys.argv = old
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        import os
        os.environ["ORION_TEST_PASSWORD"] = PASSWORD

    def test_default_table_lists_every_node(self):
        code, out, _ = self.run_cli()
        self.assertEqual(code, 0)
        self.assertIn("7 node(s)", out)
        for header in ("IPAddress", "MachineType", "SysName", "DNS"):
            self.assertIn(header, out)

    def test_csv_output_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "devices.csv"
            code, _, err = self.run_cli("--format", "csv",
                                        "--output", str(target))
            self.assertEqual(code, 0)
            self.assertIn("Wrote 7 node(s)", err)
            lines = target.read_text().strip().splitlines()
            self.assertEqual(len(lines), 8)

    def test_where_with_int_param(self):
        code, out, _ = self.run_cli("--where", "Unmanaged = @u",
                                    "--param", "u=int:0", "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)), 6)

    def test_where_with_wrong_param_type_fails_loudly(self):
        """SWQL is typed. Without the int: prefix this comparison is a
        server-side type error, and the CLI must surface it rather than
        return an empty list that reads as 'no matches'."""
        code, _, err = self.run_cli("--where", "Unmanaged = @u",
                                    "--param", "u=0", "--format", "json")
        self.assertEqual(code, 1)
        self.assertIn("ERROR", err)

    def test_extra_columns_are_added(self):
        code, out, _ = self.run_cli("--extra-columns", "Vendor,Status",
                                    "--format", "json")
        self.assertEqual(code, 0)
        parsed = json.loads(out)
        self.assertIn("Vendor", parsed[0])
        # Status must be rendered as a label, not left as a bare integer.
        self.assertIn("Up", [r["Status"] for r in parsed])

    def test_unknown_column_exits_nonzero_with_swis_message(self):
        code, _, err = self.run_cli("--extra-columns", "NoSuchColumn")
        self.assertEqual(code, 1)
        self.assertIn("NoSuchColumn", err)
        self.assertIn("SolarWinds.Data.SwisException", err)

    def test_list_columns(self):
        code, out, _ = self.run_cli("--list-columns")
        self.assertEqual(code, 0)
        self.assertIn("MachineType", out)

    def test_list_custom_properties(self):
        code, out, _ = self.run_cli("--list-custom-properties")
        self.assertEqual(code, 0)
        self.assertIn("Site", out)

    def test_missing_password_env_is_a_clear_error(self):
        import os
        os.environ.pop("ORION_TEST_PASSWORD", None)
        code, _, err = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("ORION_TEST_PASSWORD", err)


import orion_inventory_sync as sync  # noqa: E402


class ReconcileTests(unittest.TestCase):
    """The matching rules, tested directly. reconcile() is a pure
    function of (Orion rows, inventory indexes), so the rules can be
    exercised without standing up an inventory -- and each rule can be
    isolated, which a whole-inventory test cannot do."""

    def verdicts(self, rows, by_ip=None, by_name=None, by_short=None,
                 short_name_match=True):
        return sync.reconcile(rows, by_ip or {}, by_name or {},
                              by_short or {}, short_name_match=short_name_match)

    def test_new_when_nothing_matches(self):
        [v] = self.verdicts([{"Caption": "core1", "IPAddress": "10.0.0.1"}])
        self.assertEqual(v.state, sync.Verdict.NEW)

    def test_polling_ip_match_wins(self):
        [v] = self.verdicts(
            [{"Caption": "core1", "IPAddress": "10.0.0.1"}],
            by_ip={"10.0.0.1": ["rtr-core-1"]},
            by_name={"core1": ["rtr-core-1"]},
        )
        self.assertEqual(v.state, sync.Verdict.EXISTS)
        self.assertEqual(v.rule, "polling-ip")
        self.assertEqual(v.matched_host, "rtr-core-1")

    def test_exact_name_match_is_case_insensitive(self):
        [v] = self.verdicts(
            [{"Caption": "CORE1", "IPAddress": "10.0.0.1"}],
            by_name={"core1": ["core1"]},
        )
        self.assertEqual(v.state, sync.Verdict.EXISTS)
        self.assertEqual(v.rule, "name")

    def test_sysname_and_dns_are_both_considered(self):
        for field in ("SysName", "DNS"):
            with self.subTest(field=field):
                [v] = self.verdicts(
                    [{"Caption": "unrecognised", field: "core1.example.com",
                      "IPAddress": "10.0.0.1"}],
                    by_name={"core1.example.com": ["core1.example.com"]},
                )
                self.assertEqual(v.state, sync.Verdict.EXISTS)

    def test_trailing_dot_on_dns_is_normalised(self):
        [v] = self.verdicts(
            [{"Caption": "x", "DNS": "core1.example.com."}],
            by_name={"core1.example.com": ["core1.example.com"]},
        )
        self.assertEqual(v.state, sync.Verdict.EXISTS)

    def test_short_name_match(self):
        rows = [{"Caption": "core1.example.com", "IPAddress": "10.0.0.1"}]
        [v] = self.verdicts(rows, by_short={"core1": ["core1"]})
        self.assertEqual(v.state, sync.Verdict.EXISTS)
        self.assertEqual(v.rule, "short-name")

    def test_short_name_match_can_be_disabled(self):
        """The one rule that can produce a false 'already exists'. With
        it off the device must come back NEW -- a duplicate is easier to
        spot than a device silently never added."""
        rows = [{"Caption": "core1.example.com", "IPAddress": "10.0.0.1"}]
        [v] = self.verdicts(rows, by_short={"core1": ["core1"]},
                            short_name_match=False)
        self.assertEqual(v.state, sync.Verdict.NEW)

    def test_ambiguous_when_ip_and_name_disagree(self):
        [v] = self.verdicts(
            [{"Caption": "ups-a", "IPAddress": "10.0.0.4"}],
            by_ip={"10.0.0.4": ["legacy-ups"]},
            by_name={"ups-a": ["ups-a"]},
        )
        self.assertEqual(v.state, sync.Verdict.AMBIGUOUS)
        self.assertIsNone(v.matched_host)
        self.assertIn("legacy-ups", v.detail)
        self.assertIn("ups-a", v.detail)

    def test_agreeing_rules_are_not_ambiguous(self):
        [v] = self.verdicts(
            [{"Caption": "core1", "IPAddress": "10.0.0.1"}],
            by_ip={"10.0.0.1": ["core1"]},
            by_name={"core1": ["core1"]},
            by_short={"core1": ["core1"]},
        )
        self.assertEqual(v.state, sync.Verdict.EXISTS)

    def test_missing_ip_does_not_match_empty_key(self):
        """A node with no polling IP must not match an inventory entry
        just because both are blank."""
        [v] = self.verdicts([{"Caption": "orphan", "IPAddress": None}],
                            by_ip={"": ["something"]})
        self.assertEqual(v.state, sync.Verdict.NEW)


@unittest.skipUnless(HAVE_ANSIBLE, "ansible-core not installed")
class InventorySyncEndToEndTests(unittest.TestCase):
    """Drives orion_inventory_sync.main() against a real Ansible
    inventory file and the mock Orion server.

    Uses a real inventory read through Ansible's own InventoryManager
    rather than a stubbed index, because "already exists" is defined as
    "what Ansible sees" -- a hand-built dict would be testing a
    different question from the one the tool answers.
    """

    INVENTORY = """
all:
  children:
    routers:
      hosts:
        core1:
          ansible_host: 10.0.0.1
        core2.example.net:
          ansible_host: 10.99.99.99
        edge1:
          ansible_host: 10.88.88.88
        legacy-ups:
          ansible_host: 10.0.0.4
        ups-a:
          ansible_host: 10.77.77.77
"""

    @classmethod
    def setUpClass(cls):
        cls.server = MockSwisServer()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        import os
        os.environ["ORION_TEST_PASSWORD"] = PASSWORD
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.inventory = Path(self.tmp.name) / "inventory.yml"
        self.inventory.write_text(self.INVENTORY, encoding="utf-8")

        # This repo's ansible.cfg sets vault_password_file = ~/.vault_pass,
        # and Ansible insists the file exists once it is configured --
        # even for an inventory with nothing encrypted in it. Production
        # boxes have it; this one does not, so the tests supply their
        # own rather than skipping the vault path entirely.
        self.vault_pass = Path(self.tmp.name) / "vault_pass"
        self.vault_pass.write_text("not-a-real-password\n", encoding="utf-8")

    def run_sync(self, *extra):
        import io
        import contextlib
        argv = ["orion_inventory_sync.py",
                "--host", "127.0.0.1", "--username", USERNAME,
                "--password-env", "ORION_TEST_PASSWORD",
                "--port", str(self.server.port), "--insecure",
                "--vault-password-file", str(self.vault_pass),
                "--inventory", str(self.inventory), *extra]
        out, err = io.StringIO(), io.StringIO()
        old = sys.argv
        sys.argv = argv
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = sync.main()
        finally:
            sys.argv = old
        return code, out.getvalue(), err.getvalue()

    def test_report_classifies_every_orion_device(self):
        code, out, _ = self.run_sync()
        self.assertEqual(code, 0)
        # core1(1) by IP, core2(4) by name, edge1(9) by name, core1(18)
        # by name = 4 existing; ups-a(12) ambiguous; sw: lab(15) and
        # orphan(21) new.
        self.assertIn("2 new, 4 already in inventory, 1 ambiguous", out)
        self.assertIn("of 7 in Orion", out)

    def test_ambiguous_device_is_reported_and_not_added(self):
        target = Path(self.tmp.name) / "new.yml"
        code, out, _ = self.run_sync("--write-new", str(target))
        self.assertEqual(code, 0)
        self.assertIn("AMBIGUOUS", out)

        import yaml
        hosts = yaml.safe_load(target.read_text())["all"]["children"][
            "orion_discovered"]["hosts"]
        self.assertNotIn("ups-a", hosts)
        self.assertEqual(set(hosts), {"sw__lab", "orphan"})

    def test_write_new_does_not_touch_existing_inventory(self):
        before = self.inventory.read_text()
        target = Path(self.tmp.name) / "new.yml"
        code, _, _ = self.run_sync("--write-new", str(target))
        self.assertEqual(code, 0)
        self.assertEqual(self.inventory.read_text(), before)

    def test_write_new_output_is_a_usable_inventory(self):
        """Parsed by Ansible itself, not just by PyYAML -- a file that
        is valid YAML but not a valid inventory would pass a yaml.load
        check and still be useless."""
        from ansible.inventory.manager import InventoryManager
        from ansible.parsing.dataloader import DataLoader

        target = Path(self.tmp.name) / "new.yml"
        self.run_sync("--write-new", str(target))

        manager = InventoryManager(loader=DataLoader(), sources=[str(target)])
        names = sorted(h.name for h in manager.get_hosts())
        self.assertEqual(names, ["orphan", "sw__lab"])
        host = manager.get_host("sw__lab")
        self.assertEqual(host.vars["ansible_host"], "10.0.0.5")

    def test_default_inventory_discovery(self):
        """The path with no --inventory at all.

        This is where a real bug lived: find_default_inventory() returns
        a *list*, and the caller wrapped it in another one, producing
        [['inventory.yml']] which InventoryManager rejects. Every other
        test here passes --inventory explicitly, so none of them ever
        reached this code. Found by porting the module to this repo, not
        by the suite -- hence this test.
        """
        import os
        import io
        import contextlib

        from inventory_reader import find_default_inventory
        # The return shape is the whole point: a list, not a bare string.
        self.assertIsInstance(find_default_inventory(), (list, type(None)))

        cwd = os.getcwd()
        os.chdir(self.tmp.name)          # inventory.yml is in here
        try:
            argv = ["orion_inventory_sync.py",
                    "--host", "127.0.0.1", "--username", USERNAME,
                    "--password-env", "ORION_TEST_PASSWORD",
                    "--port", str(self.server.port), "--insecure",
                    "--vault-password-file", str(self.vault_pass)]
            old = sys.argv
            sys.argv = argv
            out = io.StringIO()
            try:
                with contextlib.redirect_stdout(out), \
                        contextlib.redirect_stderr(io.StringIO()):
                    code = sync.main()
            finally:
                sys.argv = old
        finally:
            os.chdir(cwd)

        self.assertEqual(code, 0)
        # Same verdicts as the explicit-inventory run: it found the same
        # file, rather than silently falling back to an empty inventory
        # (which would have reported all 7 devices as new).
        self.assertIn("2 new, 4 already in inventory, 1 ambiguous",
                      out.getvalue())

    def test_merge_into_is_additive_and_backs_up(self):
        import yaml
        before = yaml.safe_load(self.inventory.read_text())
        code, out, _ = self.run_sync("--merge-into", str(self.inventory))
        self.assertEqual(code, 0)

        backups = list(Path(self.tmp.name).glob("inventory.yml.*.bak"))
        self.assertEqual(len(backups), 1, "expected exactly one backup")
        self.assertEqual(yaml.safe_load(backups[0].read_text()), before)

        after = yaml.safe_load(self.inventory.read_text())
        # Every original host survives, unmodified.
        original = before["all"]["children"]["routers"]["hosts"]
        self.assertEqual(after["all"]["children"]["routers"]["hosts"], original)
        # And the new ones landed in their own group.
        added = after["all"]["children"]["orion_discovered"]["hosts"]
        self.assertEqual(set(added), {"sw__lab", "orphan"})

    def test_merge_into_result_is_still_a_valid_inventory(self):
        from ansible.inventory.manager import InventoryManager
        from ansible.parsing.dataloader import DataLoader

        self.run_sync("--merge-into", str(self.inventory))
        manager = InventoryManager(loader=DataLoader(),
                                   sources=[str(self.inventory)])
        names = sorted(h.name for h in manager.get_hosts())
        self.assertIn("core1", names)
        self.assertIn("sw__lab", names)
        self.assertEqual(len(names), 7)

    def test_second_merge_is_a_no_op(self):
        """Idempotence: once added, the devices match by IP and must not
        be added a second time. A sync tool that duplicates on every run
        is worse than one that does nothing."""
        self.run_sync("--merge-into", str(self.inventory))
        code, out, _ = self.run_sync("--merge-into", str(self.inventory))
        self.assertEqual(code, 0)
        self.assertIn("0 new,", out)
        self.assertIn("Nothing to add.", out)

    def test_mutually_exclusive_write_options(self):
        with self.assertRaises(SystemExit):
            self.run_sync("--write-new", "a.yml", "--merge-into", "b.yml")


if __name__ == "__main__":
    unittest.main(verbosity=2)
