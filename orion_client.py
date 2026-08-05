#!/usr/bin/env python3
"""
orion_client.py

Generic, reusable client for SolarWinds Orion's Information Service
(SWIS) REST API -- the query interface Orion itself uses, which exposes
the whole Orion database as SWQL (a SQL-like read language) over HTTPS.

Generic and not tied to any one workflow -- the device/management-IP
tooling built on top of it lives beside it (see README.md).

Originally written in workbench/ansible alongside phpipam_client.py;
moved here when the SolarWinds work got its own repo.

## Dependencies

Uses `requests`, consistent with workbench/ansible's phpipam_client.py
and confirmed available on the airgapped machine that runs this.

If SWIS ever turns out to need NTLM or Kerberos rather than Basic auth
(possible with an AD-backed Orion account), requests_ntlm /
requests_kerberos slot straight into the `auth=` argument in query() --
which is a further reason to be on requests here rather than urllib.

OrionClient.from_vault_secret() additionally imports ansible-core, and
imports it *inside the method*, so every other path in this file works
without it. On the airgapped side use --password-env or the interactive
prompt instead of the vault.

IMPORTANT -- confirmation status: the transport shape used here (base
path, POST-with-parameters query form, `results` response envelope,
HTTP Basic auth, port 17774) comes from SolarWinds' published SWIS REST
documentation. It has NOT been confirmed against a live Orion instance
-- there is no reachable Orion server on this side of the airgap.
Treat all of it as unverified until orion/orion_probe.py has been run
against the real server and its output reviewed.

The *column* names are a separate question, and the reason
discover_properties() exists: rather than assuming Orion.Nodes has a
given property, ask the instance. Metadata.Property is SWIS's own
schema catalogue, so a probe run answers "what can I actually select
here" against real data instead of against docs -- the same discipline
the discovery/ module applies to YANG models before building against
them.

## The endpoint

SWIS listens on **port 17774** (SSL) on the Orion server, under
`/SolarWinds/InformationService/v3/Json/`. So a full query URL is:

    https://orion.example.com:17774/SolarWinds/InformationService/v3/Json/Query

**The port changed in Orion 2023.1.** It was 17778 up to 2022.4.1;
2023.1 moved REST to 17774 and deprecated 17778, and later releases stop
listening on it. Pass `--port 17778` for anything 2022.4.1 or older. The
path is the same on both.

That certificate is **self-signed by default** on a stock Orion
install, so verify_ssl=False (`--insecure` on the CLIs) is commonly
needed. The password is sent in an HTTP Basic header, so keep the
scheme https:// even when skipping certificate validation -- otherwise
the credentials go over the wire in clear.

## Authentication

HTTP Basic, using an **Orion individual account**. Two kinds work:

  * A local Orion account: username as shown in Orion's Manage Accounts.
  * A Windows/AD account: username in `DOMAIN\\user` form. Note that
    in Python source that backslash must be escaped ("DOMAIN\\\\user")
    or written as a raw string; on a shell command line it usually
    needs quoting.

The account only needs read access for everything here -- nothing in
this module writes, and there is deliberately no Create/Update/Delete/
Invoke method (SWIS does offer those verbs; this client does not, so it
cannot change anything in Orion even by accident).

Credentials -- three ways to supply the password:

  1. Explicit, in code:
        client = OrionClient(host="orion.example.com",
                             username="ansible", password="...")

  2. From an environment variable (CI use, and the right choice on the
     airgapped side -- keeps it out of the command line and process
     listing):
        client = OrionClient(host="orion.example.com",
                             username="ansible",
                             password_env="ORION_PASSWORD")

  3. From an ansible-vault-encrypted secret file (RECOMMENDED on this
     side of the airgap, where ansible-core is installed) --
     OrionClient.from_vault_secret(), the same pattern phpIPAM's token
     and PeeringDB's API key already use in this repo:

        cat > orion_secret.yml <<EOF
        username: ansible
        password: <the Orion account password>
        EOF
        ansible-vault encrypt orion_secret.yml

     Commit orion_secret.yml -- it's encrypted, so it's fine alongside
     everything else, same as phpipam_secret.yml.

## Usage

    from orion_client import OrionClient

    client = OrionClient(host="orion.example.com", username="ansible",
                         password_env="ORION_PASSWORD", verify_ssl=False)

    # The straightforward thing: every node and its management IP
    for node in client.get_nodes():
        print(node["Caption"], node["IPAddress"])

    # Anything else: raw SWQL, parameterised
    rows = client.query(
        "SELECT Caption, IPAddress FROM Orion.Nodes WHERE Vendor = @v",
        parameters={"v": "Cisco"},
    )

Requires: requests, ansible-core (for from_vault_secret() only)
    pip install requests ansible-core --break-system-packages
"""

import os
from pathlib import Path

import requests

#: SWIS's SSL listener on the Orion server.
#:
#: **17774, not 17778.** Orion served the REST endpoint on 17778 up to
#: 2022.4.1; the 2023.1 release moved it to 17774 and deprecated 17778,
#: which later releases stop listening on. Confirmed the hard way: a
#: live 2026.2.1 instance returned HTTP 404 on 17778 -- something still
#: answers there, so the failure looks like a bad path rather than a
#: dead port, which is exactly what makes it slow to diagnose.
#:
#: Use LEGACY_SWIS_PORT with --port against anything at 2022.4.1 or
#: older.
DEFAULT_SWIS_PORT = 17774

#: The pre-2023.1 REST port. Only for Orion 2022.4.1 and earlier.
LEGACY_SWIS_PORT = 17778

#: Path prefix for the v3 JSON endpoint, appended to scheme://host:port.
SWIS_BASE_PATH = "/SolarWinds/InformationService/v3/Json"

#: The properties orion/orion_devices.py selects by default -- exactly
#: the four fields this module was asked for, plus Caption (Orion's
#: display name for the node, which is what a human recognises it by)
#: and NodeID (paging needs it; see get_nodes()).
#:
#: The mapping from what was asked for to Orion's property names:
#:   Polling IP address  -> IPAddress    (the address Orion polls on)
#:   Machine Type        -> MachineType  (e.g. "Cisco Catalyst 9300")
#:   System Name         -> SysName      (SNMP sysName, off the device)
#:   DNS Name            -> DNS          (Orion's resolved/stored FQDN)
#:
#: SysName and DNS are genuinely different fields and routinely
#: disagree -- SysName is whatever the device calls itself over SNMP,
#: DNS is what name resolution says. Both are selected rather than
#: picking one, because which is authoritative is a per-estate
#: question and only real data can answer it.
#:
#: Still verify these against a real instance (orion/orion_devices.py
#: --list-columns) before depending on them -- SolarWinds does move
#: properties between releases and modules.
DEFAULT_NODE_COLUMNS = [
    "NodeID",
    "Caption",
    "IPAddress",
    "MachineType",
    "SysName",
    "DNS",
]

#: Other core Orion.Nodes properties that are commonly wanted but not
#: selected by default. Pass them with --columns when needed. Listed
#: here so the useful ones are discoverable without reading SolarWinds
#: documentation -- but they carry the same "confirm against the real
#: instance" caveat as everything else here.
COMMON_EXTRA_COLUMNS = [
    "Vendor",          # "Cisco", "Juniper", ...
    "ObjectSubType",   # how Orion polls it: SNMP / ICMP / WMI / Agent
    "Status",          # see NODE_STATUS_NAMES
    "Unmanaged",       # bool: node currently unmanaged in Orion
    "NodeDescription", # SNMP sysDescr -- verbose, but has OS/version
    "Location",        # SNMP sysLocation
    "Contact",         # SNMP sysContact
    "IOSVersion",      # present on network devices in most installs
]

#: Orion status codes -> human labels. Documented by SolarWinds and
#: stable in practice, but UNCONFIRMED against this instance, and the
#: list is not exhaustive -- format_status() falls back to the raw
#: integer for anything unrecognised rather than inventing a label, so
#: an unknown code shows up as a number instead of being mislabelled.
NODE_STATUS_NAMES = {
    0: "Unknown",
    1: "Up",
    2: "Down",
    3: "Warning",
    4: "Shutdown",
    9: "Unmanaged",
    12: "Unreachable",
    14: "Critical",
    17: "Undefined",
}


def format_status(value):
    """Renders an Orion node Status code as a label, falling back to the
    raw value for codes not in NODE_STATUS_NAMES (see that dict's note
    -- an unknown code shows as e.g. "15" rather than being silently
    bucketed into a wrong label)."""
    try:
        return NODE_STATUS_NAMES.get(int(value), str(value))
    except (TypeError, ValueError):
        return "" if value is None else str(value)


class OrionError(Exception):
    """Raised for any non-success response from SWIS, or a
    connection-level failure. Carries the HTTP status code (if any) and
    SWIS's own exception type where available, so callers can tell an
    auth failure from a malformed-SWQL failure without parsing the
    message string."""

    def __init__(self, message, status_code=None, exception_type=None):
        super().__init__(message)
        self.status_code = status_code
        self.exception_type = exception_type


class OrionClient:
    """Thin, READ-ONLY wrapper around the SWIS REST API. One instance
    per Orion server/account pair -- holds the credentials and sends
    them on every request.

    Read-only by construction: the only SWIS verb wired up is Query.
    SWIS also exposes Create/Update/Delete/Invoke; they are deliberately
    absent here, so nothing in this repo can modify Orion through this
    client. If a write workflow is ever wanted, that should be a
    conscious, separately-reviewed addition rather than something a
    caller can reach by accident.
    """

    def __init__(self, host, username, password=None, password_env=None,
                 port=DEFAULT_SWIS_PORT, verify_ssl=True, timeout=60):
        """
        host: the Orion server, e.g. "orion.example.com". A bare
            hostname is expected; a full "https://host:17774" URL is
            also accepted and parsed, so callers that already have one
            don't have to pick it apart.
        username: an Orion individual account. AD accounts take the
            DOMAIN\\user form (escape the backslash in Python source).
        password/password_env: the account password directly, or the
            name of an environment variable holding it. For vault-backed
            credentials, use from_vault_secret() instead.
        port: SWIS SSL port. 17774 on Orion 2023.1 and later, 17778
            on 2022.4.1 and earlier.
        verify_ssl: set False for the self-signed certificate a stock
            Orion install ships with. The scheme stays https either way
            -- Basic auth means the password is only as protected as
            the connection.
        timeout: seconds. Defaults higher than phpipam_client's 30
            because an unfiltered SWQL query across a large Orion
            database is genuinely slow, and a timeout mid-query reads
            as a connection fault rather than "ask for less".
        """
        self.host = self._normalise_host(host)
        self.port = port
        self.username = username
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        if password is not None:
            self._password = password
        elif password_env is not None:
            self._password = os.environ.get(password_env)
            if self._password is None:
                raise OrionError(
                    f"--password-env '{password_env}' is not set in the "
                    f"environment."
                )
        else:
            raise OrionError("Either password or password_env must be given.")

    @staticmethod
    def _normalise_host(host):
        """Accepts either a bare hostname or a full URL and returns the
        bare host. Tolerant on input because the natural thing to paste
        is whatever is in the browser's address bar, and silently
        building "https://https://orion..." would fail with a confusing
        DNS error rather than an obvious one."""
        h = host.strip()
        for scheme in ("https://", "http://"):
            if h.lower().startswith(scheme):
                h = h[len(scheme):]
                break
        h = h.split("/", 1)[0]
        # Strip any port pasted along with the host -- the port is a
        # separate constructor argument, and honouring both would make
        # "which one wins" ambiguous.
        if ":" in h and not h.startswith("["):
            h = h.split(":", 1)[0]
        return h

    @property
    def base_url(self):
        return f"https://{self.host}:{self.port}{SWIS_BASE_PATH}"

    @classmethod
    def from_vault_secret(cls, host, secret_path="orion_secret.yml",
                          vault_password_file=None, port=DEFAULT_SWIS_PORT,
                          verify_ssl=True, timeout=60, username=None):
        """Builds a client from an ansible-vault-encrypted YAML file --
        the recommended way to supply Orion credentials on this side of
        the airgap, and the same pattern phpipam_client.from_vault_secret()
        and peering/stage_peeringdb_config.py already use. Needs
        ansible-core, so it is NOT the path to use on the airgapped
        side; use password_env there.

        secret_path: vault-encrypted YAML expected to contain:
                username: ansible
                password: <the Orion account password>
            (default: orion_secret.yml in the current directory.)

        username: optional override -- if given, it wins over the file's
            username and only the password is taken from the vault.
            Useful to run a one-off query as a different account without
            editing the encrypted file.

        vault_password_file: same resolution chain as every other
            vaulted file in this repo (argument > $ANSIBLE_VAULT_
            PASSWORD_FILE > ansible.cfg's vault_password_file).

        Raises OrionError if the file is missing, fails to decrypt, or
        lacks the required fields -- with the exact commands to create
        it, the same recovery shape phpipam_client.py uses.
        """
        secret_file = Path(secret_path)
        if not secret_file.exists():
            raise OrionError(
                f"{secret_file} not found. Create it with:\n"
                f"  cat > {secret_file} <<EOF\n"
                f"  username: ansible\n"
                f"  password: <the Orion account password>\n"
                f"  EOF\n"
                f"  ansible-vault encrypt {secret_file}"
            )

        # Imported here rather than at module level: ansible-core is
        # needed only by this one path, so the device-list and probe
        # scripts keep working without it.
        from inventory_reader import load_yaml_with_vault

        try:
            secret_data = load_yaml_with_vault(str(secret_file), vault_password_file)
        except Exception as e:
            raise OrionError(
                f"Failed to decrypt/parse {secret_file}: {e} -- check the "
                f"vault password file resolves correctly (same chain as "
                f"every other vaulted file in this repo: "
                f"--vault-password-file / $ANSIBLE_VAULT_PASSWORD_FILE / "
                f"ansible.cfg's vault_password_file)."
            )

        if not secret_data or "password" not in secret_data:
            raise OrionError(
                f"{secret_file} decrypted but is missing 'password'. "
                f"Expected:\n"
                f"  username: ansible\n"
                f"  password: <the Orion account password>"
            )

        resolved_user = username or secret_data.get("username")
        if not resolved_user:
            raise OrionError(
                f"No username: {secret_file} has no 'username' field and none "
                f"was passed explicitly."
            )

        # Cast to plain str -- Ansible's DataLoader returns AnsibleUnicode
        # subclasses; normalised here so nothing downstream has to care.
        return cls(
            host=host,
            username=str(resolved_user),
            password=str(secret_data["password"]),
            port=port,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )

    # -- Core request plumbing ----------------------------------------

    def query(self, swql, parameters=None):
        """Runs one SWQL query and returns its rows as a list of dicts
        (SWIS's `results` array; an empty list if the query matched
        nothing).

        parameters: optional dict of SWQL bind parameters, referenced in
            the query as @name. ALWAYS prefer these over string
            formatting for anything caller-supplied -- SWQL is a query
            language and interpolating values into it is the same class
            of mistake as SQL injection. The whole client uses the POST
            form specifically so parameters are available; the GET form
            SolarWinds also documents takes the query in the URL and
            cannot bind them.

        Raises OrionError on connection failure, auth failure, or a SWQL
        error (a malformed query, or a property that doesn't exist on
        this instance, comes back as an HTTP 400 with SWIS's own
        exception detail, which is surfaced rather than swallowed --
        that message is usually the fastest way to find the real
        property name).
        """
        url = f"{self.base_url}/Query"
        payload = {"query": swql}
        if parameters:
            payload["parameters"] = parameters

        try:
            resp = requests.post(
                url,
                json=payload,
                # HTTPBasicAuth sends the header up front rather than
                # waiting for a 401 challenge, which is both what SWIS
                # expects and one request instead of two.
                auth=(self.username, self._password),
                verify=self.verify_ssl,
                timeout=self.timeout,
                headers={"Accept": "application/json"},
            )
        except requests.exceptions.SSLError as e:
            raise OrionError(
                f"TLS failure talking to {url}: {e} -- a stock Orion install "
                f"has a self-signed certificate; pass --insecure to skip "
                f"validation."
            )
        except requests.RequestException as e:
            raise OrionError(
                f"Connection failed: POST {url}: {e} -- check the Orion "
                f"server is reachable on port {self.port}. SWIS is a separate "
                f"listener from the Orion web UI on 443 and is often "
                f"firewalled separately, so a working web UI does not imply a "
                f"working API path."
            )

        if resp.status_code == 401:
            raise OrionError(
                f"401 Unauthorized as '{self.username}' -- check the account "
                f"and password. AD accounts need the DOMAIN\\user form, and "
                f"the account must be an Orion individual account with API "
                f"access, not merely a Windows account on the server.",
                status_code=resp.status_code,
            )

        if resp.status_code == 403:
            # 403, not 401: SWIS resolved the credentials and then refused
            # the account. The overwhelmingly common cause is an AD
            # account whose Orion access comes from a Windows *group* --
            # SWIS cannot authenticate those (a long-standing SID lookup
            # problem), while the same account works fine in the web UI,
            # which is what makes it look like a credentials mystery.
            raise OrionError(
                f"403 Forbidden as '{self.username}' -- the credentials were "
                f"accepted and the account was then refused. Note SWIS "
                f"returns 401 for a bad password, so this is authorisation, "
                f"not authentication.\n\n"
                f"Most likely: this is an Active Directory account whose "
                f"Orion access comes via a Windows GROUP. SWIS cannot "
                f"authenticate group-derived accounts even though the web UI "
                f"can. Fix it either by adding the account to Orion as an "
                f"INDIVIDUAL account (Settings > Manage Accounts > Add > "
                f"Windows account), or -- better for automation -- by using "
                f"a dedicated local Orion account, which has no AD "
                f"dependency at all.\n\n"
                f"Also check: the account is enabled, and if it is an AD "
                f"account that the DOMAIN\\user form is being used. The "
                f"definitive answer is in the SWIS log on the Orion server, "
                f"C:\\ProgramData\\SolarWinds\\InformationService\\v3.0",
                status_code=resp.status_code,
            )

        if not resp.ok:
            # SWIS reports SWQL errors as JSON with Message/ExceptionType/
            # FullException. Fall back to raw text for anything that isn't
            # (e.g. an upstream proxy error page).
            message, exc_type = resp.text[:500], None
            try:
                err = resp.json()
                if isinstance(err, dict):
                    message = err.get("Message") or message
                    exc_type = err.get("ExceptionType")
            except ValueError:
                pass
            if resp.status_code == 404:
                # A 404 here is almost always the 2023.1 port move: the
                # old listener still answers on 17778 on some installs,
                # so it presents as a bad path rather than a dead port.
                # Saying so beats making the caller work it out.
                message += (
                    f"\n\nA 404 from SWIS usually means the wrong port. The "
                    f"REST endpoint moved from 17778 to {DEFAULT_SWIS_PORT} in "
                    f"Orion 2023.1, and 17778 is deprecated -- but something "
                    f"often still answers there, which is why this shows up "
                    f"as 404 rather than a refused connection. This request "
                    f"used port {self.port}. Try --port "
                    f"{LEGACY_SWIS_PORT if self.port == DEFAULT_SWIS_PORT else DEFAULT_SWIS_PORT}"
                    f", or run orion_endpoint_probe.py to find the endpoint."
                )
            raise OrionError(
                f"SWQL query failed (HTTP {resp.status_code}): {message}",
                status_code=resp.status_code,
                exception_type=exc_type,
            )

        try:
            body = resp.json()
        except ValueError:
            raise OrionError(
                f"SWIS returned a non-JSON success response: "
                f"{resp.text[:200]!r}"
            )

        return body.get("results", [])

    # -- Schema discovery ---------------------------------------------

    def discover_properties(self, entity="Orion.Nodes"):
        """Returns the property names SWIS reports for `entity`, from
        its own schema catalogue (Metadata.Property).

        This is the honest way to find out what can be selected: the
        column list in DEFAULT_NODE_COLUMNS is from documentation, and
        documentation is not the instance. Run this first against a new
        Orion server (orion/orion_devices.py --list-columns, or the
        full orion/orion_probe.py capture) and build queries from what
        comes back -- the same reason discovery/ captures real YANG
        models rather than trusting assumed element names.

        Returns a list of dicts with Name/Type/IsNavigable, ordered by
        name.
        """
        return self.query(
            "SELECT Name, Type, IsNavigable FROM Metadata.Property "
            "WHERE EntityName = @entity ORDER BY Name",
            parameters={"entity": entity},
        )

    def discover_entities(self, name_like="Orion.Node"):
        """Returns SWIS entities whose name contains `name_like` --
        useful for finding what node-adjacent tables this instance
        actually has before guessing at them."""
        return self.query(
            "SELECT FullName, BaseType, CanCreate FROM Metadata.Entity "
            "WHERE FullName LIKE @pattern ORDER BY FullName",
            parameters={"pattern": f"%{name_like}%"},
        )

    def discover_custom_properties(self):
        """Returns the custom properties defined on nodes in this Orion
        instance. Site, role and owner are almost always modelled as
        Orion custom properties rather than built-in columns, and they
        are per-installation by definition, so they can only be
        discovered, never assumed.

        Custom properties are selectable from Orion.Nodes via the
        navigable CustomProperties relation, e.g.:
            SELECT Caption, CustomProperties.Site FROM Orion.Nodes
        """
        return self.discover_properties(entity="Orion.NodesCustomProperties")

    # -- Nodes ---------------------------------------------------------

    def get_nodes(self, columns=None, where=None, parameters=None,
                  page_size=500):
        """Returns Orion nodes as a list of dicts -- the device list
        this module exists for.

        On "management IP": Orion.Nodes.IPAddress is the address Orion
        *polls the node on*, which is the operational definition of a
        management IP here -- by construction it is an address that
        answers management traffic from a management system. It is not
        necessarily the only address on the device: Orion.NodeIPAddresses
        holds every interface address discovered on a node, and is a
        different question (see get_node_ip_addresses()). For building
        an Ansible inventory, IPAddress is the one you want.

        columns: list of Orion.Nodes properties to select. Defaults to
            DEFAULT_NODE_COLUMNS. Verify against discover_properties()
            on a new instance before relying on any of them. Custom
            properties can be included with the navigable form, e.g.
            "CustomProperties.Site".
        where: optional SWQL WHERE clause *without* the WHERE keyword,
            e.g. "Vendor = @vendor". Use `parameters` for the values --
            do not interpolate them into this string.
        parameters: bind values for `where`.
        page_size: rows per request. Results are paged with a keyset
            cursor on NodeID (WHERE NodeID > last), not an offset --
            offsets re-scan and can skip or repeat rows if the node set
            changes mid-walk. Pass page_size=None to fetch everything in
            a single query instead.

        NodeID is always selected and always ordered on, whether or not
        the caller asked for it, because paging depends on it. It is
        left in the returned rows rather than stripped -- it's the key
        every other Orion entity joins on, so a caller that later wants
        interfaces or custom properties for a node needs it.
        """
        cols = list(columns) if columns else list(DEFAULT_NODE_COLUMNS)
        if "NodeID" not in cols:
            cols.insert(0, "NodeID")
        select_list = ", ".join(cols)

        base_params = dict(parameters or {})

        if page_size is None:
            swql = f"SELECT {select_list} FROM Orion.Nodes"
            if where:
                swql += f" WHERE {where}"
            swql += " ORDER BY NodeID"
            return self.query(swql, parameters=base_params or None)

        rows = []
        last_id = -1
        while True:
            params = dict(base_params)
            params["__after"] = last_id
            clause = "NodeID > @__after" + (f" AND ({where})" if where else "")
            swql = (
                f"SELECT TOP {int(page_size)} {select_list} FROM Orion.Nodes "
                f"WHERE {clause} ORDER BY NodeID"
            )
            page = self.query(swql, parameters=params)
            if not page:
                break
            rows.extend(page)

            # Defensive: if NodeID somehow isn't in the reply the cursor
            # can't advance. Failing loudly beats an infinite loop that
            # presents as a slow server.
            try:
                highest = max(int(r["NodeID"]) for r in page)
            except (KeyError, TypeError, ValueError) as e:
                raise OrionError(
                    f"Paging cannot advance: NodeID missing or non-numeric in "
                    f"the reply ({e}). Re-run with page_size=None (CLI: "
                    f"--no-paging) to fetch without paging."
                )

            # The cursor must strictly increase. If the far end ignored
            # the WHERE clause -- a misbehaving proxy, or an endpoint
            # that isn't really SWIS -- it would return the same page
            # forever and this loop would never end. A hang is the worst
            # possible failure here because it looks like a slow server,
            # so it is turned into an error instead.
            if highest <= last_id:
                raise OrionError(
                    f"Paging is not advancing: the server returned rows with "
                    f"NodeID <= {last_id} despite a 'NodeID > {last_id}' "
                    f"filter, so the cursor cannot move. The endpoint may not "
                    f"be honouring the WHERE clause. Re-run with --no-paging."
                )
            last_id = highest

            if len(page) < int(page_size):
                break

        return rows

    def get_node_ip_addresses(self, node_id=None):
        """Returns rows from Orion.NodeIPAddresses -- every IP address
        discovered on a node, not just the polling address.

        Deliberately separate from get_nodes(): "the management IP" and
        "all addresses on the device" are different questions, and
        conflating them would give a node with ten interfaces ten
        inventory entries. Use this when you actually want the full
        address inventory of a device.
        """
        if node_id is None:
            return self.query(
                "SELECT NodeID, IPAddress, IPAddressType, InterfaceIndex "
                "FROM Orion.NodeIPAddresses ORDER BY NodeID"
            )
        return self.query(
            "SELECT NodeID, IPAddress, IPAddressType, InterfaceIndex "
            "FROM Orion.NodeIPAddresses WHERE NodeID = @node_id "
            "ORDER BY InterfaceIndex",
            parameters={"node_id": node_id},
        )
