# solarwinds

Read-only tooling for **SolarWinds Orion**, built on its Information
Service (SWIS) — the SWQL query API Orion itself uses.

Two jobs:

1. **List the devices Orion monitors**, with the fields needed to drive
   an Ansible inventory.
2. **Reconcile that list against an existing Ansible inventory**, and
   report or add the devices that aren't in it yet.

| Wanted | Orion property |
|---|---|
| Polling IP address | `Orion.Nodes.IPAddress` |
| Machine Type | `Orion.Nodes.MachineType` |
| System Name | `Orion.Nodes.SysName` |
| DNS Name | `Orion.Nodes.DNS` |

plus `Caption` (Orion's display name) and `NodeID` (the key every other
Orion entity joins on).

## Read-only, by construction

The client wires up **only SWIS's `Query` verb**. SWIS also exposes
`Create`, `Update`, `Delete` and `Invoke`; they are deliberately absent,
so nothing here can modify Orion even by accident. The only thing any
script here writes is a local inventory file, and only when explicitly
asked.

## Status — core path confirmed against a live instance

**Confirmed 2026-08-05 against SolarWinds Platform 2026.2.1.** The
device query runs end to end and returns data, which establishes:

- the transport — port **17774**, the `/SolarWinds/InformationService/
  v3/Json/Query` path, the POST-with-parameters form, HTTP Basic auth,
  and the `results` response envelope;
- all four property names. SWIS rejects an unknown property with a 400,
  so a successful `SELECT` of `IPAddress`, `MachineType`, `SysName` and
  `DNS` is positive proof they exist on this version.

**Still unconfirmed**, because a single successful query does not
exercise them: the `NODE_STATUS_NAMES` map, which custom properties
this instance defines, and paging past the first page on a real node
count. `orion_probe.py` covers all three in one run and is now cheap,
since connectivity works — see `TODO.md`.

The instance is on an airgapped network and is not reachable from the
machine this was written on, so everything is still built here and
confirmed there.

What *has* been verified: the client is internally correct and speaks
the protocol it thinks it does. `orion_mock_swis_test.py` stands up a
mock SWIS server over real TLS on localhost and drives the real client
and CLIs against it — 56 tests covering Basic auth, the POST body,
bound parameters, keyset paging, TLS validation, SWIS-shaped errors,
every output format, and the inventory reconciliation end-to-end
against a real Ansible inventory. The suite has been checked against
deliberately broken copies of the code and fails on each, so it is not
a vacuous pass.

A fixture written from the same assumption as the code cannot disagree
with it, which is why the live confirmation above matters and the mock
suite alone never would have.

## Files

| File | Purpose |
|---|---|
| `orion_client.py` | Generic read-only SWIS/SWQL client |
| `orion_endpoint_probe.py` | Finds the SWIS endpoint when the expected one 404s. Self-contained — copy it across on its own |
| `orion_probe.py` | First-contact capture — run this first, on the airgapped side |
| `orion_devices.py` | The device list: table / CSV / JSON / inventory skeleton |
| `orion_inventory_sync.py` | Reconcile Orion against an Ansible inventory |
| `inventory_reader.py` | Vault-aware Ansible inventory reader |
| `orion_mock_swis_test.py` | The test suite |

## Requirements

```bash
pip install -r requirements.txt
```

- **requests** — the SWIS client.
- **ansible-core** — only for reading an Ansible inventory
  (`orion_inventory_sync.py`) and for vault-encrypted credentials.
  Imported inside the functions that need it, so `orion_devices.py` and
  `orion_probe.py` work without it.
- **PyYAML** — used for YAML output when importable, with a hand-rolled
  emitter as fallback, because it is only *probably* present on the
  airgapped side. Both paths emit identical structure and a test
  asserts they round-trip to the same data.

## 1. Probe the instance first

```bash
read -rs ORION_PASSWORD && export ORION_PASSWORD
python3 orion_probe.py --host orion.example.com \
    --username ansible --password-env ORION_PASSWORD --insecure
```

Read `orion-probe-output/summary.txt`. Every `FAIL` is a documented
assumption that does not hold on this instance and must be corrected in
`orion_client.py`. Bring the whole directory back across the airgap.

13 probes, each stating its expectation *before* it runs. The four
target fields are probed **one at a time**, so a failure names the
specific property instead of casting doubt on the whole set.

`--insecure` is usually needed — a stock Orion serves SWIS with a
self-signed certificate. The connection is still TLS; the password
rides in an HTTP Basic header, so the scheme stays `https`.

SWIS listens on **17774** on Orion 2023.1 and later (it was 17778 up to
2022.4.1 — see the 404 note below). It is a separate listener from the
web UI on 443 and often firewalled separately, so a working web UI does
not imply a working API path. That is the first thing to check if
connectivity fails.

## Troubleshooting: HTTP 404 — almost always the port

**Orion 2023.1 moved the SWIS REST endpoint from port 17778 to 17774**,
and deprecated 17778. Later releases stop listening on it. The catch is
that something often still answers on 17778, so the failure arrives as
`HTTP 404` — a bad *path* — rather than a refused connection, which is
what makes it slow to recognise.

The default here is now 17774. If you are on Orion **2022.4.1 or
earlier**, pass `--port 17778`. The URL path is identical on both.

### HTTP 403 with credentials that work in the web UI

**SWIS returns 401 for a bad password.** A 403 therefore means the
credentials were accepted and the *account* was refused — so re-checking
the password is the one thing already ruled out.

The classic cause: an **Active Directory account whose Orion access
comes from a Windows group**. SWIS cannot authenticate group-derived
accounts, a long-standing limitation attributed to a SID lookup problem,
while the same account signs into the web console perfectly well — which
is exactly what makes it look like a credentials mystery.

Two fixes:

1. Add the account to Orion as an **individual** account —
   Settings → Manage Accounts → Add → Windows account.
2. **Better for automation:** use a dedicated **local Orion account**.
   No AD dependency, no group-SID problem, and it does not break when
   someone reorganises group membership. This is the usual
   recommendation for API integrations.

Also worth confirming: the account is enabled, and AD accounts are being
passed as `DOMAIN\user` (quoted on the shell).

The definitive answer is in the SWIS log on the Orion server:
`C:\ProgramData\SolarWinds\InformationService\v3.0`.

### Timeout on 17774 while 17778 answers = a firewall in the path

Confirmed on the live 2026.2.1 instance. The symptom set:

- `--port 17774` → **ConnectTimeoutError**
- `--port 17778` → **HTTP 404** (so the host is reachable)
- Server shows `0.0.0.0:17774` listening, no host firewall

Read it as a differential rather than three separate facts: the same
client reaches the same host on one port and not the other, and both
ends are excluded. The drop is therefore **between** them — a network
firewall or ACL that was never updated when the platform moved the
port. SolarWinds' own upgrade guidance says to update firewalls before
upgrading, and existing rules typically permit 17778 only.

**Timeout vs refused is the whole signal.** A silent drop in the path
times out. A host that is not listening, or a host firewall set to
reject, gives connection refused. Do not spend time on endpoint
settings or certificates when the symptom is a timeout and another port
on the same host answers.

Confirm in two moves:

```powershell
Test-NetConnection <orion> -Port 17774    # expect False
Test-NetConnection <orion> -Port 17778    # expect True -> port-specific
```

```bash
# on the Orion server itself -- proves the endpoint is healthy
curl -k -u '<account>' "https://localhost:17774/SolarWinds/InformationService/v3/Json/Query?query=SELECT+TOP+1+NodeID+FROM+Orion.Nodes"
```

The fix is a firewall rule permitting 17774 from wherever these scripts
run. Until that lands, either run them from a host that can already
reach the server on 17774, or use the deprecated port as a stopgap (see
below).

### If 17774 is not listening either

Seen on a live 2026.2.1 instance: 17778 answers with 404, and nothing
is listening on 17774. Both endpoints are *configurable*, so this is a
server-side setting rather than anything the client can fix. In order
of likelihood:

1. **The REST endpoint on 17774 is disabled.** SolarWinds lets you
   disable the SWIS REST endpoint on either port independently.
2. **17774 cannot bind because of its certificate.** From 2023.1 that
   port is secured by a certificate named in Centralized Settings —
   `CertificateNameForSafeguardCommunicationOnSwisRestEndpoint`,
   defaulting to `SolarWinds-Orion`. The certificate must be in Local
   Machine → Personal, have an **accessible private key**, and be valid
   for TLS server authentication. This is the one to suspect if the
   port simply never comes up.
3. **A host firewall rule was never added for 17774.** The upgrade
   moves the port; it does not add the rule. Note this presents as a
   *timeout* from a remote client, while genuinely-not-bound presents
   as *connection refused* — worth distinguishing before chasing
   settings.

Check on the server itself, not from a client:

```
netstat -ano | findstr "17774 17778"
```

and map the PID back to a service. That is the only observation that
separates "not listening" from "listening but unreachable".

**The quickest unblock** is to re-enable the old port: in Advanced
Configuration (`https://<orion>/Orion/Admin/AdvancedConfiguration/Global.aspx`)
clear **`DisableSwisRestEndpointOnPort17778`**, then run any script here
with `--port 17778`. That is a deprecated path and should be a stopgap,
not the destination — but it gets data flowing while 17774 is sorted
out.

If changing the port does not fix it, the routing is genuinely unknown
and guessing costs a round trip per attempt:

```bash
python3 orion_endpoint_probe.py --host <orion> --username <account> \
    --password-env ORION_PASSWORD --insecure --output results.txt
```

It tries every plausible port/path/method combination in one run and
reports what each actually answered — status, `Server` header, content
type and the first bytes of the body. That identifies what is listening
even when nothing works, which is more useful than another guess at what
should be.

Worth checking on the server at the same time:

- Is the **SolarWinds Information Service V3** service running?
- Does `netstat -an | findstr "17774 17778"` show either listening?
- Is the host you are pointing at the one running SWIS? An Additional
  Web Server serves the UI without necessarily serving the API.

## 2. List the devices

```bash
# aligned table
python3 orion_devices.py --host orion.example.com \
    --username ansible --password-env ORION_PASSWORD --insecure

# CSV, for a spreadsheet or for carrying back
python3 orion_devices.py --host ... --insecure --format csv --output devices.csv

# an Ansible inventory skeleton
python3 orion_devices.py --host ... --insecure --format inventory
```

```
NodeID  Caption  IPAddress  MachineType    SysName            DNS
------  -------  ---------  -------------  -----------------  ------------------
1       core1    10.0.0.1   Cisco ASR9000  core1.example.net  core1.example.com
9       edge1    10.0.0.3   Juniper MX204  edge1
12      ups-a    10.0.0.4   APC UPS
```

Without `--password-env` you are prompted, and the password is not
echoed. AD accounts take the `DOMAIN\user` form — quote it on the shell.

### Check the schema when something looks wrong

```bash
python3 orion_devices.py --host ... --insecure --list-columns
python3 orion_devices.py --host ... --insecure --list-custom-properties
```

These ask the instance what it really has, via SWIS's own
`Metadata.Property` catalogue. When a query fails, SWIS names the bad
property in the error — that message is the fastest route to the real
name.

## 3. Reconcile into an Ansible inventory

```bash
# report only -- writes nothing
python3 orion_inventory_sync.py --host ... --insecure \
    --inventory /path/to/inventory.yml

# write just the new devices to their own file
... --write-new orion_discovered.yml

# or merge them into the existing inventory in place
... --merge-into /path/to/inventory.yml
```

```
Verdict    Caption  IPAddress  MachineType    Matched            Rule
NEW        orphan              Unknown
NEW        sw: lab  10.0.0.5   Yes
AMBIGUOUS  ups-a    10.0.0.4   APC UPS                           polling-ip=10.0.0.4 -> legacy-ups, name=ups-a -> ups-a
EXISTS     core1    10.0.0.1   Cisco ASR9000  core1              polling-ip
EXISTS     core2    10.0.0.2   Cisco ASR9000  core2.example.net  name

2 new, 4 already in inventory, 1 ambiguous (of 7 in Orion)
```

**Additive only.** It never removes a host and never edits an existing
one. A device that has left Orion is reported, not deleted — an
inventory entry can exist for reasons Orion knows nothing about (kit
deliberately unmonitored, hosts that aren't network devices), so
deleting on that basis would be acting on half the picture.

**"Already exists" means what Ansible sees.** The inventory is read
through `inventory_reader.py`, i.e. Ansible's own `InventoryManager`,
so group_vars, host_vars, INI inventories, inventory directories,
vault-encrypted values and configured inventory plugins all count.

Matching, first hit winning, with the report always naming the rule:

| Rule | Compares | Notes |
|---|---|---|
| `polling-ip` | Orion `IPAddress` vs a host's `ansible_host` | Strongest — literally the address Ansible would connect to |
| `name` | `Caption`/`SysName`/`DNS` vs the inventory hostname | Case-insensitive, trailing dot stripped |
| `short-name` | The same three with the domain stripped | Last, and disableable with `--no-short-name-match` |

Short-name matching is the one rule that can produce a *false* "already
exists", since short names collide across domains. It is last and
optional because the cost of a false positive — a device silently never
added — is much harder to notice than a duplicate.

Where the rules disagree (an IP matching one inventory host while a name
matches a different one) the device is reported **AMBIGUOUS** and is not
added. That is a real inconsistency between the two systems and it wants
a human rather than a default.

The `EXISTS` rows are listed too, with the rule that matched: a device
wrongly judged to already exist is the failure mode that would otherwise
be silent, so the evidence for every such judgement is on screen.

### `--write-new` vs `--merge-into`

`--merge-into` rewrites the target through a YAML round-trip, so
**comments and hand-formatting in it are lost**. A timestamped `.bak`
is written first and the tool refuses if the backup can't be created.

`--write-new` never touches the existing file. Use the generated file as
a second inventory source instead:

```bash
ansible-playbook -i inventory.yml -i orion_discovered.yml ...
```

That is the safer habit and the documented default path. Running the
sync twice is a no-op either way — devices added on the first run match
by polling IP on the second.

New hosts land in group `orion_discovered` (`--group` to change),
deliberately separate from existing groups so generated entries are
obvious and easy to reverse.

> This repo holds no inventory of its own — point `--inventory` at
> whichever one you mean. Note also that if an `ansible.cfg` in scope
> sets `vault_password_file`, Ansible requires that file to exist *even
> when nothing in the inventory is encrypted*; use
> `--vault-password-file` to point elsewhere.

## Filtering

```bash
# one vendor's kit only
--where "Vendor = @v" --param v=Cisco

# skip nodes Orion isn't currently managing
--where "Unmanaged = @u" --param u=int:0
```

Values always go through `--param`, never inline in `--where`: SWQL is a
query language and interpolating values into it is the same class of
mistake as SQL injection. Parameters are strings unless prefixed `int:`
— **SWQL is typed**, so comparing a boolean column to the string `"0"`
is a server-side error, not a silent empty result.

## Extra fields

```bash
--extra-columns Vendor,Status,IOSVersion
--extra-columns CustomProperties.Site
```

Site, role and owner are almost always Orion *custom properties* rather
than built-in columns, and they are per-installation by definition —
`--list-custom-properties` is the only way to know what exists here.

## Notes on the data

- **`IPAddress` is the polling IP** — the address Orion polls the node
  on, which is the operational definition of a management IP: by
  construction it is an address that answers management traffic from a
  management system. It is not the only address on the device;
  `Orion.NodeIPAddresses` holds every discovered interface address and
  is a different question (`OrionClient.get_node_ip_addresses()`).
- **`SysName` and `DNS` routinely disagree.** `SysName` is whatever the
  device calls itself over SNMP; `DNS` is what name resolution says.
  Both are selected rather than picking one — which is authoritative is
  a per-estate question that only real data can answer.
- **ICMP-only nodes often have neither.** The renderers emit an empty
  field rather than the string `None`.
- **Captions are not unique.** Orion does not enforce it. The inventory
  emitter appends the `NodeID` to a duplicate rather than letting two
  hosts collapse into one YAML key.
- **Nodes with no polling IP are emitted, not skipped**, carrying
  `orion_polling_ip_missing: true`. A device missing from an inventory
  is much harder to notice than one that is present and obviously
  incomplete.

## Credentials

Read access is all any of this needs.

An ansible-vault-encrypted secret file is the recommended route where
ansible-core is available:

```bash
cat > orion_secret.yml <<EOF
username: ansible
password: <the Orion account password>
EOF
ansible-vault encrypt orion_secret.yml
```

then `--use-vault-secret`. Commit it — it is encrypted.

Otherwise use `--password-env` (keeps the password out of `ps` and shell
history) or the interactive prompt.

## Tests

```bash
python3 orion_mock_swis_test.py
```

No network access and no Orion instance required — the mock server
binds to localhost. The inventory tests are skipped if ansible-core
isn't installed.

## History

This tooling started in **workbench/ansible** (issue #20) and was moved
here so the SolarWinds work stands on its own. The original commits are
`d6ac367`, `43129a5`, `a88ada5` and `fd69534` in that repo.

`inventory_reader.py` is a cut-down port of workbench/ansible's
`inventory_resolver.py` — see that file's own docstring for why it was
ported rather than imported across a repo boundary, and what that
duplication costs.
