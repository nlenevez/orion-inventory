# solarwinds — TODO

## Live-instance confirmation gate (blocked on airgapped access)

Nothing here has spoken to a real Orion server. The mock-server test
suite proves the client is internally consistent and speaks the SWIS
protocol correctly; it proves nothing about SolarWinds, because the
mock's schema is this repo's own assumption.

Run `orion_probe.py` on the airgapped side and bring the output back.
Then, from `summary.txt`:

- [ ] **connectivity** — confirms SWIS answers on port 17778 and the
      account can read `Orion.Nodes`. If this fails, nothing else in
      the capture means anything. Check the port first: SWIS is a
      separate listener from the Orion web UI on 443 and is often
      firewalled separately, so a working web UI does not imply a
      working API path.
- [ ] **field IPAddress / MachineType / SysName / DNS** — the four
      fields asked for, probed one at a time so a failure names the
      specific property. Any FAIL here means the assumed name is wrong
      on this Orion version; the SWIS error message names the bad
      property, and `orion_nodes_properties.json` lists what the
      instance really has. Correct `DEFAULT_NODE_COLUMNS` in
      `orion_client.py`.
- [ ] **status distribution** — confirms or corrects
      `NODE_STATUS_NAMES`. Any Status code appearing in the capture
      that is missing from that map renders as a bare integer. Add the
      real ones; do not guess at codes that never appear.
- [ ] **paging cursor** — confirms SWQL accepts `TOP n` plus a bound
      parameter in a `WHERE` clause, the two things `get_nodes()`
      paging depends on. If SWQL on this version rejects either,
      `--no-paging` is the fallback and the paging code needs
      rewriting against whatever the version does support.
- [ ] **node count** — tells us the size of the estate, and therefore
      whether the 500-row default page size is sensible.
- [ ] **node custom properties** — records which custom properties this
      Orion defines (site, role, owner, …). Zero rows is a legitimate
      answer. This decides whether inventory grouping is possible at
      all, and on what.

Once the capture is in hand, update `README.md` to say the fields are
confirmed against a live instance, and drop the "not yet confirmed"
language.

## Follow-ups, once the schema is confirmed

- [ ] **Decide SysName vs DNS as the authoritative device name.** They
      routinely disagree and both are captured for exactly that reason.
      Real data decides it; it cannot be decided from here.
- [ ] **Inventory grouping.** New hosts currently land in one flat
      `orion_discovered` group, because grouping needs custom
      properties whose names are unknown until the probe runs. Once
      they are known, group on site/role rather than leaving a flat
      list.
- [ ] **Decide whether this becomes a dynamic inventory source.** The
      current shape generates a static YAML file, which is inspectable
      and diffable — a genuine advantage over a plugin that queries
      Orion on every playbook run, especially given a device list that
      changes slowly, and especially across an airgap. A real Ansible
      inventory plugin is the alternative; it needs a decision, not a
      default.
- [ ] **Decide what `orion_inventory_sync.py` should do about devices
      that have *left* Orion.** It currently reports nothing about
      them: it only walks the Orion list. Detecting inventory hosts
      with no corresponding Orion node is the mirror-image query and is
      easy to add — what is not obvious is what should happen to them,
      since an inventory entry can legitimately exist for kit Orion
      does not monitor. Report-only would be safe; removal would not.
- [ ] **Non-network kit.** Orion monitors UPSes, servers and anything
      else with an IP. `--where` can exclude them today, but the right
      default filter is unknown until the real estate is visible in a
      probe capture.
- [ ] **Watch the AMBIGUOUS count on the first real run.** A large
      number would mean the inventory and Orion disagree systematically
      — most likely a naming convention difference the matching rules
      should understand — rather than a handful of one-off
      inconsistencies. That is a signal about the rules, not just about
      the data.
- [ ] **Reconcile against phpIPAM.** `phpipam_client.py` already exists
      in workbench/ansible (issue #6), and IPAM and Orion will disagree
      about what exists and at what address. Which is authoritative is a
      policy question worth settling before anything consumes both. Note
      that lives in the other repo — decide whether the reconciliation
      belongs there, here, or in neither.
- [ ] **Filtering policy for inventory generation.** Whether unmanaged
      nodes, ICMP-only nodes, or non-network kit (UPSes, servers)
      belong in an Ansible inventory at all. `--where` supports
      excluding them today; what the *default* should be is a decision.

## Notes

- No CI stage, deliberately. Everything here is read-only against a
  system on an airgapped network that the shared runner cannot reach.
  (If one is ever added, jobs need `tags: [network-jump]` on
  gitlab.l33t.net.au or they sit pending forever.)
- `orion_mock_swis_test.py` needs no network and no Orion instance, so
  it *could* run in CI if this repo ever wants a test stage. It binds
  only to localhost.
- `inventory_reader.py` duplicates logic from workbench/ansible's
  `inventory_resolver.py`. If the vault resolution chain changes there,
  change it here too.
