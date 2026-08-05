#!/usr/bin/env python3
"""
inventory_reader.py

Minimal, vault-aware reader for an Ansible inventory: enumerate every
host, and resolve the address Ansible would actually connect to.

Used by orion_inventory_sync.py to answer one question -- "is this
SolarWinds device already in the Ansible inventory?" -- and nothing
else. It deliberately does not resolve credentials, group membership,
or anything the reconciliation does not need.

## Provenance, and why this is a port rather than an import

This is a cut-down port of `inventory_resolver.py` in
**workbench/ansible**, which is the fuller implementation (credentials,
per-group enumeration, connection addresses) used by that repo's
peering, flowspec and discovery modules.

When the Orion tooling lived in workbench/ansible it imported that
module directly. Moving to this repo, the choice was between importing
across a repo boundary -- which would make this repo unusable unless
workbench/ansible happened to be checked out beside it and on
PYTHONPATH -- and porting the ~60 lines actually needed. Repo
independence won: a standalone repo that only works next to another
one is not standalone.

The cost is real and worth naming: **this logic now exists twice.** If
the vault resolution chain changes in workbench/ansible, it should
change here too. The surface is deliberately small to keep that cheap,
and the behaviour it must match is documented below rather than left
implicit.

## Why the inventory is read through Ansible

"Already in the inventory" has to mean *what Ansible sees*, so this
uses Ansible's own InventoryManager rather than parsing YAML. That way
group_vars, host_vars, INI-format inventories, inventory directories,
vault-encrypted values and any configured inventory plugins are all
accounted for. A YAML parse would be a second, subtly different opinion
about the same question -- and would silently disagree on exactly the
inventories that are most complicated.

## Vault

`ansible-playbook` wires vault decryption up during its own CLI
bootstrap; a script using the Ansible API directly does not get that
for free, so it is done explicitly here.

Resolution order, matching workbench/ansible's inventory_resolver.py:

  1. the vault_password_file argument, if given
  2. $ANSIBLE_VAULT_PASSWORD_FILE
  3. ansible.cfg's vault_password_file, found by walking upward from the
     current directory

Step 3 reads ansible.cfg **directly via configparser** rather than
through Ansible's own constants module. That is not an arbitrary
choice: workbench/ansible records that constants did not reliably
reflect ansible.cfg's configured value on every Ansible version --
returning nothing even with vault_password_file correctly set, while
`--vault-password-file` with the same path worked. Keep it this way.

Note that once a vault password file *is* configured, Ansible requires
it to exist, **even for an inventory containing nothing encrypted**.
That is Ansible's own behaviour (`ansible-playbook` fails identically),
so it is not worked around here.

Requires: ansible-core.
"""

import configparser
import os
from pathlib import Path

DEFAULT_INVENTORY_CANDIDATES = [
    "inventory.yml",
    "inventory.yaml",
    "inventory",
    "../inventory.yml",
    "../inventory.yaml",
    "../inventory",
]


def find_default_inventory():
    """Returns a LIST of inventory sources, or None if nothing was
    found. Resolution order: $ANSIBLE_INVENTORY, then the first existing
    path in DEFAULT_INVENTORY_CANDIDATES.

    The list return is worth noticing: callers that write
    `[find_default_inventory()]` build a nested list, which
    InventoryManager will not accept. Use the result directly.
    """
    env_inv = os.environ.get("ANSIBLE_INVENTORY")
    if env_inv:
        return [env_inv]
    for candidate in DEFAULT_INVENTORY_CANDIDATES:
        if Path(candidate).exists():
            return [candidate]
    return None


def _read_ansible_cfg_vault_password_file():
    """Finds vault_password_file in ansible.cfg's [defaults] section,
    walking upward from the current directory (the way git finds .git),
    then ~/.ansible.cfg, then /etc/ansible/ansible.cfg. $ANSIBLE_CONFIG
    takes precedence over all of it.

    Returns None if no config file is found, it has no [defaults]
    section, or no vault_password_file is set.
    """
    candidates = []

    if os.environ.get("ANSIBLE_CONFIG"):
        candidates.append(os.environ["ANSIBLE_CONFIG"])

    cwd = Path.cwd()
    for directory in (cwd, *cwd.parents):
        candidates.append(str(directory / "ansible.cfg"))

    candidates.append(str(Path.home() / ".ansible.cfg"))
    candidates.append("/etc/ansible/ansible.cfg")

    for candidate in candidates:
        path = Path(candidate)
        if not path.is_file():
            continue
        parser = configparser.ConfigParser()
        try:
            parser.read(path)
        except configparser.Error:
            continue
        if parser.has_option("defaults", "vault_password_file"):
            value = parser.get("defaults", "vault_password_file").strip()
            if value:
                value_path = Path(value).expanduser()
                if not value_path.is_absolute():
                    # Relative paths are relative to the config file, not
                    # to wherever the script happened to be started.
                    value_path = path.parent / value_path
                return str(value_path)
    return None


def configure_vault_secrets(loader, vault_password_file=None):
    """Attaches a vault decryption secret to an Ansible DataLoader, so
    reading vault-encrypted group_vars/host_vars works the same way it
    does under ansible-playbook. No-op if no password file is
    configured anywhere in the resolution chain."""
    from ansible.parsing.vault import get_file_vault_secret

    pwd_file = (
        vault_password_file
        or os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE")
        or _read_ansible_cfg_vault_password_file()
    )

    if not pwd_file:
        return

    secret = get_file_vault_secret(filename=pwd_file, loader=loader)
    secret.load()
    secrets = [("default", secret)]
    loader.set_vault_secrets(secrets)

    # Whole-file encryption is decrypted by the loader, and the above is
    # enough for it. Inline `!vault` scalars -- what `ansible-vault
    # encrypt_string` produces, and the common shape for an existing
    # vars file where only the sensitive values are encrypted -- are
    # different: ansible-core returns a lazy object that decrypts on
    # access, using a PROCESS-GLOBAL secrets context that ansible-playbook
    # sets up during its own CLI bootstrap. A script using the API
    # directly does not get that, so str() on such a value raises
    # "A required VaultSecretsContext context is not active" -- at the
    # point of use, far from the load that looks responsible.
    #
    # Confirmed on ansible-core 2.20.1. Guarded because the class does
    # not exist on older versions, where these scalars decrypt eagerly
    # via the loader and none of this is needed.
    try:
        from ansible.parsing.vault import VaultSecretsContext
    except ImportError:  # pragma: no cover - older ansible-core
        return

    # initialize() raises if called twice, and the context is global for
    # the process, so an existing one is left alone.
    #
    # That makes it FIRST-WRITE-WINS: if one process configures vault
    # secrets twice with different password files, inline `!vault`
    # scalars decrypt with whichever came first, while whole-file
    # decryption still honours each loader's own secrets. Not a problem
    # for these CLIs -- one invocation uses one vault password -- but it
    # is why passing a different --vault-password-file for the inventory
    # than for the credentials file would misbehave in one direction
    # only, which would be baffling without this note.
    if VaultSecretsContext.current(optional=True) is None:
        VaultSecretsContext.initialize(VaultSecretsContext(secrets=secrets))


def load_yaml_with_vault(path, vault_password_file=None):
    """Loads `path` as YAML the way Ansible itself would, transparently
    decrypting any inline `!vault |` scalars inside an otherwise-plain
    file, and whole-file `ansible-vault encrypt`ed files too.

    Used by OrionClient.from_vault_secret() to read orion_secret.yml, so
    the Orion password can sit in an encrypted file the same way this
    repo's sibling (workbench/ansible) handles phpIPAM's token and
    PeeringDB's API key.

    Values come back as Ansible's own AnsibleUnicode/AnsibleMapping
    types rather than plain str/dict. They behave like their plain
    equivalents for virtually all purposes, but callers that care --
    equality against a plain str, JSON serialisation -- should cast.
    """
    from ansible.parsing.dataloader import DataLoader

    loader = DataLoader()
    configure_vault_secrets(loader, vault_password_file)
    return loader.load_from_file(str(path))


class InventoryReader:
    """Reads an Ansible inventory and answers the two questions the
    Orion reconciliation needs: which hosts exist, and what address each
    would be reached on."""

    def __init__(self, sources, vault_password_file=None):
        from ansible.inventory.manager import InventoryManager
        from ansible.parsing.dataloader import DataLoader
        from ansible.vars.manager import VariableManager

        self._loader = DataLoader()
        configure_vault_secrets(self._loader, vault_password_file)
        self._inventory = InventoryManager(loader=self._loader, sources=sources)
        self._variables = VariableManager(loader=self._loader,
                                          inventory=self._inventory)
        self._addr_cache = {}

    def list_all_hosts(self):
        """Every hostname in the inventory, across all groups, sorted.
        Ansible de-duplicates a host that appears in several groups, so
        each name appears once regardless of how many groups it is in."""
        return sorted(host.name for host in self._inventory.get_hosts())

    def get_connection_address(self, hostname):
        """The address Ansible would actually connect to: ansible_host
        if set, otherwise the hostname itself -- the same fallback
        Ansible's own connection plugins use.

        Callers matching on IP addresses need to know about that
        fallback: a host with no ansible_host returns its own name here,
        which is not an address.
        """
        if hostname in self._addr_cache:
            return self._addr_cache[hostname]

        host = self._inventory.get_host(hostname)
        address = hostname
        if host is not None:
            ansible_host = self._variables.get_vars(host=host).get("ansible_host")
            if ansible_host:
                address = str(ansible_host)

        self._addr_cache[hostname] = address
        return address
