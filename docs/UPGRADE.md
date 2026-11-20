# Upgrading Peek

Upgrades are meant to be one command, on a box you reach over SSH, with a way
back if it goes wrong.

```bash
sudo peek update
```

## What that command actually does

1. Asks the release source (GitHub releases, or `update_url` for an internal
   mirror) for the newest version on your channel, and shows the changelog.
2. Downloads the archive for this architecture and verifies its **SHA-256**
   against `checksums.txt`.
3. Verifies the **minisign signature** of `checksums.txt` with the public key
   compiled into the running binary. A bad or missing signature stops the
   update — there is no "continue anyway" prompt, only an explicit
   `--allow-unsigned` flag you have to type yourself.
4. Takes a **backup** (database, configuration, master key, encrypted files).
5. Installs the new binary with an atomic rename, keeping the old one at
   `/usr/lib/peek/peek.previous`.
6. Restarts the service. **Migrations run at startup**, so there is no separate
   migration step.
7. Polls `/readyz` for up to 60 seconds. If the new version does not come up,
   it **puts the previous binary back automatically**, restarts, and tells you
   to look at `journalctl -u peek`.

## Options

```bash
sudo peek update --check                       # only report; exit code 10 when an update exists
sudo peek update --version 1.4.2               # a specific version, including going back
sudo peek update --channel beta                # stable (default) or beta
sudo peek update --file peek_1.4.2_linux_amd64.tar.gz   # offline host
sudo peek update --signature peek_1.4.2_linux_amd64.tar.gz.minisig
sudo peek update --yes --skip-backup           # unattended; the skip is not recommended
sudo peek rollback                             # back to the previous binary, by hand
```

`--check` is built for monitoring:

```bash
peek update --check; case $? in 0) echo up-to-date ;; 10) echo update available ;; *) echo check failed ;; esac
```

## Air-gapped hosts

Copy the archive and its signature onto the machine, then:

```bash
sudo peek update --file peek_1.4.2_linux_amd64.tar.gz
```

The signature is verified exactly as in the online path — the only difference
is where the bytes came from. Nothing contacts the internet. Set
`update_check = false` in `peek.toml` so the daily check stops too.

## Package upgrades

```bash
sudo apt install ./peek_1.4.2_linux_amd64.deb
sudo dnf upgrade ./peek-1.4.2.amd64.rpm
```

The maintainer scripts restart the service and report a failed restart on
stderr. Your configuration, database and master key are untouched.

## Rolling back

```bash
sudo peek rollback
```

This restores `/usr/lib/peek/peek.previous` and restarts. If a migration ran
and the older schema cannot be read, restore the backup `peek update` took
before the change:

```bash
sudo peek backup --list
sudo peek restore /var/backups/peek/peek-20261120T031700Z.tar.gz.age --passphrase '…'
sudo systemctl restart peek
```

## Compatibility rules

- Versions follow **SemVer**. A patch or minor release never requires manual
  steps.
- Migrations stay compatible with the previous minor version whenever that is
  possible; when it is not, the changelog says so and `peek update` asks for
  confirmation.
- A change to the configuration format is migrated automatically, keeping the
  old `peek.toml` as `peek.toml.bak`.
- Secret format versions are never redefined: `v1` links keep opening.

## Verifying by hand

```bash
sha256sum -c checksums.txt --ignore-missing
minisign -Vm checksums.txt -P "RWQ…"      # the public key is printed in the release notes
peek version
```

## High availability

With several nodes (milestone M9, PostgreSQL), upgrade one node at a time:
drain it at the load balancer, `peek update`, wait for `/readyz`, put it back.
Migrations are applied by the first node to start and are idempotent.
