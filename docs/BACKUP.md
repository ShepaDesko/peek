# Backup and restore

## What a backup contains

| Item | Why it matters |
|---|---|
| `peek.db` | a consistent snapshot of the database (SQLite `VACUUM INTO`, taken hot) |
| `peek.toml` | the configuration |
| `master.key` | the server master key |
| `files/` | the encrypted file blobs |
| `manifest.json` | version, date, host, contents |

**Read this twice.** A backup holds the **ciphertext of every still-active
secret**. It cannot be decrypted without the keys, which only live in the links
your users hold — but it is still the most sensitive file on the machine.
Keep the retention short (7 days by default), store it with restricted access,
and set a passphrase so the archive is encrypted:

```toml
[backup]
enabled    = true
dir        = "/var/backups/peek"
keep       = 7
passphrase = "a long passphrase stored in your password manager"
```

With a passphrase the archive is encrypted with **age** (scrypt recipient) and
named `.tar.gz.age`. Without one, `peek backup` warns you on every run.

**Store `master.key` separately as well.** Without it, encrypted metadata in a
restored database is unrecoverable. Backing it up next to the database in the
same archive is convenient; keeping a second copy elsewhere is what saves you.

## Scheduled backups

The package installs a timer, enabled by `peek setup`:

```bash
sudo systemctl enable --now peek-backup.timer
systemctl list-timers peek-backup.timer
journalctl -u peek-backup -n 20
```

It runs at 03:17 local time with up to 15 minutes of jitter, and catches up
after a reboot (`Persistent=true`). Change the schedule with
`systemctl edit peek-backup.timer`.

## By hand

```bash
sudo peek backup                                  # to backup.dir
sudo peek backup --to /mnt/nfs/peek --keep 14
sudo peek backup --passphrase 'ch-de-sauvegarde'
sudo peek backup --list
```

## Restoring

```bash
sudo systemctl stop peek
sudo peek restore /var/backups/peek/peek-20261120T031700Z.tar.gz.age \
     --passphrase '…' --include-config
sudo systemctl start peek
sudo peek doctor
```

- The current database is moved aside as `peek.db.before-restore-<timestamp>`
  rather than deleted: restoring the wrong archive is recoverable.
- `--include-config` also restores `peek.toml` and `master.key`. Without it,
  only the data comes back and your current configuration is kept.
- `--dry-run` reads the manifest and reports what would be restored, without
  writing anything.

## Off-site copies

Peek writes locally and deliberately does not ship credentials for remote
storage. Copy the directory with whatever your estate already uses:

```bash
# rsync over SSH
rsync -az --delete /var/backups/peek/ backup@nas:/srv/backups/peek/

# S3-compatible object storage
aws s3 sync /var/backups/peek/ s3://acme-backups/peek/ --storage-class STANDARD_IA

# A systemd timer of your own, after peek-backup.service
```

## Testing a restore

A backup you have never restored is a hypothesis. Once a quarter:

```bash
sudo peek restore --dry-run /var/backups/peek/peek-….tar.gz.age --passphrase '…'
```

and, on a spare machine, a full restore followed by `peek doctor`. The CI
pipeline runs a backup and a restore on every push, which keeps the code
honest — it cannot check your operational copy.

## Retention and privacy

- Secrets are deleted from the live database the moment they are read or
  expire; only an audit trail without content remains.
- Old backups still contain secrets that were active at the time, which is the
  real reason to keep `keep` small.
- `security.audit_retention` (one year by default) bounds the audit trail, and
  `security.anonymize_ips` keeps only a /24 or /48 prefix of each address.
