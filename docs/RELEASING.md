# Cutting a release

A release is a tag. Everything else — building the interface, embedding it,
building for each platform, the `.deb` and `.rpm`, the checksums, the
signature and the SBOM — happens in `.github/workflows/release.yml` and is
what `peek update` later verifies.

## The signing key, once

`peek update` trusts one key, and that key is **compiled into the binary** at
build time. An installed 1.0.0 verifies 1.1.0 with the key it was built with,
so the chain works with no network trust and no certificate authority — and it
also means the key cannot be rotated without every installed instance needing
a manual update. Generate it once, keep it, and do not lose it.

```bash
# passwordless: the workflow is not interactive, and the GitHub secret store
# is what protects it
minisign -G -W -p peek.pub -s peek.key
```

Then two repository secrets:

```bash
gh secret set PEEK_SIGNING_KEY < peek.key
gh secret set PEEK_SIGNING_PUBKEY --body "$(sed -n 2p peek.pub)"
```

`PEEK_SIGNING_KEY` is the whole two-line private key file.
`PEEK_SIGNING_PUBKEY` is only the second line of the `.pub` file — the
base64, without the comment.

Now put `peek.key` somewhere you will still have it in three years: a password
manager, not a laptop. GitHub will not give it back, and losing it means every
installed instance stops being able to verify an update.

The workflow refuses to run without both, rather than publishing something
unsigned.

## Then, per release

1. Move `## [Unreleased]` in `CHANGELOG.md` down into a dated version
   heading. The release notes are generated from it.
2. Make sure the tree is green:

```bash
make lint test budget
make e2e
```

3. Tag and push:

```bash
git tag -a v1.2.3 -m "Peek 1.2.3"
git push origin v1.2.3
```

The workflow runs the Go and TypeScript suites again before it publishes
anything, so a tag on a broken commit produces no release rather than a broken
one.

## What comes out

| Artefact | For |
|---|---|
| `peek_<v>_linux_amd64.tar.gz`, `_arm64` | `peek update`, and `install.sh` |
| `peek_<v>_linux_amd64.deb`, `.rpm` | Debian/Ubuntu, RHEL/Rocky/Alma |
| `peek-cli_<v>_<os>_<arch>.tar.gz` | the command-line client, three platforms |
| `checksums.txt` | SHA-256 of every artefact |
| `checksums.txt.minisig` | the signature — one signature covers everything |
| `peek_<v>.sbom.json` | CycloneDX, for whoever asks |

`peek update` downloads the checksum file, verifies the signature against the
key compiled into the running binary, verifies the archive against the
checksum, and only then replaces anything. `peek rollback` keeps the previous
binary.

## Checking it by hand

```bash
minisign -Vm checksums.txt -P "$(sed -n 2p peek.pub)"
sha256sum -c checksums.txt --ignore-missing
```

## A dry run, without publishing

```bash
make snapshot
```

Builds every artefact into `dist/` and skips the signature and the SBOM, which
need the key and `syft`. It is how you find out that a packaging change is
broken without spending a tag on it.

## Version numbers

Semantic versioning, and the thing being versioned is the **HTTP API and the
configuration file**, not the interface.

- a new `peek.toml` setting with a safe default, or a new endpoint: minor;
- a setting removed or changed in meaning, an endpoint changed, a migration
  that an older binary cannot run against: major;
- anything else: patch.

Migrations are additive, so an older node keeps working against a newer
schema — which is what makes a rolling upgrade safe. Rolling *back* past a
migration is not; see [`UPGRADE.md`](UPGRADE.md).
