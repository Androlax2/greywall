---
id: releasing
title: Releasing (Cockpit builds)
---

# Releasing (Cockpit builds)

This fork publishes the greywall builds that Agent Cockpit installs. The
workflow is `.github/workflows/cockpit-release.yml`; the build itself is
`scripts/cockpit-release-build.sh`. Upstream's GoReleaser workflow ignores
these tags.

## Cut a release

1. Make sure the commit you want is on the `dotfiles` branch and its pull
   request checks (including "Cockpit release") passed.
2. Pick the tag: `v<upstream version>-cockpit.<n>`. The upstream version is
   the greywall release `dotfiles` is built on
   (`git describe --tags --abbrev=0 --exclude '*-cockpit.*' origin/dotfiles`);
   `<n>` starts at 1 and goes up for each Cockpit build on that version.
3. Tag and push:

   ```bash
   git tag -a v0.3.7-cockpit.1 -m v0.3.7-cockpit.1 origin/dotfiles
   git push origin v0.3.7-cockpit.1
   ```

The workflow refuses a tag that does not match the pattern or that points at
a commit outside `dotfiles`. It then builds, smoke-tests each archive on its
own platform, attests provenance and publishes the release.

The tagged commit must contain this workflow and the `!v*-cockpit.*` exclusion
in `release.yml`: GitHub runs the workflow files of the tagged commit, so an
older commit would also start upstream's GoReleaser release.

## What a release contains

| Asset | Content |
| --- | --- |
| `greywall_<version>_linux_x86_64.tar.gz` | Linux amd64, tun2socks embedded |
| `greywall_<version>_linux_arm64.tar.gz` | Linux arm64, tun2socks embedded |
| `greywall_<version>_darwin_arm64.tar.gz` | macOS Apple silicon |
| `SHA256SUMS` | SHA-256 of the three archives |

Each archive holds one directory, `greywall_<version>_<target>/`, with
`greywall`, a `greywatch` symlink, `LICENSE`, `NOTICE` and `LICENSES/`.
`<version>` is the tag without the leading `v`.

Builds are reproducible: pinned Go (`GO_VERSION` in the workflow),
`CGO_ENABLED=0`, `-trimpath`, an empty build ID, the commit time as build
time, and archives with fixed owners and timestamps. tun2socks v2.5.2 is
downloaded per target and checked against the SHA-256 pinned in the build
script before it is embedded. The `greywall` binary is bit-for-bit identical on any
machine with the same Go; the `.tar.gz` around it matches only with the GNU tar and gzip of
the `ubuntu-24.04` runner, so compare the extracted binary when rebuilding
elsewhere.

## How Cockpit consumes it

Cockpit pins, per release: the tag, the commit (named in the release notes),
and for each target the asset URL and its SHA-256 from `SHA256SUMS`. It
downloads the archive for the machine, checks the SHA-256, and installs
`greywall` from it. To update, Cockpit's pin is bumped to the new tag and
checksums.

To check a download by hand:

```bash
gh release download v0.3.7-cockpit.1 -R Androlax2/greywall
sha256sum -c SHA256SUMS
gh attestation verify greywall_0.3.7-cockpit.1_linux_x86_64.tar.gz -R Androlax2/greywall
```
