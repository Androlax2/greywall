#!/usr/bin/env bash
# Builds one reproducible release archive for Cockpit (see docs/releasing.md).
#
# Usage: scripts/cockpit-release-build.sh <goos> <goarch> <version> <out-dir>
#   goos/goarch: linux/amd64, linux/arm64 or darwin/arm64
#   version:     stamped into the binary, e.g. 0.3.7-cockpit.1
#
# Run from a clean checkout: the embedded tun2socks must be the one this
# script verified, so a cached copy in internal/sandbox/bin is refused.
set -euo pipefail

TUN2SOCKS_VERSION="v2.5.2"
# SHA-256 of the upstream release zips. xjasonlyu/tun2socks publishes no
# checksum file, so these were recorded on 2026-11-01 from the GitHub release.
# darwin is absent on purpose: tun2socks is embedded on Linux only
# (internal/sandbox/tun2socks_embed.go).
TUN2SOCKS_SHA256_LINUX_AMD64="4aa7737009a9f06b9f4957c4fc12932ae0cd2039471d2ae4e5d4666ffeb40a2e"
TUN2SOCKS_SHA256_LINUX_ARM64="b83bc4961b33aa3ec0399c801a97c2c47766462991ffa488a4cbaee1ab3e0bff"

fail() {
	echo "[cockpit-release-build] $*" >&2
	exit 1
}

[ "$#" -eq 4 ] || fail "usage: $0 <goos> <goarch> <version> <out-dir>"
goos="$1"
goarch="$2"
version="$3"
out_dir="$4"

case "$goos/$goarch" in
linux/amd64) target="linux_x86_64" tun2socks_sha256="$TUN2SOCKS_SHA256_LINUX_AMD64" ;;
linux/arm64) target="linux_arm64" tun2socks_sha256="$TUN2SOCKS_SHA256_LINUX_ARM64" ;;
darwin/arm64) target="darwin_arm64" tun2socks_sha256="" ;;
*) fail "unsupported target $goos/$goarch" ;;
esac

[[ "$version" =~ ^[0-9A-Za-z.+-]+$ ]] || fail "version '$version' has unexpected characters"

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

embed_dir="internal/sandbox/bin"
if compgen -G "$embed_dir/tun2socks-*" >/dev/null; then
	fail "$embed_dir already holds tun2socks binaries; run 'make clean' so only the verified one is embedded"
fi

commit="$(git rev-parse HEAD)"
commit_epoch="$(git log -1 --format=%ct HEAD)"
commit_time="$(TZ=UTC git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd HEAD)"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"; rm -f "$repo_root/$embed_dir"/tun2socks-linux-*' EXIT

if [ "$goos" = linux ]; then
	zip_name="tun2socks-linux-$goarch.zip"
	curl -fsSL --retry 3 -o "$work_dir/$zip_name" \
		"https://github.com/xjasonlyu/tun2socks/releases/download/$TUN2SOCKS_VERSION/$zip_name"
	echo "$tun2socks_sha256  $work_dir/$zip_name" | sha256sum -c --strict -
	unzip -q "$work_dir/$zip_name" "tun2socks-linux-$goarch" -d "$work_dir/tun2socks"
	install -m 0755 "$work_dir/tun2socks/tun2socks-linux-$goarch" "$embed_dir/tun2socks-linux-$goarch"
fi

stage_name="greywall_${version}_${target}"
stage_dir="$work_dir/$stage_name"
mkdir -p "$stage_dir/LICENSES"

CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
	-trimpath -buildvcs=false \
	-ldflags "-s -w -buildid= -X main.version=$version -X main.buildTime=$commit_time -X main.gitCommit=$commit" \
	-o "$stage_dir/greywall" \
	./cmd/greywall

ln -s greywall "$stage_dir/greywatch"
cp LICENSE NOTICE "$stage_dir/"
cp LICENSES/* "$stage_dir/LICENSES/"

mkdir -p "$out_dir"
archive="$(cd "$out_dir" && pwd)/$stage_name.tar.gz"
tar --sort=name --format=gnu \
	--mtime="@$commit_epoch" --owner=0 --group=0 --numeric-owner \
	--mode='u+rwX,go+rX,go-w' \
	-C "$work_dir" -cf - "$stage_name" | gzip -n -9 >"$archive"

echo "$archive"
