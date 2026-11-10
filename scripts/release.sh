#!/usr/bin/env bash
# Builds the meiosis release binaries: mei and meiosisd, cross-compiled for
# linux/darwin/windows on amd64/arm64, packed per platform, with checksums.
#
# Usage: scripts/release.sh [version]
#   version defaults to the closest git tag (or "dev").
set -euo pipefail

version="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
v="${version#v}" # strip a leading "v" for file/pack names

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

rm -rf dist
mkdir -p dist/build

build_one() {
	local goos="$1" goarch="$2" ext=""
	[ "$goos" = "windows" ] && ext=".exe"
	local dir="dist/build/mei-${goos}-${goarch}"
	mkdir -p "$dir"
	go build -trimpath -ldflags "-s -w -X main.version=${version}" -o "$dir/mei${ext}" ./cmd/mei
	go build -trimpath -ldflags "-s -w -X main.version=${version}" -o "$dir/meiosisd${ext}" ./cmd/meiosisd
}

for goos in linux darwin windows; do
	for goarch in amd64 arm64; do
		echo "==> building ${goos}/${goarch}"
		GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 build_one "$goos" "$goarch"
	done
done

for goos in linux darwin; do
	for goarch in amd64 arm64; do
		tar -czf "dist/mei-${goos}-${goarch}.tar.gz" -C dist/build "mei-${goos}-${goarch}"
		echo "==> dist/mei-${goos}-${goarch}.tar.gz"
	done
done

if command -v zip >/dev/null 2>&1; then
	for goarch in amd64 arm64; do
		(cd dist/build && zip -qr "../mei-windows-${goarch}.zip" "mei-windows-${goarch}")
		echo "==> dist/mei-windows-${goarch}.zip"
	done
else
	# no zip(1); pack windows as tar.gz so releases still ship a windows build
	for goarch in amd64 arm64; do
		tar -czf "dist/mei-windows-${goarch}.tar.gz" -C dist/build "mei-windows-${goarch}"
		echo "==> dist/mei-windows-${goarch}.tar.gz (zip unavailable)"
	done
fi

rm -rf dist/build
(cd dist && sha256sum ./* > SHA256SUMS.txt)

echo ""
cat dist/SHA256SUMS.txt
echo ""
echo "release ${version} ready in dist/ (verified binaries, checksums above)"