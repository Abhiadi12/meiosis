#!/usr/bin/env bash
# Installs the latest meiosis release (mei and meiosisd) for the current
# platform by fetching the release archive and SHA256SUMS from GitHub, then
# installing the binaries into the user's PATH.
#
# Usage:
#   bash scripts/install.sh
#   curl -sSL <url> | bash
#
# Env overrides:
#   MEI_VERSION  - install a specific version (default: latest release)
#   MEI_REPO     - GitHub repo to fetch from (default: subhranshus-mindfire/meiosis)
#   MEI_PREFIX   - install directory (default: /usr/local/bin, on Windows
#                  $HOME/bin, falls back to $HOME/.local/bin when unwritable)
set -euo pipefail

version="${MEI_VERSION:-latest}"
repo="${MEI_REPO:-subhranshus-mindfire/meiosis}"
prefix="${MEI_PREFIX:-/usr/local/bin}"

say() { printf '\033[1;36m[mei install]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[mei install] error:\033[0m %s\n' "$*" >&2; exit 1; }

uname_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
uname_arch="$(uname -m | tr '[:upper:]' '[:lower:]')"
case "$uname_os" in
linux) goos="linux" ;;
darwin) goos="darwin" ;;
mingw* | msys* | cygwin*) goos="windows" ;;
*) die "unsupported OS: $uname_os (linux/darwin/windows only)" ;;
esac
case "$uname_arch" in
x86_64 | amd64) goarch="amd64" ;;
arm64 | aarch64) goarch="arm64" ;;
*) die "unsupported arch: $uname_arch (amd64/arm64 only)" ;;
esac

ext=""
work="mei-${goos}-${goarch}"
[ "$goos" = "windows" ] && ext=".exe"
archive="mei-${goos}-${goarch}.tar.gz"
[ "$goos" = "windows" ] && archive="mei-${goos}-${goarch}.zip"

if [ "$goos" = "windows" ] && [ -z "${MEI_PREFIX:-}" ]; then
	prefix="$([ -n "${LOCALAPPDATA:-}" ] && echo "$LOCALAPPDATA/mei" || echo "$HOME/bin")"
fi
if [ "$goos" != "windows" ] && [ "$prefix" = "/usr/local/bin" ] && [ ! -w "/usr/local/bin" ]; then
	prefix="$HOME/.local/bin"
	say "/usr/local/bin not writable, installing to ${prefix}"
fi

if [ "$version" = "latest" ]; then
	base="https://github.com/${repo}/releases/latest/download"
else
	base="https://github.com/${repo}/releases/download/${version}"
fi

say "platform: ${goos}/${goarch}, version: ${version}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if [ -t 1 ] && [ -z "${MEI_QUIET:-}" ]; then
	say "downloading ${archive} from ${repo} (this can take a moment)..."
	curl -fL --retry 3 --retry-delay 2 --speed-time 30 --speed-limit 1024 \
		--progress-bar -o "$tmp/$archive" "${base}/${archive}"
else
	say "downloading ${archive} from ${repo} (this can take a moment)..."
	curl -fsSL --retry 3 --retry-delay 2 --speed-time 30 --speed-limit 1024 \
		-o "$tmp/$archive" "${base}/${archive}"
fi
curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/SHA256SUMS.txt" "${base}/SHA256SUMS.txt"
if command -v sha256sum >/dev/null 2>&1; then
	(cd "$tmp" && sha256sum --check --status "SHA256SUMS.txt" --ignore-missing 2>/dev/null \
		|| grep "$archive" "$tmp/SHA256SUMS.txt" | sha256sum --check --status --ignore-missing -)
else
	expected="$(grep "  ${archive}$" "$tmp/SHA256SUMS.txt" | awk '{print $1}')"
	[ -n "$expected" ] || die "checksum for ${archive} not found in SHA256SUMS.txt"
	if command -v sha256sum.exe >/dev/null 2>&1; then
		actual="$(sha256sum.exe "$tmp/$archive" | awk '{print $1}')"
	else
		actual="$(certutil -hashfile "$tmp/$archive" SHA256 | tr -d '\r' | awk 'NR==2 {print $1}')"
	fi
	[ "$actual" = "$expected" ] || die "checksum mismatch for ${archive}"
	say "checksum verified"
fi

mkdir -p "$tmp/extract"
if [ "$goos" = "windows" ]; then
	if command -v unzip >/dev/null 2>&1; then
		unzip -q "$tmp/$archive" -d "$tmp/extract"
	else
		[ -n "${ProgramFiles:-}" ] && powershell.exe -NoProfile -Command \
			"Expand-Archive -LiteralPath '\"$tmp/$archive\"' -DestinationPath '\"$tmp/extract\"' -Force" \
			|| die "need unzip (or PowerShell) to extract the release"
	fi
else
	tar -xzf "$tmp/$archive" -C "$tmp/extract"
fi

srcdir="$tmp/extract/mei-${goos}-${goarch}"
mkdir -p "$prefix"
if [ "$goos" = "windows" ]; then
	cp -f "$srcdir/mei${ext}" "$prefix/"
	cp -f "$srcdir/meiosisd${ext}" "$prefix/"
else
	install -m 0755 "$srcdir/mei" "$prefix/mei"
	install -m 0755 "$srcdir/meiosisd" "$prefix/meiosisd"
fi

say "installed to ${prefix}:"
"$prefix/mei${ext}" version
"$prefix/meiosisd${ext}" -version

case "$PATH" in
*"$prefix"*) : ;;
*) say "done. add ${prefix} to your PATH, then run: mei init --ide antigravity" ;;
esac