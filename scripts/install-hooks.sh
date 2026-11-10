#!/usr/bin/env bash
# Install the git hooks (see lefthook.yml). Needs Go; installs lefthook with
# `go install` when it is missing.
#
# The hooks that lefthook generates look for `lefthook` on PATH and, if it is
# absent, print a warning and let the commit through, which silently skips every
# check. To make that impossible this script bakes the absolute path of the
# binary into each hook, so they work even when $(go env GOPATH)/bin is not on
# PATH.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

bin="$(command -v lefthook || true)"
if [ -z "$bin" ]; then
  echo "lefthook not found; installing it with 'go install'..."
  go install github.com/evilmartians/lefthook@latest
  gobin="$(go env GOBIN)"
  bin="${gobin:-$(go env GOPATH)/bin}/lefthook"
fi
[ -x "$bin" ] || { echo "error: lefthook is not at $bin" >&2; exit 1; }

"$bin" install

hooks_dir="$(git rev-parse --git-path hooks)"
for hook in "$hooks_dir"/*; do
  [ -f "$hook" ] || continue
  grep -q "call_lefthook" "$hook" || continue   # only the hooks lefthook wrote
  grep -q "LEFTHOOK_BIN default" "$hook" && continue
  # Insert after the shebang: use this binary unless the caller overrides it.
  tmp="$(mktemp)"
  { head -n 1 "$hook"
    printf '# LEFTHOOK_BIN default, set by scripts/install-hooks.sh\n: "${LEFTHOOK_BIN:=%s}"\nexport LEFTHOOK_BIN\n' "$bin"
    tail -n +2 "$hook"; } > "$tmp"
  cat "$tmp" > "$hook"; rm -f "$tmp"
done

echo "Git hooks installed (commit-msg, pre-commit, pre-push) using $bin"
case ":$PATH:" in *":$(dirname "$bin"):"*) ;; *) echo "note: $(dirname "$bin") is not on your PATH; the hooks do not need it, but you may want it there." ;; esac
