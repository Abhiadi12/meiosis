#!/usr/bin/env bash
# Install the git hooks. Prefers lefthook (see lefthook.yml); falls back to a
# plain commit-msg hook that needs only Go.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if ! command -v lefthook >/dev/null 2>&1; then
  echo "lefthook not found; installing it with 'go install'..."
  go install github.com/evilmartians/lefthook@latest || true
  PATH="$(go env GOPATH)/bin:$PATH"
fi

if command -v lefthook >/dev/null 2>&1; then
  lefthook install
  echo "Git hooks installed with lefthook (commit-msg, pre-commit, pre-push)."
else
  mkdir -p .git/hooks
  cat > .git/hooks/commit-msg <<'HOOK'
#!/usr/bin/env bash
exec go run ./tools/commitlint "$1"
HOOK
  chmod +x .git/hooks/commit-msg
  echo "lefthook unavailable: installed a commit-msg hook only."
fi
