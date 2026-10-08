#!/usr/bin/env bash
# Lanceur commun des hooks : trouve un Python (venv du projet en priorite) et lui passe stdin.
# Fail-closed : sans Python, on bloque (exit 2) plutot que de laisser passer sans garde-fou.
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${CLAUDE_PROJECT_DIR:-$(cd "$DIR/../.." && pwd)}"
SCRIPT="$1"; shift

for candidate in "$ROOT/.venv/Scripts/python.exe" "$ROOT/.venv/bin/python"; do
  if [ -x "$candidate" ]; then exec "$candidate" "$DIR/$SCRIPT" "$@"; fi
done
if command -v py >/dev/null 2>&1; then exec py -3 "$DIR/$SCRIPT" "$@"; fi
for name in python3 python; do
  if command -v "$name" >/dev/null 2>&1 && "$name" -c "import sys" >/dev/null 2>&1; then
    exec "$name" "$DIR/$SCRIPT" "$@"
  fi
done
echo "[harness] Aucun interpreteur Python trouve : hooks de securite indisponibles, action bloquee." >&2
exit 2
