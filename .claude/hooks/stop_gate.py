"""Stop / SubagentStop : empeche de declarer "fini" si la porte qualite echoue.

    stop_gate.py --mode fast      # agents qui ecrivent du code : lint + tests doivent passer
    stop_gate.py --mode collect   # test-engineer : les tests (meme rouges, TDD) doivent se charger
    stop_gate.py --mode changed   # session principale : porte rapide seulement si du code a change

stop_hook_active=True => on a deja bloque une fois : on laisse passer pour eviter une boucle.
"""

from __future__ import annotations

import json
import subprocess
import sys

from _common import LOG_DIR, PROJECT_DIR, block, read_input


def code_changed_since_last_gate() -> bool:
    try:
        last = json.loads((LOG_DIR / "last_gate.json").read_text(encoding="utf-8"))["time"]
    except (OSError, ValueError, KeyError):
        last = 0.0
    for folder in ("app", "tests"):
        for f in (PROJECT_DIR / folder).rglob("*.py"):
            if f.stat().st_mtime > last:
                return True
    return False


def main() -> None:
    payload = read_input()
    if payload.get("stop_hook_active"):
        sys.exit(0)
    mode = sys.argv[sys.argv.index("--mode") + 1] if "--mode" in sys.argv else "fast"

    if mode == "changed":
        if not code_changed_since_last_gate():
            sys.exit(0)
        mode = "fast"

    proc = subprocess.run(
        [sys.executable, str(PROJECT_DIR / "scripts" / "quality_gate.py"), f"--{mode}"],
        cwd=PROJECT_DIR, capture_output=True, text=True, timeout=600,
    )
    if proc.returncode != 0:
        block(
            "Porte qualite en echec, tu ne peux pas t'arreter. Corrige (dans ton perimetre) ou, "
            "si la correction est hors perimetre, explique precisement quoi changer et ou :\n"
            + (proc.stdout + proc.stderr)[-3500:]
        )
    sys.exit(0)


if __name__ == "__main__":
    main()
