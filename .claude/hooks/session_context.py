"""SessionStart : injecte l'etat du projet dans le contexte (stdout => contexte de Claude)."""

from __future__ import annotations

import json
import subprocess
import sys

from _common import LOG_DIR, PROJECT_DIR, read_input


def git(*args: str) -> str:
    try:
        proc = subprocess.run(["git", *args], cwd=PROJECT_DIR, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.strip()


def main() -> None:
    read_input()
    lines = ["## Etat du projet (injecte par le harness)"]
    lines.append(f"- Branche : {git('branch', '--show-current') or '(aucun commit)'}")
    status = git("status", "--short")
    lines.append(f"- Fichiers modifies : {len(status.splitlines()) if status else 0}")
    try:
        gate = json.loads((LOG_DIR / "last_gate.json").read_text(encoding="utf-8"))
        failed = [r["step"] for r in gate["results"] if r["status"] == "fail"]
        verdict = "OK" if gate["ok"] else f"ECHEC ({', '.join(failed)})"
        lines.append(f"- Derniere porte qualite ({gate['mode']}) : {verdict}")
    except (OSError, ValueError, KeyError):
        lines.append("- Porte qualite jamais lancee : `/check`")
    lines.append("- Rappel : delegue aux subagents du projet (voir CLAUDE.md), jamais a general-purpose.")
    print("\n".join(lines))
    sys.exit(0)


if __name__ == "__main__":
    main()
