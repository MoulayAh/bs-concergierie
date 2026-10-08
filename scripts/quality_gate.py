"""Porte qualite unique, utilisee par /check, les hooks Stop et la CI.

    python scripts/quality_gate.py            # complet : ruff, format, mypy, bandit, tests + couverture
    python scripts/quality_gate.py --fast     # ruff + mypy + pytest -x (sans couverture)
    python scripts/quality_gate.py --collect  # verifie seulement que les tests se chargent

Ecrit le resultat dans .claude/logs/last_gate.json.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable

PYTEST_NO_TESTS = 5


def steps(mode: str) -> list[tuple[str, list[str]]]:
    if mode == "collect":
        return [("pytest-collect", [PY, "-m", "pytest", "--collect-only", "-q"])]
    lint = [
        ("ruff", [PY, "-m", "ruff", "check", "app", "tests", "scripts"]),
        ("mypy", [PY, "-m", "mypy", "app"]),
    ]
    if mode == "fast":
        return [*lint, ("pytest", [PY, "-m", "pytest", "-x", "-q", "--no-cov"])]
    return [
        *lint,
        ("ruff-format", [PY, "-m", "ruff", "format", "--check", "app", "tests", "scripts"]),
        ("bandit", [PY, "-m", "bandit", "-q", "-r", "app"]),
        ("pytest", [PY, "-m", "pytest", "-q"]),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--fast", action="store_true")
    group.add_argument("--collect", action="store_true")
    args = parser.parse_args()
    mode = "collect" if args.collect else "fast" if args.fast else "full"

    # Windows : console en cp1252, alors que les sorties des outils contiennent de l'unicode.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}

    results = []
    failed = False
    for name, cmd in steps(mode):
        proc = subprocess.run(
            cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env
        )
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        if "No module named" in proc.stderr:
            status = "missing"
        elif proc.returncode == 0 or (name.startswith("pytest") and proc.returncode == PYTEST_NO_TESTS):
            status = "ok"
        else:
            status = "fail"
            failed = True
        results.append({"step": name, "status": status, "tail": output[-2500:]})
        print(f"[{status.upper():7}] {name}")
        if status == "fail":
            print(output[-2500:])
            if mode != "full":
                break

    log = ROOT / ".claude" / "logs" / "last_gate.json"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(
        json.dumps({"mode": mode, "ok": not failed, "time": time.time(), "results": results}, indent=2),
        encoding="utf-8",
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
