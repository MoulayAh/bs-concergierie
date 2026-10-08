"""PostToolUse (Edit|Write|MultiEdit) : controle immediat du fichier modifie.

1. Invariants metier/securite (regex) : pas de float pour l'argent, pas d'except muet, etc.
2. ruff check + mypy --strict (si installes dans l'interpreteur courant).
Exit 2 => les erreurs sont renvoyees a Claude, qui doit corriger avant de continuer.
"""

from __future__ import annotations

import re
import subprocess
import sys

from _common import PROJECT_DIR, block, read_input, rel_path

APP_RULES: list[tuple[str, str]] = [
    (r"^\s*except\s*:", "`except:` nu interdit : attrape une exception precise"),
    (r"except[^\n]*:\s*\n\s*pass\b", "exception avalee silencieusement (`except ...: pass`)"),
    (r"^\s*print\(", "`print` interdit : utilise `logging`"),
    (r"\b(eval|exec)\(", "`eval`/`exec` interdits"),
    (r"\bpickle\b", "`pickle` interdit (desserialisation dangereuse)"),
    (r"yaml\.load\((?![^)]*SafeLoader)", "`yaml.load` sans SafeLoader"),
    (r"\b(execute|text)\(\s*f[\"']", "SQL construit par f-string : utilise des parametres lies"),
    (r"#\s*type:\s*ignore(?!\[)", "`# type: ignore` sans code d'erreur precis"),
    (r"debug\s*=\s*True", "`debug=True` en dur"),
    (r"\bsecret_key\s*=\s*[\"']", "secret en dur : lis-le depuis l'environnement"),
]
MONEY_DIRS = ("app/domain/", "app/schemas/", "app/models/", "app/services/", "app/api/")
MONEY_RULE = (r"\bfloat\b", "`float` interdit pour les montants : entiers en centimes (int) ou Decimal")

TEST_RULES: list[tuple[str, str]] = [
    (r"pytest\.mark\.(skip|skipif|xfail)\b|pytest\.skip\(", "skip/xfail interdit : un test doit passer ou echouer"),
    (r"^\s*assert\s+True\s*$", "`assert True` ne teste rien"),
]


def scan(text: str, rules: list[tuple[str, str]]) -> list[str]:
    problems = []
    for pattern, reason in rules:
        for m in re.finditer(pattern, text, re.MULTILINE):
            line = text.count("\n", 0, m.start()) + 1
            problems.append(f"  L{line}: {reason}")
    return problems


def run_tool(args: list[str]) -> str | None:
    """Retourne la sortie en cas d'echec, None si OK ou outil absent."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", *args],
            cwd=PROJECT_DIR, capture_output=True, text=True, timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode == 0 or "No module named" in proc.stderr:
        return None
    return (proc.stdout + proc.stderr).strip()[-3000:]


def main() -> None:
    payload = read_input()
    tool_input = payload.get("tool_input") or {}
    rel = rel_path(str(tool_input.get("file_path", "")))
    if rel is None or not rel.endswith(".py"):
        sys.exit(0)
    path = PROJECT_DIR / rel
    if not path.exists():
        sys.exit(0)
    text = path.read_text(encoding="utf-8", errors="replace")

    problems: list[str] = []
    if rel.startswith("app/"):
        problems += scan(text, APP_RULES)
        if rel.startswith(MONEY_DIRS):
            problems += scan(text, [MONEY_RULE])
    elif rel.startswith("tests/"):
        problems += scan(text, TEST_RULES)

    if rel.startswith(("app/", "tests/", "scripts/")):
        out = run_tool(["ruff", "check", "--no-fix", rel])
        if out:
            problems.append(f"ruff:\n{out}")
    if rel.startswith("app/"):
        out = run_tool(["mypy", rel])
        if out:
            problems.append(f"mypy:\n{out}")

    if problems:
        block(f"{rel} viole les regles du projet, corrige maintenant :\n" + "\n".join(problems))
    sys.exit(0)


if __name__ == "__main__":
    main()
