"""PreToolUse (Bash|PowerShell) : filtre les commandes shell.

- Pour tout le monde : liste noire de commandes destructrices.
- Pour les subagents : en plus, liste BLANCHE de commandes par agent, et aucun
  chainage / redirection / substitution (sinon on contourne guard_files via `echo > fichier`).
"""

from __future__ import annotations

import re
import shlex
import sys

from _common import agent_from, decide, load_policy, read_input

# (regex, raison) -> refuse pour tout le monde
DENY: list[tuple[str, str]] = [
    (r"\brm\b.*\s(-\w*[rR]\w*|--recursive)\b", "suppression recursive"),
    (r"\bRemove-Item\b.*-Recurse", "suppression recursive (PowerShell)"),
    (r"\b(rmdir|rd)\s+/s\b|\bdel\s+/[sq]\b", "suppression recursive (cmd)"),
    (r"\bgit\s+push\b.*(--force|\s-f\b|--force-with-lease)", "git push force"),
    (r"\bgit\s+reset\s+--hard\b", "git reset --hard"),
    (r"\bgit\s+clean\s+-\w*f", "git clean -f"),
    (r"\bgit\s+(checkout|restore)\s+(--\s+)?\.(\s|$)", "ecrasement de toutes les modifs locales"),
    (r"\bgit\s+branch\s+-D\b", "suppression forcee de branche"),
    (r"--no-verify\b", "contournement des hooks git"),
    (r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)\b", "SQL destructeur"),
    (r"\bDELETE\s+FROM\s+\w+\s*(;|$|\")", "DELETE sans WHERE"),
    (r"\b(docker(-compose)?\s+(compose\s+)?down\b.*(-v|--volumes))|\bdocker\s+volume\s+(rm|prune)\b",
     "suppression des volumes (base de donnees)"),
    (r"\b(curl|wget|iwr|Invoke-WebRequest)\b.*\|\s*(sh|bash|iex|python|py)\b", "execution de script distant"),
    (r"\bsudo\b|\bchmod\s+(-R\s+)?777\b", "elevation / permissions"),
    (r"(\bcat|\btype|\bGet-Content|\bless|\bmore|\bhead|\btail)\b[^|]*\.env\b(?!\.example)", "lecture des secrets .env"),
    (r"\b(format|diskpart|mkfs)\b", "commande disque"),
]

# (regex, raison) -> confirmation pour la session principale, refus pour les subagents
ASK: list[tuple[str, str]] = [
    (r"\b(flask\s+db|alembic)\s+downgrade\b", "rollback de migration"),
    (r"\bpip\s+install\b(?!\s+-r\s+requirements)", "installation de dependance hors requirements"),
    (r"\bgit\s+(push|commit|rebase|merge)\b", "operation git qui publie / reecrit l'historique"),
    (r"\bpsql\b", "acces direct a la base"),
]

FORBIDDEN_SHELL = re.compile(r"[;&|<>`]|\$\(|\n")
PYTHON_NAMES = re.compile(r"(^|[\\/])(python3?|py)(\.exe)?$", re.IGNORECASE)


def normalize(tokens: list[str]) -> list[str]:
    """`.venv/Scripts/python.exe -m pytest` -> `python -m pytest`."""
    if tokens and PYTHON_NAMES.search(tokens[0]):
        tokens = ["python", *tokens[1:]]
        if len(tokens) > 1 and tokens[1] == "-3":
            tokens.pop(1)
    return tokens


def subagent_allowed(command: str, allowed: list[str]) -> bool:
    try:
        tokens = normalize(shlex.split(command, posix=True))
    except ValueError:
        return False
    for prefix in allowed:
        p = prefix.split()
        if tokens[: len(p)] == p:
            return True
    return False


def main() -> None:
    payload = read_input()
    agent = agent_from(sys.argv, payload)
    command = str((payload.get("tool_input") or {}).get("command", "")).strip()
    if not command:
        sys.exit(0)

    for pattern, reason in DENY:
        if re.search(pattern, command, re.IGNORECASE):
            decide("deny", f"Commande bloquee ({reason}) : {command}")

    if agent:
        for pattern, reason in ASK:
            if re.search(pattern, command, re.IGNORECASE):
                decide("deny", f"{agent} n'a pas le droit : {reason}.")
        if FORBIDDEN_SHELL.search(command):
            decide("deny", f"{agent} : chainage, pipe, redirection et substitution interdits. Une commande simple a la fois.")
        rules = load_policy()["agents"].get(agent, {})
        allowed = rules.get("bash", [])
        if not subagent_allowed(command, allowed):
            decide("deny", f"{agent} ne peut lancer que : {', '.join(allowed) or 'aucune commande'}.")
        sys.exit(0)

    for pattern, reason in ASK:
        if re.search(pattern, command, re.IGNORECASE):
            decide("ask", f"{reason} : {command}")
    sys.exit(0)


if __name__ == "__main__":
    main()
