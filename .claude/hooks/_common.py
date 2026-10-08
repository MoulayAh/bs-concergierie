"""Utilitaires partages par les hooks (stdlib uniquement)."""

from __future__ import annotations

import fnmatch
import json
import os
import sys
from pathlib import Path
from typing import Any, NoReturn

HOOKS_DIR = Path(__file__).resolve().parent
PROJECT_DIR = Path(os.environ.get("CLAUDE_PROJECT_DIR") or HOOKS_DIR.parents[1]).resolve()
LOG_DIR = PROJECT_DIR / ".claude" / "logs"


def read_input() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def load_policy() -> dict[str, Any]:
    with open(HOOKS_DIR / "policy.json", encoding="utf-8") as fh:
        return json.load(fh)


def agent_from(argv: list[str], payload: dict[str, Any]) -> str | None:
    """Agent courant : --agent <nom> (frontmatter du subagent) sinon champ agent_type du payload."""
    if "--agent" in argv:
        idx = argv.index("--agent")
        if idx + 1 < len(argv):
            return argv[idx + 1]
    agent = payload.get("agent_type")
    return agent if isinstance(agent, str) and agent else None


def rel_path(raw: str) -> str | None:
    """Chemin relatif POSIX au projet, ou None s'il sort du projet."""
    if not raw:
        return None
    p = Path(raw)
    if not p.is_absolute():
        p = PROJECT_DIR / p
    try:
        rel = p.resolve().relative_to(PROJECT_DIR)
    except ValueError:
        return None
    return rel.as_posix()


def matches(path: str, patterns: list[str]) -> bool:
    lowered = path.lower()
    name = lowered.rsplit("/", 1)[-1]
    for pat in patterns:
        pat_l = pat.lower()
        if fnmatch.fnmatch(lowered, pat_l) or ("/" not in pat_l and fnmatch.fnmatch(name, pat_l)):
            return True
    return False


def decide(decision: str, reason: str, event: str = "PreToolUse") -> NoReturn:
    """decision: 'deny' | 'ask' | 'allow'."""
    out = {
        "hookSpecificOutput": {
            "hookEventName": event,
            "permissionDecision": decision,
            "permissionDecisionReason": f"[harness] {reason}",
        }
    }
    print(json.dumps(out))
    sys.exit(0)


def block(reason: str) -> NoReturn:
    """Exit 2 : stderr est renvoye a Claude (PostToolUse / Stop / SubagentStop)."""
    print(f"[harness] {reason}", file=sys.stderr)
    sys.exit(2)
