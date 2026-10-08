"""PostToolUse / SubagentStart / SubagentStop : journal d'audit JSONL (.claude/logs/audit.jsonl).

Tracabilite de qui (session principale ou quel subagent) a fait quoi. Ne bloque jamais.
"""

from __future__ import annotations

import json
import sys
import time

from _common import LOG_DIR, agent_from, read_input


def main() -> None:
    try:
        payload = read_input()
        tool_input = payload.get("tool_input") or {}
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "event": payload.get("hook_event_name"),
            "agent": agent_from(sys.argv, payload) or "main",
            "tool": payload.get("tool_name"),
            "target": tool_input.get("file_path") or tool_input.get("command") or tool_input.get("subagent_type"),
            "session": payload.get("session_id"),
        }
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_DIR / "audit.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 - un log ne doit jamais casser la session
        pass
    sys.exit(0)


if __name__ == "__main__":
    main()
