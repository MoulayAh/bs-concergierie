"""PreToolUse (Agent|Task) : seuls les subagents du projet (bridés) peuvent etre lances.

Sans ce hook, la session principale pourrait deleguer a `general-purpose` ou a un fork,
qui ont tous les outils et aucune restriction de chemin.
"""

from __future__ import annotations

import sys

from _common import decide, load_policy, read_input


def main() -> None:
    payload = read_input()
    tool_input = payload.get("tool_input") or {}
    subagent = tool_input.get("subagent_type") or "general-purpose"
    allowed = load_policy()["allowed_subagents"]

    if subagent not in allowed:
        decide(
            "deny",
            f"Subagent '{subagent}' non autorise. Utilise un agent du projet : {', '.join(allowed)}.",
        )
    if tool_input.get("isolation") == "remote":
        decide("deny", "Les subagents distants sont desactives pour ce projet.")
    sys.exit(0)


if __name__ == "__main__":
    main()
