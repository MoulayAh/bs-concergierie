"""PreToolUse (Edit|Write|MultiEdit|NotebookEdit) : qui a le droit d'ecrire ou.

- Fichiers sensibles (.env, cles, .git) : interdits a tout le monde.
- Migrations deja creees : immuables (on en cree une nouvelle).
- Subagents : liste blanche de chemins par agent (policy.json). Tout le reste est refuse.
- Session principale : confirmation demandee pour le harness et la config projet.
"""

from __future__ import annotations

import sys

from _common import PROJECT_DIR, agent_from, decide, load_policy, matches, read_input, rel_path


def main() -> None:
    payload = read_input()
    policy = load_policy()
    agent = agent_from(sys.argv, payload)
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    raw = tool_input.get("file_path") or tool_input.get("notebook_path") or ""

    rel = rel_path(str(raw))
    if rel is None:
        if agent:
            decide("deny", f"{agent} ne peut pas ecrire hors du projet ({raw}).")
        decide("ask", f"Ecriture hors du projet : {raw}")

    if matches(rel, policy["protected_for_everyone"]) and not matches(rel, policy["protected_exceptions"]):
        decide("deny", f"{rel} est un fichier sensible (secrets / git). Modification interdite.")

    if matches(rel, policy["immutable_after_creation"]) and (PROJECT_DIR / rel).exists():
        decide(
            "deny",
            f"{rel} est une migration existante : elle est immuable. Cree une NOUVELLE migration.",
        )

    if agent:
        rules = policy["agents"].get(agent)
        if rules is None:
            decide("deny", f"L'agent '{agent}' est en lecture seule.")
        if not matches(rel, rules.get("write", [])) or matches(rel, rules.get("write_deny", [])):
            allowed = ", ".join(rules.get("write", [])) or "aucun"
            decide(
                "deny",
                f"{agent} n'a pas le droit d'ecrire {rel} ({tool}). Perimetre autorise : {allowed}. "
                "Si un changement est necessaire ailleurs, decris-le dans ton rapport final.",
            )
        sys.exit(0)

    if matches(rel, policy["main_session_ask"]):
        decide("ask", f"{rel} fait partie du harness / de la config projet.")
    sys.exit(0)


if __name__ == "__main__":
    main()
