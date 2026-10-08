# Harness Claude Code

## Defense en profondeur

| Couche | Fichier | Effet |
|---|---|---|
| Instructions | `CLAUDE.md`, skills | Ce que les agents *doivent* faire |
| Outils par agent | frontmatter `tools:` | Les agents lecture seule n'ont pas `Edit` |
| Permissions | `.claude/settings.json` | allow / ask / deny natifs (secrets, push, rm) |
| Hooks globaux | `.claude/settings.json` | S'appliquent a la session ET aux subagents |
| Hooks par agent | frontmatter `hooks:` des agents | Perimetre d'ecriture + commandes autorisees + porte Stop |
| Politique | `.claude/hooks/policy.json` | Source unique des droits ; non modifiable par les agents |

## Hooks

| Evenement | Script | Role |
|---|---|---|
| SessionStart | `session_context.py` | Injecte branche, fichiers modifies, derniere porte qualite |
| PreToolUse Bash/PowerShell | `guard_bash.py` | Liste noire pour tous ; liste blanche + pas de `; \| > $()` pour les subagents |
| PreToolUse Edit/Write | `guard_files.py` | Secrets interdits, migrations immuables, perimetre par agent, confirmation pour le harness |
| PreToolUse Agent | `guard_agent.py` | Seuls les agents du projet ; `general-purpose`, forks et remote bloques |
| PostToolUse Edit/Write | `post_edit_check.py` | Invariants (pas de float, pas d'except muet, pas de skip...) + ruff + mypy |
| PostToolUse *, SubagentStart/Stop | `audit_log.py` | Journal `.claude/logs/audit.jsonl` |
| Stop (session) | `stop_gate.py --mode changed` | Porte rapide si du code a change |
| Stop (agents codeurs) | `stop_gate.py --mode fast/collect` | L'agent ne peut pas finir si c'est rouge |

Tous passent par `run.sh` (choisit `.venv`, puis `py -3`, puis `python3`). Sans Python, les gardes **bloquent** (fail-closed).

## Verifier le harness

```
.venv\Scripts\python -m pytest .claude/hooks/tests -q -o addopts=""
```

## Modifier les droits

Editer `policy.json` (la session principale demande confirmation, les subagents sont refuses), puis relancer les tests du harness.
