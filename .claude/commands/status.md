---
description: Point d'avancement - etat du code, des tests, des failles connues et du journal des agents
allowed-tools: Bash(git status:*), Bash(git log:*), Bash(python -m pytest:*), Read, Glob, Grep
---

Fais un point d'avancement concis :
- `git status` et 5 derniers commits ;
- resultat de `.claude/logs/last_gate.json` ;
- plans dans `docs/plans/`, audits ouverts dans `docs/audits/` ;
- 20 dernieres lignes de `.claude/logs/audit.jsonl` (quel agent a fait quoi) ;
- etats de la machine d'etats implementes vs specifies dans la skill escrow-domain.
Termine par les 3 prochaines actions recommandees.
