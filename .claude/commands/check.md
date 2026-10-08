---
description: Porte qualite complete (ruff, format, mypy strict, bandit, pytest + couverture)
allowed-tools: Bash(python scripts/quality_gate.py:*), Bash(py -3 scripts/quality_gate.py:*), Read
---

Lance `python scripts/quality_gate.py` (ou `py -3 scripts/quality_gate.py` sous Windows sans venv actif).
Resume : etapes OK / en echec / outil manquant. Pour chaque echec, l'agent responsable (lint/types app -> backend-dev, tests -> test-engineer ou backend-dev, migrations -> db-migrator).
