---
description: Cycle TDD sur un comportement precis - test-engineer ecrit le test, backend-dev le fait passer
argument-hint: <comportement attendu>
---

Comportement : $ARGUMENTS

1. Delegue a **test-engineer** l'ecriture des tests de ce comportement. Verifie qu'ils sont rouges pour la bonne raison.
2. Delegue a **backend-dev** l'implementation minimale pour les faire passer, sans modifier les tests.
3. Lance `python -m pytest -q` et resume.
