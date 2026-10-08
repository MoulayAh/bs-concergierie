---
description: Changement de schema de base via db-migrator (nouvelle migration uniquement)
argument-hint: <changement de schema>
---

Changement : $ARGUMENTS

Delegue a **db-migrator**. Il cree une nouvelle revision (jamais d'edition d'une migration existante), ajoute les contraintes en base, et indique l'impact pour backend-dev.
Demande-moi confirmation avant tout `flask db upgrade`.
