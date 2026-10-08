---
description: Pipeline complet d'une fonctionnalite - plan, tests, modeles, code, attaques, revue
argument-hint: <description de la fonctionnalite>
---

Fonctionnalite demandee : $ARGUMENTS

Orchestre ce pipeline en deleguant aux subagents du projet. Tu restes chef d'orchestre : tu n'ecris pas le code toi-meme.

1. **architect** : produit le plan dans `docs/plans/`. Montre-moi le resume et **attends ma validation** avant de continuer.
2. **test-engineer** : ecrit les tests du plan (rouges attendus).
3. **db-migrator** : seulement si le plan demande un changement de schema.
4. **backend-dev** : implemente jusqu'a ce que les tests passent (son hook Stop l'y oblige).
5. **frontend-dev** : seulement si le plan touche l'UI.
6. **adversarial-tester** : attaque la fonctionnalite. S'il trouve des failles, renvoie-les a backend-dev (boucle max 2 fois).
7. **reviewer** : revue du diff.

A la fin : lance `python scripts/quality_gate.py` et donne-moi un resume (ce qui est fait, failles restantes, verdict du reviewer). Ne commit pas.
