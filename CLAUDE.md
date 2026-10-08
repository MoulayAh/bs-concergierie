# Luxe Escrow - sequestre de caution pour location de vehicules haut de gamme

Tiers de confiance : la caution est bloquee numeriquement et liberee des qu'un etat des lieux
signe cryptographiquement par les deux parties est valide. Le correcteur va essayer de casser
le flux (fichiers invalides, annulation en cours de route, montants negatifs) : **l'application
ne doit jamais renvoyer de 500 ni se retrouver dans un etat incoherent.**

## Stack

- Python 3.12+, Flask (app factory), SQLAlchemy 2.0 (typed), Flask-Migrate/Alembic, PostgreSQL 16
- Pydantic v2 (mode strict) pour toute entree, `cryptography` (Ed25519) pour les signatures, Pillow pour les images
- pytest + hypothesis + pytest-cov, ruff, mypy --strict, bandit

## Arborescence

```
app/
  api/        blueprints Flask (fins : parse -> service -> reponse)
  domain/     logique pure, sans Flask ni DB : state_machine.py, money.py, report.py (hash/signatures)
  services/   orchestration : transaction, verrou, appel du domaine, ecriture des evenements
  models/     SQLAlchemy (proprietaire : db-migrator)
  schemas/    Pydantic (entrees/sorties API)
  security/   uploads, auth, signatures
  templates/ static/   UI de demo (proprietaire : frontend-dev)
migrations/   Alembic (immuables une fois creees)
tests/        unit/ integration/ adversarial/ fixtures/
scripts/      quality_gate.py, demo_scenario.py
docs/         plans/ adr/ audits/ reviews/
```

## Regles de code

- Les regles metier (machine d'etats, montants, crypto, codes d'erreur) sont dans la skill **escrow-domain** ; les uploads dans **secure-uploads**. Elles font foi.
- Argent = `int` centimes. Jamais `float` (bloque par hook).
- Toute transition d'etat passe par `app/domain/state_machine.py`.
- Erreurs : exceptions metier typees + un handler global -> JSON `{"error": {...}}`.
- Typage strict, pas de `# type: ignore` sans code, pas de `print`, pas d'`except` muet.
- Tests : pas de skip/xfail. Un bug corrige = un test de non-regression.

## Commandes

- Installer : `py -3 -m venv .venv` puis `.venv\Scripts\pip install -r requirements-dev.txt`
- Base : `docker compose up -d db` puis `flask --app app db upgrade`
- Tests : `python -m pytest` (`-m adversarial` pour la red team)
- Porte qualite : `python scripts/quality_gate.py` (`--fast`)
- Lancer : `flask --app app run --debug`

## Organisation des agents (harness)

La session principale **orchestre** et delegue ; elle ne code pas elle-meme les grosses fonctionnalites.

| Agent              | Peut ecrire                                | Role                              |
|--------------------|--------------------------------------------|-----------------------------------|
| architect          | docs/plans, docs/adr                       | conception, avant tout code       |
| test-engineer      | tests/unit, tests/integration, fixtures    | specification executable (TDD)    |
| db-migrator        | app/models, migrations (nouvelles)         | schema PostgreSQL                 |
| backend-dev        | app/ sauf models, templates, static        | implementation                    |
| frontend-dev       | app/templates, app/static                  | UI de demo                        |
| adversarial-tester | tests/adversarial, docs/audits             | casser l'app comme le correcteur  |
| security-auditor   | docs/audits                                | audit lecture seule               |
| reviewer           | docs/reviews                               | revue du diff                     |

Seuls ces agents (+ Explore/Plan, en lecture seule) peuvent etre lances : `general-purpose` et les forks sont bloques.
Les restrictions sont appliquees par des hooks (`.claude/hooks/`, politique dans `policy.json`), pas seulement par ce texte.
Slash commands : `/feature`, `/plan`, `/tdd`, `/break`, `/audit`, `/review`, `/migrate`, `/check`, `/demo`, `/status`.
Details du harness : `docs/HARNESS.md`.
