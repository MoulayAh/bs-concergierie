# F1 — Création et signature d'un contrat de location

> Première fonctionnalité : le socle sur lequel reposent la caution (F2), l'état des lieux (F3) et la libération (F4).

## Objectif

Un loueur crée un contrat de location pour un véhicule et un client, avec un montant de caution.
Les deux parties le signent ; le contrat passe alors en attente de dépôt de la caution.
Tant que la caution n'est pas déposée, l'une ou l'autre partie peut annuler.

À la fin de F1, l'application sait déjà refuser proprement : montants invalides, mauvais acteur,
transitions interdites, entrées malformées. **Aucune requête utilisateur ne doit produire de 500.**

## Périmètre

**Inclus**
- Socle Flask : `create_app`, configuration par variables d'environnement, handler d'erreurs global au format JSON.
- Authentification minimale : jeton `Bearer` par utilisateur (comptes de démo créés par une commande `flask seed-demo`), jeton stocké haché en base.
- Machine d'états du domaine (`app/domain/state_machine.py`) complète, même si F1 n'utilise que ses premiers états.
- Création, consultation, signature et annulation d'un contrat.
- Journal des événements (`escrow_events`), en ajout seul.

**Exclus (fonctionnalités suivantes)**
- Dépôt de la caution (F2), état des lieux et photos (F3), signature cryptographique Ed25519 et libération (F4), litiges (F5).
- Inscription publique, mot de passe, interface de démo complète.

## Transitions d'état concernées

| Source           | Événement       | Acteur autorisé    | Cible            | Condition                                  |
|------------------|-----------------|--------------------|------------------|--------------------------------------------|
| —                | `create`        | loueur             | DRAFT            | montant et parties valides                 |
| DRAFT            | `sign_contract` | client ou loueur   | DRAFT            | première signature                         |
| DRAFT            | `sign_contract` | client ou loueur   | AWAITING_DEPOSIT | seconde signature (l'autre partie)         |
| DRAFT            | `cancel`        | client ou loueur   | CANCELLED        | —                                          |
| AWAITING_DEPOSIT | `cancel`        | client ou loueur   | CANCELLED        | —                                          |

- Une même partie qui signe deux fois → `INVALID_TRANSITION` (409), état inchangé.
- Tout événement sur un contrat CANCELLED → `INVALID_TRANSITION` (409).
- Toute transition s'exécute dans une transaction avec verrou sur la ligne du contrat (`with_for_update()`) et écrit un événement.

## Modèle de données (db-migrator)

**users** : `id` (UUID), `email` (unique), `display_name`, `role` (`client` | `owner` | `admin`), `api_token_hash` (unique), `created_at`.

**contracts**
| Colonne               | Type                     | Contrainte                                               |
|-----------------------|--------------------------|----------------------------------------------------------|
| id                    | UUID                     | PK                                                       |
| owner_id / client_id  | UUID                     | FK users, NOT NULL, `CHECK (owner_id <> client_id)`      |
| vehicle_label         | VARCHAR(120)             | NOT NULL, non vide                                       |
| vehicle_plate         | VARCHAR(16)              | NOT NULL                                                 |
| start_date / end_date | DATE                     | NOT NULL, `CHECK (end_date > start_date)`                |
| deposit_cents         | BIGINT                   | `CHECK (deposit_cents BETWEEN 1 AND 50000000)`           |
| currency              | CHAR(3)                  | `CHECK (currency IN ('EUR','CHF','GBP','USD'))`          |
| status                | ENUM `contract_status`   | NOT NULL, défaut DRAFT                                   |
| owner_signed_at / client_signed_at | TIMESTAMPTZ | NULL                                                     |
| version               | INTEGER                  | NOT NULL, incrémenté à chaque transition                 |
| created_at / updated_at | TIMESTAMPTZ            | NOT NULL                                                 |

**escrow_events** (ajout seul) : `id`, `contract_id` (FK), `event`, `actor_id`, `from_status`, `to_status`, `payload_hash`, `created_at`.

**idempotency_keys** : `key` + `user_id` (unique ensemble), `request_hash`, `response_status`, `response_body`, `created_at`.

## Contrat d'API

Toutes les routes exigent `Authorization: Bearer <jeton>`. Les routes `POST` acceptent un en-tête `Idempotency-Key` (obligatoire pour la création).

| Méthode | Route                              | Acteur            | Succès |
|---------|------------------------------------|-------------------|--------|
| POST    | `/api/contracts`                   | loueur            | 201    |
| GET     | `/api/contracts/<id>`              | une des parties   | 200    |
| GET     | `/api/contracts/<id>/events`       | une des parties   | 200    |
| POST    | `/api/contracts/<id>/sign`         | une des parties   | 200    |
| POST    | `/api/contracts/<id>/cancel`       | une des parties   | 200    |

**Entrée de création** (Pydantic, mode strict, `extra="forbid"`) :

```json
{
  "client_email": "client@demo.test",
  "vehicle_label": "Audi RS6 Avant",
  "vehicle_plate": "AB-123-CD",
  "start_date": "2026-11-01",
  "end_date": "2026-11-05",
  "deposit_cents": 2500000,
  "currency": "EUR"
}
```

**Sortie** :

```json
{
  "id": "…",
  "status": "DRAFT",
  "owner": {"id": "…", "display_name": "…"},
  "client": {"id": "…", "display_name": "…"},
  "vehicle": {"label": "Audi RS6 Avant", "plate": "AB-123-CD"},
  "period": {"start": "2026-11-01", "end": "2026-11-05"},
  "deposit": {"amount_cents": 2500000, "currency": "EUR"},
  "signatures": {"owner": null, "client": null},
  "version": 1
}
```

`cancel` accepte un corps optionnel `{"reason": "…"}` (500 caractères max).

## Cas d'erreur à couvrir

| Situation                                                        | Code                 | HTTP |
|------------------------------------------------------------------|----------------------|------|
| `deposit_cents` négatif, nul, > 50 000 000                       | INVALID_AMOUNT       | 422  |
| `deposit_cents` en chaîne, flottant, booléen, `null`, absent      | INVALID_AMOUNT / VALIDATION_ERROR | 422 |
| Devise hors liste blanche                                         | VALIDATION_ERROR     | 422  |
| `end_date` <= `start_date`, date mal formée                       | VALIDATION_ERROR     | 422  |
| Champ inconnu, JSON malformé, corps non JSON, chaîne de 1 Mo      | VALIDATION_ERROR     | 422 (ou 413 si > limite) |
| `client_email` inconnu ou égal au loueur                          | VALIDATION_ERROR     | 422  |
| Un client tente de créer un contrat                               | FORBIDDEN_ACTOR      | 403  |
| Jeton absent ou invalide                                          | UNAUTHENTICATED      | 401  |
| Contrat inexistant **ou** appartenant à d'autres (pas d'IDOR)     | NOT_FOUND            | 404  |
| Même partie qui signe deux fois                                   | INVALID_TRANSITION   | 409  |
| Signer ou annuler un contrat CANCELLED                            | INVALID_TRANSITION   | 409  |
| Même `Idempotency-Key` avec un corps différent                    | IDEMPOTENCY_CONFLICT | 409  |
| `PATCH` / `PUT` sur un contrat (modification interdite)           | méthode non autorisée | 405 |
| Même `Idempotency-Key` avec le même corps                         | réponse initiale rejouée, aucun doublon | 201 |
| Deux signatures simultanées des deux parties                      | une seule transition vers AWAITING_DEPOSIT, deux événements cohérents | 200 |

Après chaque erreur : statut, `version` et nombre d'événements du contrat **inchangés**.

## Tests à écrire

**test-engineer** (`tests/unit`, `tests/integration`)
- `test_state_machine_matrix` : chaque couple (état, événement), valide ou non, conformément à la skill escrow-domain.
- `test_deposit_amount_bounds` (hypothesis) : tout entier dans [1, 50 000 000] accepté, tout le reste refusé.
- `test_create_contract_returns_201_and_draft`
- `test_sign_by_both_parties_moves_to_awaiting_deposit`
- `test_cancel_in_draft_and_awaiting_deposit`
- `test_events_written_for_each_transition`
- `test_error_payload_format` : toujours `{"error": {"code", "message"}}`, jamais de trace.
- `test_idempotent_creation_replays_response`

**adversarial-tester** (`tests/adversarial/test_f1_contracts.py`)
- Montants piégés (-1, 0, 0.5, "100", 1e309, 2**63, true, null).
- Client qui se fait passer pour le loueur, IDOR sur l'identifiant d'un autre contrat.
- Double signature, signature après annulation, annulation après annulation.
- Tentative de modification par `PATCH`/`PUT` (405 au format JSON, contrat inchangé).
- Caution à 50 000 001 centimes (juste au-dessus du plafond).
- Signatures concurrentes (threads).
- Corps géant, JSON malformé, champs en trop, injection SQL dans `vehicle_label`.

## Découpage et ordre

1. **test-engineer** — tests ci-dessus (rouges attendus).
2. **db-migrator** — modèles `User`, `Contract`, `EscrowEvent`, `IdempotencyKey` + migration initiale.
3. **backend-dev** — `create_app`, config, handler d'erreurs, auth Bearer, `state_machine.py`, `money.py`, schémas, service `contracts`, blueprint, commande `flask seed-demo`.
4. **adversarial-tester** — attaques ; failles renvoyées à backend-dev.
5. **reviewer** — revue du diff.

## Critères d'acceptation

- [ ] `python scripts/quality_gate.py` vert (couverture ≥ 85 %).
- [ ] Tous les tests `tests/adversarial` de F1 verts.
- [ ] Aucun `float` ni aucune transition hors de `state_machine.py` (contrôlé par les hooks).
- [ ] Démo : création → double signature → AWAITING_DEPOSIT, puis tentative de montant négatif et d'annulation d'un contrat annulé, toutes deux refusées proprement.

## Décisions (validées le 2026-10-08)

- **Pas de modification d'un contrat.** Un contrat en DRAFT ne peut pas être modifié : pour corriger, on l'annule et on en crée un nouveau. Aucune route `PATCH`/`PUT` ; toute tentative renvoie 405.
- **Plafond de caution : 500 000 €** (`deposit_cents` ≤ 50 000 000), fixé par `MAX_DEPOSIT_CENTS`.
