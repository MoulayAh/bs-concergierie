# F2 — Dépôt et blocage de la caution

> S'appuie sur F1 (contrat signé, en AWAITING_DEPOSIT). Prépare F3 (état des lieux) et F4 (libération).

## Objectif

Le client dépose la caution prévue au contrat. Le paiement est **simulé** par un prestataire factice,
mais le flux est celui d'un vrai séquestre : les fonds sont bloqués, tracés et ne peuvent sortir que
par une transition autorisée. Une fois la caution bloquée :

- le loueur peut remettre le véhicule (le contrat devient ACTIVE) ;
- ou les deux parties peuvent annuler d'un commun accord, et la caution est **intégralement remboursée**.

C'est ici que se joue l'attaque « annuler la caution au milieu du processus » : passé le dépôt,
une annulation unilatérale est impossible, et passé la remise du véhicule, plus aucune annulation n'est possible.

## Périmètre

**Inclus**
- Dépôt de la caution par le client, montant et devise vérifiés contre le contrat.
- Prestataire de paiement simulé derrière une interface (`PaymentProvider`), avec scénarios de refus et de panne.
- Table `deposits` : un seul dépôt par contrat, montants bloqués / remboursés / libérés.
- Annulation mutuelle en FUNDED → REFUNDED avec remboursement intégral.
- Remise du véhicule par le loueur : FUNDED → ACTIVE.
- Correction des approbations à deux parties (voir « Dette de F1 »).

**Exclus**
- Vrai prestataire de paiement (Stripe, etc.) et toute saisie de carte bancaire.
- État des lieux de départ avec photos : arrive en F3, qui ajoutera cette condition à la remise du véhicule.
- Libération ou retenue de la caution (F4), litiges (F5).
- Règles de dates (dépôt avant la date de début, etc.) : non bloquantes pour la démo, à voir plus tard.

## Dette de F1 à corriger

`app/services/contracts.py` (`_apply_event`) calcule les approbations à partir de
`owner_signed_at` / `client_signed_at`, quel que soit l'événement. En FUNDED, les deux parties ont
déjà signé le contrat : la première demande d'annulation mutuelle est donc refusée par
`INVALID_TRANSITION` (« déjà approuvé »), et REFUNDED est inatteignable.

**Correction attendue :** les approbations sont stockées **par événement**. Pour F2, ce sont deux colonnes
dédiées à l'annulation (`owner_cancel_approved_at`, `client_cancel_approved_at`). Un test de non-régression
doit reproduire le bug avant la correction.

## Transitions d'état concernées

| Source           | Événement      | Acteur           | Cible            | Condition / effet                                        |
|------------------|----------------|------------------|------------------|----------------------------------------------------------|
| AWAITING_DEPOSIT | `deposit`      | client           | FUNDED           | montant == `deposit_cents`, devise == `currency`, paiement accepté |
| AWAITING_DEPOSIT | `cancel`       | client ou loueur | CANCELLED        | inchangé (F1), aucun fonds à rembourser                  |
| FUNDED           | `cancel`       | client ou loueur | FUNDED           | première approbation : demande d'annulation en attente   |
| FUNDED           | `cancel`       | l'autre partie   | REFUNDED         | seconde approbation : remboursement intégral             |
| FUNDED           | `start_rental` | loueur           | ACTIVE           | aucune demande d'annulation en attente                   |
| ACTIVE et après  | `cancel`       | n'importe qui    | —                | `INVALID_TRANSITION` (409)                               |

- **Paiement refusé ou prestataire en panne : le contrat reste en AWAITING_DEPOSIT.** Aucun dépôt n'est créé, et un événement `deposit_failed` est journalisé.
- **Demande d'annulation en attente :** tant que l'autre partie n'a pas répondu, `start_rental` est refusé (409, `details.reason = "CANCELLATION_PENDING"`). Le loueur ne peut donc pas remettre le véhicule en ignorant la demande du client.
- Toutes les transitions passent par `state_machine.transition` sous verrou de ligne, comme en F1.

## Modèle de données (db-migrator)

Nouvelle migration (la migration F1 est immuable).

**contracts**, colonnes ajoutées
| Colonne                    | Type        | Contrainte |
|----------------------------|-------------|------------|
| owner_cancel_approved_at   | TIMESTAMPTZ | NULL       |
| client_cancel_approved_at  | TIMESTAMPTZ | NULL       |
| started_at                 | TIMESTAMPTZ | NULL       |

**deposits** (nouvelle)
| Colonne          | Type                  | Contrainte                                                       |
|------------------|-----------------------|------------------------------------------------------------------|
| id               | UUID                  | PK                                                               |
| contract_id      | UUID                  | FK contracts, **UNIQUE** (un seul dépôt par contrat)             |
| amount_cents     | BIGINT                | `CHECK (amount_cents BETWEEN 1 AND 50000000)`                    |
| currency         | CHAR(3)               | liste blanche, identique au contrat                              |
| status           | ENUM `deposit_status` | `HELD`, `REFUNDED`, `RELEASED`, `SETTLED`                        |
| held_cents       | BIGINT                | `CHECK (held_cents >= 0)`                                        |
| refunded_cents   | BIGINT                | `CHECK (refunded_cents >= 0)`, défaut 0                          |
| released_cents   | BIGINT                | `CHECK (released_cents >= 0)`, défaut 0 (utilisé en F4)          |
| retained_cents   | BIGINT                | `CHECK (retained_cents >= 0)`, défaut 0 (utilisé en F4)          |
| provider         | VARCHAR(32)           | NOT NULL (`simulated`)                                           |
| provider_ref     | VARCHAR(64)           | NOT NULL, UNIQUE                                                 |
| created_at / updated_at | TIMESTAMPTZ    | NOT NULL                                                         |

**Invariant comptable vérifié par PostgreSQL :**
`CHECK (held_cents + refunded_cents + released_cents + retained_cents = amount_cents)`.
Un euro ne peut ni apparaître ni disparaître.

## Prestataire de paiement simulé

`app/services/payments.py` définit une interface `PaymentProvider` avec deux opérations : `hold(amount, currency, method, key)` et `refund(ref)`.
L'implémentation `SimulatedProvider` répond selon un **moyen de paiement de démo** issu d'une liste blanche :

| `payment_method`        | Résultat                                   |
|-------------------------|--------------------------------------------|
| `demo_card_ok`          | fonds bloqués, renvoie un `provider_ref`   |
| `demo_card_declined`    | refus → `PAYMENT_DECLINED` (402)           |
| `demo_insufficient_funds` | refus → `PAYMENT_DECLINED` (402)         |
| `demo_provider_down`    | panne → `PAYMENT_UNAVAILABLE` (503)        |

- L'appel au prestataire reçoit la clé d'idempotence : rejouer un dépôt après une panne ne bloque jamais deux fois les fonds.
- **Aucune donnée de carte n'est jamais acceptée :** tout champ en trop (`card_number`, etc.) est refusé par le schéma strict.

## Contrat d'API

| Méthode | Route                              | Acteur          | Idempotency-Key | Succès |
|---------|------------------------------------|-----------------|-----------------|--------|
| POST    | `/api/contracts/<id>/deposit`      | client          | **obligatoire** | 200    |
| GET     | `/api/contracts/<id>/deposit`      | une des parties | —               | 200    |
| POST    | `/api/contracts/<id>/cancel`       | une des parties | recommandé      | 200    |
| POST    | `/api/contracts/<id>/start`        | loueur          | recommandé      | 200    |

**Entrée de dépôt** (Pydantic strict, `extra="forbid"`) :

```json
{ "amount_cents": 2500000, "currency": "EUR", "payment_method": "demo_card_ok" }
```

Le client renvoie le montant et la devise : le serveur les compare au contrat, ce qui empêche de déposer
un montant différent de celui signé.

**Sortie** : le contrat (format F1), enrichi de :

```json
{
  "status": "FUNDED",
  "funds": {
    "deposit_status": "HELD",
    "amount_cents": 2500000,
    "held_cents": 2500000,
    "refunded_cents": 0,
    "released_cents": 0,
    "retained_cents": 0,
    "currency": "EUR"
  },
  "cancellation": {"owner_approved": false, "client_approved": false}
}
```

## Nouveaux codes d'erreur

À ajouter à `app/domain/errors.py` et à la skill escrow-domain.

| Code                | HTTP | Cas                                          |
|---------------------|------|----------------------------------------------|
| PAYMENT_DECLINED    | 402  | Paiement refusé par le prestataire           |
| PAYMENT_UNAVAILABLE | 503  | Prestataire injoignable ; réessai possible avec la même clé |

## Cas d'erreur à couvrir

| Situation                                                          | Code                 | HTTP |
|--------------------------------------------------------------------|----------------------|------|
| Montant ≠ `deposit_cents` du contrat (même d'un centime)           | INVALID_AMOUNT       | 422  |
| Montant négatif, nul, flottant, chaîne, booléen, `null`, absent    | INVALID_AMOUNT / VALIDATION_ERROR | 422 |
| Devise ≠ devise du contrat                                         | VALIDATION_ERROR     | 422  |
| `payment_method` hors liste blanche, champ `card_number` ajouté    | VALIDATION_ERROR     | 422  |
| `Idempotency-Key` absente sur un dépôt                             | VALIDATION_ERROR     | 422  |
| Le loueur tente de déposer                                         | FORBIDDEN_ACTOR      | 403  |
| Dépôt sur un contrat DRAFT, FUNDED, CANCELLED…                     | INVALID_TRANSITION   | 409  |
| Second dépôt (autre clé) sur un contrat déjà FUNDED                | INVALID_TRANSITION   | 409  |
| Même clé, même corps                                               | réponse rejouée, un seul dépôt | 200 |
| Même clé, corps différent                                          | IDEMPOTENCY_CONFLICT | 409  |
| Paiement refusé                                                    | PAYMENT_DECLINED     | 402  |
| Prestataire en panne, puis réessai avec la même clé                | 503, puis 200 avec un seul blocage de fonds | — |
| Annulation unilatérale en FUNDED                                   | demande en attente, statut FUNDED, fonds toujours bloqués | 200 |
| Même partie qui approuve l'annulation deux fois                    | INVALID_TRANSITION   | 409  |
| `start_rental` par le client                                       | FORBIDDEN_ACTOR      | 403  |
| `start_rental` avec une annulation en attente                      | INVALID_TRANSITION   | 409  |
| Annulation en ACTIVE                                               | INVALID_TRANSITION   | 409  |
| Deux dépôts simultanés (clés différentes)                          | un seul FUNDED, l'autre 409, un seul blocage de fonds | — |
| Annulation et `start_rental` simultanés                            | une seule transition gagne, état cohérent | — |

Après chaque erreur, rien n'a changé : statut du contrat, `version`, ligne `deposits`, montants et événements de transition.

## Tests à écrire

**test-engineer**
- `test_state_machine_matrix` : compléter avec les transitions FUNDED / ACTIVE.
- `test_mutual_cancel_after_contract_signed` : **non-régression** de la dette de F1.
- `test_deposit_moves_to_funded_and_holds_funds`
- `test_deposit_amount_must_match_contract` (hypothesis : tout entier ≠ `deposit_cents` est refusé)
- `test_declined_payment_leaves_contract_unchanged`
- `test_provider_down_then_retry_same_key_holds_once`
- `test_mutual_cancel_refunds_in_full` : `refunded_cents == amount_cents`, `held_cents == 0`
- `test_start_rental_blocked_by_pending_cancellation`
- `test_ledger_invariant_enforced_by_database` : un UPDATE SQL direct qui casse la somme est rejeté par PostgreSQL.
- `test_contract_output_exposes_funds`

**adversarial-tester** (`tests/adversarial/test_f2_deposit.py`)
- Montants piégés (déposer 1 centime, 0, -2500000, 2**63, `"2500000"`, 2500000.0).
- Ajout de `card_number`, `held_cents`, `status` dans le corps (tentative d'écrire un champ serveur).
- Dépôt par le loueur ou par un tiers ; dépôt sur le contrat d'un autre client (IDOR → 404).
- Double dépôt concurrent, rejeu de clé, conflit de clé.
- Annulation unilatérale en FUNDED puis tentative de récupérer les fonds.
- Tentative de retirer une demande d'annulation (`DELETE /cancel`, champ `{"withdraw": true}`) : refusée, la demande reste en attente.
- Annulation après `start_rental`, `start_rental` après annulation.
- Course entre annulation et `start_rental`.

## Découpage et ordre

1. **test-engineer** : tests ci-dessus, dont la non-régression de la dette de F1 (rouges attendus).
2. **db-migrator** : nouvelle migration (`deposits`, enum `deposit_status`, colonnes d'annulation et `started_at`, CHECK de l'invariant).
3. **backend-dev** :
   - approbations par événement (correction de la dette) ;
   - `PaymentProvider` et `SimulatedProvider` ;
   - service et routes `deposit` / `start` ;
   - remboursement à l'annulation mutuelle ;
   - nouveaux codes d'erreur ;
   - mise à jour de la skill escrow-domain (à faire valider par toi, car les agents ne peuvent pas modifier `.claude/`).
4. **adversarial-tester** : attaques, failles renvoyées à backend-dev.
5. **reviewer** : revue du diff.

## Critères d'acceptation

- [ ] `python scripts/quality_gate.py` vert, tests F1 toujours verts.
- [ ] Tous les tests `tests/adversarial` de F2 verts.
- [ ] Invariant comptable garanti par PostgreSQL, pas seulement par Python.
- [ ] Démo : dépôt de 25 000 € → FUNDED, fonds bloqués affichés. Puis, en direct, trois tentatives toutes refusées proprement : dépôt d'un montant différent, annulation unilatérale (fonds toujours bloqués), annulation après la remise du véhicule.

## Décisions (validées le 2026-10-08)

1. **Une demande d'annulation en attente bloque la remise du véhicule.** `start_rental` renvoie 409 (`details.reason = "CANCELLATION_PENDING"`) tant que l'autre partie n'a pas répondu.
2. **Une demande d'annulation ne peut pas être retirée.** Il n'y a pas de route de retrait : le loueur ne peut lever le blocage qu'en acceptant l'annulation, ce qui rembourse le client. Approuver deux fois renvoie 409.
3. **En F2, le loueur déclenche seul la remise du véhicule.** F3 ajoutera la condition « état des lieux de départ signé par les deux parties ».
