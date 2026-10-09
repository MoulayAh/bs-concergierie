# F4 — Signature du rapport de retour et libération de la caution

> S'appuie sur F3 (rapport de retour figé, contrat INSPECTION_PENDING, mécanisme de signature Ed25519).
> Termine le parcours de démo : contrat → caution → états des lieux → **libération**.

## Objectif

Tenir la promesse du pitch : **la caution est libérée instantanément dès que l'état des lieux de retour
est validé par les deux parties.**

1. Le rapport de retour figé contient la retenue demandée par le loueur (`claimed_retention_cents`, 0 si rien).
2. Chaque partie signe l'empreinte du rapport. En signant, le client **accepte** le montant de la retenue.
3. À la seconde signature valide, **dans la même transaction** :
   - le rapport passe en SIGNED ;
   - le prestataire de paiement rend la caution au client, moins la retenue, et verse la retenue au loueur ;
   - le contrat passe en RELEASED (retenue nulle) ou SETTLED (retenue positive) ;
   - une **quittance** signée par le serveur est émise.
4. Tout le monde peut vérifier la quittance hors ligne, sans faire confiance au serveur.

Après la libération, le contrat est définitif : plus aucune action ne peut modifier les fonds.

## Périmètre

**Inclus**
- Signature du rapport de retour, avec le mécanisme de F3 : même message signé, `kind = return`.
- Règle de justification d'une retenue.
- Opération `settle` du prestataire simulé : libération et versement en un seul appel idempotent.
- Mise à jour du dépôt (`released_cents`, `retained_cents`, `held_cents = 0`) et du contrat.
- Quittance de libération : JSON canonique, empreinte, signature Ed25519 du serveur.
- Route publique de la clé du serveur et script de vérification hors ligne `scripts/verify_receipt.py`.
- **Journal chaîné** : chaque événement de `escrow_events` contient l'empreinte du précédent. La quittance inclut l'empreinte du dernier événement.
- Achèvement du scénario `scripts/demo_scenario.py` et de l'écran final de la démo.

**Exclus**
- Contestation du rapport, litige et arbitrage par l'admin (F5).
- Délai d'expiration lorsqu'une partie ne signe jamais (F5).
- Vrai prestataire de paiement, virements réels.

## Transitions d'état concernées

| Source             | Événement     | Acteur           | Cible              | Condition                                                   |
|--------------------|---------------|------------------|--------------------|-------------------------------------------------------------|
| INSPECTION_PENDING | `sign_report` | client ou loueur | INSPECTION_PENDING | première signature valide du rapport de retour              |
| INSPECTION_PENDING | `sign_report` | l'autre partie   | **RELEASED**       | seconde signature, `claimed_retention_cents = 0`            |
| INSPECTION_PENDING | `sign_report` | l'autre partie   | **SETTLED**        | seconde signature, `claimed_retention_cents > 0`            |
| RELEASED, SETTLED  | tout événement | n'importe qui   | —                  | `INVALID_TRANSITION` (409), état terminal                   |

- Les approbations viennent des **signatures du rapport de retour actif**, et non de celles du contrat. C'est la même correction que la dette de F1, appliquée à cet événement.
- **Remplacement :** tant que la seconde signature n'est pas posée, le loueur peut remplacer le rapport de retour (mécanisme de F3), par exemple pour corriger la retenue après une discussion. La nouvelle révision doit être signée à nouveau par les deux parties.
- Seule la machine d'états (`state_machine.transition`) décide de la cible, à partir du montant figé dans le rapport.

## Règle de justification d'une retenue

Vérifiée au **gel** du rapport de retour (complément de la validation de F3) :

- `claimed_retention_cents > 0` exige **au moins un dommage** dans le rapport de retour, et chaque dommage invoqué doit avoir **au moins une photo**.
- `0 ≤ claimed_retention_cents ≤ deposit_cents`. C'est déjà le cas en F3, et c'est aussi vérifié par PostgreSQL.
- Un rapport de retour sans dommage a forcément une retenue nulle.

## Libération : ordre des opérations

Tout se passe dans une transaction, sous verrou du contrat, du rapport et du dépôt (toujours dans cet ordre, pour éviter les interblocages) :

1. Vérifier la signature, comme en F3 : clé active, bonne partie, empreinte recalculée par le serveur, pas de double signature.
2. Si c'est la seconde signature, calculer `(rendu_client, retenue) = split_deposit(deposit_cents, claimed_retention_cents)` (fonction existante de `app/domain/money.py`).
3. Appeler `provider.settle(provider_ref, release_cents=rendu_client, capture_cents=retenue, key="settle:<deposit_id>")`. La clé ne dépend que du dépôt : un réessai ne paie jamais deux fois.
4. Mettre à jour le dépôt (`held_cents = 0`, `released_cents`, `retained_cents`, statut, `settled_at`, `settlement_ref`), le rapport (SIGNED) et le contrat (RELEASED ou SETTLED).
5. Écrire la signature, l'événement `sign_report` et la quittance.
6. Valider la transaction.

**Si le prestataire échoue** (décision par défaut, voir question 1) : la seconde signature est **refusée** avec `PAYMENT_UNAVAILABLE` (503). Rien n'est écrit, et la partie peut renvoyer la même requête. Si la transaction échoue après un `settle` réussi, le réessai rappelle `settle` avec la même clé, et le prestataire renvoie le résultat déjà obtenu sans repayer.

## Quittance de libération

Contenu canonique (même canonisation qu'en F3) :

```json
{
  "schema": "luxe-escrow/receipt/v1",
  "contract_id": "…",
  "outcome": "SETTLED",
  "currency": "EUR",
  "deposit_cents": 2500000,
  "released_to_client_cents": 2380000,
  "retained_by_owner_cents": 120000,
  "return_report": {"id": "…", "revision": 2, "hash": "…"},
  "checkout_report": {"id": "…", "hash": "…"},
  "signatures": [
    {"party": "owner",  "key_fingerprint": "…", "signature": "…", "signed_at": "…"},
    {"party": "client", "key_fingerprint": "…", "signature": "…", "signed_at": "…"}
  ],
  "settlement_ref": "sim_…",
  "settled_at": "2026-11-05T18:02:11Z",
  "event_chain": {"length": 14, "head": "…"}
}
```

`event_chain.head` est l'empreinte de l'événement `sign_report` final. L'écriture de la quittance n'est pas un événement de transition : la quittance vient sceller la chaîne.

- `receipt_hash = sha256(canonique)`.
- Le serveur signe `b"luxe-escrow:receipt:v1:" + receipt_hash` avec **sa propre clé Ed25519**.
- La clé privée du serveur est lue depuis `SERVER_SIGNING_KEY` (`.env`, jamais dans le dépôt). Le démarrage échoue si elle est absente. Sa clé publique est servie par `GET /api/server-key`.

**Vérification hors ligne (`scripts/verify_receipt.py <receipt.json>`) :**
- recalcule l'empreinte de la quittance et vérifie la signature du serveur ;
- vérifie les deux signatures des parties sur l'empreinte du rapport de retour ;
- vérifie `released_to_client_cents + retained_by_owner_cents == deposit_cents` ;
- avec `--events events.json` (export de `GET /api/contracts/<id>/events`), recalcule toute la chaîne d'événements et vérifie que sa longueur et sa tête correspondent à `event_chain`.

C'est le moment fort de la démo : la preuve se vérifie sans faire confiance à l'application.

## Modèle de données (db-migrator)

Nouvelle migration.

**deposits**, colonnes ajoutées
| Colonne        | Type        | Contrainte                                                        |
|----------------|-------------|-------------------------------------------------------------------|
| settled_at     | TIMESTAMPTZ | NULL tant que HELD                                                |
| settlement_ref | VARCHAR(64) | UNIQUE, NULL tant que HELD                                        |

Contraintes ajoutées :
- `CHECK (status <> 'HELD' OR (released_cents = 0 AND retained_cents = 0))` ;
- `CHECK (status NOT IN ('RELEASED','SETTLED') OR held_cents = 0)` ;
- `CHECK (status <> 'RELEASED' OR retained_cents = 0)` ;
- `CHECK (status <> 'SETTLED' OR retained_cents > 0)`.

L'invariant de F2 (`held + refunded + released + retained = amount`) reste en place.

Trigger PostgreSQL : un dépôt RELEASED, SETTLED ou REFUNDED ne peut plus être modifié.

**escrow_events** : chaîne de hachage, colonnes ajoutées

| Colonne    | Type     | Contrainte                                                 |
|------------|----------|------------------------------------------------------------|
| seq        | INTEGER  | NOT NULL, `CHECK (seq >= 1)` ; UNIQUE (contract_id, seq)   |
| prev_hash  | CHAR(64) | NOT NULL ; 64 zéros pour `seq = 1`                         |
| event_hash | CHAR(64) | NOT NULL, UNIQUE                                           |

- **Calcul de l'empreinte :** `event_hash = sha256(prev_hash + ":" + canonique({contract_id, seq, event, actor_id, from_status, to_status, payload_hash, created_at}))`. Une seule fonction, dans `app/domain/event_chain.py`, est utilisée à la fois par le service et par `verify_receipt.py`.
- **Écriture :** le service écrit sous le verrou du contrat déjà pris, donc il n'y a pas de course entre deux événements d'un même contrat.
- **Contrôle par PostgreSQL :** un trigger vérifie à l'insertion que `seq` vaut le maximum précédent + 1 et que `prev_hash` est égal à l'`event_hash` de l'événement précédent.
- **Événements existants :** la migration recalcule la chaîne des événements de F1 à F3, contrat par contrat, dans l'ordre (`created_at`, `id`). Elle suspend temporairement le trigger d'ajout seul, uniquement dans cette migration, et vérifie la chaîne avant de valider.
- `GET /api/contracts/<id>/events` expose désormais `seq`, `prev_hash` et `event_hash`.

**settlement_receipts**
| Colonne               | Type        | Contrainte                                       |
|-----------------------|-------------|--------------------------------------------------|
| id                    | UUID        | PK                                               |
| contract_id           | UUID        | FK contracts, **UNIQUE** (une seule quittance)   |
| deposit_id            | UUID        | FK deposits, UNIQUE                              |
| return_report_id      | UUID        | FK inspection_reports                            |
| canonical_json        | BYTEA       | NOT NULL                                         |
| receipt_hash          | CHAR(64)    | NOT NULL, UNIQUE                                 |
| server_signature      | BYTEA       | `CHECK (length(server_signature) = 64)`          |
| server_key_fingerprint| CHAR(64)    | NOT NULL                                         |
| created_at            | TIMESTAMPTZ | NOT NULL                                         |

Trigger PostgreSQL : table en ajout seul (pas d'UPDATE ni de DELETE).

## Prestataire de paiement simulé

Ajout à `PaymentProvider` :
`settle(ref, *, release_cents, capture_cents, key) -> str`

- Idempotent par `key` : même clé et mêmes montants, même `settlement_ref` ; même clé et montants différents, erreur.
- Refus si `release_cents + capture_cents` est différent du montant bloqué, ou si un montant est négatif.
- Pour la démo et les tests, le moyen de paiement `demo_provider_down` provoque aussi une panne au moment de la libération.

## Contrat d'API

| Méthode | Route                                          | Acteur          | Idempotency-Key | Succès |
|---------|------------------------------------------------|-----------------|-----------------|--------|
| POST    | `/api/contracts/<id>/reports/return/signatures`| une des parties | **obligatoire** | 200    |
| GET     | `/api/contracts/<id>/receipt`                  | une des parties | —               | 200    |
| GET     | `/api/server-key`                              | public          | —               | 200    |

- **Signature :** `{"signature": "<base64 64 octets>"}`, comme en F3.
- **Réponse à la seconde signature :** le contrat (statut RELEASED ou SETTLED), le bloc `funds` (format F2) à jour et l'objet `receipt` (`canonical_json`, `receipt_hash`, `server_signature`).
- `GET /receipt` avant la libération renvoie 404 `NOT_FOUND`.

## Cas d'erreur à couvrir

| Situation                                                                  | Code                 | HTTP |
|----------------------------------------------------------------------------|----------------------|------|
| Signature du rapport de retour encore en DRAFT                             | INVALID_TRANSITION   | 409  |
| Signature alors que le contrat n'est pas INSPECTION_PENDING                | INVALID_TRANSITION   | 409  |
| Signature valide du rapport de **départ** présentée pour le retour (rejeu) | SIGNATURE_INVALID    | 422  |
| Signature d'une révision remplacée                                         | INVALID_TRANSITION / SIGNATURE_INVALID | 409 / 422 |
| Même partie qui signe deux fois                                            | INVALID_TRANSITION   | 409  |
| Gel d'un retour avec une retenue > 0 sans dommage, ou un dommage sans photo | VALIDATION_ERROR    | 422  |
| Prestataire en panne à la seconde signature                                | PAYMENT_UNAVAILABLE  | 503  |
| Réessai après la panne, même clé                                           | libération unique    | 200  |
| Deux secondes signatures simultanées (rejeu concurrent)                    | une seule libération, une seule quittance | — |
| Annulation, dépôt, remplacement ou nouvelle signature après la libération  | INVALID_TRANSITION   | 409  |
| Tentative d'injecter `retained_cents` ou `release_cents` dans le corps     | VALIDATION_ERROR     | 422  |
| UPDATE SQL direct d'un dépôt libéré ou d'une quittance                     | rejeté par PostgreSQL | —   |
| Quittance d'un autre contrat (IDOR)                                        | NOT_FOUND            | 404  |
| `SERVER_SIGNING_KEY` absente au démarrage                                  | l'application refuse de démarrer | — |

Après chaque erreur, rien n'a changé : statut du contrat, du rapport et du dépôt, montants, signatures, quittance (absente) et appels au prestataire (aucun paiement effectué).

## Tests à écrire

**test-engineer**
- `test_double_signed_return_without_retention_releases_full_deposit`
- `test_double_signed_return_with_retention_settles_split` (hypothesis : pour toute retenue valide, rendu + retenu = caution)
- `test_first_return_signature_keeps_funds_held`
- `test_retention_requires_damage_with_photo`
- `test_settle_is_idempotent_on_retry_after_provider_failure`
- `test_provider_failure_leaves_everything_unchanged`
- `test_receipt_verifies_offline` (exécute la logique de `verify_receipt.py`)
- `test_receipt_tampering_detected` (un centime modifié invalide la signature du serveur)
- `test_terminal_contract_rejects_every_event` (matrice : tous les événements × RELEASED, SETTLED)
- `test_released_deposit_immutable_in_database`
- `test_app_refuses_to_start_without_server_key`
- `test_event_chain_links_every_event` (chaque `prev_hash` égal à l'`event_hash` précédent, `seq` sans trou)
- `test_chain_broken_insert_rejected_by_database` (insertion SQL avec un mauvais `prev_hash` ou un `seq` sauté)
- `test_migration_backfills_existing_chain`
- `test_verify_receipt_detects_removed_or_altered_event`

**adversarial-tester** (`tests/adversarial/test_f4_release.py`)
- Rejeu de la signature du rapport de départ, ou d'une signature d'un autre contrat, sur le retour.
- Libération déclenchée deux fois en parallèle, avec la même clé puis avec des clés différentes.
- Client qui tente de signer avec une retenue modifiée dans le corps.
- Loueur qui remplace le rapport juste après la signature du client, pour augmenter la retenue : la nouvelle révision exige une nouvelle signature du client.
- Annulation, contestation ou nouveau dépôt après RELEASED ou SETTLED.
- Quittance falsifiée (montant, empreinte, ordre des signatures), soumise au script de vérification.
- Panne du prestataire suivie d'un réessai rapide multiple.
- Export d'événements falsifié (un événement supprimé, réordonné ou modifié), soumis à `verify_receipt.py --events`.
- Écriture concurrente d'événements sur un même contrat : la chaîne reste linéaire.

## Découpage et ordre

1. **test-engineer** : tests ci-dessus (rouges attendus).
2. **db-migrator** : nouvelle migration (colonnes de `deposits`, CHECK, trigger d'immuabilité, `settlement_receipts`, chaîne de `escrow_events` avec son trigger et le recalcul des événements existants).
3. **backend-dev** :
   - `sign_return` et la libération atomique ;
   - `settle` du prestataire simulé ;
   - règle de justification de la retenue ;
   - quittance (`app/domain/receipt.py`, `app/security/server_key.py`) ;
   - routes ;
   - `scripts/verify_receipt.py` ;
   - fin de `scripts/demo_scenario.py`.
4. **frontend-dev** : signature du retour dans le navigateur, puis écran final avec la ventilation des fonds, la quittance téléchargeable et le badge « vérifiée ».
5. **adversarial-tester** : attaques, failles renvoyées à backend-dev.
6. **security-auditor** : audit ciblé sur le flux d'argent et la clé du serveur (`/audit`).
7. **reviewer** : revue du diff.

Mise à jour de la skill escrow-domain (règle de retenue, quittance, `settle`) à valider par toi, car les agents ne peuvent pas modifier `.claude/`.
Ajout de `SERVER_SIGNING_KEY` dans `.env.example`, avec une commande `flask gen-server-key` qui affiche une clé sans jamais l'écrire dans le dépôt.

## Critères d'acceptation

- [ ] `python scripts/quality_gate.py` vert, tests F1, F2 et F3 toujours verts.
- [ ] Tous les tests `tests/adversarial` de F4 verts.
- [ ] Pour tout contrat terminé : `released + retained + refunded = deposit`, vérifié par PostgreSQL.
- [ ] `scripts/demo_scenario.py` déroule le parcours complet sans erreur.
- [ ] Démo :
  - signature du retour par les deux parties, et libération immédiate affichée ;
  - quittance téléchargée et vérifiée par `verify_receipt.py` ;
  - un centime modifié dans la quittance fait échouer la vérification ;
  - une nouvelle tentative de libération est refusée proprement.

## Décisions (validées le 2026-10-09)

1. **Prestataire en panne à la seconde signature : la signature est refusée** (503 `PAYMENT_UNAVAILABLE`). Rien n'est écrit, et la partie réessaie avec la même clé. Pas de file de paiements (« outbox ») en F4.
2. **Retenue : un montant total unique** (`claimed_retention_cents`), justifié par au moins un dommage avec photo. Le format du rapport de F3 (`luxe-escrow/report/v1`) reste inchangé.
3. **Journal chaîné : oui.** Les événements forment une chaîne de hachage par contrat, contrôlée par PostgreSQL. La quittance en scelle la tête, et `verify_receipt.py --events` peut prouver qu'aucun événement n'a été supprimé ou modifié.
