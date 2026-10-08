---
name: escrow-domain
description: Regles metier du sequestre de caution - machine d'etats du contrat, regles sur les montants, signature cryptographique de l'etat des lieux, catalogue des codes d'erreur. A consulter avant de concevoir, coder ou tester tout ce qui touche un contrat, une caution ou un etat des lieux.
---

# Domaine : sequestre de caution

## Machine d'etats (source de verite : `app/domain/state_machine.py`)

| Etat source          | Evenement                      | Acteur            | Etat cible           |
|----------------------|--------------------------------|-------------------|----------------------|
| DRAFT                | `sign_contract` (x2)           | client + loueur   | AWAITING_DEPOSIT     |
| DRAFT                | `cancel`                       | client ou loueur  | CANCELLED            |
| AWAITING_DEPOSIT     | `deposit`                      | client            | FUNDED               |
| AWAITING_DEPOSIT     | `cancel`                       | client ou loueur  | CANCELLED            |
| FUNDED               | `start_rental` (etat des lieux de depart signe x2) | loueur | ACTIVE   |
| FUNDED               | `cancel` (accord mutuel, x2)   | client + loueur   | REFUNDED             |
| ACTIVE               | `submit_return_report`         | loueur            | INSPECTION_PENDING   |
| INSPECTION_PENDING   | `sign_report` (x2, sans retenue) | client + loueur | RELEASED             |
| INSPECTION_PENDING   | `sign_report` (x2, retenue <= caution) | client + loueur | SETTLED     |
| INSPECTION_PENDING   | `contest`                      | client ou loueur  | DISPUTED             |
| DISPUTED             | `resolve`                      | admin             | SETTLED              |

- Etats terminaux : CANCELLED, REFUNDED, RELEASED, SETTLED. Plus aucun evenement accepte.
- **Toute autre combinaison => `INVALID_TRANSITION` (409), etat inchange.** En particulier : pas d'annulation a partir de ACTIVE.
- Chaque transition ecrit une ligne dans `escrow_events` (append-only) : `contract_id, event, actor, from, to, payload_hash, at`.
- Transition = une transaction SQL avec `SELECT ... FOR UPDATE` sur le contrat + cle d'idempotence (`Idempotency-Key`).

## Montants

- Type : `int` en **centimes**. `float` interdit partout (hook).
- Caution : `1 <= deposit_cents <= 50_000_000` (500 000 EUR). Retenue : `0 <= retained_cents <= deposit_cents`.
- Devise : ISO 4217 parmi une liste blanche (`EUR`, `CHF`, `GBP`, `USD`).
- Pydantic en mode strict : `"100"`, `100.0`, `true`, `null` sont refuses (422), pas convertis.
- Invariant comptable : `released_to_client + retained_to_owner == deposit_cents`, toujours.

## Etat des lieux cryptographique

1. Le rapport est un JSON canonique (`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`) incluant `contract_id`, `kind` (`checkout`/`return`), kilometrage, carburant, liste de dommages, et le SHA-256 de chaque photo.
2. `report_hash = sha256(canonical)`. Une fois une signature posee, le rapport est **gele** : toute modification invalide les signatures.
3. Chaque partie signe `report_hash` avec sa cle Ed25519 (cle publique enregistree a la creation du compte). Le serveur verifie avec `cryptography` ; comparaison de hash via `hmac.compare_digest`.
4. Liberation uniquement si : 2 signatures valides, des 2 bonnes parties, sur le meme hash, contrat en INSPECTION_PENDING.

## Contrat d'erreur API

Toujours `{"error": {"code": "<CODE>", "message": "<texte lisible>", "details": {...}?}}`, jamais de stacktrace.

| Code                  | HTTP | Cas                                             |
|-----------------------|------|-------------------------------------------------|
| VALIDATION_ERROR      | 422  | Schema invalide, champ manquant/en trop         |
| INVALID_AMOUNT        | 422  | Montant hors bornes / mauvais type              |
| INVALID_TRANSITION    | 409  | Evenement interdit dans l'etat courant          |
| FORBIDDEN_ACTOR       | 403  | Mauvaise partie pour cette action               |
| NOT_FOUND             | 404  | Contrat inexistant OU pas a toi (pas d'IDOR)    |
| UNSUPPORTED_FILE      | 415  | Type de fichier refuse                          |
| FILE_TOO_LARGE        | 413  | Fichier > limite                                |
| SIGNATURE_INVALID     | 422  | Signature ne verifie pas / mauvais hash         |
| IDEMPOTENCY_CONFLICT  | 409  | Meme cle, corps different                       |
| UNAUTHENTICATED       | 401  | Pas de session / token                          |
