# F3 — États des lieux numériques (départ et retour)

> S'appuie sur F2 (caution bloquée, contrat FUNDED). Prépare F4 (signature du rapport de retour et libération).

## Objectif

Remplacer la feuille papier par un état des lieux numérique **infalsifiable** :

1. Le loueur remplit le rapport : kilométrage, carburant, dommages, photos et PDF.
2. Le rapport est **figé** : il est mis sous forme canonique et son empreinte SHA-256 est calculée. Il ne peut plus être modifié.
3. Chaque partie **signe l'empreinte** avec sa clé Ed25519. Le serveur vérifie la signature, sans jamais connaître la clé privée.

Deux rapports par contrat :
- **Départ (`checkout`)** : sa double signature devient la condition pour remettre le véhicule (décision 3 de F2).
- **Retour (`return`)** : une fois figé, le contrat passe en INSPECTION_PENDING. Sa signature et la libération des fonds arrivent en F4.

C'est ici que se joue l'attaque « uploader des formats de fichiers invalides » : toutes les règles de la skill **secure-uploads** s'appliquent.

## Périmètre

**Inclus**
- Enregistrement des clés publiques Ed25519 des utilisateurs.
- Création, édition (tant qu'il n'est pas figé), gel et consultation des rapports de départ et de retour.
- Upload sécurisé de photos (JPEG, PNG) et de PDF, téléchargement authentifié.
- Signature du rapport de départ par les deux parties, et vérification côté serveur.
- `start_rental` exige désormais un rapport de départ signé par les deux parties.
- Gel du rapport de retour : transition ACTIVE → INSPECTION_PENDING (`submit_return_report`).
- Commande `flask seed-demo` étendue : génère une paire de clés par compte de démo et affiche les clés privées **une seule fois**, pour le script de démo.

**Exclus**
- Signature du rapport de retour, libération et retenue (F4). Le montant de retenue demandé est saisi et figé dès F3, mais n'a aucun effet sur les fonds avant F4.
- Contestation et litige (F5).
- Analyse automatique des photos, géolocalisation, horodatage par un tiers de confiance.

**Conséquence sur la feuille de route :** le mécanisme de signature est construit ici. F4 se limite donc à signer le rapport de retour (avec le même mécanisme) et à libérer ou retenir les fonds.

## Transitions d'état concernées

| Source  | Événement                  | Acteur  | Cible              | Condition                                                         |
|---------|----------------------------|---------|--------------------|-------------------------------------------------------------------|
| FUNDED  | `start_rental`             | loueur  | ACTIVE             | **nouveau :** rapport `checkout` signé par les deux parties, et aucune annulation en attente (F2) |
| ACTIVE  | `submit_return_report`     | loueur  | INSPECTION_PENDING | rapport `return` figé (déclenché par le gel lui-même)             |

Les rapports ont leur propre cycle de vie, dans `app/domain/report.py` (logique pure) :

| État du rapport | Actions permises                                         | Passage                         |
|-----------------|----------------------------------------------------------|---------------------------------|
| DRAFT           | modifier les champs, ajouter ou retirer des fichiers     | `finalize` (loueur) → FROZEN    |
| FROZEN          | signer (l'empreinte ne change plus jamais)               | 2 signatures valides → SIGNED ; `supersede` (loueur) → SUPERSEDED |
| SIGNED          | lecture seule                                            | —                               |
| SUPERSEDED      | lecture seule, conservé dans l'historique                | —                               |

- Un rapport `checkout` ne peut être créé que si le contrat est FUNDED, un rapport `return` que s'il est ACTIVE.
- Un seul rapport **actif** (non SUPERSEDED) de chaque type par contrat.
- **Remplacement (`supersede`)** : possible uniquement sur un rapport FROZEN qui n'a pas ses deux signatures.
  - L'ancien passe en SUPERSEDED et une nouvelle révision DRAFT est créée (`revision + 1`), avec une copie des champs et des fichiers.
  - Les signatures de l'ancienne révision restent attachées à celle-ci. Elles sont donc caduques pour la nouvelle, dont l'empreinte diffère.
  - Un rapport SIGNED ne peut jamais être remplacé.
- **Photos** : les deux parties peuvent en ajouter tant que le rapport est en DRAFT. Chacun ne peut supprimer **que ses propres fichiers** : le loueur ne peut pas effacer une photo prise par le client. Seul le loueur remplit les champs et fige le rapport.
- Toute modification d'un rapport FROZEN ou SIGNED renvoie `INVALID_TRANSITION` (409, `details.reason = "REPORT_FROZEN"`).

## Rapport canonique et empreinte

Contenu figé (Pydantic strict, `extra="forbid"`) :

```json
{
  "schema": "luxe-escrow/report/v1",
  "contract_id": "…",
  "kind": "checkout",
  "vehicle_plate": "AB-123-CD",
  "deposit": {"amount_cents": 2500000, "currency": "EUR"},
  "odometer_km": 12450,
  "fuel_eighths": 8,
  "damages": [
    {"zone": "front_bumper", "severity": "minor", "description": "Rayure 3 cm", "file_ids": ["…"]}
  ],
  "claimed_retention_cents": 0,
  "files": [
    {"id": "…", "sha256": "…", "mime": "image/jpeg", "size_bytes": 482113}
  ],
  "notes": "",
  "frozen_at": "2026-11-01T09:12:44Z"
}
```

Règles de contenu :

| Champ                     | Règle                                                                          |
|---------------------------|--------------------------------------------------------------------------------|
| `odometer_km`             | entier, 0 à 2 000 000. Au retour : ≥ valeur du départ.                         |
| `fuel_eighths`            | entier, 0 à 8                                                                  |
| `damages`                 | 0 à 30 éléments                                                                |
| `damages[].zone`          | liste blanche (`front_bumper`, `rear_bumper`, `hood`, `roof`, `left_side`, `right_side`, `windshield`, `wheels`, `interior`, `other`) |
| `damages[].severity`      | `minor`, `moderate`, `major`                                                   |
| `damages[].description`   | 500 caractères maximum                                                         |
| `damages[].file_ids`      | doivent appartenir à ce rapport                                                |
| `claimed_retention_cents` | entier, 0 ≤ montant ≤ `deposit_cents` ; doit valoir 0 au départ                |
| `files`                   | au moins 1 photo au départ comme au retour, 20 fichiers maximum                |

- Forme canonique : `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. Les fichiers sont triés par `sha256`.
- Empreinte : `report_hash = sha256(canonique)`, en hexadécimal.
- L'API renvoie le JSON canonique exact et son empreinte, pour que chacun puisse les recalculer lui-même.

## Signature

- **Message signé :** `b"luxe-escrow:report:v1:" + contract_id + b":" + kind + b":" + report_hash`. La séparation de domaine empêche de réutiliser une signature sur un autre contrat, sur l'autre rapport ou dans un autre contexte.
- **Algorithme :** Ed25519 (`cryptography`). La clé publique fait 32 octets bruts, encodés en base64. La signature fait 64 octets, encodés en base64.
- **Vérification serveur :**
  - le signataire est bien une des deux parties du contrat ;
  - sa clé est enregistrée et non révoquée ;
  - la signature est valide sur l'empreinte **recalculée par le serveur** à partir du contenu stocké (pas sur une empreinte fournie par le client) ;
  - la partie n'a pas déjà signé.
- Une clé ne peut signer qu'au nom de son propriétaire.

## Modèle de données (db-migrator)

Nouvelle migration.

**user_keys**
| Colonne      | Type        | Contrainte                                      |
|--------------|-------------|-------------------------------------------------|
| id           | UUID        | PK                                              |
| user_id      | UUID        | FK users, NOT NULL                              |
| public_key   | BYTEA       | `CHECK (length(public_key) = 32)`, UNIQUE       |
| fingerprint  | CHAR(64)    | sha256 de la clé, UNIQUE                        |
| created_at / revoked_at | TIMESTAMPTZ | `revoked_at` NULL tant que la clé est active |

Au plus une clé active par utilisateur (index unique partiel `WHERE revoked_at IS NULL`).

**inspection_reports**
| Colonne                   | Type                  | Contrainte                                   |
|---------------------------|-----------------------|----------------------------------------------|
| id                        | UUID                  | PK                                           |
| contract_id               | UUID                  | FK contracts                                 |
| kind                      | ENUM `report_kind`    | `checkout`, `return`                         |
| revision                  | INTEGER               | `CHECK (revision >= 1)` ; UNIQUE (contract_id, kind, revision) |
| status                    | ENUM `report_status`  | `DRAFT`, `FROZEN`, `SIGNED`, `SUPERSEDED`    |
| supersedes_id             | UUID                  | FK inspection_reports, NULL pour la révision 1 |
| odometer_km               | INTEGER               | `CHECK (odometer_km BETWEEN 0 AND 2000000)`  |
| fuel_eighths              | SMALLINT              | `CHECK (fuel_eighths BETWEEN 0 AND 8)`       |
| damages                   | JSONB                 | NOT NULL, défaut `[]`                        |
| claimed_retention_cents   | BIGINT                | `CHECK (claimed_retention_cents >= 0)`       |
| notes                     | VARCHAR(2000)         |                                              |
| canonical_json            | BYTEA                 | NULL tant que DRAFT                          |
| report_hash               | CHAR(64)              | NULL tant que DRAFT                          |
| frozen_at                 | TIMESTAMPTZ           |                                              |
| version                   | INTEGER               |                                              |

Contraintes :
- `CHECK ((status = 'DRAFT') = (report_hash IS NULL))` ;
- index unique partiel sur `(contract_id, kind) WHERE status <> 'SUPERSEDED'`, pour un seul rapport actif par type.

Trigger PostgreSQL :
- un rapport non DRAFT ne peut plus voir changer son contenu ni son empreinte ;
- seul le passage de FROZEN à SIGNED ou à SUPERSEDED reste autorisé, et SIGNED ne peut jamais passer à SUPERSEDED.

Le contenu canonique inclut `revision` et `supersedes_id` : deux révisions ont donc toujours des empreintes différentes.

**report_files**
| Colonne        | Type         | Contrainte                                          |
|----------------|--------------|-----------------------------------------------------|
| id             | UUID         | PK                                                  |
| report_id      | UUID         | FK inspection_reports                               |
| uploaded_by    | UUID         | FK users                                            |
| sha256         | CHAR(64)     | NOT NULL ; UNIQUE (report_id, sha256), pas de doublon |
| mime           | VARCHAR(32)  | `CHECK (mime IN ('image/jpeg','image/png','application/pdf'))` |
| size_bytes     | INTEGER      | `CHECK (size_bytes BETWEEN 1 AND 10485760)`         |
| storage_name   | VARCHAR(64)  | `<uuid4>.<ext>` ; partagé entre révisions copiées (non UNIQUE) |
| original_name  | VARCHAR(255) | nettoyé, métadonnée seulement                       |
| width / height | INTEGER      | NULL pour un PDF                                    |
| created_at     | TIMESTAMPTZ  |                                                     |

**report_signatures**
| Colonne     | Type        | Contrainte                                       |
|-------------|-------------|--------------------------------------------------|
| id          | UUID        | PK                                               |
| report_id   | UUID        | FK                                               |
| party       | ENUM        | `owner`, `client` ; UNIQUE (report_id, party)    |
| user_id     | UUID        | FK users                                         |
| key_id      | UUID        | FK user_keys                                     |
| report_hash | CHAR(64)    | égal à l'empreinte du rapport au moment de la signature |
| signature   | BYTEA       | `CHECK (length(signature) = 64)`                 |
| signed_at   | TIMESTAMPTZ |                                                  |

## Uploads (application de la skill secure-uploads)

Chaque upload passe par `app/security/uploads.py`, dans cet ordre :

1. **Taille :** `MAX_CONTENT_LENGTH` à 10 Mo → 413 **au format JSON**. Le handler doit intercepter `RequestEntityTooLarge` de Werkzeug. Un fichier vide → 415.
2. **Type réel :** il est lu dans les premiers octets du fichier (JPEG, PNG ou PDF uniquement). L'extension déclarée doit correspondre au type réel. Le `Content-Type` envoyé par le client est ignoré.
3. **Images :**
   - Pillow avec `MAX_IMAGE_PIXELS` borné, puis `verify()` ;
   - dimensions de 8000 × 8000 au maximum ;
   - **ré-encodage**, qui supprime l'EXIF et les contenus cachés ;
   - `DecompressionBombWarning` et `DecompressionBombError` sont convertis en 415. Attention, pytest est configuré avec `filterwarnings = error`.
4. **PDF :** refus si le fichier contient `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFile`, `/OpenAction` ou `/AA`, ou s'il dépasse 20 pages.
5. **Stockage :**
   - le fichier est enregistré sous `UPLOAD_DIR/<uuid4>.<ext>`, hors de `app/static` ;
   - il est d'abord écrit dans un fichier temporaire, puis déplacé atomiquement ;
   - si la transaction échoue, le fichier est supprimé.
6. **Empreinte :** SHA-256 calculé **sur les octets stockés** après ré-encodage.
7. **Téléchargement :** route authentifiée, accessible aux parties du contrat uniquement, avec `Content-Disposition: attachment` et `X-Content-Type-Options: nosniff`.

Un fichier par requête (multipart, champ `file`). Le rapport est verrouillé pendant l'upload, pour qu'aucun fichier ne s'ajoute pendant un gel.

Les fichiers stockés sont immuables. Un fichier n'est effacé du disque que si plus aucune ligne `report_files` ne le référence, ce qui n'arrive jamais pour une révision SUPERSEDED, puisque l'historique est conservé.

## Contrat d'API

| Méthode | Route                                                   | Acteur          | Succès |
|---------|---------------------------------------------------------|-----------------|--------|
| POST    | `/api/me/keys`                                          | tout utilisateur | 201   |
| GET     | `/api/me/keys`                                          | tout utilisateur | 200   |
| DELETE  | `/api/me/keys/<key_id>`                                 | propriétaire de la clé | 204 |
| POST    | `/api/contracts/<id>/reports`                           | loueur          | 201    |
| GET     | `/api/contracts/<id>/reports/<kind>`                    | une des parties | 200    |
| GET     | `/api/contracts/<id>/reports/<kind>/history`            | une des parties | 200    |
| PUT     | `/api/contracts/<id>/reports/<kind>`                    | loueur, DRAFT   | 200    |
| POST    | `/api/contracts/<id>/reports/<kind>/files`              | une des parties, DRAFT | 201 |
| DELETE  | `/api/contracts/<id>/reports/<kind>/files/<file_id>`    | auteur du fichier, DRAFT | 204 |
| GET     | `/api/contracts/<id>/reports/<kind>/files/<file_id>`    | une des parties | 200    |
| POST    | `/api/contracts/<id>/reports/<kind>/finalize`           | loueur          | 200    |
| POST    | `/api/contracts/<id>/reports/<kind>/supersede`          | loueur, FROZEN incomplet | 201 |
| POST    | `/api/contracts/<id>/reports/checkout/signatures`       | une des parties | 200    |

- **Révocation d'une clé** : `DELETE /api/me/keys/<key_id>` permet ensuite d'en enregistrer une nouvelle, par exemple après un changement de navigateur. Les signatures déjà posées restent valides : elles l'étaient au moment de la signature.

- **Enregistrement d'une clé :** `{"public_key": "<base64 32 octets>"}`.
- **Signature :** `{"signature": "<base64 64 octets>"}`.
- Les `POST` acceptent `Idempotency-Key`, obligatoire pour `finalize` et les signatures.

## Nouveaux codes d'erreur

| Code                 | HTTP | Cas                                                    |
|----------------------|------|--------------------------------------------------------|
| KEY_NOT_REGISTERED   | 422  | Signature sans clé active enregistrée                  |
| KEY_ALREADY_ACTIVE   | 409  | Deuxième clé active (révoquer l'ancienne d'abord)      |

`UNSUPPORTED_FILE` (415), `FILE_TOO_LARGE` (413) et `SIGNATURE_INVALID` (422) existent déjà.

## Cas d'erreur à couvrir

| Situation                                                                 | Code                 | HTTP |
|---------------------------------------------------------------------------|----------------------|------|
| `.exe` renommé `.jpg`, PNG nommé `.pdf`, SVG, GIF, HEIC, ZIP              | UNSUPPORTED_FILE     | 415  |
| PDF contenant `/JavaScript` ou `/OpenAction`                              | UNSUPPORTED_FILE     | 415  |
| Fichier vide, fichier de 1 octet, JPEG tronqué                            | UNSUPPORTED_FILE     | 415  |
| Fichier > 10 Mo                                                           | FILE_TOO_LARGE       | 413  |
| Image de 20 000 × 20 000 (bombe de décompression)                         | UNSUPPORTED_FILE     | 415  |
| Nom `../../etc/passwd.jpg`, nom de 10 000 caractères, octet nul           | accepté et renommé en UUID, rien d'écrit hors `UPLOAD_DIR` | 201 |
| Requête sans champ `file`, ou plusieurs fichiers                          | VALIDATION_ERROR     | 422  |
| 21e fichier, même fichier deux fois                                       | VALIDATION_ERROR     | 422  |
| Upload, modification ou suppression sur un rapport FROZEN                 | INVALID_TRANSITION   | 409  |
| `fuel_eighths` = 9, `odometer_km` négatif, kilométrage de retour < départ | VALIDATION_ERROR     | 422  |
| `claimed_retention_cents` > caution ou négatif, ou ≠ 0 au départ          | INVALID_AMOUNT       | 422  |
| `file_ids` d'un dommage pointant vers le fichier d'un autre rapport       | VALIDATION_ERROR     | 422  |
| Gel sans aucune photo                                                     | VALIDATION_ERROR     | 422  |
| Rapport `checkout` sur un contrat non FUNDED, `return` sur un non ACTIVE  | INVALID_TRANSITION   | 409  |
| Deuxième rapport du même type                                             | INVALID_TRANSITION   | 409  |
| Signature invalide, tronquée, en base64 malformé                          | SIGNATURE_INVALID    | 422  |
| Signature valide mais d'un autre contrat ou de l'autre rapport (rejeu)    | SIGNATURE_INVALID    | 422  |
| Signature avant le gel                                                    | INVALID_TRANSITION   | 409  |
| Même partie qui signe deux fois                                           | INVALID_TRANSITION   | 409  |
| Signature sans clé enregistrée                                            | KEY_NOT_REGISTERED   | 422  |
| Clé publique de 31 octets, ou déjà utilisée par un autre compte           | VALIDATION_ERROR     | 422  |
| `start_rental` avec un rapport de départ signé par une seule partie       | INVALID_TRANSITION   | 409  |
| Téléchargement du fichier d'un autre contrat (IDOR)                       | NOT_FOUND            | 404  |
| Le loueur supprime une photo ajoutée par le client                        | FORBIDDEN_ACTOR      | 403  |
| Le client modifie les champs, fige ou remplace le rapport                 | FORBIDDEN_ACTOR      | 403  |
| Remplacement d'un rapport DRAFT ou SIGNED                                 | INVALID_TRANSITION   | 409  |
| Signature postée sur une révision SUPERSEDED                              | INVALID_TRANSITION   | 409  |
| Ancienne signature présentée pour la nouvelle révision                    | SIGNATURE_INVALID    | 422  |
| Signature avec une clé révoquée                                           | KEY_NOT_REGISTERED   | 422  |
| UPDATE SQL direct du contenu d'un rapport FROZEN                          | rejeté par le trigger PostgreSQL | — |

Après chaque erreur, rien n'a changé : statut du rapport, empreinte, fichiers stockés sur disque, signatures et statut du contrat.

## Tests à écrire

**test-engineer**
- `test_report_lifecycle_draft_frozen_signed`
- `test_canonical_json_is_deterministic` (hypothesis : l'ordre des clés et des fichiers n'influe pas sur l'empreinte)
- `test_any_content_change_changes_hash`
- `test_signature_roundtrip_with_registered_key`
- `test_signature_bound_to_contract_and_kind` (rejeu refusé)
- `test_start_rental_requires_double_signed_checkout`
- `test_finalize_return_moves_contract_to_inspection_pending`
- `test_upload_accepts_jpeg_png_pdf_and_strips_exif`
- `test_stored_sha256_matches_bytes_on_disk`
- `test_download_headers_attachment_nosniff`
- `test_frozen_report_rejected_by_database_trigger`
- `test_supersede_creates_new_revision_and_voids_signatures`
- `test_signed_report_cannot_be_superseded`
- `test_history_lists_all_revisions_with_hashes`
- `test_each_party_deletes_only_own_files`
- `test_revoked_key_keeps_past_signatures_valid`
- Fichiers de test générés par du code dans `tests/fixtures/files/`, sans aucun vrai logiciel malveillant.

**adversarial-tester** (`tests/adversarial/test_f3_reports.py`)
- Tout le catalogue de fichiers piégés de la skill secure-uploads, plus : polyglotte JPEG/ZIP, PNG avec bloc `tEXt` contenant du HTML, PDF chiffré.
- Changement de `Content-Type` et d'extension dans tous les sens.
- Course entre un upload et le gel (le fichier ne doit pas entrer dans un rapport figé avec une empreinte différente).
- Signature avec la clé de l'autre partie, signature d'une empreinte fournie par le client, signature réutilisée sur un autre contrat.
- Client qui crée, modifie ou fige un rapport ; tiers qui télécharge une photo.
- Kilométrage qui recule, retenue supérieure à la caution.
- Le loueur remplace le rapport juste après la signature du client, pour retirer une photo gênante : la photo reste visible dans l'historique et la nouvelle révision doit être resignée.
- Course entre la seconde signature et un remplacement : un seul gagne, et jamais un rapport SIGNED remplacé.

## Découpage et ordre

1. **test-engineer** : tests et générateurs de fichiers de test (rouges attendus).
2. **db-migrator** : nouvelle migration (`user_keys`, `inspection_reports`, `report_files`, `report_signatures`, enums, trigger de gel).
3. **backend-dev** :
   - `app/domain/report.py` (canonisation, empreinte, cycle de vie) ;
   - `app/security/signatures.py` ;
   - `app/security/uploads.py` ;
   - services et routes ;
   - condition supplémentaire sur `start_rental` ;
   - handler JSON pour l'erreur 413 ;
   - extension de `seed-demo`.
4. **frontend-dev** (obligatoire, voir décision 3) :
   - écran d'état des lieux avec upload des photos ;
   - génération et enregistrement de la clé dans le navigateur ;
   - signature WebCrypto Ed25519 ;
   - affichage de l'empreinte et de l'historique des révisions.
5. **adversarial-tester** : attaques, failles renvoyées à backend-dev.
6. **security-auditor** : audit ciblé uploads et crypto (`/audit`).
7. **reviewer** : revue du diff.

Mise à jour de la skill escrow-domain (cycle de vie des rapports, message signé, nouveaux codes d'erreur) à valider par toi, car les agents ne peuvent pas modifier `.claude/`.

## Critères d'acceptation

- [ ] `python scripts/quality_gate.py` vert, tests F1 et F2 toujours verts.
- [ ] Tous les tests `tests/adversarial` de F3 verts.
- [ ] `bandit` sans alerte sur `app/security/`.
- [ ] Aucun fichier écrit hors de `UPLOAD_DIR`, et aucun fichier orphelin après une erreur.
- [ ] Démo : état des lieux de départ (2 photos, 1 dommage), gel avec empreinte affichée, double signature, remise du véhicule. Puis, en direct, trois tentatives toutes refusées proprement : `.exe` renommé `.jpg`, modification du rapport après signature, remise du véhicule avant la signature du client.

## Décisions (validées le 2026-10-09)

1. **Les deux parties peuvent ajouter des photos** tant que le rapport est en DRAFT. Chacun ne peut supprimer que ses propres fichiers. Seul le loueur remplit les champs, fige et remplace le rapport.
2. **Un rapport figé peut être remplacé** tant que les deux signatures ne sont pas posées. Une nouvelle révision est créée, l'ancienne reste consultable dans l'historique avec son empreinte, et ses signatures ne valent pas pour la nouvelle. Un rapport SIGNED est définitif.
3. **Signature dans le navigateur** avec WebCrypto Ed25519 :
   - la clé est générée localement et conservée dans IndexedDB comme `CryptoKey` non exportable ;
   - seule la clé publique est envoyée au serveur ;
   - le serveur ne détient jamais de clé privée ;
   - `seed-demo` génère des clés uniquement pour le script de démo en ligne de commande, et les affiche une seule fois ;
   - un navigateur sans Ed25519 dans WebCrypto doit afficher un message clair, et non une erreur muette.
