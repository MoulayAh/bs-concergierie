# Audit adversarial F1 (creation / signature / annulation de contrat) — 2026-10-08

Auteur : adversarial-tester. Tests : `tests/adversarial/test_f1_contracts.py` (marqueur `adversarial`).
Commande : `python -m pytest -m adversarial` (venv Python 3.14, PostgreSQL de test localhost:5433).

Boucle 1 : **6 failed, 423 passed, 328 deselected in 144.29s** (couverture 92,40 %, seuil 85 % atteint).
Boucle 2 : **16 failed, 486 passed, 328 deselected in 214.40s** (voir section suivante).
Aucun 500, aucun etat incoherent, aucune escalade d'acces. Deux failles de validation (faible / moyenne).
Les 6 tests rouges sont des failles volontairement laissees rouges (pas de skip/xfail).

## Boucle 2 (apres correctifs backend-dev) — resultat courant

**Resultat : 16 failed, 486 passed, 328 deselected in 214.40s** (couverture 92,84 %).
- F1-ADV-2 (erreurs non bornees) : **corrige**, contournements echoues (voir plus bas).
- F1-ADV-1 (Cf / bidi) : correctif valide pour Cf (les 4 tests d'origine sont verts), mais **contourne** -> F1-ADV-3.

### F1-ADV-3 — caracteres « vides » non Cf : contournement de has_forbidden_chars / has_visible_char (Moyenne)

Reproduction (loueur, `POST /api/contracts`, toutes -> **201**) :

```
"vehicle_label": "ㅤㅤ"      (HANGUL FILLER, categorie Lo -> compte comme lettre « visible »)
"vehicle_label": "ᅟᅠ"      (fillers Hangul choseong/jungseong, Lo)
"vehicle_label": "ﾠ"            (halfwidth Hangul filler, Lo)
"vehicle_label": "⠀⠀"      (BRAILLE PATTERN BLANK, So -> compte comme symbole)
"vehicle_label": "ㅤ️"      (filler + selecteur de variation)
memes valeurs dans "vehicle_plate"   -> 201
"vehicle_plate": "AB︀-123-CD"   (selecteur de variation, Mn)      s'affiche AB-123-CD
"vehicle_plate": "AB-123-CD\U000e0100" (selecteur supplementaire, Mn)
"vehicle_plate": "AB͏-123-CD"   (COMBINING GRAPHEME JOINER, Mn)
"vehicle_plate": "AB឴-123-CD"   (KHMER VOWEL INHERENT AQ, Mn)
"vehicle_plate": "AB-123-CDㅤ"   /  "AB⠀-123-CD"
```

Cause : le filtre raisonne par categorie generale. Ces caracteres sont `Lo`, `So` ou `Mn`, donc ni rejetes
(seuls Cc/Cs/Cf le sont) ni consideres invisibles (`has_visible_char` accepte L/N/S/P). Ils ont pourtant la
propriete Unicode `Default_Ignorable_Code_Point` (sauf U+2800) et s'affichent vides.
Impact : meme classe que F1-ADV-1 — libelle vide en apparence, et surtout plaque signee qui s'affiche
« AB-123-CD » mais dont la valeur stockee differe (deux contrats « identiques » a l'ecran, recherche/
rapprochement par plaque casse).
Correctif suggere :
1. Rejeter les `Default_Ignorable_Code_Point` (liste DerivedCoreProperties : U+034F, U+115F-1160,
   U+17B4-17B5, U+180B-180F, U+200B-200F, U+202A-202E, U+2060-206F, U+3164, U+FE00-FE0F, U+FEFF,
   U+FFA0, U+1BCA0-1BCA3, U+1D173-1D17A, U+E0000-E0FFF) + U+2800 explicitement, dans libelle, plaque, reason.
2. Plaque : `unicodedata.normalize("NFKC", v).upper()` puis liste blanche `^[A-Z0-9 -]{1,16}$` avec au
   moins un caractere alphanumerique — regle aussi homoglyphes, pleine chasse et ponctuation seule.
3. `has_visible_char` : exiger au moins un caractere L/N qui n'est pas default-ignorable.

Tests rouges : `test_round2_blank_looking_letters_or_symbols_are_refused[*]` (10),
`test_round2_invisible_chars_hidden_inside_plate_are_refused[*]` (6).

### Contournements tentes sans succes (OK)

| Attaque | Resultat |
|---------|----------|
| Espaces Zs seuls (U+00A0, U+2000-200A, U+3000), marques combinantes seules, selecteurs seuls, tags U+E0041, soft hyphen, U+180E | 422 |
| Cf a l'interieur de la plaque (U+00AD, tag, U+2063, U+061C ALM) | 422 |
| Cf / filler dans `client_email` | 422 |
| `deposit_cents` invalide + 6 autres erreurs + 40 cles « deposit_cents_N » + cle XSS de 5 000 car. | 422 INVALID_AMOUNT, 20 erreurs max, `truncated: true`, `deposit_cents` liste, aucun nom de cle recopie, < 8 Ko |
| 30 cles en trop nommees `deposit_cents0..29` | VALIDATION_ERROR (pas de faux INVALID_AMOUNT), noms remplaces par « (champ inconnu) » |
| Valeurs imbriquees (dict/listes profondes, cle de 10 000 car.) dans deposit_cents / vehicle_label / start_date / reason + 100 cles en trop | 422 borne (< 8 Ko, champs <= 64 car.), etat inchange |
| reason = 500 points de code pile : e+U+0301 x250, 500 emoji astraux, 500 CJK, `\n\t` x250 | 200 ; 501 -> 422 (comptage en points de code, coherent) |
| reason via paires de surrogates echappees (500) / surrogate orphelin haut, bas, paire inversee | 200 / 422 |

### Observations boucle 2 (pas de test rouge)

- **Homoglyphes et normalisation acceptes** : plaque cyrillique `АВ-123-СD`, pleine chasse `ＡＢ-１２３-ＣＤ`,
  NFD `É-123-CD`, hebreu RTL, `-` ou `.` seuls comme plaque ; libelles `.`, `—`, `Audi RS6`
  (separateur de ligne), usage prive U+E000, non assigne U+0378 : stockes et restitues verbatim, sans 500.
  Le point 2 du correctif F1-ADV-3 les traite pour la plaque.
- **Faux positif d'utilisabilite** : refuser tout `Cf` rejette les emoji ZWJ (famille
  `U+1F468 U+200D U+1F469 U+200D U+1F467` -> 422 dans `reason`), les drapeaux a tags et le ZWNJ
  indispensable au persan/indien. Acceptable pour plaque/libelle ; pour `reason`, autoriser U+200C/U+200D
  entre deux caracteres non ignorables serait plus juste.

## Boucle 1 — failles initiales

| # | Attaque | Resultat | Gravite | Tests rouges |
|---|---------|----------|---------|--------------|
| F1-ADV-1 | Texte invisible ou bidi dans les champs signes (`vehicle_label`, `vehicle_plate`) | **FAILLE** : 201 (corrige boucle 2 pour Cf, contourne -> F1-ADV-3) | Moyenne | `test_invisible_or_bidi_only_texts_are_refused[*]` (4) |
| F1-ADV-2 | Amplification / reflexion dans `details.errors` des 422 | **FAILLE** : corps non borne (corrige boucle 2, tests verts) | Faible | `test_many_extra_fields_do_not_produce_unbounded_error_payload`, `test_giant_unknown_key_name_is_not_reflected_in_error` |

### F1-ADV-1 — libelle/plaque invisibles ou reordonnes (Trojan Source)

Reproduction (loueur authentifie, `Idempotency-Key` quelconque) :

```
POST /api/contracts  {..., "vehicle_label": "​​"}            -> 201, label "​​"
POST /api/contracts  {..., "vehicle_label": "⁠﻿"}            -> 201
POST /api/contracts  {..., "vehicle_plate": "‮DC-321-BA"}          -> 201 (s'affiche "AB-123-CD")
POST /api/contracts  {..., "vehicle_label": "Audi RS6 ⁦‮0003 x⁩"} -> 201
```

Cause : `has_forbidden_chars` (`app/schemas/parsing.py`) ne refuse que les categories `Cc`/`Cs` ; les
caracteres de format `Cf` (zero-width, BOM, word joiner, overrides/isolates bidi U+202A-202E, U+2066-2069)
passent. Le strip Pydantic et le `CHECK length(btrim(...)) > 0` ne les retirent pas.
Impact : un contrat que le client signe peut afficher une plaque differente de celle stockee
(le loueur fait signer « AB-123-CD » alors que la valeur est « ‮DC-321-BA »), ou un libelle vide
en apparence, contrairement au plan (« non vide »). Sur un sequestre ou la signature engage la caution,
c'est une alteration de ce qui est reellement signe.
Correctif : refuser aussi la categorie `Cf` (au minimum U+200B-U+200F, U+202A-U+202E, U+2060-U+2069,
U+FEFF) dans `vehicle_label`, `vehicle_plate` (et `reason`) ; pour la plaque, imposer une liste blanche
`^[A-Z0-9 -]{1,16}$` apres normalisation NFKC + majuscules ; exiger au moins un caractere de categorie
L/N dans le libelle.

### F1-ADV-2 — erreurs de validation non bornees

Reproduction :

```
POST /api/contracts  VALID_BODY + {"k0":0, ..., "k19999":0}   (~240 Ko)  -> 422 avec 20 000 entrees dans details.errors (> 1 Mo)
POST /api/contracts  VALID_BODY + {"<script>alert(1)</script>KKK...(1 Mo)": 1} -> 422 de 1 048 748 octets, cle reflechie telle quelle
```

Cause : `validate_model` recopie toutes les erreurs Pydantic, y compris le nom de la cle inconnue (`loc`).
Impact : amplification ~5x du trafic sortant et CPU de serialisation par requete (DoS bon marche),
reflexion de contenu arbitraire (non exploitable en XSS grace a `application/json` + `nosniff`, mais
inutile et risquee si un client affiche `details`).
Correctif : tronquer la liste (ex. 20 premieres erreurs + `"truncated": true`), tronquer chaque `field`
(ex. 64 caracteres) ou, pour `extra_forbidden`, ne pas renvoyer le nom de la cle ; option : limiter le
nombre de cles du corps avant validation.

## Attaques repoussees (OK)

| Zone | Attaques | Resultat |
|------|----------|----------|
| Montants | -1, 0, -0, 0.5, 1.0, 2500000.0, 1e2, "100", "", "NaN", 1e309, -1e309, 2**63, -2**63, 2**64, 5000 chiffres, true, false, null, absent, 50 000 001, NaN/Infinity litteraux, [..], {..}, 0x10, 02500000, +2500000 | OK : 422 INVALID_AMOUNT / VALIDATION_ERROR, aucune ligne ecrite ; 50 000 000 accepte en entier exact |
| Devise | XXX, eur, "EUR ", EURO, €, "", null, 978, ["EUR"], BTC, NUL | OK : 422 |
| Usurpation | client qui cree (meme avec `owner_id`), client qui signe deux fois avec en-tetes/corps « as owner » | OK : 403 FORBIDDEN_ACTOR / 409, signature loueur toujours nulle |
| IDOR | tiers client, autre loueur, admin sur GET, /events, /sign, /cancel ; formes alias de l'UUID (majuscules, accolades, urn:uuid:, sans tirets, chiffres arabes) ; rejeu de la cle d'idempotence de la victime | OK : 404 octet pour octet identique a un UUID inexistant (corps + en-tetes), etat inchange |
| Auth | vide, `Bearer`, `Bearer `, sans schema, double schema, Basic, Token, virgule, deux jetons, hash SHA-256 vole, prefixe/suffixe, casse inversee, null/undefined, SQL, `%`, latin-1, DEL, 20 000 car., 257 car. ; fuzz hypothesis | OK : 401 sur toutes les routes, jeton jamais renvoye |
| Flux | double signature (x3), signature unique, signer/annuler apres annulation (6 chemins), signer en AWAITING_DEPOSIT, rejeu sans cle, rejeu d'une vieille cle apres annulation, rejeu de la cle de creation apres annulation | OK : 409 INVALID_TRANSITION, statut/version/evenements inchanges, chaine d'evenements coherente |
| Methodes | PATCH/PUT/DELETE sur contrat, /sign, /cancel, /events, collection (avec et sans jeton) ; `X-HTTP-Method-Override` | OK : 405 JSON + `Allow`, contrat inchange ; override ignore |
| Mass assignment | status, version, owner_id, client_id, id, *_signed_at, signatures, created_at, role, deposit dans le corps de creation ; query string ; corps de /sign ; champs en trop dans /cancel | OK : 422 (extra forbid) ou ignore sans effet |
| Entrees | JSON vide/tronque/garbage/double objet/commentaires/quotes simples/virgule finale/null/[]/scalaires/UTF-8 invalide/imbrication 200 000/XML/formulaire/NUL ; Content-Type mensonger (text/plain, form, multipart, html, xml, vide, jsonp...) ; charset menteur, UTF-16, BOM ; > 10 Mo (413 JSON sur create/cancel) ; chaines de 1 Mo non renvoyees ; injection SQL dans label/plaque/motif/e-mail/cle | OK : 422/413, aucune ecriture, SQL stocke verbatim, LIKE (`%`, `_`) sans effet |
| Unicode | NUL, BEL, ANSI, CR/LF, NEL interne, surrogates isoles, espaces Unicode seuls ; emoji/arabe/chinois/combinants aller-retour exact ; 120 vs 121 emoji | OK |
| Dates | an 0, an 10000, 29/02 non bissextile, 30/02, mois 13, jour 0, datetime, fuseau, semaine ISO, compact, sans zero, chiffres arabes/pleine chasse, espaces, NUL, negatif, egales, inversees, types non chaine | OK : 422 ; an 1, an 9999, 29/02/2028 : 201 et aller-retour exact |
| Idempotency-Key | vide, espace, 256, 10 Ko, latin-1, €, tab, DEL sur create/sign/cancel ; 255 car., SQL, `%_%` ; reutilisation create->sign, sign->cancel, entre contrats, motif different, entre parties, par un tiers | OK : 422 / 409 IDEMPOTENCY_CONFLICT / rejeu identique ; portee (cle, utilisateur) respectee |
| Concurrence | 6 rejeux simultanes de la meme cle (sign, create) ; meme cle corps differents ; meme cle sur 2 contrats ; double annulation ; tempete 10 threads sign/cancel (avec et sans pre-signature) ; signatures/annulation avec cles | OK : une seule transition par cle, version == nb d'evenements, chaine from/to continue, un seul `cancel` |
| Fuites | jeton, hash de jeton, e-mails absents des reponses ; valeurs soumises non renvoyees ; message identique pour e-mail inconnu / admin / autre loueur / soi-meme ; `nosniff` + JSON sur les erreurs | OK |
| Fuzz | hypothesis (120 exemples x 4) : champ unique, corps entier, corps d'annulation, en-tetes Authorization/Idempotency-Key | OK : jamais de 500, contrats crees toujours dans les invariants |

## Observations (non bloquantes, pas de test rouge)

- **Dates passees / durees extremes acceptees** : `0001-01-01 -> 9999-12-31` donne 201. Le plan ne l'interdit
  pas ; a trancher par l'architecte (ex. `start_date >= aujourd'hui - 1 j`, duree max).
- **Priorite du code d'erreur** : un corps `{"x": ...}` (montant absent + champ inconnu) renvoie
  `INVALID_AMOUNT` ; tolere par le plan (« absent »), mais `VALIDATION_ERROR` serait plus juste quand
  d'autres champs sont en faute.
- **405 avant 401** : PATCH/PUT/DELETE sans jeton renvoient 405 (le `before_request` du blueprint ne
  tourne pas si le routage echoue). Divulgue seulement l'existence des methodes.
- **Verrou pris avant le controle d'acces** : `_load_for_party(lock=True)` pose `FOR UPDATE` avant de
  verifier la partie ; un tiers connaissant un UUID peut brievement bloquer la ligne. Risque negligeable
  (UUIDv4), mais verifier la partie sans verrou puis verrouiller serait plus propre.
- **Corps ignore sur /sign** : un corps arbitraire (y compris > 10 Mo) est accepte sans lecture. Sans
  impact sur l'etat.
- **Timing de l'authentification** : non pertinent (SHA-256 du jeton + recherche indexee, aucune
  comparaison de secret cote Python).

---

# F2 — depot / blocage de caution / annulation mutuelle (boucle 1)

Tests : `tests/adversarial/test_f2_deposit.py` — **1 failed, 89 passed**.

### F2-ADV-1 — cle d'idempotence partagee entre deux clients => 500 et blocage partage (Haute)

- **Attaque** : client A depose sur son contrat avec `Idempotency-Key: shared-key-0001` (200). Client B
  depose sur SON contrat avec la meme cle. Test : `test_two_clients_same_key_never_share_a_hold`.
- **Resultat** : FAILLE. 500 `INTERNAL_ERROR` (`UniqueViolation uq_deposits_provider_ref`).
- **Cause** : la table `idempotency_keys` est scopee par utilisateur, mais `deposit_funds` passe la cle
  BRUTE a `provider.hold(...)`. `SimulatedProvider` (et tout vrai prestataire, ex. Stripe : cles par
  compte marchand) renvoie alors la reference du blocage de A pour B. Seule la contrainte UNIQUE evite
  qu'un contrat B soit FUNDED sur l'argent de A (et rembourse ensuite le blocage de A). Consequences :
  500 (interdit), et deni de service sur le depot de B si la cle est previsible / rejouee.
- **Correctif** : deriver la cle prestataire d'un scope serveur, ex.
  `provider_key = sha256(f"{user_id}:{contract_id}:{idempotency_key}")` (ou l'id de la ligne
  d'idempotence) ; en defense en profondeur, mapper `IntegrityError` sur `provider_ref` vers un 409
  propre et ne jamais attacher un `provider_ref` deja lie a un autre contrat. Test de non-regression = ce test.

### Attaques F2 repoussees (OK)

| Zone | Attaques | Resultat |
|------|----------|----------|
| Montants | 1, 0, -2500000, 2**63, -(2**63), "2500000", 2500000.0, true, null, absent, +/-1 centime, liste, objet ; JSON brut 1e309, NaN, Infinity, 2500000e0, 2.5e6, hex, entier de 5000 chiffres, tronque, `[]`, `null`, vide | OK : 422, aucun `hold`, etat complet inchange |
| Devise | CHF/USD sur contrat EUR, `eur`, `EUR `, XXX, "", null, 978 ; EUR sur contrat CHF | OK : 422 VALIDATION_ERROR |
| Champs serveur | card_number, cvv, held/refunded/released_cents, status, deposit_status, provider_ref, contract_id, version | OK : 422 |
| Corps | payment_method inconnu / 1 Mo, sans Idempotency-Key, mauvais Content-Type | OK |
| Acces | loueur depose (403), tiers / UUID inconnu / id non UUID (404 identiques), GET /deposit tiers, sans jeton (401), tiers cancel/start | OK ; `provider_ref` jamais expose |
| Double depot | etats DRAFT/FUNDED/CANCELLED (409), rejeu meme cle, conflit de cle, cle reutilisee sur autre contrat, panne 503 puis reessai, refus 402 puis autre cle, 5 depots concurrents (cles differentes / meme cle) | OK : un seul blocage, une ligne, version 4 |
| Annulation FUNDED | re-cancel meme partie, `{"withdraw": true}`, champs forges, DELETE /cancel (405), depot, start (409 / 403), sign, rejeu meme cle | OK : FUNDED, HELD, 0 refund |
| Remboursement | mutuel puis rejeu / re-cancel / depot / start ; panne prestataire au refund puis reessai | OK : 1 seul refund, ledger equilibre, etat intact apres 503 |
| Courses (threads) | cancel/start, cancel x4 (2 par partie), cancel/cancel/start, deposit/cancel | OK : un seul etat final, refund 0 ou 1 selon l'etat |

Observation (pas de test rouge) : apres un refund prestataire reussi, un echec du `commit` laisserait
le contrat FUNDED/HELD alors que l'argent est rendu ; le reessai rappelle `refund` (idempotent par
contrat d'interface). A couvrir par une reconciliation / outbox en F3.

---

# F3 — etats des lieux (boucle 1, 2026-10-09)

Tests : `tests/adversarial/test_f3_reports.py` — **3 failed, 98 passed** (F3-ADV-2 rouge au 1er passage,
verte au second : le regex `_PDF_FORBIDDEN` de `uploads.py` refuse desormais `/ObjStm`, correctif fait en
parallele).

### F3-ADV-1 — cle publique d'ordre faible : signature universelle acceptee (Haute)

- **Attaque** : le client enregistre `public_key = base64(01 00..00)` (point neutre), puis signe le
  checkout avec `R = 01 00..00, S = 0` (64 octets fixes). Tests : `test_weak_public_key_refused`,
  `test_universal_signature_never_accepted`.
- **Resultat** : FAILLE. Cle acceptee (201), signature acceptee (200). Cette signature verifie pour
  TOUT message : elle ne lie ni le contrat ni l'empreinte. La non-repudiation, raison d'etre du tiers de
  confiance, disparait (le signataire peut nier, la preuve ne vaut rien).
- **Correctif** : dans `decode_public_key`, refuser les 8 encodages de points d'ordre faible (liste
  connue, ex. libsodium `has_small_order`) et les encodages non canoniques ; en defense, refuser aussi
  un `R` d'ordre faible dans `verify_signature` (ou verifier via libsodium/PyNaCl, qui le fait).

### F3-ADV-2 — PDF : JavaScript cache dans un flux d'objets compresse (Moyenne)

- **Attaque** : PDF 1.5 dont le catalogue (`/OpenAction`) et l'action `/S /JavaScript` sont dans un
  `/ObjStm /FlateDecode`. Test : `test_trapped_file_refused_without_side_effect[pdf_objstm_javascript]`.
- **Resultat** : FAILLE au 1er passage (201) ; CORRIGEE depuis (`/ObjStm` refuse). Reste a surveiller :
  un `/JavaScript` dans un flux de contenu compresse ordinaire n'est toujours pas decompresse avant la
  recherche.
- **Correctif** : refuser tout PDF contenant `/ObjStm` ou `/XRef` stream et tout flux filtre hors
  liste blanche, ou decompresser (borne) chaque flux avant la recherche ; plus sur : ne pas accepter le
  PDF (photos seules) ou le re-rasteriser.

### F3-ADV-3 — polyglotte PDF/ZIP stocke tel quel (Basse)

- **Attaque** : archive ZIP inseree avant `xref` d'un PDF sain (`zipfile.is_zipfile` vrai). Test :
  `[pdf_zip_polyglot]`. **Resultat** : FAILLE, 201, octets stockes et servis intacts (impact limite par
  `attachment` + `nosniff`). **Correctif** : refuser les signatures `PK\x03\x04` / `PK\x05\x06` dans
  un PDF, ou lier l'acceptation des PDF au correctif F3-ADV-2 (re-rendu).

### Attaques F3 repoussees (OK)

| Zone | Attaques | Resultat |
|------|----------|----------|
| Fichiers | exe/zip/svg en .jpg/.png, GIF, HEIC, vide, 1 octet, JPEG tronque, PNG<->JPEG<->PDF par extension, `.jpg.exe`, sans extension, PDF /JavaScript /JS /OpenAction /Launch /EmbeddedFile /AA, `/Java#53cript`, chiffre, 25 pages, bombe PNG 20000x20000, 8001 px, 10 Mo+1 et 50 Mo, multipart vide/2 fichiers/mauvais champ/JSON | OK : 415/413/422, etat + disque inchanges |
| Contenu | EXIF, tEXt HTML, polyglotte JPEG/ZIP, Content-Type menteur | OK : re-encodes, type reel retenu |
| Noms | `../../etc/passwd.jpg`, `..\..\`, absolu, 10 000 car., RTLO, injection Content-Disposition, octet nul | OK : UUID dans UPLOAD_DIR, rien hors dossier |
| Signatures | cle de l'autre partie, empreinte client, autre contrat, domaine `return`, revision supersedee, cle revoquee, double (sequentielle et concurrente), DRAFT, base64 malforme x13, bit inverse | OK : 422/409, etat inchange |
| Acteurs | client create/update/finalize/supersede (403), loueur supprime photo client (403), tiers / IDOR (404 identiques), sans jeton (401) | OK |
| Metier | retenue != 0 au depart, retenue > caution, kilometrage qui recule, start sans signature client, rapport SIGNED intouchable | OK |
| Courses | upload x4 vs gel, 2e signature vs supersede, remplacement apres signature client | OK : empreinte = fichiers, aucun orphelin, jamais SIGNED remplace, historique conserve |

# F4 — liberation de la caution (boucle 1, 2026-10-09)

Tests : `tests/adversarial/test_f4_release.py` — **2 failed, 35 passed**.

### F4-ADV-1 — reglement execute mais non confirme, puis revision : prestataire paye, base HELD (Haute)

- **Attaque** : le prestataire execute `settle` puis la reponse se perd (timeout => 503). Le loueur
  remplace alors le retour (`supersede` 201), retenue 0, gel, double signature : la 2e signature renvoie
  503 a chaque essai (meme cle `settle:<deposit_id>`, autres montants => refus du prestataire). Test :
  `test_ambiguous_settle_then_revision_never_diverges_from_provider`.
- **Resultat** : FAILLE. Argent deja ventile chez le prestataire (2 380 000 / 120 000), depot `HELD` en
  base, contrat bloque en INSPECTION_PENDING sans issue : etat incoherent, caution jamais liberable.
- **Correctif** : journaliser la tentative (montants + cle) dans une transaction committee AVANT
  l'appel ; tant qu'une tentative existe, refuser `supersede`/`update` du retour (409) et ne reessayer
  qu'avec les montants journalises ; a defaut, interroger le prestataire (statut de la cle) pour
  reconcilier avant tout nouveau reglement.

### F4-ADV-2 — champ `payload` de l'export d'evenements hors chaine (Basse)

- **Attaque** : dans l'export `/events`, remplacer `payload.report_id/report_hash` de l'evenement de
  liberation ; `verify_receipt --events` accepte. Test : `test_forged_event_exports_rejected_offline`.
- **Resultat** : FAILLE. `payload` (colonne JSON) n'entre ni dans `payload_hash` (calcule sur un autre
  dictionnaire) ni dans `event_hash` : un export retouche reste « verifie » et peut afficher une
  empreinte de rapport mensongere.
- **Correctif** : `payload_hash = sha256(canonique(payload stocke))` et le verifier dans `verify_chain`
  (ou retirer `payload` de l'export) ; dans `verify_receipt`, exiger
  `events[-1].payload.report_hash == return_report.hash`.

### Attaques F4 repoussees (OK)

| Zone | Attaques | Resultat |
|------|----------|----------|
| Rejeu | signature du depart (hash/kind croises), autre contrat, revision supersedee, client qui resigne | OK : 422 SIGNATURE_INVALID / 409, rien ne change |
| Retenue | loueur qui passe la retenue a 100 % apres signature client ; injection `retained_cents`, `release_cents`, `claimed_retention_cents`, `report_hash`, `deposit_cents`, `party` | OK : nouvelle signature client exigee ; 422, retenue figee seule appliquee |
| Concurrence | 4x meme cle, 5x cles differentes, 2+2 premieres signatures simultanees, panne + 6 reessais paralleles, 3 pannes + reessais meme cle | OK : un seul settle reussi, une quittance, rendu + retenu = caution |
| Terminal | cancel x2, deposit, start, sign, supersede retour/depart, finalize, update, create, resignature, upload (RELEASED et SETTLED) | OK : 409, etat, quittance et prestataire inchanges |
| Preuve | 1 centime (avec/sans hash), empreinte, ordre des signatures, cle client remplacee, signature/contenu d'une autre quittance, mauvaise cle serveur ; export supprime/reordonne/acteur/statut/autre contrat/vide, CLI | OK : ReceiptInvalid / code 1 |
| Acces | /receipt tiers, sans jeton, UUID fantome, avant liberation ; /api/server-key POST/PUT/DELETE ; `SERVER_SIGNING_KEY` dans `app.config` | OK : 404/401/405, aucune fuite de la graine |
| Chaine | 6 depots en panne + 2 valides en parallele | OK : seq 1..n, chaine lineaire, un seul FUNDED |
