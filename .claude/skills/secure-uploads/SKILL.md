---
name: secure-uploads
description: Comment accepter, valider et stocker les photos/PDF de l'etat des lieux sans se faire pieger (magic bytes, re-encodage, limites de taille, noms de fichiers). A utiliser pour tout code ou test touchant un upload.
---

# Uploads securises (etat des lieux)

## Pipeline obligatoire (`app/security/uploads.py`)

1. **Taille** : `MAX_CONTENT_LENGTH = 10 Mo` dans la config Flask (=> 413 avant meme la route) + verification par fichier ; fichier vide => 415.
2. **Type reel par magic bytes**, jamais par extension ni par `Content-Type` :
   - JPEG `FF D8 FF`, PNG `89 50 4E 47 0D 0A 1A 0A`, PDF `25 50 44 46 2D` (`%PDF-`).
   - Tout le reste (SVG, HEIC, GIF, exe, zip...) => `UNSUPPORTED_FILE` (415).
   - L'extension declaree doit etre coherente avec le type detecte, sinon 415.
3. **Images** : ouvrir avec Pillow, `Image.MAX_IMAGE_PIXELS` borne (anti decompression bomb), `verify()`, puis **re-encoder** (supprime EXIF, polyglottes, payloads caches). Limite de dimensions (ex. 8000x8000).
4. **PDF** : refuser si contient `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFile`, `/OpenAction` ; limite de pages.
5. **Nom** : ignorer le nom client. Stocker sous `<uuid4>.<ext_detectee>` dans `UPLOAD_DIR` (hors de `app/static`). Le nom d'origine n'est garde qu'en metadonnee, nettoye et tronque.
6. **Integrite** : calculer le SHA-256 des octets stockes ; c'est ce hash qui entre dans le rapport signe.
7. Servir les fichiers via une route authentifiee avec `Content-Disposition: attachment` et `X-Content-Type-Options: nosniff`.

## Tests minimum (fixtures dans `tests/fixtures/files/`, generees par code, pas de vrais malwares)

- JPEG/PNG/PDF valides acceptes.
- `.exe` (en-tete `MZ`) renomme `.jpg` => 415.
- PNG avec extension `.pdf` => 415.
- SVG avec `<script>` => 415.
- PDF contenant `/JavaScript` => 415.
- Fichier vide, fichier de 1 octet => 415.
- Fichier > 10 Mo => 413.
- Nom `../../etc/passwd.jpg` => accepte mais stocke sous un UUID, rien ecrit hors `UPLOAD_DIR`.
- Image 20000x20000 => refusee sans exploser la memoire.
