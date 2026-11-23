# L'API HTTP

Ce document décrit les points de terminaison **tels qu'implémentés**. `/api/v1`
est stable, décrit par un document OpenAPI 3.1 engendré depuis la table des
routes de l'instance, et c'est ce qu'utilisent l'interface et `peek-cli`.

Tous les corps sont du JSON. Toutes les chaînes d'octets sont en **base64url,
sans remplissage**. Tout ce qui est sous `/api/v1` est servi avec
`Cache-Control: no-store`.

## Où un point de terminaison est servi

| Point de terminaison | Écoute publique | Écoute interne |
|---|---|---|
| `GET /healthz`, `GET /readyz` | oui | oui |
| `GET /api/v1/branding`, `GET /branding.css` | oui | oui |
| `GET /api/v1/ip` | oui | oui |
| `GET /api/v1/secrets/{id}` | oui | oui |
| `POST /api/v1/secrets/{id}/reveal` | oui | oui |
| `DELETE /api/v1/secrets/{id}` | oui | oui |
| `GET /api/v1/files/{id}` | oui | oui |
| `GET /api/v1/requests/{id}` | oui | oui |
| `POST /api/v1/requests/{id}/open` | oui | oui |
| `POST /api/v1/requests/{id}/deposit` | oui | oui |
| `POST /api/v1/secrets` | **non** | oui |
| `POST /api/v1/files` | **non** | oui |
| `POST /api/v1/requests` | **non** | oui |
| `GET /api/v1/secrets/{id}/receipt` | **non** | oui |
| `POST /api/v1/secrets/{id}/burn` | **non** | oui |
| `POST /api/v1/requests/{id}/receipt`, `DELETE /api/v1/requests/{id}` | **non** | oui |
| `GET /api/v1/policy`, `/api/v1/audit`, `/api/v1/instance` | **non** | oui |

L'envoi de fichiers est derrière le filtre de création, pas celui de lecture :
une instance qui ne vous laisse pas créer un secret n'est pas non plus un endroit
où déposer cent mégaoctets. Le téléchargement regarde le destinataire, mais
demande une autorisation que seule une révélation réussie délivre.

« Écoute publique » veut dire celle configurée comme `server.public_listen`.
Avec une seule écoute, tout y est servi, et c'est
`security.admin_allowed_cidrs` qui restreint la surface d'administration.

## Les erreurs

```json
{ "error": { "code": "policy", "message": "views: 50 views requested, the limit is 10", "field": "views" } }
```

| Statut | Code | Ce que ça veut dire |
|---|---|---|
| 400 | `bad_request` | Corps malformé, champ inconnu, mauvais base64 |
| 403 | `bad_token` | Mauvais jeton de lecture ou mauvaise passphrase ; porte `attempts_left` |
| 403 | `creation_disabled` | `security.anonymous_create` est à false |
| 404 | `not_found` | Inconnu, expiré, consommé ou détruit — volontairement indiscernables |
| 409 | `conflict` | Identifiant déjà utilisé |
| 410 | `locked` | Trop d'essais ratés ; le secret a été détruit |
| 422 | `policy` | Refusé par la politique de l'instance ; `field` nomme le réglage |
| 429 | `rate_limited` | Seau à jetons épuisé ; voir `Retry-After` |
| 411 | `length_required` | Un envoi est arrivé sans `Content-Length` |
| 413 | `too_large` | Fichier au-delà de `policy.max_file_bytes` |
| 410 | `closed` | Une demande de secret a eu toutes les réponses qu'elle accepte |
| 503 | `no_storage` | Aucun stockage de fichiers configuré sur cette instance |
| 401 | `bad_api_token` | Jeton d'API inconnu, révoqué ou expiré |
| 403 | `missing_scope` | Le jeton ne porte pas la portée dont cet appel a besoin |
| 403 | `session_required` | L'appel demande une session, pas un jeton |

## S'authentifier depuis un script

Deux entrées. L'interface utilise un cookie de session plus un en-tête CSRF en
double soumission ; un script utilise un **jeton porteur** :

```http
Authorization: Bearer peek_<id>.<secret>
```

Le préfixe `peek_` est là pour que les scanners de secrets en reconnaissent un à
vue. Un jeton n'envoie aucun cookie, aucun en-tête CSRF n'est donc nécessaire ni
souhaitable.

Un jeton appartient à un utilisateur et **ne peut jamais dépasser le rôle de cet
utilisateur** — il le restreint. Par-dessus le rôle, il porte des portées :

| Portée | Ce qu'elle ouvre |
|---|---|
| `secrets:write` | `POST /secrets`, `POST /files`, `POST /requests` |
| `secrets:manage` | les accusés, `burn`, `email`, les accusés de demande, la fermeture d'une demande |
| `audit:read` | `GET /audit`, `GET /audit/export` |
| `instance:read` | `GET /instance` |

Tout le reste est fermé à un jeton, quelles que soient ses portées : changer un
mot de passe, lister les sessions, gérer les utilisateurs, modifier la marque —
et créer un autre jeton. Une chaîne qui fuit ne doit pas devenir une usine à
clés.

| Statut | Code | Ce que ça veut dire |
|---|---|---|
| 401 | `bad_api_token` | Inconnu, révoqué ou expiré — une seule réponse pour les trois |
| 403 | `missing_scope` | Jeton valide, mais pas pour cet appel |
| 403 | `session_required` | Cet appel demande une personne connectée |

### Gérer les jetons

Depuis la page du compte, ou depuis le shell sur le serveur :

```bash
sudo peek token create --email ops@acme.com --name "CI" --scopes secrets:write --ttl 90d
sudo peek token list --all
sudo peek token revoke --id <id>
```

En HTTP (session seulement, jamais avec un jeton) :

```http
GET    /api/v1/auth/tokens
POST   /api/v1/auth/tokens      { "name": "CI", "scopes": ["secrets:write"], "ttl_seconds": 7776000 }
DELETE /api/v1/auth/tokens/{id}
```

La réponse à la création est le **seul** endroit où le texte clair apparaît
jamais ; la base en garde le SHA-256. Révoquer est un horodatage, pas une
suppression, pour qu'une entrée d'audit qui nomme un jeton reste lisible. Un
administrateur peut révoquer le jeton de n'importe qui — un collègue part, ses
scripts s'arrêtent.

```bash
TOKEN=peek_...
curl -sS -H "Authorization: Bearer $TOKEN" https://secrets.acme.com/api/v1/policy
```

## Santé

```http
GET /healthz   →  200  "ok"
GET /readyz    →  200  {"ready":true,"checks":[{"name":"database","ok":true}]}
               →  503  quand un contrôle échoue
```

Pointez votre répartiteur sur `/readyz`.

## Diagnostic

```http
GET /api/v1/ip
```

```json
{ "client_ip": "203.0.113.5", "peer_addr": "10.0.0.10:52118",
  "scheme": "https", "host": "secrets.acme.com",
  "listener": "public", "trusted_peer": true }
```

C'est le moyen le plus rapide de savoir si la configuration de votre proxy
fonctionne.

## La marque

```http
GET /api/v1/branding        → le thème en JSON, avec un ETag
GET /branding.css           → le même thème en propriétés CSS personnalisées
```

Les deux supportent `If-None-Match` et répondent 304.

## La politique

```http
GET /api/v1/policy
```

Retourne les limites que l'interface doit respecter : TTL et lectures maximum,
si une passphrase est obligatoire, les types autorisés, les limites de taille et
les paramètres de KDF à utiliser. Écoute interne seulement.

## Créer un secret

```http
POST /api/v1/secrets
Content-Type: application/json
```

```json
{
  "id": "4C8Wft7uBQb8G-tWya6P2g",
  "kind": "text",
  "ciphertext": "<base64url(nonce || AES-256-GCM)>",
  "read_token_hash": "<base64url(SHA-256(jeton de lecture))>",
  "receipt_token_hash": "<base64url(SHA-256(jeton d'accusé))>",
  "kdf": { "salt": "<base64url(16 o)>", "memory_kib": 19456, "iterations": 2, "parallelism": 1 },
  "has_passphrase": false,
  "ttl_seconds": 86400,
  "views": 1,
  "retrieval_step": true,
  "deletable_by_recipient": false
}
```

L'identifiant, la clé, le sel et les deux jetons sont engendrés par le client.
Le serveur ne voit ni clé ni passphrase. La réponse :

```json
{ "id": "4C8Wft7uBQb8G-tWya6P2g", "kind": "text", "views_max": 1,
  "expires_at": "2026-11-21T14:43:45Z", "created_at": "2026-11-20T14:43:45Z",
  "url": "https://secrets.acme.com/s/4C8Wft7uBQb8G-tWya6P2g" }
```

Le lien dont le destinataire a besoin est `url` plus
`#v1.<base64url(clé de contenu)>`, assemblé par le client.

## Lire les métadonnées

```http
GET /api/v1/secrets/{id}
```

```json
{ "id": "…", "kind": "text", "has_passphrase": true, "retrieval_step": true,
  "deletable_by_recipient": false, "views_remaining": 1, "views_max": 1,
  "expires_at": "2026-11-21T14:43:45Z", "size_bytes": 108, "attempts_left": 5,
  "kdf": { "salt": "…", "memory_kib": 19456, "iterations": 2, "parallelism": 1 } }
```

**Aucune lecture n'est consommée.** C'est ce qui rend les robots d'aperçu de
lien inoffensifs.

## Révéler

```http
POST /api/v1/secrets/{id}/reveal
{ "read_token": "<base64url(32 o)>" }
```

```json
{ "kind": "text", "ciphertext": "…", "views_remaining": 0,
  "destroyed": true, "size_bytes": 108 }
```

Un mauvais jeton répond 403 avec `attempts_left` et ne consomme aucune lecture.
Une fois le budget épuisé, le secret est détruit et la réponse devient 410.

## Suppression par le destinataire

```http
DELETE /api/v1/secrets/{id}
X-Peek-Token: <base64url(jeton de lecture)>
```

`204` en cas de succès, `404` quand l'expéditeur ne l'a pas autorisé. Le jeton
peut aussi être envoyé dans un corps JSON sous `read_token` ; l'en-tête le garde
en dehors de tout journal de proxy.

## L'accusé de l'expéditeur

```http
GET  /api/v1/secrets/{id}/receipt
POST /api/v1/secrets/{id}/burn
X-Peek-Token: <base64url(jeton d'accusé)>
```

```json
{ "id": "…", "status": "active", "kind": "text", "views_used": 0, "views_max": 1,
  "views_remaining": 1, "created_at": "…", "expires_at": "…",
  "last_viewed_at": null, "has_passphrase": true, "url": "…" }
```

`status` vaut `active`, `viewed`, `expired`, `burned`, `deleted` ou `locked`. Il
continue de répondre après la disparition du secret, depuis la pierre tombale.
`burn` répond `204`.

## Les pièces jointes

Un fichier est chiffré dans le navigateur **avant** d'être envoyé, par morceaux,
avec le format décrit dans [CRYPTO.md](CRYPTO.md#6-les-fichiers). Le serveur
stocke un flux opaque et sa longueur ; le nom, le type MIME et la clé par
fichier vivent à l'intérieur de la charge utile scellée du secret de chaque
destinataire.

### Envoyer

```http
POST /api/v1/files
Content-Type: application/octet-stream
Content-Length: 1048625
X-Peek-CSRF: <le cookie peek_csrf>

<le flux chiffré, en-tête compris>
```

`Content-Length` est obligatoire : le stockage écrit exactement ce nombre
d'octets, et S3 a besoin de la longueur pour signer un `PUT` non découpé. Un
corps plus court ou plus long qu'annoncé est refusé et rien n'est gardé.

```json
{ "id": "mKQ7s1eWQmSb9dJ0vV0kHg",
  "token": "<base64url(32 o)>",
  "size": 1048625,
  "expires_at": "2026-11-20T16:43:45Z" }
```

`token` est le **jeton de réclamation**. Il est délivré une fois et stocké
haché : c'est ce qui prouve, au moment de la création, que vous êtes celui qui a
envoyé ce blob. Sans lui, quiconque devinerait un identifiant pourrait attacher
l'envoi de quelqu'un d'autre à son propre secret.

Un blob envoyé qu'aucun secret ne réclame avant `expires_at`
(`policy.upload_window`, deux heures par défaut) est ramassé par la purge.

### Attacher

Ajoutez `files` à la requête de création :

```json
{ "id": "…", "kind": "file", "ciphertext": "…",
  "files": [ { "id": "mKQ7s1eWQmSb9dJ0vV0kHg", "token": "<jeton de réclamation>" } ] }
```

Les blobs deviennent injoignables quand chaque secret qui les référence a
disparu et qu'aucune autorisation de téléchargement n'est en cours — ils
disparaissent donc vraiment à la dernière lecture ou quand l'expéditeur détruit
le secret, et pas seulement à l'expiration d'origine.

### Télécharger

Une révélation réussie d'un secret qui a des pièces jointes retourne deux
champs de plus :

```json
{ "kind": "file", "ciphertext": "…", "destroyed": true,
  "download_token": "<base64url(32 o)>",
  "download_expires_at": "2026-11-20T15:13:45Z" }
```

Cette autorisation est le seul moyen d'aller chercher les blobs, et elle existe
parce que la ligne du secret est déjà supprimée au moment où un secret à une
lecture est révélé : sans elle, une pièce jointe de 100 Mio deviendrait illisible
à l'instant où elle devient lisible. Elle dure `policy.download_window` (trente
minutes par défaut).

```http
GET /api/v1/files/{id}
X-Peek-Download: <base64url(autorisation)>
```

```http
200 OK
Content-Type: application/octet-stream
Content-Length: 1048625
```

L'autorisation voyage dans un en-tête, jamais dans une chaîne de requête : les
proxys journalisent les URL, et une autorisation dans le journal d'accès de
quelqu'un est un secret lisible. Une autorisation manquante, une expirée, ou une
émise pour un autre lot répondent toutes `404` — un destinataire ne doit pas
pouvoir sonder laquelle c'était.

## Plusieurs destinataires

Un secret, plusieurs liens, chacun avec sa clé, son expiration, ses lectures, sa
passphrase et son journal d'audit — et **un** seul envoi des pièces jointes,
partagé entre eux.

```http
POST /api/v1/secrets
```

```json
{
  "recipients": [
    { "id": "…", "kind": "file", "ciphertext": "…", "read_token_hash": "…",
      "receipt_token_hash": "…", "kdf": { … }, "ttl_seconds": 86400, "views": 1 },
    { "id": "…", "kind": "file", "ciphertext": "…", "read_token_hash": "…",
      "receipt_token_hash": "…", "kdf": { … }, "ttl_seconds": 3600, "views": 3 }
  ],
  "files": [ { "id": "…", "token": "…" } ]
}
```

Chaque entrée est exactement le corps d'un secret unique. Envoyer les deux
formes à la fois — des champs à la racine *et* `recipients` — répond `400` : on
ne saurait pas quels réglages s'appliquent. La limite est
`policy.max_recipients` (dix par défaut).

```json
{ "bundle_id": "<l'identifiant du premier lien>",
  "secrets": [ { "id": "…", "url": "…", … }, { "id": "…", "url": "…", … } ] }
```

La création est tout ou rien : un lot créé à moitié donnerait à un destinataire
un lien dont les pièces jointes n'ont jamais été attachées.

## Les demandes de secret

« Envoie-moi le mot de passe du compte X. » Le sens est inversé : celui qui
demande doit être le seul à pouvoir lire, et celui qui répond ne doit pas pouvoir
relire ce qu'il a déposé.

Le navigateur du demandeur engendre une paire de clés P-256. La moitié publique
est stockée ici pour qu'une réponse puisse lui être scellée ; la moitié privée ne
quitte jamais le fragment du lien de suivi du demandeur. Une **clé de demande**
symétrique, portée dans le lien de dépôt, scelle l'intitulé et prouve la
possession — elle joue exactement le rôle qu'une clé de contenu joue pour un
secret.

Le lien de dépôt est `/q/{id}#v1q.<base64url(clé de demande || clé publique)>`,
et le lien de suivi est
`/qs/{id}#v1r.<base64url(privée || publique)>~<clé de demande>~<jeton d'accusé>`.
**La clé publique est dans le lien, pas récupérée depuis cette API**, et c'est
exprès : un serveur qui servirait sa propre clé publique à la place pourrait lire
chaque réponse, et un navigateur qui ne la prend jamais que dans le fragment ne
peut pas être trompé comme ça.

### Créer une demande

```http
POST /api/v1/requests
```

```json
{ "id": "…", "public_key": "<base64url(65 o, SEC1 P-256 non compressé)>",
  "read_token_hash": "…", "receipt_token_hash": "…",
  "prompt_enc": "<base64url(nonce || AES-256-GCM)>",
  "kdf": { "salt": "…", "memory_kib": 19456, "iterations": 2, "parallelism": 1 },
  "ttl_seconds": 86400, "max_deposits": 1, "notify_email": "moi@acme.com" }
```

Une `public_key` qui n'est pas un point de P-256 est refusée avec `422` : un
point invalide serait une attaque sur l'échange de clés du déposant lui-même.

```json
{ "id": "…", "max_deposits": 1, "expires_at": "…", "created_at": "…",
  "url": "https://secrets.acme.com/q/…" }
```

### Y répondre

```http
GET  /api/v1/requests/{id}        → { "id", "deposits_remaining", "expires_at", "kdf" }
POST /api/v1/requests/{id}/open   → { "id", "prompt_enc", "expires_at" }
```

`open` prend `{ "read_token": "…" }`, dérivé de la clé de demande qui est dans le
lien, et relâche l'intitulé. Il ne consomme rien : l'intitulé n'est pas la
réponse, et un déposant peut très bien recharger la page avant d'être prêt.

```http
POST /api/v1/requests/{id}/deposit
```

```json
{ "read_token": "…",
  "wrapped_key": "<base64url(125 o : publique éphémère || nonce || clé de contenu scellée)>",
  "secret": { "id": "…", "kind": "text", "ciphertext": "…", … },
  "files": [ { "id": "…", "token": "…" } ] }
```

`secret` est un corps de création ordinaire : un dépôt *est* un secret, et c'est
pour ça qu'il hérite gratuitement de tout le cycle de vie — lectures,
expiration, purge, audit. Ce qui en fait un dépôt, c'est `wrapped_key` : la clé
de contenu scellée vers la clé publique du demandeur avec ECIES (ECDH éphémère,
HKDF-SHA256, AES-256-GCM).

Le compteur et le secret bougent ensemble dans une seule transaction : une
demande à usage unique accepte donc exactement une réponse, même avec plusieurs
nœuds. Elle répond `410` (`closed`) une fois pleine.

### Suivre une demande

```http
POST /api/v1/requests/{id}/receipt
{ "receipt_token": "…" }
```

```json
{ "id": "…", "max_deposits": 1, "deposits_used": 1, "deposits_remaining": 0,
  "created_at": "…", "expires_at": "…",
  "deposits": [ { "secret_id": "…", "wrapped_key": "…", "kdf": { … },
                  "has_passphrase": false, "size_bytes": 108,
                  "created_at": "…", "views_remaining": 1 } ] }
```

Le demandeur déballe chaque `wrapped_key` avec la clé privée venue de son propre
fragment, dérive le jeton de lecture depuis la clé de contenu, et lit le dépôt
par le `POST /api/v1/secrets/{id}/reveal` ordinaire.

```http
DELETE /api/v1/requests/{id}
{ "receipt_token": "…" }
```

`204`. Fermer une demande ne détruit jamais une réponse déjà reçue : les dépôts
gardent leur propre cycle de vie, la porte se ferme donc sans brûler ce qu'il y
a dedans.

## L'audit

```http
GET /api/v1/audit?secret_id=…&event=…&limit=200&offset=0
```

```json
{ "count": 3, "events": [
  { "id": 3, "org_id": "default", "secret_id": "…", "event": "secret.revealed",
    "at": "2026-11-20T14:44:02Z", "ip": "203.0.113.5", "user_agent": "…",
    "detail": { "views_remaining": "0", "destroyed": "true" } } ] }
```

Les événements : `secret.created`, `secret.page_viewed`, `secret.revealed`,
`secret.bad_passphrase`, `secret.burned`, `secret.deleted`, `secret.expired`,
`secret.purged`, `secret.not_found`, `secret.file_uploaded`,
`secret.file_downloaded`, `request.created`, `request.opened`,
`request.deposited`, `request.closed`, `request.not_found`, `token.created`,
`token.revoked`, `token.scope_refused`, `request.rate_limited`,
`request.admin_blocked`. Le contenu d'un secret n'y apparaît jamais, et un test
l'affirme.

## L'instance

```http
GET /api/v1/instance
```

```json
{ "version": "1.0.0", "crypto_version": "v1", "uptime_seconds": 1204,
  "driver": "sqlite", "active_secrets": 12, "multi_org": false,
  "public_listener": true }
```

## Les webhooks

Peek vous appelle quand quelque chose arrive à un secret. Les points de
terminaison sont déclarés dans `peek.toml` (voir `docs/CONFIG.md`) et nulle part
ailleurs — une URL que l'API pourrait fixer ferait récupérer le serveur pour le
compte d'un appelant, depuis l'intérieur du réseau que cet appelant ne peut pas
joindre.

### Ce qui arrive

```http
POST /votre/endpoint
Content-Type: application/json; charset=utf-8
User-Agent: Peek/1.0.0 (+webhook)
X-Peek-Event: secret.revealed
X-Peek-Delivery: 9mJ2v7QpR1sT4uW8xY0zAb
X-Peek-Timestamp: 1763894400
X-Peek-Attempt: 1
X-Peek-Signature: v1=4f1c…
```

```json
{
  "id": "9mJ2v7QpR1sT4uW8xY0zAb",
  "event": "secret.revealed",
  "at": "2026-11-23T10:00:00Z",
  "instance": "https://secrets.acme.com",
  "org": "default",
  "secret_id": "KJh8s0LmNpQrStUvWxYz12",
  "ip": "203.0.113.4",
  "user_agent": "Mozilla/5.0 …",
  "detail": { "views_left": "0" }
}
```

Le jeu de champs est fixe — `id`, `event`, `at`, `instance`, `org`, `secret_id`,
`user_id`, `ip`, `user_agent`, `detail` — et un test échoue s'il change : en
ajouter un est donc une décision délibérée plutôt qu'un accident. Rien d'autre ne
peut quitter l'instance par ce chemin : pas de chiffré, pas de clé, pas de
passphrase, pas de fragment.

### Vérifier une livraison

La signature est un `HMAC-SHA256` sur `<X-Peek-Timestamp>.<corps brut>`, avec le
`secret` du point de terminaison en clé, encodé en hexadécimal et préfixé `v1=`.
L'horodatage est à l'intérieur de la chaîne signée, pas seulement dans
l'en-tête : une livraison enregistrée ne peut donc pas être rejouée avec un
horodatage frais.

Comparez en temps constant, et refusez un horodatage vieux de plus de quelques
minutes.

```python
import hashlib, hmac, time
from flask import Flask, request

SECRET = b"une longue chaine aleatoire"
app = Flask(__name__)

@app.post("/peek")
def peek():
    body = request.get_data()                      # les octets bruts, pas le JSON analysé
    ts = request.headers.get("X-Peek-Timestamp", "")
    if abs(time.time() - int(ts or 0)) > 300:
        return "stale", 400
    want = "v1=" + hmac.new(SECRET, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, request.headers.get("X-Peek-Signature", "")):
        return "bad signature", 401
    # X-Peek-Delivery se répète pour une relance : servez-vous-en pour être idempotent.
    handle(request.get_json())
    return "", 204
```

Un récepteur écrit en Go peut importer `internal/webhooks` et appeler
`webhooks.Verify`.

### Les relances, et ce que veut dire le code de statut

Répondez `2xx` et la livraison est finie. Tout le reste est retenté après 30
secondes, 2 minutes, 10 minutes, 1 heure et 6 heures, puis abandonné et gardé
pour l'exploitant.

`5xx`, `408`, `429` et un échec de connexion sont temporaires. **Tout autre
`4xx` est définitif** : le récepteur a compris et a refusé, relancer pendant six
heures ne remplirait que ses journaux. Un `3xx` est refusé net — le suivre
enverrait le corps signé à un hôte que personne n'a configuré.

La livraison est *au moins une fois* : un récepteur qui expire après avoir traité
le corps reçoit le même `X-Peek-Delivery` à nouveau. Cet identifiant est la façon
de rendre votre côté idempotent.

### Surveiller la file

```http
GET    /api/v1/webhooks                  # les points de terminaison, les comptes en file, le schéma de signature
GET    /api/v1/webhooks/deliveries       # ?state=pending|delivered|failed&endpoint=&event=&limit=
POST   /api/v1/webhooks/{name}/test      # un peek.ping, de façon synchrone
POST   /api/v1/webhooks/retry            # {} | {"endpoint":"siem"} | {"id":"…"}
```

Les deux `GET` prennent `instance:read`, un script de supervision peut donc les
interroger. Les deux `POST` demandent une session : faire appeler le serveur vers
l'extérieur, c'est un administrateur devant un clavier, pas un jeton dans un
cron. Le listing ne retourne jamais le corps — ce sont les octets signés, et ils
appartiennent au récepteur.

`POST /webhooks/{name}/test` répond `200` avec `{"ok": false, "error": …}` quand
le récepteur refuse : l'appel a marché, la livraison non, et c'est cette
différence que vous êtes en train de déboguer.

Depuis la machine, avec le service arrêté s'il le faut :

```bash
sudo peek webhook list
sudo peek webhook test siem
sudo peek webhook queue --state failed
sudo peek webhook retry --endpoint siem
```

## La description exploitable par une machine

```http
GET /api/v1/openapi.json
```

Un document OpenAPI 3.1, **engendré depuis la table des routes de l'instance
elle-même** — pas écrit à côté. Une route sans description fait échouer un test
qui la nomme, et une description restée après le retrait d'une route fait échouer
le même test : le document ne peut donc pas dériver en silence. Il porte, par
opération, quelle écoute la sert, quelle authentification elle prend et quelle
portée de jeton il lui faut.

Une copie est commitée dans [`api/openapi.json`](../api/openapi.json) pour la
lire ou engendrer un client sans serveur qui tourne ; la CI la régénère et
échoue sur le moindre écart. Régénérez-la vous-même avec `make openapi`.

```bash
# un client, directement depuis l'instance
curl -sS https://secrets.acme.com/api/v1/openapi.json -o openapi.json
```

## Le scripter

`peek-cli` fait déjà tout cela et chiffre localement :

```bash
echo -n "s3cret" | peek-cli push --server https://secrets.acme.com --views 1 --ttl 24h
peek-cli get "https://secrets.acme.com/s/<id>#v1.<clé>" --passphrase "…"
```

Écrire votre propre client veut dire implémenter le format v1 — partez de
[CRYPTO.md](CRYPTO.md) et faites passer `crypto/vectors/v1.json`.
