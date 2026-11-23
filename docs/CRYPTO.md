# Cryptographie — format v1

Ce document est la description normative de ce que Peek chiffre, de l'endroit où
vit chaque clé, et de ce que le serveur est en mesure d'apprendre. Deux
implémentations le suivent — Go (`internal/crypto`, utilisée par le serveur et
`peek-cli`) et TypeScript (`web/src/crypto`, utilisée par le navigateur) — et
elles sont tenues ensemble par des vecteurs de test partagés que les deux
doivent reproduire octet pour octet.

## 1. Primitives

| À quoi | Primitive |
|---|---|
| Chiffrement de la charge utile | AES-256-GCM, nonce de 96 bits, tag de 128 bits |
| Dérivation de clé | HKDF-SHA256 (RFC 5869) |
| Étirement de passphrase | Argon2id, 19 456 Kio, 2 passes, 1 voie, sortie de 32 octets |
| Empreinte du jeton de lecture | SHA-256 |
| Aléa | `crypto/rand` (Go), `crypto.getRandomValues` (navigateur) |

Argon2id tourne en WebAssembly dans le navigateur. Ces paramètres suivent les
recommandations actuelles de l'OWASP et restent utilisables sur un téléphone de
milieu de gamme (de l'ordre de 100 à 300 ms) ; ils sont stockés par secret, ils
peuvent donc être relevés plus tard sans casser les anciens liens.

## 2. Les valeurs, et où elles vivent

| Valeur | Taille | Où elle existe |
|---|---|---|
| Clé de contenu `K` | 32 o | Engendrée dans le navigateur ; vit **uniquement** dans le fragment d'URL |
| Passphrase | — | Seulement dans la tête de l'expéditeur et du destinataire ; jamais transmise |
| Sel du KDF | 16 o | Stocké côté serveur (public, inutile seul) |
| Clé finale | 32 o | Dérivée dans le navigateur, jamais transmise |
| Clé de chiffrement | 32 o | Dérivée dans le navigateur, jamais transmise |
| Jeton de lecture | 32 o | Dérivé dans le navigateur, envoyé **une fois** pour prouver la possession |
| `SHA-256(jeton de lecture)` | 32 o | Stocké côté serveur |
| Jeton d'accusé | 32 o | Engendré dans le navigateur, gardé dans le fragment de l'URL d'accusé |
| `SHA-256(jeton d'accusé)` | 32 o | Stocké côté serveur |
| Chiffré | n | Stocké côté serveur |

Un fragment d'URL (`#…`) n'est jamais envoyé dans une requête HTTP. Combiné à
`Referrer-Policy: no-referrer` et à une CSP qui interdit les origines tierces,
la clé ne peut pas fuiter vers le serveur, vers un proxy, ni vers un autre site.

## 3. Dérivation

```
A      = passphrase = ""  ?  (rien)  :  Argon2id(passphrase, sel, m, t, p, 32)
final  = HKDF-SHA256(ikm = K ‖ A, salt = sel, info = "peek-key-v1",  len = 32)
enc    = HKDF-Expand(final, info = "peek-enc-v1",  len = 32)
token  = HKDF-Expand(final, info = "peek-read-v1", len = 32)
stored = SHA-256(token)
```

`HKDF-Expand` est la moitié « expand » seule, sans second extract. WebCrypto
n'expose que la forme combinée, le navigateur implémente donc extract et expand
directement au-dessus de HMAC-SHA256 — c'est pour ça que
`web/src/crypto/hkdf.ts` existe, et pour ça que les vecteurs le couvrent.

## 4. Le scellement

```
AAD   = "peek-v1|" ‖ secret_id
blob  = nonce (12 octets aléatoires) ‖ AES-256-GCM(enc, nonce, clair, AAD)
```

L'identifiant public est engendré **par le client** (16 octets aléatoires,
base64url) et lié dans l'AAD : un chiffré ne peut donc pas être déplacé d'un
identifiant à un autre. Le serveur refuse un identifiant en double plutôt que de
l'écraser.

Le clair est une charge utile JSON ; le type, le message de l'expéditeur et tout
nom de fichier sont à l'intérieur du chiffré, jamais dans les métadonnées :

```json
{ "v": 1, "kind": "text", "text": "…", "message": "…" }
```

## 5. La preuve de possession avant la révélation

C'est l'étape qui rend réelle la garantie du clic pour révéler.

1. `GET /api/v1/secrets/{id}` ne retourne que des métadonnées publiques : s'il
   faut une passphrase, les paramètres du KDF, les lectures restantes,
   l'expiration. **Aucune lecture n'est consommée**, et c'est pour ça qu'un robot
   d'aperçu de lien (Teams, Slack, Outlook Safe Links, un antivirus de
   messagerie) ne coûte rien.
2. Le navigateur dérive le jeton de lecture et l'envoie à
   `POST /api/v1/secrets/{id}/reveal`.
3. Le serveur compare `SHA-256(token)` à l'empreinte stockée **en temps
   constant**. En cas de non-correspondance, il incrémente un compteur d'échecs
   et retourne 403 avec les essais restants ; aucune lecture n'est dépensée et
   aucun chiffré n'est relâché. Après `security.max_passphrase_attempts` échecs,
   le secret est détruit.
4. En cas de correspondance, dans une seule transaction, le serveur décrémente
   le compteur de lectures avec un `UPDATE … WHERE views_remaining > 0`
   conditionnel, vérifie qu'exactement une ligne a changé — ce qui est la preuve
   que cet appelant a gagné la course — et supprime la ligne quand la dernière
   lecture est dépensée.

Cinquante lectures simultanées d'un secret à une lecture produisent donc
exactement un succès. Cette propriété est testée au niveau du store et à travers
HTTP (`internal/store/store_test.go`, `internal/server/server_test.go`).

## 6. Les fichiers

Un fichier n'atteint jamais le serveur en clair, et il n'est jamais tenu en
entier dans un onglet non plus : il est scellé morceau par morceau à mesure
qu'il est lu, et envoyé en flux.

```
flux   = en-tête || morceau[0] || morceau[1] || … || morceau[n-1]
en-tête = "PEEKF1" || taille de morceau (uint32 BE) || préfixe de nonce (7 o) = 17 octets
```

La clé par fichier `F` est 256 bits aléatoires frais, portée **à l'intérieur de
la charge utile scellée** du secret de chaque destinataire — c'est pour ça qu'un
seul envoi peut servir dix liens sans que le serveur apprenne quoi que ce soit.

```
clé de chiffrement du fichier = HKDF-Expand(F, "peek-file-v1", 32)
nonce[i]      = préfixe de nonce || i (uint32 BE) || drapeau de fin (0x00 ou 0x01)
morceau[i]    = AES-256-GCM(clé du fichier, nonce[i], clair[i], AAD = en-tête)
```

C'est la construction STREAM (Rogaway et Hoang), la même forme qu'utilise `age`,
et chacune de ses parties gagne sa place :

- le **compteur dans le nonce** authentifie l'ordre : échangez deux morceaux et
  aucun des deux ne s'ouvre, parce que chacun a été scellé sous le compteur de sa
  propre position ;
- le **drapeau de fin** authentifie la fin du flux : un fichier tronqué est
  privé du morceau qui le porte, le lecteur refuse donc le tout plutôt que de
  rendre quelque chose de plus court. Ajouter des morceaux échoue de la même
  façon ;
- l'**en-tête en AAD** lie la taille de morceau et le préfixe de nonce : ni l'un
  ni l'autre ne peut être réécrit en transit.

Chaque morceau sauf le dernier fait exactement `taille de morceau` octets de
clair (1 Mio par défaut). Un fichier vide produit quand même un morceau, final
et vide, si bien que le flux d'un fichier de zéro octet fait 33 octets et n'est
un cas particulier nulle part.

La longueur chiffrée est donc exacte et connue avant que le premier octet ne
soit lu — `17 + clair + 16 par morceau` — et c'est ce qui permet au serveur de
vérifier une taille d'envoi annoncée et de signer un `PUT` S3 non découpé.

Les noms et les types MIME ne sont **pas** dans le flux. Ils sont dans la charge
utile :

```json
{ "v": 1, "kind": "file", "message": "…",
  "files": [ { "id": "…", "name": "vpn.ovpn", "mime": "application/x-openvpn-profile",
               "size": 4096, "key": "<base64url(F)>", "chunk_size": 1048576 } ] }
```

## 7. Les demandes de secret

Une demande de secret inverse le sens habituel : celui qui demande doit être le
seul à pouvoir lire, et celui qui répond ne doit pas pouvoir relire ce qu'il a
déposé — ni personne qui détient simplement le lien de la demande.

Le demandeur engendre une **paire de clés P-256**. La moitié publique est
stockée sur le serveur pour qu'un dépôt puisse lui être scellé ; la moitié privée
ne quitte jamais le fragment du lien de suivi du demandeur. Une **clé de
demande** symétrique `R`, séparée, voyage dans le lien de dépôt et joue
exactement le rôle qu'une clé de contenu joue pour un secret : `HKDF` en donne
une clé de chiffrement qui scelle l'intitulé, et un jeton de lecture dont le
serveur stocke l'empreinte.

Un dépôt est un secret v1 ordinaire. Ce qui en fait un dépôt, c'est que sa clé
de contenu `K` est enveloppée vers la clé publique du demandeur avec ECIES :

```
Z   = ECDH(privée éphémère, publique du demandeur)      // coordonnée X, 32 octets
key = HKDF-SHA256(ikm = Z || publique éphémère || publique du demandeur,
                  salt = nil, info = "peek-request-v1")
box = publique éphémère (65 o) || nonce (12 o) || AES-256-GCM(key, nonce, K,
                                                 AAD = "peek-req-v1|" || id de la demande)
```

Les deux clés publiques sont dans l'IKM, la dérivation est donc liée à la paire
exacte en jeu : substituer une autre clé éphémère tombe sur un autre matériel de
clé et la boîte ne s'ouvre plus. L'AAD lie la boîte à une demande, un dépôt
capturé sur l'une ne peut donc pas être rejoué dans une autre.

**P-256 et non X25519.** X25519 n'est arrivé que récemment dans Safari et
Firefox, et Peek tourne dans des navigateurs d'entreprise administrés qui ont
couramment plusieurs versions de retard ; l'ECDH P-256 est dans chaque
implémentation de WebCrypto depuis dix ans. L'arbitrage est consigné dans
[DECISIONS.md](DECISIONS.md).

**La clé publique voyage dans le lien, jamais par l'API.** C'est la partie
porteuse. Un serveur compromis qui pourrait distribuer sa propre clé publique
lirait chaque réponse ; un navigateur qui ne la prend jamais que dans le fragment
ne peut pas être trompé comme ça. Rien dans la page de dépôt ne demande une clé
au serveur.

Les points invalides sont refusés à l'entrée, à la création d'une demande comme
à l'analyse d'un lien : donner un point qui n'est pas sur la courbe à l'ECDH de
quelqu'un d'autre est une attaque connue, et il ne coûte qu'une vérification de
la fermer.

## 8. Les formats de lien

```
destinataire : https://hôte/s/<id>#v1.<base64url(K)>
expéditeur   : https://hôte/r/<id>#v1.<base64url(K)>~<base64url(jeton d'accusé)>
dépôt        : https://hôte/q/<id>#v1q.<base64url(R || publique du demandeur)>
suivi        : https://hôte/qs/<id>#v1r.<base64url(privée || publique)>~<R>~<jeton d'accusé>
```

La page de l'expéditeur détient les deux jetons : la clé de contenu, pour
reconstruire le lien destinataire, et le jeton d'accusé, qui autorise les
vérifications d'état et la destruction. Les deux restent dans le fragment.

Chaque préfixe est distinct — `v1`, `v1q`, `v1r` — pour que les trois sortes ne
puissent jamais être prises l'une pour l'autre : l'une est une clé symétrique,
l'une porte une clé publique, l'une porte une clé privée. Analyser la mauvaise
sorte échoue plutôt que de marcher à moitié, et un test l'affirme des deux côtés.

Le lien de suivi porte la clé privée de la demande, ce qui veut dire que le
perdre, c'est perdre les réponses. La page le dit en autant de mots ; le serveur
n'en a pas de copie, par construction.

## 9. Ce que le serveur peut et ne peut pas

**Ne peut pas** : lire un secret, retrouver une passphrase, casser une clé par
force brute (256 bits, uniformément aléatoires), prouver à quel secret
appartient un chiffré donné sans son identifiant, ou restaurer un secret une
fois consommé.

**Peut**, et c'est délibéré : savoir qu'un secret existe, sa taille, quand il a
été créé, quand il expire, combien de lectures restent, s'il porte une
passphrase, et les adresses IP qui ont interagi avec lui (sous réserve de
`security.anonymize_ips`).

**Un serveur compromis** peut servir du JavaScript modifié aux visiteurs à venir
et capturer ce qu'ils tapent. Le zero-knowledge protège les données au repos et
en transit, pas un back-end que vous ne contrôlez plus.
[THREAT-MODEL.md](THREAT-MODEL.md) dit quoi y faire.

## 10. Les vecteurs de test

`crypto/vectors/v1.json` porte trois familles de cas, toutes avec des entrées
fixes **et des sorties attendues fixes** :

- **secrets** — sans passphrase, avec une passphrase aux paramètres par défaut,
  avec une passphrase à des paramètres bon marché, et un clair vide. Chacun fixe
  la clé finale, la clé de chiffrement, le jeton de lecture, son empreinte, le
  blob scellé pour un nonce fixe, et le fragment.
- **fichiers** — un fichier vide, un court, un qui fait exactement un morceau
  (sans morceau de fin parasite), et un de plusieurs morceaux plus un reste.
  Chacun fixe la clé dérivée et le flux entier pour un préfixe de nonce fixe. Ce
  sont les bornes qu'on se trompe à écrire.
- **demandes de secret** — une clé de contenu enveloppée pour une paire de clés,
  une clé éphémère et un nonce fixes. La boîte n'est pas reproductible depuis le
  côté TypeScript sans la clé privée éphémère, le test du navigateur ouvre donc
  ce que Go a scellé : un format, deux implémentations.

```bash
go test ./internal/crypto/...      # Go lit les vecteurs
npm run test --prefix web          # TypeScript lit le même fichier
go run ./tools/genvectors          # les régénérer ; la CI échoue si le fichier change
```

La CI régénère les vecteurs et échoue sur le moindre écart : changer le format
sans incrémenter sa version est attrapé avant d'être livré.

## 11. Changer le format

La version `v1` est gelée. Un nouveau format reçoit `v2`, un nouveau jeu de
chaînes `info` et ses propres vecteurs ; `v1` reste lisible pour que les liens
existants continuent de fonctionner. La version préfixe chaque fragment, un
client sait donc toujours ce qu'il tient.
