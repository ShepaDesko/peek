# Configuration

Peek lit un seul fichier TOML, `/etc/peek/peek.toml` par défaut. `peek setup`
l'écrit ; `PEEK_CONFIG` ou `--config` le fait chercher ailleurs.

```bash
peek config check      # valider, et afficher un résumé
peek config show       # afficher la configuration effective, secrets masqués
```

Un réglage inconnu est une erreur, pas un avertissement : une faute de frappe
dans un réglage de sécurité ne doit jamais être ignorée. Les durées s'écrivent
`45s`, `30m`, `12h`, `7d`.

Un fichier de référence avec chaque valeur par défaut se trouve dans
`/usr/share/doc/peek/peek.toml.example`.

## À la racine

| Réglage | Défaut | Ce qu'il fait |
|---|---|---|
| `public_url` | `http://localhost:8080` | L'URL que tapent les utilisateurs. Les liens, les cookies, la CSP et les redirections en découlent. Doit correspondre à ce que publie le proxy. |
| `default_language` | `fr` | `fr` ou `en`. Le choix du visiteur est mémorisé localement. |
| `multi_org` | `false` | Plusieurs organisations sur une instance — voir [le mode multi-organisation](#mode-multi-organisation). |
| `update_check` | `true` | Vérification quotidienne d'une nouvelle version. Mettez `false` sur une machine coupée du réseau. |
| `update_url` | vide | Un miroir interne à la place des releases GitHub. |
| `update_channel` | `stable` | `stable` ou `beta`. |
| `master_key_file` | `/etc/peek/master.key` | 32 octets aléatoires, mode 0400. Sauvegardez-la séparément. |
| `data_dir` | `/var/lib/peek` | Base, fichiers chiffrés, assets de marque. |

## `[server]`

| Réglage | Défaut | Ce qu'il fait |
|---|---|---|
| `internal_listen` | `127.0.0.1:8080` | Sert tout : création, tableau de bord, administration, API. |
| `public_listen` | vide | Ne sert **que les routes destinataire**. C'est celle-là qu'on publie à travers le répartiteur. |
| `trusted_proxies` | `[]` | Les seules sources dont les en-têtes `X-Forwarded-*` et `Forwarded` sont crus. Vide veut dire jamais. |
| `proxy_protocol` | `false` | Protocole PROXY v1/v2 pour les répartiteurs de couche 4. Demande `trusted_proxies`, et refuse de démarrer sans. |
| `read_timeout` | `30s` | |
| `write_timeout` | `2m` | À relever pour de gros envois chiffrés. |
| `idle_timeout` | `1m30s` | |
| `shutdown_grace` | `20s` | Le temps laissé aux requêtes en vol à l'arrêt. |
| `max_body_bytes` | `8388608` | Plafond du corps d'une requête. |
| `max_header_bytes` | `1048576` | |

Voir [REVERSE-PROXY.md](REVERSE-PROXY.md) pour la façon dont tout cela se
combine.

## `[tls]`

| Réglage | Défaut | Ce qu'il fait |
|---|---|---|
| `mode` | `none` | `none` (terminé en amont), `file` (un certificat que vous fournissez), `acme` (Let's Encrypt). |
| `cert_file`, `key_file` | vide | Obligatoires pour `file`. |
| `acme_hosts` | `[]` | Obligatoire pour `acme`. De vrais noms d'hôtes qui résolvent vers cette machine — pas une adresse, pas `localhost`. |
| `acme_email` | vide | Obligatoire pour `acme` : le seul moyen pour l'autorité de vous avertir avant qu'un certificat cesse de se renouveler. |
| `acme_dir` | `/var/lib/peek/acme` | Contient la clé de compte et chaque clé privée émise. `0700`. |
| `acme_directory_url` | vide | Pointez sur un annuaire de recette pour répéter. Les certificats qui en viennent ne sont pas de confiance pour les navigateurs. |
| `hsts` | `false` | Envoyer `Strict-Transport-Security`. Laissez désactivé quand le proxy l'envoie déjà. |
| `hsts_max_age` | `31536000` | |

`mode = "none"` est la bonne réponse derrière un Kemp, un F5, HAProxy ou nginx :
le proxy détient le certificat et Peek sert du HTTP en clair sur la boucle
locale.

### ACME, quand Peek est seul à écouter

```toml
[tls]
mode       = "acme"
acme_hosts = ["secrets.acme.com"]
acme_email = "ops@acme.com"
```

Le défi est **TLS-ALPN-01**, répondu sur l'écoute TLS qui est déjà là. Le port
80 n'est pas nécessaire et rien de plus n'est publié — c'est toute la raison de
le préférer à HTTP-01.

Ce que cela demande :

- l'écoute joignable depuis Internet sur le **443**. Mettez
  `server.internal_listen` ou `server.public_listen` à `:443` et donnez à
  l'unité `AmbientCapabilities=CAP_NET_BIND_SERVICE` (les deux lignes sont dans
  l'unité du paquet, en commentaire) ;
- chaque nom d'`acme_hosts` qui résout vers cette machine. `peek doctor` les
  résout et le dit, sans faire un seul appel ACME — ceux-là sont limités par
  compte et par domaine, et un diagnostic qu'on lance en boucle ne doit pas
  pouvoir épuiser un quota hebdomadaire.

La première connexion à chaque hôte obtient le certificat et prend quelques
secondes. Le renouvellement est automatique et ne demande aucun redémarrage.

Répétez d'abord contre la recette :

```toml
acme_directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
```

`peek doctor` avertit tant que c'est en place, parce qu'un certificat de recette
n'est de confiance pour aucun navigateur.

## `[database]`

| Réglage | Défaut | Ce qu'il fait |
|---|---|---|
| `driver` | `sqlite` | `sqlite`, ou `postgres` pour plusieurs nœuds — voir [HIGH-AVAILABILITY.md](HIGH-AVAILABILITY.md). |
| `dsn` | `/var/lib/peek/peek.db` | Un chemin de fichier, ou un DSN PostgreSQL. |

SQLite tourne en mode WAL. Pour plusieurs nœuds il faut PostgreSQL : ne pointez
pas deux instances sur un seul fichier SQLite posé sur du NFS.

## `[storage]`

| Réglage | Défaut | Ce qu'il fait |
|---|---|---|
| `backend` | `local` | `local`, ou `s3`. |
| `path` | `/var/lib/peek/files` | Les blobs chiffrés, en stockage local. Peut être un montage partagé en haute disponibilité. |
| `s3_bucket` | — | Obligatoire pour `s3`. |
| `s3_region` | `us-east-1` | La région de signature. La plupart des appliances compatibles S3 acceptent n'importe quoi de cohérent. |
| `s3_endpoint` | — | L'URL complète du point d'accès. Vide veut dire AWS. |
| `s3_prefix` | — | Préfixe de clé dans le bucket : lettres, chiffres, `-`, `_`, `.` et `/`. |
| `s3_path_style` | implicite | Le bucket dans le chemin plutôt que dans le nom d'hôte. Posé automatiquement quand `s3_endpoint` est donné, parce que les appliances ont rarement un certificat joker. |
| `s3_access_key` / `s3_secret_key` | — | Les identifiants. Le secret est masqué dans `peek config show`. |

Peek signe lui-même les requêtes S3 (SigV4) et utilise `PUT`, `GET`, `HEAD`,
`DELETE` et `ListObjectsV2` — rien d'autre. Il n'y a pas de SDK AWS dans le
binaire, ce qui veut dire aussi **pas de chaîne d'identifiants** : les clés
viennent de ce fichier et de nulle part ailleurs, et rien ne sonde jamais un
point d'accès de métadonnées d'instance. Le raisonnement est dans
[DECISIONS.md](DECISIONS.md).

```toml
[storage]
backend       = "s3"
s3_bucket     = "peek-secrets"
s3_endpoint   = "https://minio.acme.internal:9000"
s3_region     = "eu-west-3"
s3_access_key = "…"
s3_secret_key = "…"
```

Quel que soit le stockage, un blob est déjà chiffré quand il arrive : le bucket
contient des flux opaques et leurs longueurs, et les clés sont dans des charges
utiles que le serveur ne peut pas lire.

## `[security]`

| Réglage | Défaut | Ce qu'il fait |
|---|---|---|
| `admin_allowed_cidrs` | `[]` | Restreint les routes d'administration, d'audit et de politique à ces réseaux. Répond 404 ailleurs. |
| `create_allowed_cidrs` | `[]` | Restreint la création de secrets. |
| `anonymous_create` | `false` | Autoriser la création sans compte. Les destinataires n'ont de toute façon jamais besoin d'un compte. |
| `max_passphrase_attempts` | `5` | Essais ratés avant que le secret ne soit détruit. |
| `anonymize_ips` | `false` | Ne garder qu'un préfixe /24 (IPv4) ou /48 (IPv6) dans les journaux et les entrées d'audit. |
| `audit_retention` | `365d` | `0` garde le journal d'audit pour toujours. |

### Les limites de débit

Quatre seaux à jetons, chacun par IP cliente réelle : `rate_create`,
`rate_read`, `rate_login`, `rate_api`.

```toml
[security.rate_read]
burst  = 30      # l'allocation immédiate ; 0 désactive la limite
rate   = 300     # le rechargement soutenu…
window = "1h"    # …par cette fenêtre
```

En mémoire sur un nœud unique, qui est le déploiement par défaut ; partagées à
travers la base dès que `database.driver = "postgres"`, donc une limite pour la
grappe et non une par nœud.

## `[policy]`

| Réglage | Défaut | Ce qu'il fait |
|---|---|---|
| `max_ttl` / `default_ttl` | `30d` / `1d` | Plafond et valeur par défaut d'expiration. |
| `max_views` / `default_views` | `100` / `1` | Plafond et valeur par défaut de lectures. |
| `require_passphrase` | `false` | Refuser une création sans passphrase. |
| `force_retrieval_step` | `false` | Forcer l'étape du clic pour révéler. |
| `allowed_kinds` | `["text","url","file"]` | Les types que cette instance accepte. |
| `max_file_bytes` | `104857600` | 100 Mio de clair par fichier. L'envoi accepté est un peu plus gros : le format par morceaux ajoute un en-tête de 17 octets et 16 octets par mébioctet. |
| `max_secret_bytes` | `1048576` | Plafond du chiffré pour un secret texte. |
| `max_recipients` | `10` | Liens par lot multi-destinataires. |
| `max_files_per_secret` | `10` | Pièces jointes par lot. |
| `upload_window` | `2h` | Le temps qu'un blob envoyé attend qu'un secret le réclame. Un expéditeur qui ferme l'onglet ne laisse rien derrière lui plus longtemps que ça. |
| `download_window` | `30m` | Le temps pendant lequel un destinataire garde accès aux pièces jointes après avoir révélé. La ligne du secret a déjà disparu à ce moment-là ; c'est ce qui permet à un gros téléchargement de finir. |
| `max_deposits` | `1` | Les réponses qu'une demande de secret peut accepter. |

Relever `download_window` garde les blobs plus longtemps sur le disque après
lecture ; l'abaisser peut couper le téléchargement lent d'un gros fichier.
Trente minutes, c'est à peu près un fichier de 100 Mio sur une mauvaise
connexion, avec de la marge.

## `[mail]`

Laissez `host` vide pour désactiver toutes les fonctions d'e-mail.

| Réglage | Défaut | Ce qu'il fait |
|---|---|---|
| `host`, `port` | vide, `587` | Le serveur SMTP. |
| `username`, `password` | vide | Omettez les deux pour un relais interne anonyme. |
| `encryption` | `starttls` | `none`, `starttls` ou `tls`. |
| `from_name`, `from_address` | `Peek`, vide | L'identité de l'expéditeur. |
| `skip_tls_verify` | `false` | Pour un relais interne avec une autorité privée. Préférez faire confiance à l'autorité. |
| `allowed_recipient_domains` | `[]` | Restreindre à qui un lien peut être envoyé par e-mail. |

`peek doctor` se connecte, négocie STARTTLS et s'authentifie, sans rien envoyer.

## `[log]`

| Réglage | Défaut | Ce qu'il fait |
|---|---|---|
| `level` | `info` | `debug`, `info`, `warn`, `error`. |
| `format` | `json` | `json` ou `text`. |
| `file` | vide | Vide veut dire la sortie standard, captée par journald. Mettez un chemin pour logrotate. |

Les secrets, les clés, les passphrases, les fragments d'URL et les corps de
requête ne sont jamais journalisés, à aucun niveau. Le journal d'accès consigne
le motif de route apparié, pas l'URL.

## `[branding]`

| Réglage | Défaut | Ce qu'il fait |
|---|---|---|
| `service_name` | `Peek` | Affiché partout, y compris dans le titre de l'onglet. |
| `primary_color`, `accent_color` | `#4f46e5`, `#0ea5e9` | Une palette complète est engendrée, avec un contrôle de contraste WCAG AA qui avertit plutôt que de corriger en silence. |
| `[branding.colors]` | vide | Épingle un jeton de palette à la main, pour une charte qui spécifie ses nuances. Voir ci-dessous. |
| `default_theme` | `dark` | Ce que voit un visiteur qui n'a jamais touché le bouton : `dark`, `light`, ou `system` pour suivre sa machine. Son choix, lui, est mémorisé dans son navigateur et gagne toujours. |
| `hide_powered_by` | `false` | |
| `support_url`, `legal_url`, `privacy_url` | vide | Les liens du pied de page. |

### Épingler une nuance

```toml
[branding.colors]
primary-hover = "#1b3fa8"
on-primary    = "#ffffff"
```

Les huit jetons : `primary`, `primary-hover`, `primary-active`,
`primary-soft`, `primary-ring`, `on-primary`, `accent`, `accent-soft`. Ce qui
n'est pas épinglé reste dérivé de la primaire et de l'accent.

Un jeton inconnu ou une valeur qui n'est pas une couleur **empêchent le
démarrage** : un réglage de couleur ignoré en silence est un appel au support
trois semaines plus tard. Le contraste est mesuré sur la palette finale, donc
épingler `on-primary` ne contourne pas le contrôle WCAG AA.

Voir [BRANDING.md](BRANDING.md).

## `[backup]`

| Réglage | Défaut | Ce qu'il fait |
|---|---|---|
| `enabled` | `true` | Utilisé par le minuteur systemd. |
| `dir` | `/var/backups/peek` | |
| `keep` | `7` | Les archives gardées. Une archive contient le chiffré des secrets actifs : gardez ce nombre petit. |
| `passphrase` | vide | Mettez-en une : l'archive est alors chiffrée avec age. |
| `interval` | `1d` | |

## Mode multi-organisation

```toml
multi_org = true
```

Désactivé par défaut, et désactivé est la bonne réponse pour presque toutes les
installations : une instance, un client, `public_url` dans ce fichier et rien
d'autre à quoi penser.

Activez-le et une installation héberge plusieurs organisations. Chacune a sa
marque, ses utilisateurs, ses politiques, ses secrets et son journal d'audit, et
c'est l'**en-tête Host** qui dit à laquelle appartient une requête.

Cet en-tête est contrôlé par l'attaquant sur une connexion directe, deux choses
le rendent donc sûr à exploiter :

- il est lu depuis `X-Forwarded-Host` seulement quand le pair est dans
  `server.trusted_proxies`, et depuis la connexion sinon — la même règle que
  suit le code de l'IP cliente réelle ;
- un domaine ne résout vers rien jusqu'à ce qu'un **enregistrement DNS TXT**
  l'ait prouvé. Sans cette preuve, n'importe qui pouvant pointer un nom sur
  cette instance pourrait porter la marque d'un autre client, et un destinataire
  verrait le bon logo au-dessus de la page de la mauvaise organisation.

### En monter une

```bash
sudo peek org create acme --name "ACME SARL"
sudo peek org domain-add secrets.acme.com --slug acme
# publiez l'enregistrement TXT qu'il affiche, puis :
sudo peek org domain-verify secrets.acme.com
```

L'enregistrement est
`_peek-challenge.secrets.acme.com. IN TXT "peek-verification=<jeton>"`. Un label
dédié plutôt que l'apex, parce qu'un enregistrement TXT à l'apex est partagé
avec SPF, DMARC et une demi-douzaine d'autres jetons de vérification, et que les
exploitants s'effacent les uns les autres.

La résolution de vérification est **la seule requête DNS sortante que fait
Peek**, et elle a lieu parce que quelqu'un l'a demandée. Rien n'est résolu sur
le chemin de requête d'un destinataire, une instance coupée du réseau n'y arrive
donc jamais.

Un domaine prouvé une fois reste prouvé : une revérification en échec consigne
plus tard ce que le résolveur a vu et laisse `verified_at` tranquille. Retirer sa
marque à un client parce que son registrar était lent serait la mauvaise panne.

### Ce qui change

| | Mono-client | Multi-organisation |
|---|---|---|
| Marque | `public_url`, une marque | résolue par domaine vérifié |
| Liens | construits sur `public_url` | construits sur le domaine principal de l'organisation |
| E-mails | la marque de l'instance | la marque de l'organisation |
| Comptes | un seul vivier | un vivier par organisation, `(org_id, email)` unique |
| Rôles | `admin` au sommet | `platform_admin` au-dessus |
| Interface | la notion est masquée | un onglet Organisations, pour `platform_admin` seulement |

Le premier domaine qu'une organisation vérifie devient aussi son domaine
**principal** — l'origine sur laquelle ses liens sont construits — pour que
l'adresse dans un lien, le certificat qui la sert et la marque sur la page
s'accordent. Changez-le avec `peek org domain-primary`.

Une organisation **suspendue** garde chaque ligne et cesse de résoudre : un
client qui n'a pas payé n'est pas un client dont on supprime les secrets.

### Le rôle de plateforme

`platform_admin` est au-dessus d'`admin` et c'est le seul rôle qui puisse créer
une organisation ou toucher à un domaine. Sur une instance hébergée, la personne
qui accueille un client n'est pas celle qui administre ce client, et un
administrateur d'une organisation ne doit pas pouvoir voir que les autres
existent.

```bash
sudo peek admin set-role --email ops@example.com --role platform_admin
```

Aucun rôle ne peut accorder un rôle au-dessus du sien, ce qui est vérifié une
fois dans le service des comptes plutôt qu'à chaque point d'appel.

## `[sso]`

L'authentification unique OpenID Connect. Un fournisseur par instance : une
instance appartient à une organisation avec un annuaire, et deux fournisseurs
voudraient dire deux sources de vérité sur qui est quelqu'un.

```toml
[sso]
enabled       = true
provider      = "entra"
issuer        = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
client_id     = "11111111-1111-1111-1111-111111111111"
client_secret = "…"
scopes        = ["openid", "profile", "email"]

provision     = true
default_role  = "member"
groups_claim  = "groups"
admin_groups  = ["3f6c…"]      # Entra envoie des identifiants d'objet, pas des noms
manager_groups = ["a91b…"]
sync_role_on_login = true
```

| Réglage | Défaut | Ce qu'il fait |
|---|---|---|
| `enabled` | `false` | |
| `provider` | `generic` | `entra`, `google`, `keycloak`, `authentik`, `adfs` ou `generic`. Cela ne choisit que le libellé du bouton et la forme des messages d'erreur ; le protocole est le même. |
| `display_name` | d'après `provider` | Ce que dit le bouton de connexion. |
| `issuer` | obligatoire | Doit être en `https`, et doit être exactement égal à la revendication `iss` de chaque jeton. |
| `client_id`, `client_secret` | obligatoires | Peek s'authentifie auprès du point d'accès de jetons en client confidentiel. |
| `scopes` | `["openid","profile","email"]` | Ajoutez ce que votre fournisseur demande qu'on demande pour envoyer les groupes. |
| `discovery` | `true` | Lit `<issuer>/.well-known/openid-configuration`. |
| `authorize_url`, `token_url`, `jwks_url`, `userinfo_url` | vide | Obligatoires quand `discovery = false`. |
| `ca_file` | vide | Épingler l'autorité du fournisseur, pour un Keycloak ou un ADFS interne. |
| `required` | `false` | Refuse **chaque** identifiant local, mot de passe comme clé d'accès. Ne se contente pas de masquer le formulaire. |
| `password_exempt` | `[]` | Les adresses qui peuvent encore se connecter localement quand `required` est posé. |
| `provision` | `true` | Créer un compte à la première connexion. Désactivé veut dire que seuls les comptes existants peuvent se connecter. |
| `default_role` | `member` | Pour un utilisateur dont les groupes ne correspondent à rien. |
| `allowed_domains` | `[]` | Des domaines nus, par exemple `["acme.com"]`. Vide veut dire n'importe quel domaine dont le fournisseur se porte garant. |
| `groups_claim` | `groups` | `roles` pour un enregistrement d'application Entra à rôles. |
| `admin_groups`, `manager_groups`, `auditor_groups`, `member_groups` | `[]` | Un utilisateur dans plusieurs obtient le rôle le **plus fort**. |
| `require_group` | `false` | Refuser quiconque dont les groupes ne correspondent à aucune des tables. |
| `sync_role_on_login` | `true` | Réappliquer la correspondance à chaque connexion, pour qu'un changement dans l'annuaire prenne effet sans toucher à Peek. Désactivé veut dire que le rôle est posé à la création et que les modifications locales tiennent. |

### L'URI de redirection à enregistrer

```
<public_url>/auth/sso/callback
```

Caractère pour caractère. Elle est fixe — un chemin de rappel configurable est
une redirection ouverte configurable qui attend d'être mal tapée — et
`peek doctor` affiche la valeur exacte à coller dans l'application chez le
fournisseur.

### `required`, et pourquoi l'issue de secours est explicite

`sso.required` refuse les identifiants locaux sur le serveur, pas dans
l'interface. Cela veut dire qu'une instance dont le fournisseur est injoignable
— une panne, un secret client expiré, un changement réseau — est une instance où
personne ne peut se connecter, avec le fichier de configuration qui corrigerait
cela lisible par root seulement.

L'issue de secours est donc nommée plutôt que sous-entendue. Il n'y a pas
d'exception cachée pour les administrateurs : mettez un ou deux comptes de
secours dans `sso.password_exempt`, donnez-leur un second facteur, et auditez-les.
`peek doctor` **échoue** quand `required` est posé et que la liste est vide.

### Les comptes, et ce qui les lie

Un compte est lié à une identité d'annuaire par `(émetteur, sujet)`, jamais par
l'adresse e-mail. Une adresse est une étiquette qui change ; un sujet est
l'identifiant propre de l'annuaire et ne change pas. Une boîte renommée suit donc
la personne, et une boîte réattribuée ne devient pas une entrée dans son compte.

À une première connexion, dans cet ordre :

1. le domaine de l'e-mail est contrôlé contre `allowed_domains` ;
2. un compte avec ce couple `(émetteur, sujet)` est cherché ;
3. puis un compte avec cette adresse — le lier exige que ce compte ne soit pas
   déjà lié, et que le fournisseur n'ait pas marqué l'adresse comme non
   vérifiée ;
4. et alors seulement, si `provision` est actif, un nouveau compte est créé, sans
   aucune empreinte de mot de passe.

Un administrateur peut détacher une identité d'un compte
(`DELETE /api/v1/users/{id}/sso`), ce qui est la sortie d'un sujet lié au mauvais
compte.

### Entra ID : le débordement de groupes

Passé environ deux cents groupes, Entra remplace la liste des groupes dans le
jeton par un pointeur vers Microsoft Graph. Peek n'appellera pas Graph — ce
serait une seconde dépendance sortante et un second identifiant — il **refuse
donc la connexion et le dit**, plutôt que de ne voir aucun groupe et de
distribuer `default_role`, ce qui rétrograderait silencieusement un
administrateur.

Utilisez plutôt des rôles d'application (`groups_claim = "roles"`), ou posez un
filtre de groupes dans l'enregistrement de l'application pour que seuls les
groupes pertinents soient envoyés.

## `[[webhook]]`

Répétable. Chaque table déclare un point de terminaison sortant.

```toml
[[webhook]]
name    = "siem"
url     = "https://hooks.example.com/peek"
secret  = "une longue chaîne aléatoire, 16 caractères au minimum"
events  = ["secret.revealed", "secret.expired", "secret.burned", "request.deposited"]

[[webhook]]
name     = "chat"
url      = "http://mattermost.internal/hooks/xxxx"
secret   = "une autre longue chaîne aléatoire"
events   = ["*"]
ca_file  = "/etc/ssl/certs/internal-ca.pem"
```

| Réglage | Défaut | Ce qu'il fait |
|---|---|---|
| `name` | obligatoire | Comment la file, les journaux et `peek webhook` le désignent. Changez l'URL et les événements en file survivent. |
| `url` | obligatoire | `http` ou `https`. |
| `secret` | obligatoire, 16 caractères au minimum | La clé HMAC-SHA256 que le récepteur vérifie. Un webhook non signé est une notification que quiconque peut joindre le récepteur peut forger. |
| `events` | les quatre ci-dessous | Des noms d'événements d'audit, ou `["*"]` pour tout le journal. |
| `max_attempts` | `6` | Compte le premier essai. |
| `timeout` | `10s` | Par tentative. |
| `disabled` | `false` | Garde la déclaration en la faisant taire. |
| `skip_tls_verify` | `false` | Un vrai affaiblissement : la signature prouve qui a envoyé le corps, pas qui l'a lu. Préférez `ca_file`. |
| `ca_file` | vide | Épingler l'autorité du récepteur. La bonne réponse sur un réseau interne. |

L'abonnement par défaut est le cycle de vie côté expéditeur :
`secret.revealed`, `secret.expired`, `secret.burned`, `request.deposited`.

Il n'y a pas d'appel d'API qui crée un point de terminaison, et il n'y en aura
jamais : une URL qu'un appelant pourrait fixer ferait récupérer Peek pour son
compte, depuis l'intérieur d'un réseau qu'il ne peut pas joindre. Les points de
terminaison vivent dans ce fichier.

Le corps d'une livraison est une entrée d'audit. Ce journal est construit pour ne
jamais contenir un secret, une clé, une passphrase ni un fragment d'URL, le
transmettre est donc sûr par construction — mais il porte bien des identifiants
et parfois une adresse e-mail. Pointez un webhook vers un endroit où vous seriez
content de voir le journal d'audit.

`docs/API.md` donne le schéma de signature et un récepteur en vingt lignes.
`peek webhook list|test|queue|retry` l'inspecte depuis la machine, et
`peek doctor` avertit quand la file cesse de se vider.

## Les surcharges par l'environnement

Pour l'empaquetage et les tests, pas pour des secrets : `PEEK_CONFIG`,
`PEEK_PUBLIC_URL`, `PEEK_INTERNAL_LISTEN`, `PEEK_PUBLIC_LISTEN`, `PEEK_DB_DSN`,
`PEEK_DATA_DIR`, `PEEK_LOG_LEVEL`. `PEEK_UPDATE_TOKEN` est lu par `peek update`
pour un miroir de releases authentifié.

## Appliquer un changement

```bash
sudo nano /etc/peek/peek.toml
sudo peek config check
sudo systemctl restart peek
sudo peek doctor
```
