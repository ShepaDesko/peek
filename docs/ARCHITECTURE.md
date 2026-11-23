# Architecture

## Un seul binaire

```
peek (environ 29 Mo, statique, CGO désactivé)
├── serveur HTTP, routage et intergiciels de durcissement
├── cycle de vie des secrets et politiques
├── accès SQLite ou PostgreSQL, migrations embarquées
├── l'interface React compilée (go:embed)
├── tâches de fond (purge, rétention d'audit, webhooks)
└── commandes d'administration (setup, doctor, backup, restore, update…)
```

Aucun environnement d'exécution à installer, aucun répertoire d'assets, pas de
Docker. Déployer, c'est un fichier et une unité systemd.

## Paquets

| Paquet | Responsabilité |
|---|---|
| `cmd/peek` | Répartition des commandes, la boucle `serve`, mise en place des logs |
| `cmd/peek-cli` | Client en terminal : `push`, `get` — le même chiffrement que le navigateur |
| `internal/config` | Charge et valide `peek.toml` ; durées lisibles ; expurgation |
| `internal/crypto` | Format v1 : dérivation, scellement, identifiants, fragments |
| `internal/store` | Schéma, migrations, cycle de vie des secrets, journal d'audit |
| `internal/secrets` | Application des politiques, règles de révélation, purge |
| `internal/requests` | Demandes de secret et dépôts |
| `internal/server` | Routes, intergiciels, gestionnaires, écouteurs, IP client réelle |
| `internal/accounts` | Comptes, rôles, sessions, second facteur, jetons d'API |
| `internal/oidc` | OpenID Connect : découverte, PKCE, vérification des assertions |
| `internal/orgs` | Résolution d'organisation par domaine, vérification DNS |
| `internal/storage` | Stockage des blobs : local ou S3 (SigV4 signé à la main) |
| `internal/webhooks` | File de livraison, signature HMAC, réessais |
| `internal/branding` | Résolution du thème, génération de palette, contrôle de contraste |
| `internal/webui` | La SPA embarquée |
| `internal/jobs` | Purge périodique, rétention d'audit, drainage des webhooks |
| `internal/setup` | L'assistant `peek setup` |
| `internal/doctor` | Diagnostics, y compris les vérifications externes |
| `internal/backup` | Sauvegardes à chaud, chiffrement age, restauration |
| `internal/update` | Découverte des versions, vérification empreinte et signature, bascule |
| `web/` | Interface React ; `web/src/crypto` est la référence TypeScript |
| `crypto/vectors` | Vecteurs de test partagés qui lient Go et TypeScript |

Les dépendances vont dans un seul sens : `server`, puis `secrets`, puis
`store`, puis `crypto`. `config` et `crypto` ne dépendent de rien à nous.

## Une requête, de bout en bout

Créer un secret :

```
navigateur                      peek
  │ génère id, clé, sel
  │ dérive enc + jeton de lecture
  │ scelle la charge utile
  ├── POST /api/v1/secrets ────► withContext      résout l'IP client réelle
  │                              securityHeaders  CSP, no-referrer, noindex
  │                              internalOnly     refuse sur l'écouteur public
  │                              restrictCIDR     create_allowed_cidrs
  │                              rateLimit        seau à jetons par IP
  │                              handleCreate     décode, valide les formes
  │                              secrets.Create   politique : durée, lectures, taille, plancher KDF
  │                              store.Create     insère, refuse un id en double
  │                              audit            secret.created (sans contenu)
  ◄── 201 {id, expires_at} ─────┤
  │ construit les liens localement (la clé n'est jamais partie)
```

Révéler :

```
GET  /api/v1/secrets/{id}   métadonnées seulement, audit secret.page_viewed, aucune lecture consommée
POST /api/v1/secrets/{id}/reveal
     comparaison en temps constant de SHA-256(jeton de lecture)
     différent -> compteur d'échecs, 403 avec le nombre d'essais restants, rien n'est libéré
     identique -> transaction -> UPDATE conditionnel -> le nombre de lignes doit valoir 1
                  dernière lecture -> la ligne est supprimée, la pierre tombale écrite
     200 {ciphertext}  -> déchiffré dans le navigateur
```

## Les deux écouteurs

`Server.Handler(role)` construit un routeur par écouteur. Les routes qui
appartiennent à l'émetteur ou à l'administrateur sont enveloppées dans
`internalOnly`, qui les refuse sur l'écouteur public quel que soit le chemin —
une erreur de routage ne peut donc pas exposer la surface d'administration.
Les filtres CIDR sont un second verrou, indépendant.

## Modèle de données

`secrets` ne contient que les secrets vivants. Un secret lu, expiré, brûlé ou
verrouillé est supprimé et remplacé par une ligne dans `secret_tombstones`
(statut et compteurs, sans contenu), pour que la page reçu de l'émetteur
continue de fonctionner. `audit_events` est en ajout seul et n'enregistre
jamais de contenu, de clé ni de fragment.

En mode multi-organisation, `org_domains` porte le lien entre un domaine et
une organisation, et une ligne ne résout que si `verified_at` est renseigné.

## Interface

React 19, Vite, Tailwind 4, aucune dépendance de routage (quelques routes),
aucune bibliothèque de composants, aucun appel réseau en dehors de cette même
origine. `web/src/crypto` est un module autonome sans dépendance à React — le
même code qu'un futur SDK publierait. Le résultat du build est copié dans
`internal/webui/dist` et embarqué ; seul un `.gitignore` y est commité, donc
`go build` fonctionne sur un dépôt frais sans Node installé.

## Concurrence

SQLite tourne en mode WAL avec `_txlock=immediate` et une seule connexion, ce
qui sérialise les écrivains et supprime l'agitation des `SQLITE_BUSY` à ce
volume de requêtes. La garantie de lecture unique ne repose pas là-dessus :
elle vient de l'`UPDATE` conditionnel et de son nombre de lignes, qui tient
aussi sur PostgreSQL et entre plusieurs nœuds.

Pour plusieurs nœuds, la coordination est dans la base et nulle part ailleurs :
des baux nommés dans `job_locks` pour les tâches périodiques, et un seau à
jetons dépensé en un seul `upsert` pour que la grappe ait une limite de débit
et non une par nœud. Voir [HIGH-AVAILABILITY.md](HIGH-AVAILABILITY.md).

## Observabilité

Logs JSON structurés sur la sortie standard, pour journald. Le journal d'accès
enregistre le motif de route qui a correspondu — jamais l'URL — parce qu'un
chemin contient un identifiant de secret et qu'un fragment ne doit jamais
atteindre un log. `/healthz` dit si le processus vit, `/readyz` vérifie la base
de données, et `/api/v1/ip` rapporte l'IP client résolue pour diagnostiquer un
proxy.
