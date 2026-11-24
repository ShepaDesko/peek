# Peek

**Partage de secrets par liens éphémères, auto-hébergé, en marque blanche.**
Un seul binaire Linux, géré par systemd. Pas de Docker, aucun runtime à
installer, rien que le navigateur aille chercher sur Internet.

Un secret est chiffré **dans le navigateur de l'émetteur**. Le serveur ne
stocke qu'un chiffré et deux empreintes. La clé voyage dans le fragment de
l'URL, que les navigateurs n'envoient jamais. Peek ne peut pas lire ce qu'il
héberge — par construction, pas par politique interne.

```
┌── navigateur émetteur ──────┐        ┌── peek ──────────────────┐
│ AES-256-GCM + HKDF          │ POST   │ chiffré                  │
│ (+ Argon2id si passphrase)  │ ─────► │ SHA-256(jeton de lecture)│
│ la clé reste dans le #      │        │ expiration, compteur     │
└─────────────────────────────┘        └──────────────────────────┘
          │  https://coffre.acme.fr/s/<id>#<clé>
          ▼
┌── navigateur destinataire ──┐  preuve de possession, puis une vue est consommée
│ dérive le jeton de lecture  │ ─────► chiffré ─────► déchiffré localement
└─────────────────────────────┘
```

## Ce que fait Peek

| Domaine | |
|---|---|
| Secrets texte, URL et fichiers, chiffrés de bout en bout dans le navigateur | ✅ |
| Expiration par **durée** et par **nombre de lectures**, appliquée atomiquement | ✅ |
| Étape « cliquer pour révéler » : les robots d'aperçu ne consomment aucune vue | ✅ |
| Passphrase optionnelle (Argon2id), tentatives limitées, secret détruit au-delà | ✅ |
| Pièces jointes jusqu'à 100 Mo, chiffrées par morceaux, stockage local ou S3 | ✅ |
| Multi-destinataires : un envoi, plusieurs liens, réglages par destinataire | ✅ |
| **Demandes de secret** : un lien pour qu'on vous envoie quelque chose | ✅ |
| Page reçu : statut en direct, QR code, « détruire maintenant » | ✅ |
| Tableau de bord, suppression par le destinataire, purge chaque minute | ✅ |
| Journal d'audit append-only, export CSV/JSON, export syslog RFC 5424 | ✅ |
| Comptes, quatre rôles, invitations, TOTP, codes de secours, passkeys | ✅ |
| **SSO OpenID Connect** : Entra ID, Google, Keycloak, authentik, ADFS | ✅ |
| Marque blanche complète : éditeur avec aperçu en direct, e-mails brandés | ✅ |
| **API REST** décrite en OpenAPI 3.1, jetons à portée limitée | ✅ |
| **Webhooks** signés HMAC, mis en file et réessayés | ✅ |
| SQLite ou PostgreSQL, **plusieurs nœuds** derrière un répartiteur | ✅ |
| **Multi-organisation** : domaines vérifiés par enregistrement DNS | ✅ |
| Deux écouteurs : n'exposer que les pages destinataires | ✅ |
| IP client réelle derrière Kemp, F5, HAProxy, nginx (+ PROXY protocol) | ✅ |
| TLS : terminé en amont, certificat fourni, ou **Let's Encrypt intégré** | ✅ |
| Français et anglais, thèmes clair et sombre, **WCAG 2.2 AA vérifié** | ✅ |
| `setup`, `doctor`, `backup`, `restore`, `update` signé avec retour arrière | ✅ |
| `.deb`, `.rpm`, `.tar.gz`, unités systemd durcies, `install.sh` | ✅ |
| `peek-cli push` / `get`, compatible bit à bit avec le navigateur | ✅ |

Rien n'est en demi-teinte : il n'y a plus de réglage qui fasse semblant. Ce
principe reste en place pour la suite — une fonction non terminée refuse au
démarrage avec un message explicite plutôt que de basculer en silence sur
autre chose.

### Ce que ça coûte

Sur une machine virtuelle à **un seul vCPU** et 2 Go de RAM : 372 créations et
372 lectures par seconde, p50 13 ms, aucune erreur, 31 Mo de mémoire. Le
binaire pèse 28,8 Mo, la page destinataire 131 ko de JavaScript gzippé — tout
compris, y compris le module Argon2id en WebAssembly, puisque rien n'est
chargé depuis l'extérieur. Détails et méthode :
[docs/PERFORMANCE.md](docs/PERFORMANCE.md).

### Ce que Peek ne fait pas

- **Il ne peut pas lire ce qu'il héberge.** Ce n'est pas une politique, c'est
  la construction : la clé ne quitte jamais le navigateur.
- **Il ne vous protège pas d'un serveur compromis qui servirait un JavaScript
  modifié.** Aucune application web ne le peut. C'est écrit noir sur blanc
  dans [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md), avec ce qu'il faut faire
  à la place.
- **Il n'appelle rien à l'extérieur par défaut** — ni CDN, ni police web, ni
  analytique. Les seuls appels sortants possibles sont ceux que vous
  configurez : SMTP, votre fournisseur d'identité, vos webhooks, la
  vérification de mise à jour.
- **Il n'y a pas de Docker.** Un binaire, une unité systemd.

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/ShepaDesko/peek/main/packaging/install.sh | sudo sh
```

ou depuis un paquet téléchargé :

```bash
sudo apt install ./peek_*_linux_amd64.deb   # Debian, Ubuntu
sudo dnf install ./peek-*.amd64.rpm         # RHEL, Rocky, Alma
sudo peek setup
```

`peek setup` demande l'URL publique, le mode d'exposition, les écouteurs, le
TLS, la base de données et le SMTP, écrit `/etc/peek/peek.toml`, génère la clé
maîtresse, crée le compte de service et les répertoires, démarre le service,
active la sauvegarde quotidienne et termine par un `peek doctor`.

Détails : [docs/INSTALL.md](docs/INSTALL.md).

## HTTPS obligatoire

Le chiffrement a lieu dans le navigateur, et les navigateurs n'exposent
WebCrypto qu'en `https://` ou sur `localhost`. Une instance publiée en HTTP
simple sur une adresse de LAN s'affiche, explique clairement le problème, et
refuse de chiffrer. Trois façons de régler ça : terminer le TLS sur votre
répartiteur (`tls.mode = "none"`, le cas normal), fournir un certificat
(`tls.mode = "file"`), ou laisser Peek obtenir et renouveler lui-même un
certificat Let's Encrypt (`tls.mode = "acme"`, via TLS-ALPN-01, sans port 80).

## Mise à jour

```bash
sudo peek update              # vérifie la signature, sauvegarde, remplace, contrôle, revient en arrière si besoin
sudo peek update --check      # code de retour 10 si une version est disponible
sudo peek update --file peek_1.4.2_linux_amd64.tar.gz   # serveur hors ligne
sudo peek rollback
```

Détails : [docs/UPGRADE.md](docs/UPGRADE.md).

## Exposer l'instance sans exposer l'administration

Peek est prévu pour vivre derrière un répartiteur de charge en ne publiant que
ses pages destinataires :

```toml
[server]
internal_listen = "10.0.0.5:8080"   # création, tableau de bord, administration, API
public_listen   = "10.0.0.5:8081"   # pages destinataires uniquement — publiez celui-ci
trusted_proxies = ["10.0.0.0/24"]   # seules sources dont les X-Forwarded-* sont crus
```

Configurations prêtes à l'emploi pour Kemp LoadMaster, HAProxy, nginx, F5,
Apache et Traefik : [docs/REVERSE-PROXY.md](docs/REVERSE-PROXY.md).
Puis, depuis le serveur :

```bash
sudo peek doctor --external
```

Il indique l'IP client que Peek résout réellement, l'état du certificat, et
surtout si l'administration répond à travers l'URL publique — l'erreur qui
compte.

## Compiler depuis les sources

Go 1.26+ et Node 22+. Pas de Docker.

```bash
make deps
make build        # compile l'interface, l'embarque, produit bin/peek
make test         # tests Go avec -race, tests TypeScript, vecteurs de crypto partagés
make lint
./bin/peek version
```

Boucle de développement (API sur :8080, Vite sur :5173) :

```bash
make dev-config
make dev
```

## Documentation

| Document | Contenu |
|---|---|
| [INSTALL.md](docs/INSTALL.md) | Installation, compte de service, première mise en route |
| [CONFIG.md](docs/CONFIG.md) | Tous les réglages de `peek.toml` |
| [REVERSE-PROXY.md](docs/REVERSE-PROXY.md) | Kemp, HAProxy, nginx, F5, Apache, Traefik, exposition directe |
| [HIGH-AVAILABILITY.md](docs/HIGH-AVAILABILITY.md) | Plusieurs nœuds, PostgreSQL partagé, stockage partagé |
| [PERFORMANCE.md](docs/PERFORMANCE.md) | Ce que ça coûte à faire tourner, mesuré |
| [UPGRADE.md](docs/UPGRADE.md) | Mises à jour, mise à jour hors ligne, retour arrière |
| [BACKUP.md](docs/BACKUP.md) | Sauvegarde, restauration, contenu d'une archive |
| [CRYPTO.md](docs/CRYPTO.md) | Le format v1, dérivation des clés, vecteurs de test |
| [THREAT-MODEL.md](docs/THREAT-MODEL.md) | Ce que le zero-knowledge protège, et ce qu'il ne protège pas |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Organisation du code et parcours d'une requête |
| [BRANDING.md](docs/BRANDING.md) | Mettre une instance aux couleurs d'un client |
| [DESIGN.md](docs/DESIGN.md) | La direction artistique de l'interface, et ce qui reste à y passer |
| [API.md](docs/API.md) | Les points d'entrée HTTP tels qu'implémentés |
| [RELEASING.md](docs/RELEASING.md) | Couper une version, la clé de signature |
| [DECISIONS.md](docs/DECISIONS.md) | Les décisions prises, et pourquoi |
| [SECURITY.md](SECURITY.md) | Signaler une vulnérabilité |

Les documents du dossier `docs/` sont rédigés en anglais ; dites-le si vous les
voulez en français, la traduction est mécanique.

## Licence

Propriétaire. Voir [LICENSE](LICENSE).
