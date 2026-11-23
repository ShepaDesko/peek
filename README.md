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

## Ce qui fonctionne aujourd'hui

| Domaine | État |
|---|---|
| Secrets texte et URL, chiffrés de bout en bout | ✅ |
| Expiration par **durée** et par **nombre de lectures**, appliquée atomiquement | ✅ |
| Étape « cliquer pour révéler » : les robots d'aperçu ne consomment aucune vue | ✅ |
| Passphrase optionnelle, tentatives limitées, secret détruit au-delà | ✅ |
| Page reçu pour l'émetteur : statut en direct, QR code, « détruire maintenant » | ✅ |
| Suppression par le destinataire, suppression réelle à l'expiration, purge chaque minute | ✅ |
| Journal d'audit append-only, sans jamais le contenu d'un secret | ✅ |
| Limitation de débit, CSP stricte, `no-store`, `noindex` | ✅ |
| Marque blanche : nom, couleurs, palette générée avec contrôle de contraste | ✅ |
| Français et anglais, thèmes clair et sombre | ✅ |
| Deux écouteurs : n'exposer que les pages destinataires | ✅ |
| IP client réelle derrière Kemp, F5, HAProxy, nginx (+ PROXY protocol) | ✅ |
| `setup`, `doctor`, `backup`, `restore`, `update` signé avec retour arrière | ✅ |
| `.deb`, `.rpm`, `.tar.gz`, unités systemd durcies, `install.sh` | ✅ |
| `peek-cli push` / `get`, compatible bit à bit avec le navigateur | ✅ |
| Comptes, rôles, SSO, TOTP, passkeys | jalon M5 |
| Éditeur de marque avec aperçu en direct, e-mails brandés | jalon M6 |
| Fichiers, multi-destinataires, demandes de secret, S3 | jalon M7 |
| API REST documentée, jetons, webhooks | jalon M8 |
| PostgreSQL, haute disponibilité, multi-organisation | jalon M9 |

Ce qui n'est pas terminé **refuse franchement** au lieu de faire semblant :
mettre `database.driver = "postgres"` ou `tls.mode = "acme"` empêche le
démarrage avec un message explicite, plutôt que de basculer en silence sur
autre chose.

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/ShepaDesko/peek/main/packaging/install.sh | sudo sh
```

ou depuis un paquet téléchargé :

```bash
sudo apt install ./peek_1.0.0_linux_amd64.deb   # Debian, Ubuntu
sudo dnf install ./peek-1.0.0.amd64.rpm         # RHEL, Rocky, Alma
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
refuse de chiffrer. Terminez le TLS sur votre répartiteur, ou mettez
`tls.mode = "file"`.

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
| [UPGRADE.md](docs/UPGRADE.md) | Mises à jour, mise à jour hors ligne, retour arrière |
| [BACKUP.md](docs/BACKUP.md) | Sauvegarde, restauration, contenu d'une archive |
| [CRYPTO.md](docs/CRYPTO.md) | Le format v1, dérivation des clés, vecteurs de test |
| [THREAT-MODEL.md](docs/THREAT-MODEL.md) | Ce que le zero-knowledge protège, et ce qu'il ne protège pas |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Organisation du code et parcours d'une requête |
| [BRANDING.md](docs/BRANDING.md) | Mettre une instance aux couleurs d'un client |
| [API.md](docs/API.md) | Les points d'entrée HTTP tels qu'implémentés |
| [DECISIONS.md](docs/DECISIONS.md) | Les décisions prises, et pourquoi |
| [SECURITY.md](SECURITY.md) | Signaler une vulnérabilité |

Les documents du dossier `docs/` sont rédigés en anglais ; dites-le si vous les
voulez en français, la traduction est mécanique.

## Licence

Propriétaire. Voir [LICENSE](LICENSE).
