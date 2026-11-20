# SPEC.md — Peek : partage de secrets éphémères, auto-hébergé, en marque blanche

> **Peek** est une application de partage de secrets par liens éphémères (type OneTimeSecret / Password Pusher / Dele.to), installée **nativement sur Linux (sans Docker)**, déployée **en local chez chaque client**, exposable sur Internet si le client le souhaite (derrière un Kemp, F5, HAProxy, nginx… ou en direct).
> Ce document est le cahier des charges de référence pour Claude Code. Le lire en entier avant toute action.

---

## 0. Instructions pour Claude Code (à lire en premier)

1. **Commence en mode plan.** Lis ce fichier, propose un plan d'implémentation découpé selon les jalons de la section 13. N'écris pas de code avant que je valide le plan.
2. **Pose-moi les questions de la section 14 ("Décisions à valider")** avant le jalon M0. Si je ne réponds pas à une question, applique la valeur par défaut et note-la dans `docs/DECISIONS.md`.
3. **Travaille jalon par jalon.** À la fin de chaque jalon : tests verts, lint propre, `docs/` à jour, commits en Conventional Commits, puis arrête-toi et fais-moi un résumé (ce qui marche, ce qui reste, ce que je dois tester).
4. **La sécurité passe avant les fonctionnalités.** Entre "pratique" et "sûr", choisis "sûr" et signale-le moi.
5. **Pas de Docker, nulle part** (ni pour l'exécution, ni dans la doc d'installation). Le produit est un **binaire Linux natif** géré par **systemd**. Docker/Testcontainers est toléré **uniquement** en CI pour les tests d'intégration PostgreSQL, si nécessaire.
6. **Aucune dépendance externe à l'exécution côté navigateur** : pas de CDN, pas de Google Fonts, pas d'analytics, pas de script tiers. Tout est embarqué dans le binaire.
7. **Aucun appel sortant par défaut** depuis le serveur, sauf : SMTP configuré, IdP SSO configuré, webhooks configurés, et la vérification de mise à jour (désactivable). Peek doit fonctionner sur un réseau isolé (air-gapped).
8. **Ne jamais logger** un secret, une clé, une passphrase, un fragment d'URL, un corps de requête de création/lecture, ni un jeton d'API en clair.
9. Crée et maintiens un `CLAUDE.md` à la racine : commandes (dev, test, lint, build, release locale), conventions, pièges connus. Court.
10. Vérifie les versions actuelles et la documentation des bibliothèques plutôt que de te fier à ta mémoire.

---

## 1. Vision

| Inspiration | Ce qu'on reprend |
|---|---|
| **OneTimeSecret** | Simplicité extrême, page "reçu" pour l'émetteur (statut lu/non lu, brûler le secret), domaine personnalisé, API |
| **Password Pusher** | Expiration par vues **et/ou** durée, étape de récupération en 1 clic (anti-robots de prévisualisation), suppression par le destinataire, fichiers / URL / QR codes, **demandes de secret**, journal d'audit complet (tentatives échouées incluses), générateur de mots de passe, envoi par e-mail, API JSON, multilingue, mode sombre |
| **Dele.to / Yopass / PrivateBin** | **Chiffrement de bout en bout dans le navigateur (zero-knowledge)** ; partage **multi-destinataires** avec réglages individuels |

**Différenciateurs de Peek** : zero-knowledge **+** fonctions entreprise (audit, SSO, API, politiques) **+** marque blanche complète **+** installation native en un binaire, mise à jour en une commande, prévu pour l'on-premise et l'exposition contrôlée.

---

## 2. Modèle de déploiement

- **Une installation = un client** (mode par défaut, *single-tenant*) : la marque, les utilisateurs, les politiques sont ceux de l'instance.
- **Mode multi-organisation optionnel** (`multi_org = true`) : une même instance héberge plusieurs organisations, chacune avec sa marque et son domaine (utile si j'héberge Peek pour plusieurs clients). Le code doit être pensé multi-org dès le départ (`org_id` partout), mais l'interface masque cette notion en mode single-tenant.
- Topologies supportées :
  1. **Interne uniquement** : accessible sur le LAN / VPN.
  2. **Exposé directement** : Peek termine lui-même le TLS (certificat fourni ou ACME/Let's Encrypt).
  3. **Derrière un répartiteur / reverse proxy** : Kemp LoadMaster, F5, HAProxy, nginx, Apache, Traefik… avec terminaison TLS au proxy (*SSL offload*) ou re-chiffrement.
  4. **Haute disponibilité** : plusieurs nœuds Peek derrière le répartiteur, base PostgreSQL partagée, stockage fichiers partagé (S3-compatible ou NFS).
- **Séparation interne / externe** (fonction clé pour l'exposition) : possibilité de n'exposer à l'extérieur **que** les pages destinataires (lecture de secret, dépôt sur une demande), tandis que la connexion, la création, le tableau de bord, l'administration et l'API restent **réservés au réseau interne**. Deux façons, cumulables :
   - listes `admin_allowed_cidrs` / `create_allowed_cidrs` (contrôlées sur l'IP client réelle, après résolution des proxys de confiance) ;
   - **deux écouteurs distincts** : `public_listen` (routes destinataires uniquement) et `internal_listen` (tout), pour publier seulement le premier sur le répartiteur.

---

## 3. Périmètre fonctionnel

### 3.1 Types de secrets
- **Texte / mot de passe**, avec générateur intégré (longueur, classes de caractères, passphrase de mots FR/EN, exclusion des caractères ambigus, indicateur d'entropie).
- **Fichier(s)** : un ou plusieurs, chiffrés dans le navigateur avant envoi (par morceaux, en streaming pour les gros fichiers). Taille max configurable.
- **URL** : affichée au destinataire avec un bouton d'ouverture (jamais de redirection automatique).
- **Texte + fichiers** combinés.
- **QR code** du lien de partage ; option "secret affiché en QR" (ex. Wi-Fi).

### 3.2 Options à la création
- Expiration par **durée** (5 min → 30 jours, bornée par la politique) **et/ou** **nombre de vues** (1 → 100).
- **Passphrase** optionnelle (à transmettre par un autre canal).
- **Étape de récupération** ("Cliquer pour révéler") activée par défaut : un robot de prévisualisation (Teams, Slack, Outlook Safe Links, antivirus mail…) ne consomme **jamais** une vue.
- **Suppression par le destinataire** autorisée ou non.
- **Libellé privé** et **note interne** (visibles uniquement par l'émetteur).
- **Multi-destinataires** : N liens distincts (défaut max 10), chacun avec sa propre expiration, ses vues, sa passphrase et sa propre ligne d'audit.
- **Envoi du lien par e-mail** (si SMTP configuré). La passphrase n'est **jamais** envoyée par e-mail.
- **Notification à l'émetteur** (e-mail et/ou webhook) à la lecture, l'expiration ou la suppression.

### 3.3 Côté destinataire
- Page aux couleurs du client, message optionnel de l'émetteur (chiffré lui aussi), avertissement "ne s'affiche qu'une fois".
- "Révéler" → passphrase si requise → affichage. Boutons : copier, afficher/masquer, télécharger, "Supprimer maintenant" (si autorisé).
- Réponse **identique** côté serveur pour "expiré", "déjà consulté" et "inexistant" (ne pas révéler l'existence d'un secret). Message brandé.

### 3.4 Côté émetteur
- **Page reçu** : lien(s), QR code, récapitulatif, statut en temps réel, "Brûler maintenant".
- **Tableau de bord** : secrets envoyés avec statut (actif / consulté / expiré / brûlé), filtres, recherche par libellé, audit par secret, brûlage.
- **Demandes de secret** : je crée un lien de demande ("Envoie-moi le mot de passe du compte X"), le destinataire y dépose un secret chiffré **avec ma clé publique**, moi seul peux le lire. Usage unique, expiration configurable.

### 3.5 Comptes et rôles
- Rôles : `admin` (administre l'instance), `manager` (gère utilisateurs et politiques), `member`, `auditor` (lecture seule de l'audit). En mode multi-org : `platform_admin` au-dessus.
- Création anonyme : désactivée par défaut, activable (avec restriction par CIDR possible).
- Invitations par e-mail, désactivation, transfert de propriété des secrets d'un utilisateur parti.

### 3.6 Authentification
- Comptes locaux : e-mail + mot de passe (Argon2id), **TOTP** (obligatoire si la politique l'exige), codes de secours.
- **Passkeys (WebAuthn)**.
- **SSO OIDC** (Microsoft Entra ID, Google Workspace, Keycloak, Authentik, ADFS en OIDC…), option "SSO obligatoire", provisionnement à la première connexion, mapping groupes → rôles.
- **LDAP / Active Directory** (bind + filtre de groupe) : jalon ultérieur, mais prévoir l'interface `AuthProvider`.
- Sessions : cookie `HttpOnly; Secure; SameSite=Lax`, rotation, expiration d'inactivité configurable, sessions actives révocables.

### 3.7 Politiques
- Durée max/défaut, vues max/défaut, passphrase obligatoire, étape de récupération forcée, types autorisés, taille max fichiers, CIDR autorisés pour créer / administrer / lire, domaines e-mail autorisés pour les destinataires, nombre max de tentatives de passphrase.

### 3.8 Audit et conformité
- Journal **append-only** par secret et global : création, consultation de la page, tentative de passphrase échouée, révélation, suppression, expiration, purge — horodatage, IP (anonymisation optionnelle), user-agent, utilisateur.
- Journal d'administration : marque, politiques, rôles, SSO, jetons d'API, mises à jour de Peek.
- Export CSV/JSON ; **export syslog** optionnel (RFC 5424, UDP/TCP/TLS) pour le SIEM du client.
- Rétention configurable des journaux et des IP (RGPD). Pages mentions légales / confidentialité éditables.
- Le contenu des secrets n'apparaît **jamais** dans l'audit.

### 3.9 API et intégrations
- **API REST `/api/v1`**, spécification **OpenAPI 3.1** générée depuis le code, page de documentation intégrée.
- **Jetons d'API** avec portées (`secrets:create`, `secrets:read_meta`, `audit:read`, `admin`), expiration, révocation, dernier usage.
- Le chiffrement étant côté client : **SDK JavaScript** (`web/src/crypto`, publiable) et **CLI** `peek-cli` (push / get / request) qui chiffrent localement, compatibles bit à bit grâce aux vecteurs de test.
- **Webhooks** signés HMAC : `secret.viewed`, `secret.expired`, `secret.burned`, `request.fulfilled`.
- Plus tard : bot Teams/Slack, extension navigateur.

### 3.10 Interface
- Responsive (mobile d'abord), clair/sombre (système + choix manuel).
- **i18n** FR + EN minimum, extensible ; langue par défaut définie par l'admin, choix du visiteur mémorisé.
- **Accessibilité WCAG 2.2 AA**.
- Esthétique soignée et sobre, pas de "template par défaut".

---

## 4. Marque blanche — exigence centrale

Page **"Personnalisation"** avec **aperçu en direct** (accueil, page destinataire, e-mail) :

### 4.1 Identité visuelle
- Nom affiché du service (ex. "Coffre ACME" au lieu de "Peek").
- Logo clair + logo sombre (SVG assaini côté serveur, PNG, WebP), favicon (tailles générées automatiquement), image Open Graph.
- Couleur primaire + accent → palette complète générée automatiquement, **contrôle de contraste AA** avec avertissement.
- Rayon des coins, style des boutons, police parmi une liste **embarquée** dans le binaire.
- Fond (couleur ou image).
- **CSS personnalisé** (admin uniquement, assaini, taille limitée, ni `@import` ni `url()` externe).

### 4.2 Textes
- Titre/sous-titre d'accueil, texte d'aide, message par défaut au destinataire, texte "secret expiré", pied de page, liens (support, mentions, confidentialité), contact.
- Chaque texte traduisible (un champ par langue activée).
- "Masquer *Propulsé par Peek*" (réglable).

### 4.3 E-mails
- Nom et adresse d'expéditeur, SMTP (STARTTLS/TLS, authentification ou relais anonyme interne).
- Modèles (envoi de lien, notification, invitation, demande) HTML + texte, aux couleurs du client, éditables avec variables et aperçu, bouton "envoyer un e-mail de test".

### 4.4 Domaine(s)
- Mode single-tenant : `public_url` dans la configuration.
- Mode multi-org : un ou plusieurs domaines par org, vérifiés par enregistrement DNS TXT ; la marque est résolue par l'en-tête `Host` (pris uniquement d'un proxy de confiance ou de la connexion directe).

### 4.5 Implémentation
- Thème servi en **variables CSS** via `/api/v1/branding` (cache + ETag).
- Assets stockés dans le répertoire de données (ou S3), servis par Peek.
- **Export / import de la marque** en un fichier (`peek branding export > acme.peekbrand`) pour préparer une marque une fois et la déployer chez un client.

---

## 5. Modèle de sécurité (non négociable)

### 5.1 Chiffrement zero-knowledge
- Chiffrement dans le navigateur (WebCrypto) : **AES-256-GCM**, clé aléatoire 256 bits par secret (et par destinataire).
- Clé dans le **fragment d'URL** (`https://…/s/<id>#<clé>`) : jamais envoyée au serveur, absente des logs et du `Referer`.
- **Avec passphrase** : clé finale = `HKDF-SHA256(clé_aléatoire ‖ Argon2id(passphrase, sel))`. Argon2id en WASM côté navigateur (paramètres adaptés au mobile, documentés).
- **Preuve de possession avant révélation** : le client dérive de la clé finale un `jeton_de_lecture` (HKDF, info `"peek-read-v1"`). Le serveur ne stocke que `SHA-256(jeton_de_lecture)`. Le chiffré n'est renvoyé, et la vue décomptée, **qu'après** vérification en temps constant. Une mauvaise passphrase ou un robot ne consomme donc rien. Les échecs sont comptés et limités (défaut 5, puis secret brûlé).
- **Fichiers** : chiffrement par morceaux (nonce par morceau, authentification de l'ordre et de la fin du flux), noms et types MIME chiffrés.
- **Demandes de secret** : paire ECDH (P-256, ou X25519 si dispo dans WebCrypto) générée chez le demandeur ; clé privée uniquement dans le fragment de son lien "reçu" ; dépôt chiffré par ECIES (ECDH + HKDF + AES-GCM).
- Format chiffré **versionné** (`v1`).
- **Vecteurs de test** partagés entre le navigateur (TS), le serveur et la CLI (Go) : ils doivent tous passer.

### 5.2 Serveur
- Stocke uniquement : identifiant aléatoire (≥ 128 bits), chiffré, métadonnées minimales, hash du jeton de lecture, paramètres KDF.
- Décompte de vue + suppression **atomiques** (transaction) : jamais deux lectures d'un secret à vue unique, y compris en multi-nœuds.
- **Suppression réelle** à l'expiration ou à la dernière vue (ligne + fichier), seule la trace d'audit reste. Purge planifiée chaque minute (+ orphelins), avec verrou pour qu'un seul nœud la fasse en HA.
- Métadonnées sensibles (libellés, e-mails destinataires, secrets SMTP/OIDC) **chiffrées au repos** avec une clé serveur (fichier `/etc/peek/master.key`, rotation outillée : `peek key rotate`).

### 5.3 Web
- CSP stricte (`default-src 'self'`, pas de `unsafe-inline` pour les scripts), `Referrer-Policy: no-referrer`, HSTS (désactivable si TLS géré ailleurs), `X-Content-Type-Options`, `Permissions-Policy`, COOP, `frame-ancestors 'none'`.
- `Cache-Control: no-store` sur tout ce qui touche aux secrets.
- CSRF sur les routes à session, validation stricte des entrées, limites de taille.
- **Rate limiting** sur création, lecture, passphrase, connexion, API, basé sur l'IP client **réelle** (voir §7.3). En mémoire en mono-nœud, en base en multi-nœuds.
- `noindex` + `robots.txt`.
- `SECURITY.md` : modèle de menace (ce que le zero-knowledge protège ou non, ex. serveur compromis servant un JS modifié), politique de divulgation.

---

## 6. Stack technique

| Couche | Choix | Raison |
|---|---|---|
| Backend | **Go** (dernière version stable), `net/http` + routeur léger (chi) | **Un seul binaire statique**, sans runtime à installer, idéal en natif et on-prem |
| Front | **React + Vite + TypeScript + Tailwind CSS** + composants accessibles (Radix) | Compilé puis **embarqué dans le binaire** (`go:embed`) |
| Crypto navigateur | WebCrypto + hash-wasm (Argon2id) | Natif, embarqué |
| Crypto Go (CLI, vecteurs) | stdlib `crypto/*` + `golang.org/x/crypto` (argon2, hkdf) | Pas de CGO |
| Base de données | **SQLite** (mode WAL, driver pur Go sans CGO) **par défaut** ; **PostgreSQL** pour la haute disponibilité | Zéro dépendance pour une install simple, Postgres quand il faut plusieurs nœuds |
| Accès données | Requêtes SQL typées (sqlc ou équivalent) avec couche compatible SQLite + PostgreSQL ; migrations versionnées embarquées (goose ou équivalent) | |
| Stockage fichiers | Interface `Storage` : **disque local** (défaut), **S3-compatible** (MinIO, Scaleway, OVH, NetApp…) | Le disque local peut être un NFS partagé en HA |
| Jobs | Planificateur interne (goroutines) + verrou en base en multi-nœuds | Pas de Redis nécessaire |
| E-mails | `html/template` + mise en forme compatible clients mail | |
| Auth | `go-oidc`, `go-webauthn`, `pquerna/otp`, Argon2id | |
| TLS intégré | `crypto/tls` + ACME (certmagic) optionnel | Exposition directe sans proxy |
| Tests | `go test` (+ `-race`), Vitest (front et crypto TS), **Playwright** (E2E) | |
| Packaging | **GoReleaser** : `.tar.gz`, **`.deb`**, **`.rpm`**, pour **amd64 et arm64** ; sommes SHA-256 ; **signature** (minisign ou cosign) ; SBOM | |

Repli possible si je refuse Go (voir §14) : Node.js LTS installé nativement, mais l'installation et les mises à jour deviennent plus lourdes ; le signaler avant.

---

## 7. Installation native, configuration, exposition

### 7.1 Arborescence sur le serveur (FHS)
```
/usr/bin/peek                  # binaire unique (serveur + commandes d'admin)
/etc/peek/peek.toml            # configuration (commentée)
/etc/peek/master.key           # clé de chiffrement serveur (0600, propriétaire peek)
/etc/peek/tls/                 # certificats si Peek termine le TLS
/var/lib/peek/                 # base SQLite, fichiers chiffrés, assets de marque
/var/backups/peek/             # sauvegardes locales
/usr/lib/systemd/system/peek.service
/usr/lib/systemd/system/peek-backup.{service,timer}
```
- Utilisateur système dédié `peek`, sans shell.
- Logs : **journald** (JSON structuré sur stdout), option fichier + logrotate.

### 7.2 Installation
Trois voies, documentées dans `docs/INSTALL.md` :
1. **Paquet** : `apt install ./peek_1.0.0_amd64.deb` ou `dnf install ./peek-1.0.0.x86_64.rpm`, puis `sudo peek setup`.
2. **Dépôt APT/YUM** (jalon ultérieur, hébergé sur GitHub Pages ou serveur de téléchargement) pour `apt upgrade`.
3. **Script** : `curl -fsSL https://<url>/install.sh | sudo bash` (vérifie la signature, détecte la distribution et l'architecture, installe le paquet adapté). Le script doit aussi pouvoir être téléchargé, relu, puis exécuté.

`sudo peek setup` — **assistant interactif** (et version non interactive via options/variables pour l'automatisation) :
- URL publique, langue, mode (interne / exposé direct / derrière un proxy), écoute(s), TLS (aucun / certificat fourni / ACME), SQLite ou PostgreSQL (test de connexion), stockage, SMTP (test d'envoi), séparation interne/externe.
- Génère `master.key`, écrit `peek.toml`, crée l'utilisateur `peek` et les répertoires avec les bons droits, active et démarre `peek.service`, active le timer de sauvegarde.
- Crée le premier `admin` via un **lien d'initialisation à usage unique** affiché dans le terminal.
- Termine par un `peek doctor`.

Distributions cibles (testées en CI) : **Debian 12/13, Ubuntu 22.04/24.04, RHEL/Rocky/Alma 9**.

### 7.3 Exposition externe / répartiteur de charge
- `public_url` = URL vue par les utilisateurs (sert aux liens, cookies, CSP, redirections OIDC).
- `trusted_proxies` = liste de CIDR. **Seulement** depuis ces IP, Peek honore `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` (et `Forwarded` RFC 7239, et optionnellement **PROXY protocol v1/v2**). Ailleurs, ces en-têtes sont ignorés.
- Health checks pour le répartiteur : `/healthz` (vivant), `/readyz` (base + stockage OK) ; réponses légères, sans authentification, sans infos sensibles.
- Pas de sessions collantes nécessaires en multi-nœuds (sessions en base).
- Prise en charge des gros fichiers via proxy (envoi par morceaux, tailles et délais documentés).
- **`docs/REVERSE-PROXY.md`** avec exemples prêts à l'emploi : **Kemp LoadMaster** (Virtual Service, SSL offload ou re-chiffrement, insertion de X-Forwarded-For, health check sur `/readyz`, publication du seul écouteur public), **F5**, **HAProxy**, **nginx**, **Apache**, **Traefik**, ainsi qu'une section "exposition directe avec Let's Encrypt".
- `peek doctor --external` : vérifie depuis le serveur que l'URL publique répond, que le certificat est valide, que l'IP client est bien résolue (page de diagnostic qui affiche l'IP vue par Peek), et que les routes d'admin ne sont pas joignables depuis l'écouteur public.

### 7.4 Commandes du binaire
```
peek serve                 # lancé par systemd
peek setup                 # assistant d'installation / reconfiguration
peek doctor [--external]   # diagnostic complet (config, droits, base, stockage, SMTP, TLS, horloge, espace disque)
peek config check|show     # validation / affichage (secrets masqués)
peek admin create|reset-password|disable-2fa
peek backup [--to DIR]     # sauvegarde à chaud cohérente
peek restore FILE
peek update [...]          # voir §8
peek migrate status|up     # normalement automatique
peek key rotate
peek branding export|import
peek version
```

---

## 8. Mises à jour faciles (exigence forte)

### 8.1 `sudo peek update`
1. Interroge les **GitHub Releases** (ou une URL de mise à jour configurable / un miroir interne) et affiche la version disponible + le résumé du changelog.
2. Télécharge l'archive de la bonne architecture, **vérifie la somme SHA-256 et la signature** (clé publique embarquée dans le binaire). Refus net en cas d'échec.
3. **Sauvegarde automatique** (base + config + clé) avant toute modification.
4. Remplace le binaire de façon atomique, garde l'ancien (`/usr/lib/peek/peek.previous`).
5. Redémarre le service ; les **migrations s'appliquent au démarrage**.
6. Vérifie `/readyz` pendant N secondes. En cas d'échec : **retour arrière automatique** (ancien binaire + restauration de la base si une migration a été appliquée), puis affiche le journal d'erreur.
7. Écrit l'opération dans le journal d'administration.

Options :
- `peek update --check` : affiche seulement s'il y a une mise à jour (code de retour exploitable en script/supervision).
- `peek update --version 1.4.2` : version précise (y compris retour à une version antérieure si les migrations le permettent).
- `peek update --file peek_1.4.2_linux_amd64.tar.gz` : **mise à jour hors ligne** pour les serveurs sans accès Internet (signature vérifiée de la même manière).
- `peek update --channel stable|beta`.
- `peek rollback` : revient à la version précédente.

### 8.2 Autres canaux
- Si installé par paquet : `apt install ./peek_x.y.z.deb` / `dnf upgrade ./peek-x.y.z.rpm` doit produire le même résultat (scripts de post-installation : sauvegarde, redémarrage, contrôle de santé).
- Plus tard : dépôt APT/YUM signé pour `apt upgrade`.

### 8.3 Dans l'interface
- Bannière admin "Nouvelle version disponible" avec changelog (vérification quotidienne, **désactivable** via `update_check = false`).
- **Pas** de mise à jour déclenchée depuis le navigateur en v1 (le processus web n'a pas les droits root) ; afficher la commande à lancer.

### 8.4 Règles de compatibilité
- Versionnement **SemVer**. Les migrations doivent rester compatibles avec un retour à la version mineure précédente quand c'est possible ; sinon, le changelog l'indique clairement et `peek update` demande confirmation.
- Tout changement de format de configuration est migré automatiquement avec sauvegarde de l'ancien `peek.toml`.
- Test CI obligatoire : installer la version N-1, créer des données, mettre à jour vers N, vérifier que tout fonctionne, faire un rollback.

---

## 9. Sauvegarde et restauration
- `peek-backup.timer` quotidien (heure configurable) : sauvegarde cohérente à chaud (SQLite `VACUUM INTO` / `pg_dump`), fichiers, `peek.toml`, `master.key` ; archive **chiffrée** (age, avec clé ou phrase définie au setup) ; rotation (défaut 7 jours) ; copie distante optionnelle (S3, SFTP, rsync).
- `peek restore` testé en CI.
- Note dans `docs/BACKUP.md` : les sauvegardes contiennent les chiffrés des secrets encore actifs → garder une rétention courte. Sans `master.key`, les métadonnées chiffrées sont irrécupérables → la sauvegarder à part.

---

## 10. Architecture du dépôt
```
peek/
├── cmd/
│   ├── peek/                 # binaire serveur + commandes d'admin
│   └── peek-cli/             # CLI utilisateur (push/get/request)
├── internal/
│   ├── server/  api/  auth/  secrets/  requests/  audit/  branding/
│   ├── crypto/               # implémentation Go + vecteurs de test
│   ├── store/                # SQLite + PostgreSQL, migrations embarquées
│   ├── storage/              # local, S3
│   ├── mail/  webhooks/  jobs/  update/  backup/  setup/  doctor/
│   └── config/
├── web/                      # SPA React (embarquée au build)
│   └── src/crypto/           # implémentation TS + mêmes vecteurs de test
├── packaging/
│   ├── systemd/  (peek.service durci, peek-backup.service/.timer)
│   ├── deb/ rpm/ (scripts pre/post install/upgrade/remove)
│   ├── install.sh
│   └── peek.toml.example
├── docs/
│   ├── INSTALL.md  UPGRADE.md  BACKUP.md  CONFIG.md  REVERSE-PROXY.md
│   ├── ARCHITECTURE.md  CRYPTO.md  THREAT-MODEL.md  BRANDING.md  API.md
│   └── DECISIONS.md
├── test/e2e/                 # Playwright
├── .github/workflows/
│   ├── ci.yml                # lint, tests Go (-race) + TS, E2E, govulncheck, audit npm, tests d'install sur VMs/containers de CI des distributions cibles
│   └── release.yml           # sur tag vX.Y.Z : GoReleaser → tar.gz/.deb/.rpm amd64+arm64, signatures, SBOM, notes de version
├── .goreleaser.yaml
├── CLAUDE.md  README.md  SECURITY.md  LICENSE  CHANGELOG.md
```

### Unité systemd (exigences de durcissement)
`User=peek`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/peek /var/backups/peek`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernel*=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`, `AmbientCapabilities=CAP_NET_BIND_SERVICE` uniquement si écoute sur 80/443, `Restart=on-failure`. Vérifier avec `systemd-analyze security peek` (objectif : note "OK" ou mieux).

---

## 11. Modèle de données (indicatif)
- `organizations` (id, slug, nom, politiques JSON) — une seule ligne en mode single-tenant
- `org_domains` (org_id, domaine, jeton_vérif, vérifié_le)
- `branding` (org_id, couleurs, police, textes i18n JSON, logos, favicon, css_perso, masquer_powered_by, version)
- `users`, `memberships`, `sessions`, `passkeys`, `totp`, `recovery_codes`
- `sso_providers` (org_id, issuer, client_id, secret chiffré, mapping groupes→rôles, obligatoire)
- `api_tokens` (hash, portées, expiration, dernier_usage)
- `secrets` (id public, org_id, créateur nullable, type, chiffré ou référence stockage, taille, hash_jeton_lecture, sel/params KDF, a_passphrase, vues_restantes, vues_max, expire_le, étape_récupération, supprimable_par_destinataire, tentatives_échouées, libellé chiffré, groupe_id multi-destinataires, statut)
- `secret_requests` (id, org_id, créateur, clé publique, texte, expire_le, statut)
- `audit_events` (append-only)
- `webhooks`, `webhook_deliveries`, `email_templates`, `settings`, `job_locks`, `update_history`

---

## 12. Qualité
- Go : `gofmt`, `golangci-lint`, `go test -race`, `govulncheck`. TS : strict, ESLint, Prettier.
- Couverture élevée sur la crypto (Go et TS) et sur la consommation des secrets.
- E2E Playwright indispensables : créer → révéler → relire (échec) ; mauvaise passphrase (aucune vue consommée) ; robot de prévisualisation (GET sans clic = aucune vue) ; multi-destinataires ; fichier de 100 Mo ; demande de secret ; changement de marque visible ; écouteur public n'expose pas l'admin ; IP réelle correcte derrière un proxy de confiance et en-têtes ignorés sinon.
- Concurrence : 50 lectures simultanées d'un secret à 1 vue → exactement 1 succès (SQLite **et** PostgreSQL, et à deux nœuds).
- Tests d'installation, de mise à jour N-1 → N, de rollback et de restauration sur chaque distribution cible.
- Accessibilité automatisée (axe).
- Budgets : binaire < 60 Mo, mémoire au repos < 100 Mo, page destinataire < 150 Ko JS gzip.

---

## 13. Jalons

| Jalon | Contenu | Critère de fin |
|---|---|---|
| **M0 – Fondations** | Repo, outillage Go + front, `go:embed` du front, CI, `CLAUDE.md`, config TOML, `/healthz` `/readyz`, logs | `make dev` lance tout ; CI verte ; un binaire unique sert la SPA |
| **M1 – Cœur crypto** | Crypto TS + Go, vecteurs de test communs, `CRYPTO.md` | Vecteurs OK en navigateur, Node et Go |
| **M2 – Secrets texte (MVP)** | Création, lien, étape de récupération, passphrase, vues/durée, reçu, brûlage, purge, rate limiting, en-têtes de sécurité, SQLite | E2E de base + test de concurrence verts |
| **M3 – Installation & mises à jour** | GoReleaser (.deb/.rpm/.tar.gz signés), systemd durci, `peek setup`, `peek doctor`, `peek update` (en ligne + hors ligne + rollback), `peek backup/restore`, `install.sh`, `INSTALL.md`/`UPGRADE.md` | Installation de zéro sur Debian 12 et Rocky 9 en < 5 min ; mise à jour N-1 → N et rollback automatiques testés |
| **M4 – Exposition** | `trusted_proxies`, PROXY protocol, double écouteur, CIDR admin/création, TLS intégré + ACME, `doctor --external`, `REVERSE-PROXY.md` (Kemp en premier) | Peek fonctionne derrière HAProxy en CI avec IP réelle correcte ; admin injoignable depuis l'écouteur public |
| **M5 – Comptes & audit** | Auth locale + TOTP + passkeys, rôles, invitations, tableau de bord, audit, export syslog, politiques | Un manager gère ses utilisateurs et consulte l'audit |
| **M6 – Marque blanche** | Personnalisation complète avec aperçu, e-mails brandés, export/import de marque, i18n FR/EN | Changer logo/couleurs/textes se reflète partout, y compris dans les e-mails |
| **M7 – Fichiers, URL, QR, multi-destinataires, demandes** | §3.1–3.4 restants, stockage S3 | E2E correspondants verts |
| **M8 – API, CLI, webhooks, SSO OIDC** | `/api/v1` + OpenAPI, jetons, `peek-cli`, webhooks signés, SSO (Entra ID testé) | CLI push/get OK contre une instance |
| **M9 – PostgreSQL & HA, multi-org** | Support Postgres, verrous de jobs, rate limiting partagé, mode multi-org + domaines | Deux nœuds derrière un répartiteur, test de concurrence OK |
| **M10 – Durcissement & v1.0.0** | Revue de sécurité complète, `systemd-analyze security`, accessibilité, perfs, docs finales | Checklist de la section 5 entièrement cochée, release `v1.0.0` signée |

Plus tard : LDAP/AD, SAML, SCIM, dépôt APT/YUM, bot Teams/Slack, extension navigateur.

---

## 14. Décisions à valider (Claude Code : pose-moi ces questions avant M0)

| # | Question | Défaut si pas de réponse |
|---|---|---|
| 1 | Backend en **Go** (binaire unique, recommandé pour du natif) ou autre préférence ? | Go |
| 2 | Base par défaut : SQLite (zéro dépendance) avec PostgreSQL en option HA, ou PostgreSQL obligatoire ? | SQLite par défaut + PostgreSQL optionnel |
| 3 | Repo GitHub **public ou privé** ? (Si privé, les clients ne peuvent pas télécharger les releases sans jeton → prévoir un serveur de téléchargement ou un miroir, ou une URL de mise à jour avec jeton dans `peek.toml`.) | Privé + URL de mise à jour configurable avec jeton optionnel |
| 4 | Licence ? | Propriétaire |
| 5 | Distributions à supporter en priorité ? | Debian 12/13, Ubuntu 24.04, Rocky/Alma 9 |
| 6 | Fournisseurs SSO prioritaires ? LDAP/AD nécessaire dès la v1 ? | Entra ID + OIDC générique ; LDAP plus tard |
| 7 | Taille max des fichiers par défaut ? | 100 Mo |
| 8 | Répartiteurs à documenter en priorité (Kemp, F5, HAProxy, nginx…) ? | Kemp, HAProxy, nginx |
| 9 | Création anonyme possible par défaut ? | Non (activable) |
| 10 | Langues dès la v1 ? | FR + EN |
