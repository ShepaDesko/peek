# Installer Peek

Peek est un unique binaire Linux statique piloté par systemd. Il n'y a pas de
Docker, pas d'environnement d'exécution à installer, pas de serveur
d'application et aucun répertoire d'assets à déployer.

Testé sur **Debian 12 et 13, Ubuntu 22.04 et 24.04, RHEL / Rocky / Alma 9**, en
**amd64 et arm64**.

## Ce qu'il faut

| Élément | Minimum | Confortable |
|---|---|---|
| CPU | 1 cœur | 2 cœurs |
| RAM | 256 Mo | 512 Mo |
| Disque | 1 Go | 10 Go (pièces jointes, sauvegardes) |
| Réseau | un port TCP | deux (destinataire et interne) |

SQLite est la base par défaut et ne demande rien à installer.

## 1. Installer le paquet

### Debian, Ubuntu

```bash
sudo apt install ./peek_1.0.0_linux_amd64.deb
```

### RHEL, Rocky, Alma

```bash
sudo dnf install ./peek-1.0.0.amd64.rpm
```

### Le script

```bash
curl -fsSL https://raw.githubusercontent.com/ShepaDesko/peek/main/packaging/install.sh | sudo sh
```

Le script détecte la distribution et l'architecture, télécharge le bon paquet,
vérifie son SHA-256 contre `checksums.txt` et — si vous passez `--pubkey` et que
`minisign` est installé — vérifie la signature de la version avant d'installer
quoi que ce soit.

Pour le lire avant de le lancer, ce qui est la bonne habitude :

```bash
curl -fsSLO https://raw.githubusercontent.com/ShepaDesko/peek/main/packaging/install.sh
less install.sh
sudo sh install.sh --pubkey "RWQ…"
```

### L'archive, sans gestionnaire de paquets

```bash
tar xzf peek_1.0.0_linux_amd64.tar.gz
sudo install -m 0755 peek /usr/bin/peek
sudo install -m 0644 packaging/systemd/peek.service /usr/lib/systemd/system/
sudo install -m 0644 packaging/systemd/peek-backup.service /usr/lib/systemd/system/
sudo install -m 0644 packaging/systemd/peek-backup.timer /usr/lib/systemd/system/
sudo useradd --system --home-dir /var/lib/peek --no-create-home --shell /sbin/nologin peek
sudo install -d -o peek -g peek -m 0750 /var/lib/peek /var/backups/peek
sudo systemctl daemon-reload
sudo peek setup
```

Ce que le paquet installe :

```
/usr/bin/peek                              le binaire (serveur + commandes d'admin)
/usr/lib/systemd/system/peek.service       l'unité de service durcie
/usr/lib/systemd/system/peek-backup.*      le service et le minuteur de sauvegarde
/usr/share/doc/peek/peek.toml.example      la configuration de référence
/var/lib/peek/                             base, fichiers chiffrés, assets
/var/backups/peek/                         les sauvegardes locales
```

Le paquet crée le compte système `peek` (sans shell, sans home) et les
répertoires avec les bons propriétaires. Il ne démarre jamais le service avant
que vous n'ayez lancé `peek setup`.

## 2. Lancer l'assistant

```bash
sudo peek setup
```

Il demande :

- le nom du service montré aux utilisateurs, l'URL publique et la langue par
  défaut ;
- le mode d'exposition — `internal` (LAN seulement), `proxy` (derrière Kemp, F5,
  HAProxy, nginx…) ou `direct` (Peek termine le TLS) ;
- les écoutes : `internal_listen` sert tout, et en mode `proxy` une seconde
  écoute `public_listen` vous est proposée, qui ne sert **que** les pages
  destinataire — le répartiteur peut ainsi ne publier que celle-là ;
- les adresses de vos répartiteurs, qui deviennent `trusted_proxies` : les
  seules sources dont Peek croira les en-têtes `X-Forwarded-*` ;
- le TLS : rien, ou un fichier de certificat et de clé ;
- la base (fichier SQLite ou DSN PostgreSQL) et le répertoire de données ;
- le SMTP, si vous voulez des e-mails ;
- si des secrets peuvent être créés sans compte.

Il écrit ensuite `/etc/peek/peek.toml` (mode 0640, en gardant un `.bak` du
précédent), engendre `/etc/peek/master.key` (32 octets aléatoires, mode 0400),
crée les répertoires et leur donne le bon propriétaire, propose d'activer et de
démarrer le service, et finit en lançant `peek doctor`.

Une installation scriptée prend les mêmes réponses en options :

```bash
sudo peek setup --non-interactive --force \
  --service-name "Coffre ACME" \
  --public-url https://secrets.acme.com \
  --mode proxy \
  --internal-listen 10.0.0.5:8080 \
  --public-listen 10.0.0.5:8081 \
  --trusted-proxies 10.0.0.10/32,10.0.0.11/32 \
  --db sqlite --dsn /var/lib/peek/peek.db \
  --anonymous-create
```

## 3. HTTPS n'est pas une option

Peek chiffre dans le navigateur, et les navigateurs n'exposent WebCrypto que
dans un **contexte sécurisé** : une origine `https://`, ou `localhost`. Servie
en `http://` sur une adresse de LAN, l'interface se charge, le dit clairement,
et refuse de chiffrer quoi que ce soit, parce qu'elle ne peut pas.

Donc, pour tout ce qui dépasse un essai local :

- terminez le TLS sur votre répartiteur et publiez `https://…` (voir
  [REVERSE-PROXY.md](REVERSE-PROXY.md)), ou
- mettez `tls.mode = "file"` avec un certificat et une clé, et laissez Peek le
  terminer.

`public_url` doit correspondre à ce que les utilisateurs tapent vraiment ;
`peek doctor` avertit quand elle est encore en `http://`.

## 4. Vérifier

```bash
sudo peek doctor
```

Il inspecte la configuration et ses permissions, la clé maîtresse, chaque
répertoire et son espace libre, le stockage des fichiers — et pour un bucket S3,
qu'il répond vraiment avec les identifiants configurés — la base et ses
migrations, les deux écoutes, les réglages de confiance du proxy, le TLS et
l'expiration du certificat, l'horloge et le SMTP. Chaque ligne est `OK`, `WARN`,
`FAIL` ou `SKIP`, avec la commande qui corrige. Le code de retour est non nul si
quelque chose a échoué, ce qui le rend directement utilisable dans Ansible ou
dans une sonde de supervision (`--json` donne une sortie exploitable par une
machine).

Une fois l'instance publiée à travers votre répartiteur :

```bash
sudo peek doctor --external
```

Cela vérifie en plus l'URL publique, la chaîne de certification, quelle IP
cliente Peek résout à travers le proxy, et si la surface d'administration est
joignable depuis l'extérieur.

Il vérifie réellement la chaîne, ce qui veut dire qu'un **certificat auto-signé
le fait échouer** avec `certificate signed by unknown authority` — le contrôle
fonctionne, il n'est pas cassé. Sur un labo ou une instance interne, faites
confiance au certificat sur la machine et relancez-le :

```bash
sudo cp /etc/peek/tls/peek.crt /usr/local/share/ca-certificates/peek-lab.crt
sudo update-ca-certificates                       # Debian, Ubuntu
# RHEL, Rocky, Alma :
# sudo cp /etc/peek/tls/peek.crt /etc/pki/ca-trust/source/anchors/
# sudo update-ca-trust
```

## 5. Gérer le service

```bash
sudo systemctl status peek
sudo systemctl restart peek
sudo journalctl -u peek -f            # journaux JSON structurés
sudo systemctl list-timers peek-backup.timer
```

Contrôler le durcissement de l'unité :

```bash
systemd-analyze security peek
```

## 6. Première utilisation

Ouvrez l'URL publique. Une instance neuve n'a aucun compte, l'interface propose
donc d'en créer le premier : un **administrateur**, avec son adresse e-mail, son
mot de passe et — si `security.require_totp` est actif — son second facteur.
Cette page n'est servie que tant qu'aucun compte n'existe ; elle disparaît
ensuite, il n'y a donc pas de fenêtre pendant laquelle un inconnu peut s'emparer
de l'instance.

L'administrateur invite ensuite les autres, et `peek admin` fait les mêmes
choses depuis le shell quand un navigateur est malcommode :

```bash
sudo peek admin create --email ops@acme.com --role manager
sudo peek admin list
```

Les rôles : `admin` administre l'instance, `manager` gère les utilisateurs et
les politiques, `member` envoie des secrets, `auditor` lit le journal d'audit et
rien d'autre.

Créer un secret **sans** compte est désactivé par défaut, et deux réglages le
commandent :

```toml
[security]
anonymous_create     = true               # désactivé par défaut
create_allowed_cidrs = ["10.0.0.0/8"]     # et, si vous voulez, restreindre qui
```

Les destinataires n'ont de toute façon jamais besoin d'un compte : un lien et,
le cas échéant, la passphrase suffisent.

## 7. Désinstaller

```bash
sudo apt remove peek        # ou : sudo dnf remove peek
```

La suppression garde volontairement `/etc/peek` (configuration et clé
maîtresse), `/var/lib/peek` (base et blobs chiffrés) et `/var/backups/peek`.
Effacez-les à la main si c'est vraiment ce que vous voulez — sans `master.key`,
les métadonnées chiffrées d'une sauvegarde sont irrécupérables.

## Quand ça ne marche pas

| Symptôme | Où regarder |
|---|---|
| Le service ne démarre pas | `journalctl -u peek -n 50`, puis `peek config check` |
| « unknown setting » au démarrage | une faute dans `peek.toml` ; le message nomme le réglage |
| Le navigateur dit « interface non compilée » | binaire construit sans `make web-build` |
| Les secrets disent toujours « plus valable » | regardez l'horloge : `peek doctor` la rapporte |
| Peek voit l'IP du proxy comme celle du client | `trusted_proxies`, et le proxy doit envoyer `X-Forwarded-For` — voir [REVERSE-PROXY.md](REVERSE-PROXY.md) |
| Permission refusée sur `/var/lib/peek` | `sudo chown -R peek:peek /var/lib/peek` |
| L'étape passphrase échoue dans le navigateur | un proxy en amont réécrit la CSP ; `script-src` doit garder `'wasm-unsafe-eval'` pour Argon2id |
