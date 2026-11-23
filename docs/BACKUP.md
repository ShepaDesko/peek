# Sauvegarde et restauration

## Ce que contient une sauvegarde

| Élément | Pourquoi il compte |
|---|---|
| `peek.db` ou `peek.dump` | un instantané cohérent de la base, pris à chaud |
| `peek.toml` | la configuration |
| `master.key` | la clé maîtresse du serveur |
| `files/` | les blobs de fichiers chiffrés |
| `manifest.json` | version, date, hôte, contenu |

**Lisez ce paragraphe deux fois.** Une sauvegarde contient le **chiffré de
chaque secret encore actif**. Il n'est pas déchiffrable sans les clés, qui ne
vivent que dans les liens détenus par vos utilisateurs — mais c'est quand même
le fichier le plus sensible de la machine. Gardez une rétention courte (7 jours
par défaut), rangez-la avec un accès restreint, et mettez une passphrase pour
que l'archive soit chiffrée :

```toml
[backup]
enabled    = true
dir        = "/var/backups/peek"
keep       = 7
passphrase = "une longue phrase de passe rangée dans votre gestionnaire de mots de passe"
```

Avec une passphrase, l'archive est chiffrée avec **age** (destinataire scrypt)
et nommée `.tar.gz.age`. Sans, `peek backup` vous avertit à chaque exécution et
`peek doctor` échoue — l'archive porte `peek.toml` et `master.key`, donc lire le
répertoire de sauvegarde suffirait à prendre l'instance.

**Rangez aussi `master.key` séparément.** Sans elle, les métadonnées chiffrées
d'une base restaurée sont irrécupérables. La sauvegarder à côté de la base dans
la même archive est pratique ; en garder une seconde copie ailleurs est ce qui
vous sauve.

## PostgreSQL

Avec `database.driver = "postgres"`, l'instantané est un `pg_dump` au format
« custom » — compressé, restaurable avec `pg_restore`, et pas quelque chose
qu'un `psql` égaré peut appliquer à moitié comme un fichier `.sql`. Tout le
reste de l'archive est identique.

Il faut les outils client sur la machine :

```bash
sudo apt install postgresql-client     # Debian, Ubuntu
sudo dnf install postgresql            # RHEL, Rocky, Alma
```

`peek doctor` le dit quand ils manquent, ce qui vaut mieux que de l'apprendre
du minuteur nocturne. Les paramètres de connexion passent par l'environnement
et le mot de passe par un fichier `.pgpass` en 0600 supprimé ensuite : jamais
par `argv`, parce que `/proc/<pid>/cmdline` est lisible par tout le monde
pendant toute la durée du dump.

Une restauration lance `pg_restore --clean --single-transaction` : chaque objet
est supprimé puis recréé dans une seule transaction, donc un échec laisse la
base exactement comme elle était. Arrêtez le service d'abord.

Une archive prise sur une instance SQLite ne se restaure pas dans PostgreSQL,
ni l'inverse. `peek restore` le dit plutôt que d'en restaurer la moitié.

**Avec plusieurs nœuds, restaurez une seule fois.** Ils partagent la base :
restaurer sur un nœud restaure pour tous — et les autres doivent être arrêtés
pendant l'opération, sinon ils écrivent dans une base qu'on supprime sous eux.

## Sauvegardes planifiées

Le paquet installe un minuteur, activé par `peek setup` :

```bash
sudo systemctl enable --now peek-backup.timer
systemctl list-timers peek-backup.timer
journalctl -u peek-backup -n 20
```

Il part à 03h17 heure locale avec jusqu'à 15 minutes de décalage aléatoire, et
rattrape après un redémarrage (`Persistent=true`). Changez l'horaire avec
`systemctl edit peek-backup.timer`.

## À la main

```bash
sudo peek backup                                  # vers backup.dir
sudo peek backup --to /mnt/nfs/peek --keep 14
sudo peek backup --passphrase 'phrase-de-sauvegarde'
sudo peek backup --list
```

## Restaurer

```bash
sudo systemctl stop peek
sudo peek restore /var/backups/peek/peek-20261120T031700Z.tar.gz.age \
     --passphrase '…' --include-config
sudo systemctl start peek
sudo peek doctor
```

- La passphrase est prise dans `peek.toml` quand `--passphrase` est omis :
  vous l'y avez déjà mise.
- En SQLite, la base courante est mise de côté sous le nom
  `peek.db.before-restore-<horodatage>` plutôt que supprimée : restaurer la
  mauvaise archive reste réparable.
- `--include-config` restaure aussi `peek.toml` et `master.key`. Sans lui,
  seules les données reviennent et votre configuration actuelle est conservée.
- `--dry-run` lit le manifeste et rapporte ce qui serait restauré, sans rien
  écrire.

## Copies hors site

Peek écrit localement et, volontairement, n'embarque pas d'identifiants pour un
stockage distant. Copiez le répertoire avec ce que votre parc utilise déjà :

```bash
# rsync via SSH
rsync -az --delete /var/backups/peek/ backup@nas:/srv/backups/peek/

# stockage objet compatible S3
aws s3 sync /var/backups/peek/ s3://acme-backups/peek/ --storage-class STANDARD_IA

# un minuteur systemd à vous, après peek-backup.service
```

## Tester une restauration

Une sauvegarde que vous n'avez jamais restaurée est une hypothèse. Une fois par
trimestre :

```bash
sudo peek restore --dry-run /var/backups/peek/peek-….tar.gz.age --passphrase '…'
```

et, sur une machine de côté, une restauration complète suivie d'un
`peek doctor`. La chaîne d'intégration lance une sauvegarde et une restauration
à chaque poussée, ce qui garde le code honnête — elle ne peut pas vérifier
votre copie d'exploitation.

## Rétention et vie privée

- Les secrets sont supprimés de la base vivante dès qu'ils sont lus ou
  expirent ; il ne reste qu'un journal d'audit sans contenu.
- Les anciennes sauvegardes contiennent encore les secrets qui étaient actifs à
  ce moment-là, et c'est la vraie raison de garder `keep` petit.
- `security.audit_retention` (un an par défaut) borne le journal d'audit, et
  `security.anonymize_ips` ne garde qu'un préfixe /24 ou /48 de chaque adresse.
