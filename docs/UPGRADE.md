# Mettre Peek à jour

Une mise à jour, c'est une commande, sur une machine à laquelle vous accédez
en SSH, avec un chemin de retour si ça tourne mal.

```bash
sudo peek update
```

## Ce que fait cette commande, précisément

1. Demande à la source de publication (les releases GitHub, ou `update_url`
   pour un miroir interne) la dernière version de votre canal, et affiche le
   journal des modifications.
2. Télécharge l'archive de cette architecture et vérifie son **SHA-256**
   contre `checksums.txt`.
3. Vérifie la **signature minisign** de `checksums.txt` avec la clé publique
   compilée dans le binaire en cours d'exécution. Une signature absente ou
   invalide arrête la mise à jour — il n'y a pas de « continuer quand même »,
   seulement un `--allow-unsigned` explicite que vous devez taper vous-même.
4. Prend une **sauvegarde** (base de données, configuration, clé maîtresse,
   fichiers chiffrés).
5. Installe le nouveau binaire par un renommage atomique, en gardant l'ancien
   dans `/usr/lib/peek/peek.previous`.
6. Redémarre le service. **Les migrations s'appliquent au démarrage** : il n'y
   a pas d'étape de migration séparée.
7. Interroge `/readyz` pendant 60 secondes au plus. Si la nouvelle version ne
   répond pas, **l'ancien binaire est remis en place automatiquement**, le
   service redémarre, et la commande vous dit de regarder
   `journalctl -u peek`.

## Options

```bash
sudo peek update --check                       # ne fait que signaler ; code de retour 10 si une version existe
sudo peek update --version 1.4.2               # une version précise, y compris pour revenir en arrière
sudo peek update --channel beta                # stable (par défaut) ou beta
sudo peek update --file peek_1.4.2_linux_amd64.tar.gz   # machine hors ligne
sudo peek update --signature peek_1.4.2_linux_amd64.tar.gz.minisig
sudo peek update --yes --skip-backup           # non interactif ; sauter la sauvegarde n'est pas recommandé
sudo peek rollback                             # revenir à l'ancien binaire, à la main
```

`--check` est fait pour la supervision :

```bash
peek update --check; case $? in 0) echo à-jour ;; 10) echo mise-à-jour-disponible ;; *) echo échec-de-la-vérification ;; esac
```

## Machines isolées du réseau

Copiez l'archive et sa signature sur la machine, puis :

```bash
sudo peek update --file peek_1.4.2_linux_amd64.tar.gz
```

La signature est vérifiée exactement comme dans le cas en ligne — la seule
différence est l'origine des octets. Rien ne contacte Internet. Mettez
`update_check = false` dans `peek.toml` pour arrêter aussi la vérification
quotidienne.

## Mise à jour par paquet

```bash
sudo apt install ./peek_1.4.2_linux_amd64.deb
sudo dnf upgrade ./peek-1.4.2.amd64.rpm
```

Les scripts du paquet redémarrent le service et signalent un redémarrage
échoué sur la sortie d'erreur. Votre configuration, votre base et votre clé
maîtresse ne sont pas touchées.

## Revenir en arrière

```bash
sudo peek rollback
```

Cela remet `/usr/lib/peek/peek.previous` en place et redémarre. Si une
migration s'est appliquée et que l'ancien schéma n'est plus lisible, restaurez
la sauvegarde que `peek update` a prise avant le changement :

```bash
sudo peek backup --list
sudo peek restore /var/backups/peek/peek-20261120T031700Z.tar.gz.age --passphrase '…'
sudo systemctl restart peek
```

## Règles de compatibilité

- Les versions suivent **SemVer**. Une version corrective ou mineure ne
  demande jamais d'intervention manuelle.
- Les migrations restent compatibles avec la version mineure précédente quand
  c'est possible ; quand ce n'est pas le cas, le journal des modifications le
  dit et `peek update` demande confirmation.
- Un changement de format de la configuration est migré automatiquement, en
  gardant l'ancien `peek.toml` sous le nom `peek.toml.bak`.
- Les versions du format de chiffrement ne sont jamais redéfinies : les liens
  `v1` continuent de s'ouvrir.

## Vérifier à la main

```bash
sha256sum -c checksums.txt --ignore-missing
minisign -Vm checksums.txt -P "RWQ…"      # la clé publique figure dans les notes de version
peek version
```

## Haute disponibilité

Avec plusieurs nœuds partageant PostgreSQL, mettez à jour un nœud à la fois :
sortez-le du répartiteur, `peek update`, attendez `/readyz`, remettez-le.
Les migrations sont appliquées par le premier nœud qui démarre et sont
idempotentes.

En revanche, **ne redescendez pas** un nœud en dessous d'une migration déjà
appliquée : les migrations sont additives, donc un ancien binaire fonctionne
contre un schéma plus récent, mais l'inverse n'est pas vrai.
