# Faire tourner plusieurs nœuds

Peek sur un seul nœud n'a besoin de rien de cette page. SQLite, un processus,
une unité systemd : c'est la bonne réponse pour presque toutes les
installations, et elle encaisse plus de trafic que la plupart des
organisations n'en enverront jamais.

Plusieurs nœuds, c'est pour la disponibilité, pas pour le débit. Le but, c'est
qu'un nœud puisse être redémarré, mis à jour ou perdu sans que le service
parte avec lui.

Trois choses doivent être partagées, et rien d'autre.

| | Quoi | Pourquoi |
|---|---|---|
| Base de données | PostgreSQL 14 ou plus récent | Chaque nœud lit et écrit les mêmes lignes. La garantie de lecture unique vient de là. |
| Stockage des fichiers | compatible S3, ou NFS | Un blob envoyé sur un nœud est téléchargé depuis un autre. |
| Clé maîtresse | la même `master.key` sur chaque nœud | Elle déchiffre ce qui est dans la base partagée : seconds facteurs, adresses de notification. |

Il n'y a **ni Redis, ni bus de messages, ni ordonnanceur externe**. Peek se
coordonne à travers la base de données qu'il a déjà.

---

## Ce que la grappe fait d'elle-même

**Un lecteur par secret.** Sur un nœud, la garantie vient d'un `UPDATE`
conditionnel et de son nombre de lignes. Sur une grappe, elle vient de la même
instruction, dans PostgreSQL — et c'est pour ça qu'elle a été écrite comme ça
plutôt qu'en lecture suivie d'écriture. Quarante lectures simultanées d'un
secret à vue unique à travers un répartiteur sur deux nœuds : une obtient le
chiffré, trente-neuf obtiennent la réponse que donnerait un lien n'ayant
jamais existé.

**Une limite de débit, pas une par nœud.** Le seau à jetons vit dans la base et
se dépense en un seul `upsert`. Deux nœuds avec `burst = 30` donnent trente
requêtes au client, pas soixante. Deux conséquences à connaître :

- relever une limite dans `peek.toml` ne recharge pas un seau déjà vide. Il se
  remplit au nouveau rythme, depuis là où il est. Un seau vidé par un test de
  charge reste vide un moment ;
- une base injoignable fait échouer la limitation **en ouvert**, et le
  journalise. Un limiteur qui emporte le service avec lui est pire que pas de
  limiteur.

**Une tâche périodique, pas une par nœud.** La purge, la rétention d'audit et
le drainage des webhooks sont chacun réclamés par un bail dans `job_locks`. Un
nœud qui meurt au milieu d'une tâche retarde la suivante d'un tic au plus ; il
ne bloque pas les autres. Une livraison de webhook quitte la grappe par
événement, pas une par nœud.

**N'importe quel nœud, n'importe quelle session.** Une session est une ligne :
un cookie émis par un nœud est accepté par le suivant. Les sessions collantes
sont inutiles, et les configurer masque une grappe qui n'en est pas vraiment
une — ne le faites pas.

---

## La recette

### 1. PostgreSQL

```sql
CREATE ROLE peek LOGIN PASSWORD '…';
CREATE DATABASE peek OWNER peek;
```

Rien d'autre. Chaque nœud applique les migrations au démarrage, et elles
supportent d'être lancées en parallèle : le premier arrivé les applique, les
autres ne trouvent rien à faire.

```toml
[database]
driver = "postgres"
dsn    = "postgres://peek:…@db.internal:5432/peek?sslmode=verify-full"
```

Utilisez `sslmode=verify-full` pour tout ce qui n'est pas une connexion locale.
La base contient chaque chiffré.

### 2. Un stockage de fichiers partagé

Le compatible S3 est le plus simple des deux :

```toml
[storage]
backend     = "s3"
s3_bucket   = "peek-blobs"
s3_region   = "us-east-1"
s3_endpoint = "https://minio.internal:9000"
s3_access_key = "…"
s3_secret_key = "…"
```

Vérifié contre MinIO et Garage. NFS fonctionne aussi — pointez
`storage.path` sur le montage — mais un descripteur NFS périmé au milieu d'un
téléchargement de 100 Mio est un échec plus désagréable qu'un délai S3.

### 3. La même clé maîtresse partout

```bash
# sur le premier nœud
sudo peek key rotate --init
sudo install -m 0640 -o root -g peek /etc/peek/master.key /mnt/transfer/master.key
# sur chacun des autres
sudo install -m 0640 -o root -g peek /mnt/transfer/master.key /etc/peek/master.key
```

Copiez-la, n'en engendrez pas une seconde. Un nœud avec une clé différente ne
peut pas lire les seconds facteurs ni les adresses de notification que les
autres ont écrits, et les fonctions qui en ont besoin refusent avec un message
clair plutôt que d'échouer bizarrement.

### 4. Le répartiteur

Tourniquet, pas d'affinité de session, vérification de santé sur `/readyz`.
`/readyz` répond `503` tant que la base est injoignable, c'est-à-dire
exactement quand le nœud doit sortir de la rotation.

```nginx
upstream peek_recipients {
    server node1.internal:8081;
    server node2.internal:8081;
    keepalive 16;
}
upstream peek_internal {
    server node1.internal:8080;
    server node2.internal:8080;
    keepalive 16;
}
```

Le reste — en-têtes, TLS, taille de corps — est dans
[`REVERSE-PROXY.md`](REVERSE-PROXY.md). Deux points comptent davantage avec
plusieurs nœuds :

- `server.trusted_proxies` doit lister les adresses du répartiteur, sinon
  chaque nœud journalise l'IP du répartiteur comme celle du client et chaque
  limite de débit s'applique au répartiteur au lieu de l'appelant ;
- publiez `public_listen` vers l'extérieur et gardez `internal_listen` sur le
  LAN, **par nœud**. La séparation est par processus : elle doit être
  configurée sur chacun.

### 5. L'unité

Utilisez l'unité du paquet (`/usr/lib/systemd/system/peek.service`) telle
quelle. Elle obtient 1.5 OK à `systemd-analyze security` ; une unité écrite à
la main pour une seconde instance fait généralement moins bien, et une unité
plus faible sur un nœud, c'est une grappe plus faible.

Pour faire tourner deux instances sur une machine — pour un test, pas pour la
disponibilité — copiez l'unité du paquet dans un gabarit et ne changez que
`ExecStart` et `ReadWritePaths`.

---

## Vérifier

```bash
# chaque nœud voit le même schéma
sudo peek migrate status

# chaque nœud répond
curl -fsS https://node1.internal:8080/readyz
curl -fsS https://node2.internal:8080/readyz

# la garantie de lecture unique, à travers le répartiteur
#   créez un secret à vue unique, puis lisez-le depuis quarante clients à la
#   fois : exactement un doit obtenir le chiffré, les autres un 404.
```

La campagne d'acceptation du dépôt, sur deux nœuds contre PostgreSQL 17
derrière nginx :

- 40 lectures simultanées × 8 tours → 1 lecteur chaque fois, 39 × `404`
- un secret créé sur le nœud 1, lu sur le nœud 2, et disparu sur le nœud 1
- une pièce jointe de 512 Kio envoyée au nœud 1, servie par le nœud 2 avec
  l'autorisation que le nœud 2 a émise
- une session émise par le nœud 1, acceptée par le nœud 2
- une livraison de webhook `secret.revealed` pour un événement, avec les deux
  nœuds qui regardent
- `burst = 30` partagé : 30 requêtes passent et 10 sont refusées sur 40
- 5 à 7 Mo résidents par nœud au repos

---

## Le mode multi-organisation sur une grappe

Rien de plus à configurer. La réponse « quel Host appartient à quelle
organisation » est mise en cache par nœud pendant trente secondes : ajouter ou
vérifier un domaine prend effet immédiatement sur le nœud qui l'a fait, et
dans les trente secondes partout ailleurs. Cette fenêtre est la seule chose
qu'une grappe change au
[mode multi-organisation](CONFIG.md#mode-multi-organisation).

---

## Ce qui n'est pas résolu ici

**La base de données est un point unique de défaillance.** Peek ne réplique
pas PostgreSQL pour vous ; utilisez ce que votre organisation fait déjà tourner
— Patroni, un service managé, de la réplication en flux avec une VIP. Un nœud
qui perd la base répond `503` sur `/readyz` et refuse de travailler plutôt que
de servir quelque chose de faux.

**Il n'y a pas d'histoire multi-site.** Deux centres de données partageant un
PostgreSQL à travers un WAN fonctionneront, et seront lents, parce que chaque
lecture de secret est une écriture. Si vous avez besoin de ça, faites tourner
deux instances et donnez à chacune son domaine.

**Les mises à jour nœud par nœud ne sont sûres que dans un sens.** Un nouveau
binaire applique les migrations en attente au démarrage, et les migrations sont
additives : un nœud plus ancien continue de fonctionner contre le schéma plus
récent. Mettez donc à jour un nœud à la fois, le plus ancien d'abord, et ne
**redescendez** pas un nœud en dessous d'une migration déjà appliquée — voir
[`UPGRADE.md`](UPGRADE.md).
