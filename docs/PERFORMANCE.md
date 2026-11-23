# Ce que ça coûte à faire tourner

En bref : un cœur et un quart de gigaoctet. Les chiffres ci-dessous ont été
mesurés sur une machine délibérément petite, parce que la question
intéressante n'est pas à quelle vitesse Peek peut aller sur du bon matériel —
c'est de savoir si la plus petite machine virtuelle qu'une organisation vous
donnera suffit. Elle suffit.

## Les budgets

La section 13 du cahier des charges en fixe trois, et `make budget` les
vérifie (la CI le lance à chaque build, ils ne peuvent donc pas dériver en
silence) :

| | Budget | Mesuré |
|---|---|---|
| Binaire, interface embarquée | < 60 Mo | **29,5 Mo** |
| Page destinataire, JavaScript gzippé | < 150 ko | **131,3 ko** |
| Mémoire au repos | < 100 Mo | **5–7 Mo** |

Le budget de la page est celui qui compte le plus : un destinataire n'a pas
choisi d'utiliser Peek, et il ouvre peut-être le lien sur un téléphone dans un
train. 131 ko, c'est l'application entière — module Argon2id en WebAssembly
compris — parce que rien n'est chargé depuis ailleurs.

## Débit

Un vCPU, 2 Go de RAM, Debian 13. Seize clients simultanés qui créent un secret
et le lisent immédiatement, pendant vingt secondes, limites de débit relevées
pour que la mesure porte sur Peek et non sur son propre bridage.

| Déploiement | Créations/s | Lectures/s | p50 | p99 | Erreurs |
|---|---|---|---|---|---|
| Un nœud, SQLite (le cas par défaut) | **372** | **372** | 13 ms | 66 ms | aucune |
| Un nœud, PostgreSQL | 182 | 182 | 32 / 48 ms | 104 / 127 ms | aucune |
| Deux nœuds, PostgreSQL, derrière nginx en TLS | 92 | 92 | 81 / 90 ms | 142 / 131 ms | aucune |

Ces trois lignes disent exactement ce qu'elles disent. SQLite sur un nœud est
le plus rapide parce que la base est un appel de fonction et non une socket.
PostgreSQL coûte un aller-retour par requête, et c'est ce qui achète l'état
partagé dont plusieurs nœuds ont besoin. La troisième ligne est plus basse
encore parce qu'un seul vCPU fait tourner nginx, la terminaison TLS **et** deux
processus Peek — la machine est saturée, pas le logiciel.

La mémoire a culminé à **31 Mo** sur le nœud SQLite et à **15 Mo** par nœud
dans la paire, après sept mille secrets chacun.

Donc : 744 requêtes par seconde sur la plus petite machine raisonnable, chaque
secret étant créé, lu et détruit en base. Une organisation de quelques milliers
de personnes ne remarquera pas que Peek est là.

## Où le temps passe réellement

```
BenchmarkSeal/1KiB                581 ns      1,8 Go/s
BenchmarkSeal/64KiB            13 013 ns      5,0 Go/s
BenchmarkSeal/1MiB            194 949 ns      5,4 Go/s
BenchmarkDeriveKeysNoPassphrase 1 408 ns
BenchmarkDeriveKeys        11 623 939 ns
BenchmarkSealFileStream     1 824 251 ns      4,6 Go/s  (8 Mio, morceaux de 1 Mio)
BenchmarkOpenFileStream     1 805 487 ns      4,6 Go/s
```

`make bench`, sur un Ryzen 9 de bureau. Deux choses à lire dans cette liste.

**AES-GCM est gratuit.** 5,4 Go/s veut dire que c'est l'instruction matérielle
qui travaille ; le chiffrement n'est jamais le goulot d'étranglement, ni dans
le navigateur ni sur le serveur. Le chemin fichier raconte la même histoire à
4,6 Go/s, morceau par morceau, donc une pièce jointe de 100 Mio est bornée par
le disque et le réseau, et par rien d'autre.

**Argon2id est huit mille fois plus lent que le chemin sans lui, et c'est
exactement le but.** 11,6 ms pour une dérivation avec les paramètres livrés
(19 Mio, deux passes, une voie — les chiffres de l'OWASP), c'est ce qui rend
cher un essai hors ligne contre un secret protégé par passphrase. Cela tourne
dans le navigateur du destinataire, donc le serveur ne paie rien, et c'est
pourquoi les paramètres peuvent être généreux.

Si ce benchmark rapporte un jour un dixième de ce chiffre, quelqu'un a affaibli
les paramètres. C'est la principale raison de son existence.

## À quoi ressemble une pièce jointe de 100 Mio

Mesuré de bout en bout à travers nginx sur la même machine virtuelle, en TLS
réel :

- envoi : 106 Mo/s, limité par le lien
- téléchargement : 719 ms
- le SHA-256 du fichier sorti correspond à celui du fichier entré
- le secret a été détruit par la lecture qui a démarré le téléchargement, et le
  téléchargement s'est quand même terminé — c'est à ça que sert l'autorisation
  de téléchargement

## Réglages, dans l'ordre où ça valait la peine d'essayer

1. **Ne touchez pas aux limites de débit** sans raison. Elles sont par adresse
   client et généreuses : 20 créations et 30 lectures en rafale. C'est ce qui
   empêche un seul script de remplir le disque.
2. **Gardez SQLite** sauf si vous avez besoin de plusieurs nœuds. C'est plus
   rapide, et un fichier est bien plus simple à sauvegarder qu'une grappe de
   bases.
3. **Mettez les blobs sur S3** avant de vous inquiéter d'autre chose, si vous
   attendez de grosses pièces jointes. La base ne contient que le chiffré des
   secrets texte ; les fichiers n'y passent jamais.
4. **`policy.max_file_bytes`** est le bouton qui décide de votre disque, pas le
   nombre d'utilisateurs.
5. Si les lectures sont lentes et que la machine est inactive, regardez le
   proxy. Un p50 de 80 ms là où Peek rapporte 30 ms, c'est la terminaison TLS
   et un saut réseau, pas Peek.

Un détail qui a surpris pendant les essais : relever une limite de débit ne
recharge pas un seau déjà vide. Il se remplit au nouveau rythme, depuis là où
il est. Un seau vidé par un test de charge reste vide un moment.

`peek doctor` rapporte la taille de la base, le nombre de blobs et l'espace
libre de chaque répertoire, ce qui suffit en général à voir ce qui grossit.
