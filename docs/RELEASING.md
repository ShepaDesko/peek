# Couper une version

Une version, c'est un tag. Tout le reste — construire l'interface, l'embarquer,
compiler pour chaque plateforme, produire les `.deb` et `.rpm`, les empreintes,
la signature et le SBOM — se passe dans `.github/workflows/release.yml`, et
c'est ce que `peek update` vérifie ensuite.

## La clé de signature, une fois pour toutes

`peek update` fait confiance à une seule clé, et cette clé est **compilée dans
le binaire** au moment du build. Une 1.0.0 installée vérifie la 1.1.0 avec la
clé avec laquelle elle a été construite : la chaîne fonctionne sans confiance
réseau et sans autorité de certification — et la même propriété veut dire que
la clé ne peut pas être changée sans que chaque instance installée ait besoin
d'une intervention manuelle. Engendrez-la une fois, gardez-la, et ne la perdez
pas.

```bash
# sans mot de passe : le workflow n'est pas interactif, et c'est le coffre à
# secrets de GitHub qui la protège
minisign -G -W -p peek.pub -s peek.key
```

Puis deux secrets de dépôt :

```bash
gh secret set PEEK_SIGNING_KEY < peek.key
gh secret set PEEK_SIGNING_PUBKEY --body "$(sed -n 2p peek.pub)"
```

`PEEK_SIGNING_KEY` est le fichier de clé privée entier, ses deux lignes.
`PEEK_SIGNING_PUBKEY` n'est que la deuxième ligne du fichier `.pub` — le
base64, sans le commentaire.

Rangez maintenant `peek.key` quelque part où vous l'aurez encore dans trois
ans : un gestionnaire de mots de passe, pas un portable. GitHub ne vous la
rendra pas, et la perdre veut dire que chaque instance installée cesse de
pouvoir vérifier une mise à jour.

Le workflow refuse de tourner sans les deux, plutôt que de publier quelque
chose de non signé.

## Puis, à chaque version

1. Descendez `## [Unreleased]` de `CHANGELOG.md` dans un titre de version
   daté. Les notes de version en sont engendrées.
2. Assurez-vous que l'arbre est vert :

```bash
make lint test budget
make e2e
```

3. Posez le tag et poussez-le :

```bash
git tag -a v1.2.3 -m "Peek 1.2.3"
git push origin v1.2.3
```

Le workflow relance les suites Go et TypeScript avant de publier quoi que ce
soit : un tag sur un commit cassé ne produit donc pas de release, plutôt
qu'une release cassée.

## Ce qui en sort

| Artefact | Pour |
|---|---|
| `peek_<v>_linux_amd64.tar.gz`, `_arm64` | `peek update`, et `install.sh` |
| `peek_<v>_linux_amd64.deb`, `.rpm` | Debian/Ubuntu, RHEL/Rocky/Alma |
| `peek-cli_<v>_<os>_<arch>.tar.gz` | le client en ligne de commande, trois plateformes |
| `checksums.txt` | le SHA-256 de chaque artefact |
| `checksums.txt.minisig` | la signature — une seule couvre tout |
| `peek_<v>.sbom.json` | CycloneDX, pour qui le demande |

`peek update` télécharge le fichier d'empreintes, vérifie la signature avec la
clé compilée dans le binaire en cours, vérifie l'archive contre l'empreinte, et
seulement après remplace quoi que ce soit. `peek rollback` garde le binaire
précédent.

## Vérifier à la main

```bash
minisign -Vm checksums.txt -P "$(sed -n 2p peek.pub)"
sha256sum -c checksums.txt --ignore-missing
```

## Un essai à blanc, sans publier

```bash
make snapshot
```

Construit chaque artefact dans `dist/` et saute la signature et le SBOM, qui
demandent la clé et `syft`. C'est comme ça qu'on découvre qu'un changement
d'empaquetage est cassé sans y dépenser un tag.

## Numéros de version

Versionnage sémantique, et ce qui est versionné, c'est l'**API HTTP et le
fichier de configuration**, pas l'interface.

- un nouveau réglage `peek.toml` avec une valeur par défaut sûre, ou un nouvel
  endpoint : mineure ;
- un réglage retiré ou dont le sens change, un endpoint modifié, une migration
  qu'un binaire plus ancien ne peut pas supporter : majeure ;
- tout le reste : corrective.

Les migrations sont additives, donc un nœud plus ancien continue de
fonctionner contre un schéma plus récent — c'est ce qui rend une mise à jour
nœud par nœud sûre. Redescendre **en dessous** d'une migration ne l'est pas ;
voir [`UPGRADE.md`](UPGRADE.md).
