# Direction artistique

La page destinataire et le formulaire de création ont été refaits. **Tout le
reste doit les rejoindre** : tableau de bord, administration, page d'accusé,
connexion, demandes de secret. Ce document décrit ce qui a été décidé, pour
qu'on n'ait pas à le redécider.

La règle qui prime sur toutes les autres : **la couleur appartient au client**.
L'identité de Peek tient dans la structure, la typographie et la composition —
jamais dans une palette. Tout ce qui suit doit tenir en bleu NORDEX, en orange
ACME et en vert HELVIA.

## Le registre

Coffre-fort, au niveau de finition de NordVPN ou NordPass : simple, net,
assuré. La confiance vient de **ce qui est fini**, pas de ce qui est original.
Pas de dégradé violet, pas d'emoji, pas d'illustration ronde. Et pas d'exercice
de style non plus : la direction retenue est le standard du métier joué droit.

Le seul échec possible, dans les mots de l'utilisateur : **être générique**.
Une capture d'écran de Peek doit être reconnaissable.

## Les surfaces, et laquelle reçoit quoi

| Surface | Qui la voit | Traitement |
|---|---|---|
| `/s/`, `/q/` | un inconnu, souvent sur téléphone | **Page dédiée** : pas de navigation, marque du client au-dessus, panneau scellé centré dans la fenêtre |
| Création, accusé | l'expéditeur, pressé | Coquille de l'application, mais un titre et une action à leur taille |
| Tableau de bord, administration | un habitué | Coquille dense. Les jetons s'appliquent, la mise en scène non |

Une page destinataire n'est pas une page d'application avec moins de contenu :
c'est une page d'un autre genre. Ne pas lui remettre la barre de navigation.

## Le sceau

Le motif propre au produit : une bande de 6 px à la couleur de marque et une
ligne de perforation de 3 px sous elle, en haut du panneau (`.peek-seal`).
C'est ce qui fait lire la boîte comme un objet scellé plutôt que comme une
carte de plus.

Trois règles :

- **il n'apparaît que sur l'objet scellé** — la page destinataire et le dépôt.
  Le mettre sur le formulaire d'envoi ou sur un tableau le réduirait à une
  décoration ;
- **il ne porte pas de texte.** Le nom du service est au-dessus du panneau,
  là où est le logo. La première version l'écrivait aux deux endroits ;
- **il se retire quand le lien est mort** (`.peek-seal-spent`) : plus de
  couleur, plus de marque. Il n'y a plus rien à nommer.

Il est fait de deux couches de `background-image` sur un seul élément, jamais
d'un pseudo-élément déplacé : le `overflow: hidden` du panneau découpe ce qui
dépasse.

## Les composants posés

Dans `web/src/styles.css`, en `@layer components` :

| Classe | À quoi |
|---|---|
| `.peek-panel` | Le panneau du destinataire : surface, bordure, rayon + 6, ombre portée |
| `.peek-seal`, `.peek-seal-spent` | Le sceau, intact ou consommé |
| `.peek-glow` | La lueur de marque derrière le panneau, décorative, `aria-hidden` |
| `.peek-rows` | L'état en lignes `dt`/`dd` avec filets ; `dd.peek-figure` pour le nombre |
| `.peek-btn-lg` | L'action unique d'une page : pleine largeur, 3,4 rem |

## Les règles qui se cassent si on les oublie

1. **L'état se lit en chiffres, pas en pastilles.** Qui cherche combien de
   lectures il reste doit tomber sur un nombre aligné à droite.
2. **Une page a une action.** Elle prend `.peek-btn-lg`. Tout ce qui est
   au-dessus est un réglage avec une valeur par défaut raisonnable.
3. **Les textes ne changent pas.** Ils viennent de `web/src/lib/i18n.ts`, dans
   les deux langues. Un libellé scindé en étiquette et valeur prend **deux
   clés** ; ne jamais découper une chaîne traduite à la regex pour en extraire
   l'étiquette — ça marche en français et casse à la première inversion.
4. **Rien d'externe.** Pas de police web, pas d'icône téléchargée, pas de
   bibliothèque d'animation. Les icônes sont des SVG en ligne, au trait, avec
   `aria-hidden="true"`. Budget : 150 ko gzip pour la page destinataire.
5. **Le thème sombre est le défaut**, pas la préférence système. Une instance
   en change avec `branding.default_theme`.
6. **Un fond coloré ne prend jamais un jeton pré-calculé pour l'autre thème.**
   `--peek-primary-soft` est calculé par le serveur à 88 % de blanc : il est
   clair sur les deux thèmes. Un fond doit se dériver de la surface :
   `color-mix(in srgb, var(--peek-primary) 14%, var(--peek-surface))`.
7. **Les contrôles natifs trahissent le navigateur.** `<select>` et
   `<input type="file">` sont les deux endroits où l'interface a l'air
   inachevée. À reprendre.

## Ce qui reste à faire

Dans l'ordre où ça se voit :

- [ ] **Le survol des boutons fantômes est illisible en thème sombre.** Au
      survol, `.peek-btn-ghost` prend `--peek-primary-soft` en fond et garde
      `--peek-text` en texte : clair sur clair. Même famille que le bug déjà
      documenté sur les contrôles segmentés. Appliquer la règle 6 ci-dessus, et
      ajouter un test qui **survole puis lance axe** — axe ne survole pas de
      lui-même, c'est pour ça que les 18 tests passent.
- [ ] La page d'accusé expéditeur.
- [ ] Le tableau de bord et l'administration.
- [ ] Les `select` et le champ fichier du formulaire de création.
- [ ] Les pages de connexion et de demande de secret.

## Les maquettes

Trois directions ont été dessinées et comparées sur la page destinataire ; la
direction retenue est « le scellé », avec l'identité remontée au-dessus de la
boîte. Les planches, les variantes téléphone dans trois marques clientes et les
états sont dans un canevas Design sur claude.ai, pas dans le dépôt.
