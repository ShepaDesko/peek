# Direction artistique

Toute l'interface est passée à cette direction : la page destinataire, le
dépôt, le formulaire de création, la page d'accusé, les demandes de secret, la
connexion, le tableau de bord et l'administration. Ce document décrit ce qui a
été décidé, pour qu'on n'ait pas à le redécider, et **tout écran ajouté doit
s'y conformer**.

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
| Création, accusé, demande | l'expéditeur, pressé | Coquille de l'application, mais un titre et une action à leur taille |
| Connexion, invitation, réinitialisation | quelqu'un qui n'est pas encore entré | Carte centrée, `max-w-md`, un titre et une action à leur taille |
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
| `.peek-table` | La table des surfaces denses : en-tête en capitales discrètes, filets identiques à `.peek-rows` |
| `.peek-num` | Une colonne de chiffres, en chasse tabulaire |
| `.peek-select` | Le chevron du `<select>`, à la place de celui du système |
| `.peek-file` | Le bouton d'un `<input type="file">`, via `::file-selector-button` |

Et deux jetons dérivés, déclarés une fois dans `@layer base` :

| Jeton | À quoi |
|---|---|
| `--peek-tint` | Un fond teinté de marque, calculé **à partir de la surface peinte** |
| `--peek-primary-ink` | La couleur de marque utilisée comme texte, tirée de 35 % vers `--peek-text` |

Côté React, `Row` (dans `web/src/ui.tsx`) est la ligne d'état : elle s'emploie
dans un `<dl className="peek-rows">`, avec `figure` pour le nombre qu'on
cherche et `mono` pour une valeur technique. Les quatre marques — cadenas
ouvert, cadenas fermé, clé, copie — y sont aussi, en SVG en ligne.

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
   clair sur les deux thèmes. Un fond teinté prend `var(--peek-tint)`, un
   texte de marque `var(--peek-primary-ink)` — les deux se dérivent de la
   surface réellement peinte. `TestNoPaleTokenUsedAsABackground`, dans
   `internal/branding`, refuse la rechute, feuille engendrée comprise.
7. **Les contrôles natifs se rhabillent, ils ne se remplacent pas.** Un
   `<select>` garde son chevron, un champ fichier garde son bouton système :
   `.peek-select` et `.peek-file` les reprennent sans toucher à l'élément
   lui-même, pour que le clavier, l'étiquette et le lecteur d'écran restent
   ceux de la plateforme. La liste qu'ouvre le navigateur, elle, suit
   `color-scheme`, déclaré avec la palette.

## Ce qui a été fait

- [x] **Le survol des boutons fantômes, illisible en thème sombre.**
      `.peek-btn-ghost:hover` prenait `--peek-primary-soft` en fond en gardant
      `--peek-text` en texte : clair sur clair dès qu'une instance a une
      marque. Même famille sur `.peek-toggle-soft` (1,8:1) et sur le bouton
      primaire en style `outline` de la feuille engendrée. Les trois passent
      maintenant par les jetons dérivés. Deux gardes : un test Go sur les deux
      feuilles, et un test Playwright qui **survole chaque bouton fantôme, sur
      les deux thèmes, puis lance axe** — axe ne survole pas de lui-même,
      c'est pour ça que les dix-huit audits passaient.
- [x] La page d'accusé : un titre, le lien, l'action à sa taille, l'état en
      lignes et en chiffres.
- [x] Le dépôt (`/q/`) : panneau et sceau, comme la page destinataire — c'est
      l'autre objet scellé du produit.
- [x] Les `select` et le champ fichier.
- [x] Les pages de connexion, d'invitation et de demande de secret.
- [x] Le tableau de bord et l'administration : `.peek-table` partout, les
      pastilles d'état remplacées par la valeur elle-même.

## Ce qui reste

- [ ] Les téléphones : tout a été vérifié à 1180 px. Les tables denses
      débordent dans un `overflow-x-auto`, ce qui marche mais n'est pas un
      choix.
- [ ] La page de personnalisation (`/admin`, onglet Personnalisation) est la
      plus dense du produit et mériterait d'être découpée.
- [ ] Un thème clair audité au survol dans l'aperçu en direct de la
      personnalisation, où la palette du client est appliquée pour de bon.

## Les maquettes

Trois directions ont été dessinées et comparées sur la page destinataire ; la
direction retenue est « le scellé », avec l'identité remontée au-dessus de la
boîte. Les planches, les variantes téléphone dans trois marques clientes et les
états sont dans un canevas Design sur claude.ai, pas dans le dépôt.
