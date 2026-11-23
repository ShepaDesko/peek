# Marque blanche

Peek est fait pour être installé chez un client et ressembler à **son**
service, pas à un produit qu'il a acheté.

Il y a deux entrées. `peek.toml` porte l'identité de repli, utilisée sur une
installation neuve et avant que quoi que ce soit n'ait été enregistré. Tout le
reste vit dans la base, par organisation, et s'édite dans
**Administration → Personnalisation**, avec un aperçu en direct de l'accueil,
de la page destinataire et d'un e-mail. Là où les deux sont renseignés, la base
gagne.

## Ce que porte `peek.toml`

```toml
[branding]
service_name   = "Coffre ACME"
primary_color  = "#1d4ed8"
accent_color   = "#0e9488"
hide_powered_by = true
support_url    = "https://support.acme.example"
legal_url      = "https://acme.example/mentions-legales"
privacy_url    = "https://acme.example/confidentialite"

default_language = "fr"
```

```bash
sudo peek config check && sudo systemctl restart peek
```

Le nom apparaît dans l'en-tête, le titre de l'onglet et le pied de page. Les
deux couleurs engendrent une palette complète, que l'interface consomme sous
forme de propriétés CSS personnalisées.

## La palette engendrée

À partir de `primary_color` et `accent_color`, Peek dérive :

```
--peek-primary          --peek-accent
--peek-primary-hover    --peek-accent-soft
--peek-primary-active   --peek-on-primary
--peek-primary-soft
--peek-primary-ring
```

## Le contrôle de contraste

`--peek-on-primary` est choisi en mesurant le **rapport de contraste WCAG 2.2**
du blanc et du quasi-noir contre votre couleur primaire, et en gardant le
meilleur des deux. Si aucun n'atteint 4,5:1, le thème porte un avertissement
plutôt que de rendre silencieusement un texte illisible :

```bash
curl -s https://secrets.acme.com/api/v1/branding | jq .warnings
```

```json
["contrast between the primary colour and white text is 3.12:1, below the 4.5:1 required by WCAG 2.2 AA; pick a darker primary"]
```

L'accessibilité est une exigence affichée du produit : une marque qui y échoue
est signalée, pas masquée. C'est aussi la raison pour laquelle
`--peek-on-primary` est une variable et non du blanc écrit en dur — une marque
ne peut pas rendre l'interface inaccessible par accident.

## Comment cela arrive au navigateur

```http
GET /api/v1/branding   → le thème en JSON (ETag, revalidé)
GET /branding.css      → le même thème en propriétés CSS personnalisées
```

`index.html` charge `/branding.css` avant le bundle. La feuille de style du
bundle garde ses propres valeurs par défaut dans `@layer base`, et les couches
de cascade CSS placent les règles hors couche au-dessus de toutes les
couches — la marque de l'instance gagne donc toujours, sans `!important` et
sans recompilation. Changez une couleur, redémarrez, rechargez : c'est
appliqué.

Le mode sombre suit la préférence système et le visiteur peut le basculer ; son
choix n'est mémorisé que dans son navigateur.

## Ce que l'éditeur ajoute

- Un aperçu en direct de l'accueil, de la page destinataire et d'un e-mail,
  qui se met à jour à la frappe.
- Des logos clair et sombre (SVG assaini côté serveur, PNG, WebP), un favicon
  et une image Open Graph.
- Rayon des coins, style des boutons, et une police choisie dans une liste
  **embarquée dans le binaire** — jamais une police web récupérée sur
  Internet, parce que ce serait un tiers qui regarde chaque destinataire
  ouvrir un secret.
- Chaque texte modifiable par langue activée : titres, aides, message par
  défaut au destinataire, page du secret expiré, pied de page.
- CSS personnalisé, réservé à l'administrateur, assaini, borné en taille, sans
  `@import` et sans `url()` externe.
- Modèles d'e-mail brandés, HTML et texte, avec variables, aperçu et bouton
  « envoyer un test ».

## Déplacer une marque d'une instance à l'autre

```bash
# la préparer une fois
sudo peek branding export > acme.peekbrand

# et chez le client
sudo peek branding import acme.peekbrand
```

Le fichier est du JSON : version de format, date d'export, et le thème. Il
porte les couleurs, les textes et les assets. Il ne porte ni utilisateurs, ni
secrets, ni clés. L'import valide le résultat et affiche tout avertissement de
contraste avant que vous ne redémarriez.

## Domaine

En mono-client, qui est le cas par défaut : `public_url` est le domaine de la
marque. Tous les liens, les cookies et les redirections en découlent.

Le [mode multi-organisation](CONFIG.md#mode-multi-organisation) résout la
marque depuis l'en-tête `Host`, pris uniquement d'un proxy de confiance ou
d'une connexion directe, et seulement pour un domaine qu'un enregistrement DNS
TXT a prouvé. Chaque organisation a sa marque, et un e-mail envoyé pour le
compte de l'une porte celle-là.
