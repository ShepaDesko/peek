# Décisions

Le cahier des charges (section 14) listait dix questions à poser avant de
commencer, et disait d'appliquer la valeur par défaut et de la consigner si
aucune réponse ne venait. Aucune réponse n'a été donnée, chaque défaut a donc
été appliqué. Ils sont consignés ici avec leurs conséquences, et chacun peut
être rouvert.

## Venant de la section 14 du cahier des charges

| # | Question | Décision | Conséquence |
|---|---|---|---|
| 1 | Langage du serveur | **Go** | Un binaire statique, pas d'environnement d'exécution à installer, déploiement systemd natif |
| 2 | Base par défaut | **SQLite**, PostgreSQL en option | Zéro dépendance pour un nœud unique ; PostgreSQL est arrivé avec la haute disponibilité en M9 et c'est ce qu'il faut dès qu'il y a plusieurs nœuds |
| 3 | Visibilité du dépôt | **Privé**, URL de mise à jour configurable | Les clients ne peuvent pas récupérer les releases GitHub sans jeton : pointez `update_url` sur un miroir, ou utilisez `peek update --file` |
| 4 | Licence | **Propriétaire** | Voir `LICENSE` ; la redistribution demande une autorisation écrite |
| 5 | Distributions | **Debian 12/13, Ubuntu 22.04/24.04, Rocky/Alma 9** | `.deb` et `.rpm`, amd64 et arm64, installation testée dans la CI |
| 6 | Fournisseurs SSO | **Entra ID + OIDC générique**, LDAP plus tard | Livré en M8 : code d'autorisation avec PKCE, sans bibliothèque OIDC |
| 7 | Taille de fichier maximale | **100 Mio** | `policy.max_file_bytes` ; les pièces jointes elles-mêmes sont arrivées en M7 |
| 8 | Répartiteurs à documenter | **Kemp d'abord, puis HAProxy et nginx** | F5, Apache et Traefik sont documentés aussi |
| 9 | Création anonyme | **Désactivée par défaut** | `security.anonymous_create` ; une instance exposée n'est pas un relais ouvert à la sortie de la boîte |
| 10 | Langues | **Français et anglais** | Le français est la langue par défaut ; le choix du visiteur est mémorisé |

## Décisions prises en construisant

### Le client engendre l'identifiant du secret

Le navigateur engendre l'identifiant de 128 bits et le lie dans les données
additionnelles d'AES-GCM. Un chiffré ne peut donc pas être déplacé vers un autre
identifiant, et le serveur refuse un doublon plutôt que de l'écraser. Le coût :
une collision (d'une rareté qui tend vers rien) doit être retentée par le
client.

### Le jeton de lecture est une preuve de possession, pas un mot de passe

Le serveur stocke `SHA-256(jeton de lecture)` et compare en temps constant avant
de relâcher quoi que ce soit. C'est ce qui rend vrais en même temps « un robot
d'aperçu ne dépense pas de lecture » et « une mauvaise passphrase ne coûte
rien », avec un seul mécanisme.

### Le jeton d'accusé est engendré côté client

La page de l'expéditeur est autorisée par un jeton aléatoire dont seule
l'empreinte est stockée. Aucun compte n'est nécessaire pour suivre ou détruire
un secret, et le serveur ne peut pas forger un accusé. Les deux jetons vivent
dans le fragment de l'URL d'accusé.

### Une pierre tombale survit au secret

Supprimer un secret écrit une petite ligne qui porte son état et ses compteurs —
jamais de contenu — pour que la page d'accusé de l'expéditeur puisse encore dire
« lu » ou « expiré » après la disparition des données.

### HKDF est implémenté à la main dans le navigateur

WebCrypto n'expose qu'extract-puis-expand, alors que la référence Go utilise
expand seul pour les sous-clés. Le navigateur implémente les deux moitiés
au-dessus de HMAC-SHA256 pour que les deux côtés soient identiques octet pour
octet, ce que vérifient les vecteurs partagés.

### `wasm-unsafe-eval` est dans la CSP

Argon2id tourne en WebAssembly, et `script-src 'self'` seul bloque la
compilation WebAssembly — découvert en lançant la vraie page dans un vrai
navigateur, pas en relecture. `'wasm-unsafe-eval'` n'autorise que WebAssembly :
il ne permet ni `eval()` ni script en ligne, et `'unsafe-inline'` et
`'unsafe-eval'` restent absents. Un test affirme les trois faits.

### Les couleurs de repli sont dans une couche CSS

Le binaire sert `/branding.css` hors couche, et la feuille de style empaquetée
garde ses valeurs par défaut dans `@layer base`. Les règles hors couche gagnent
sur n'importe quelle couche, la marque d'une instance écrase donc les valeurs
par défaut sans `!important` et sans recompilation.

### Les zones inachevées refusent bruyamment

`database.driver = "postgres"` et `tls.mode = "acme"` retournaient une erreur
explicite nommant le jalon plutôt que de retomber silencieusement sur autre
chose ; les deux ont depuis été livrés, en M9 et en M10, et la règle reste. Un
repli silencieux vers SQLite sur plusieurs nœuds casserait la garantie de
lecture unique ; un repli silencieux depuis ACME servirait du HTTP en clair sur
une écoute qu'un exploitant croit chiffrée.

### 404 plutôt que 403 sur un filtre réseau

Un appelant venant d'un réseau non autorisé, ou qui sonde une route
d'administration sur l'écoute publique, obtient la même réponse que pour une
route qui n'existe pas.

### Les handlers vivent dans `internal/server`

Le cahier des charges esquissait un `internal/api` à côté d'`internal/server`.
Séparer les handlers HTTP du routeur sur lequel ils sont montés aurait ajouté une
frontière de paquet et un paquet d'utilitaires partagés sans rien séparer de
significatif. Les règles métier sont dans `internal/secrets`, l'accès aux
données dans `internal/store`, et `internal/server` possède la surface HTTP.

### Playwright pilote le binaire construit

La campagne de bout en bout démarre le vrai binaire avec son interface
embarquée plutôt qu'un serveur de développement : ce que la CI exerce est ce qui
est livré.

### P-256 pour les demandes de secret, pas X25519

Le cahier des charges autorisait les deux. X25519 n'est arrivé que récemment
dans Safari et Firefox, et Peek est déployé dans des navigateurs d'entreprise
administrés qui ont couramment plusieurs versions de retard sur le canal de
publication ; l'ECDH P-256 est dans chaque implémentation de WebCrypto depuis
dix ans. Un échange de clés qui fonctionne partout vaut mieux qu'une courbe un
peu plus élégante qui échoue pour un dixième des utilisateurs avec une erreur
sur laquelle ils ne peuvent rien.

Une conséquence qui vaut d'être connue : WebCrypto ne peut pas importer une clé
privée P-256 depuis le seul scalaire — un JWK a besoin de `x` et `y`, et le
support d'une clé PKCS#8 sans sa moitié publique varie d'un navigateur à
l'autre. Le lien de suivi porte donc les deux moitiés. Cela coûte 65 octets dans
une URL et supprime toute une classe de pannes propres à un navigateur.

### Pas de SDK AWS pour le stockage S3

Peek signe lui-même en SigV4 et parle les cinq opérations S3 dont il a besoin.
Deux raisons, dont aucune ne concerne la qualité du SDK. Il ajouterait une
dizaine de mégaoctets à un binaire qui a un budget de soixante. Et sa chaîne
d'identifiants par défaut sonde le point d'accès de métadonnées d'instance, ce
qui est un appel sortant que Peek promet de ne pas faire : les identifiants
viennent de `peek.toml` et de nulle part ailleurs.

Le code de signature fait environ deux cents lignes, et la campagne de tests le
vérifie contre une transcription indépendante de la spécification, puis contre
un vrai MinIO avant chaque version.

### Une autorisation de téléchargement, plutôt que de garder le secret en vie

La ligne d'un secret à une lecture est supprimée dans la transaction qui
consomme la dernière lecture. Sans autre chose, une pièce jointe de 100 Mio
deviendrait injoignable à l'instant où elle devient lisible. Une révélation
réussie délivre donc une autorisation de courte durée, stockée hachée comme
chaque autre jeton, et l'expiration des blobs est poussée au-delà de sa fin.
Garder la ligne du secret en vie « juste pour les fichiers » était l'autre
option, et elle aurait voulu dire un secret lisible après le moment où il était
censé avoir disparu.

### Les points de terminaison des webhooks vivent dans le fichier de configuration, pas dans l'API

Tous les autres produits de ce domaine laissent un utilisateur ajouter une URL
de webhook dans l'interface. Peek ne le fait pas, et ne le fera pas.

Une URL de point de terminaison qu'un appelant peut fixer transforme le serveur
en relayeur de requêtes : il se connectera à tout ce qui est joignable depuis où
il tourne, c'est-à-dire, sur une installation sur site, le réseau du client
lui-même — le service de métadonnées, l'interface de gestion de l'hyperviseur,
une API interne sans authentification. La parade habituelle est une liste de
blocage des plages privées, et Peek est *installé dans* ces plages privées : la
liste de blocage devrait donc interdire exactement les hôtes vers lesquels un
webhook légitime pointe.

Le vecteur est donc supprimé plutôt que filtré. Les points de terminaison sont
des tables `[[webhook]]` dans `peek.toml`, que seul root peut écrire, et l'API
offre de la visibilité et des relances sur cette liste, et rien d'autre. Le coût
est réel : ajouter un point de terminaison demande un changement de
configuration et un redémarrage. Pour un produit dont toute la promesse est
qu'il est sûr de l'installer dans un réseau, c'est le bon côté de l'arbitrage.

### Un corps de webhook est une entrée d'audit, et la liste des champs est un test

La charge utile aurait pu être construite par événement, en portant ce que cet
événement avait sous la main. À la place, chaque livraison est les mêmes dix
champs, pris de l'entrée d'audit qui l'a déclenchée.

Le journal d'audit est déjà construit pour ne jamais contenir un secret, une
clé, une passphrase ni un fragment d'URL — c'est la règle numéro un du projet,
appliquée partout où il est écrit. Le réutiliser veut dire que le transfert est
sûr *par construction* plutôt que par relecture : il n'y a pas de chemin par
lequel un futur événement tendrait au répartiteur un champ auquel personne n'a
pensé. Un test affirme le jeu exact de champs, en ajouter un est donc une
décision que quelqu'un doit prendre exprès.

### La file de livraison est une table de la base

L'implémentation évidente est une goroutine avec un canal et une boucle de
relance. Elle échoue deux fois. Un redémarrage pendant une fenêtre de relance
perd l'événement — et les événements qui valent un webhook sont ceux qu'un
exploitant guette. Et une grappe de trois nœuds derrière un répartiteur envoie
trois copies de tout, parce que chacun a vu la révélation.

Des lignes dans `webhook_deliveries` corrigent les deux. Le drainage est réclamé
par le même verrou de tâche que la purge, un nœud à la fois envoie donc, ce qui
rend la livraison au-moins-une-fois par grappe plutôt qu'une fois par nœud.
L'identifiant dans `X-Peek-Delivery` est le moyen pour un récepteur de rendre
son propre côté idempotent ; la documentation le dit, plutôt que de prétendre à
l'exactement-une-fois, qu'aucune notification HTTP ne peut honnêtement offrir.

La mise en file est un petit insert sur le chemin de la requête, à côté de
l'insert d'audit qui y est déjà. Rien dans un handler n'attend un appel
sortant : un récepteur qui reste pendu trente secondes ne peut pas ralentir une
révélation d'une milliseconde.

### L'authentification unique, c'est deux routes de navigateur, pas une danse d'API

`GET /auth/sso` répond une redirection vers le fournisseur ;
`GET /auth/sso/callback` revient et pose le même cookie de session qu'une
connexion par mot de passe. L'application monopage n'est impliquée dans ni l'un
ni l'autre.

L'autre voie — le script qui démarre le flux, lit le code dans l'URL, le poste à
un point de terminaison — met un code d'autorisation quelque part où
`document.location` peut le lire, demande que le fragment soit analysé en
JavaScript, et finit généralement par un jeton dans `localStorage`. Rien de
cela n'achète quoi que ce soit ici, puisque Peek sert sa propre interface depuis
sa propre origine. Deux navigations ordinaires et un cookie `HttpOnly`
suppriment toute la catégorie.

Les valeurs à usage unique d'une tentative — state, nonce, vérificateur PKCE et
le chemin de retour — vivent dans un seul cookie scellé avec la clé maîtresse du
serveur, plutôt que dans une table qu'il faudrait balayer. C'est aussi pour ça
que l'authentification unique refuse de démarrer sans clé maîtresse : un cookie
de state forgeable n'est pas une protection du tout.

### Pas de bibliothèque OIDC

`internal/oidc` fait environ six cents lignes et n'importe rien en dehors de la
bibliothèque standard. Le protocole dont Peek a besoin est un flux avec un
fournisseur : pas d'enregistrement dynamique, pas de type de réponse implicite
ni hybride, pas d'introspection, pas de rafraîchissement. Ce que les
bibliothèques ajoutent par-dessus, c'est de la souplesse, et la souplesse est
exactement la propriété qui fait se tromper sur la vérification des JWT —
chaque échec célèbre est un vérificateur qui accepte un algorithme que
l'appelant n'avait pas l'intention d'accepter.

La table des algorithmes est donc fermée et ne contient aucune entrée
symétrique. `alg: none` et la famille HMAC ne sont pas rejetés par un contrôle
qui pourrait être contourné : ils sont absents, et un jeton qui en demande un
obtient un message expliquant que Peek ne vérifie que des signatures
asymétriques. Une clé RSA de moins de 2048 bits est refusée. Une clé EC est
reconstruite en point non compressé puis analysée, de sorte que la vérification
d'appartenance à la courbe est celle de l'analyseur plutôt qu'une chose de plus
à ne pas oublier.

Un jeton qui arrive sans `kid` est confronté à une unique clé publiée, et un jeu
de clés ambigu est refusé plutôt qu'essayé l'une après l'autre : itérer sur les
clés jusqu'à ce qu'une vérifie, c'est ainsi qu'un vérificateur finit par accepter
une signature venant d'une clé qui n'a jamais été destinée aux jetons.

### `sso.required` est appliqué par le serveur, et nomme sa propre issue de secours

Masquer le formulaire de mot de passe, ce n'est pas exiger l'authentification
unique. `required` refuse donc chaque identifiant local — mot de passe comme
clé d'accès — dans le service des comptes, qui est l'unique endroit par lequel
passe tout chemin de connexion locale.

La conséquence est réelle : une instance dont le fournisseur est injoignable, ou
dont le secret client a expiré dans la nuit, est une instance où personne ne
peut se connecter, et le fichier qui corrigerait cela n'est lisible que par
root. Les produits traitent généralement ce cas par une exception non écrite
pour les administrateurs, ce qui est un « obligatoire » qui ne l'est pas et une
remarque d'auditeur qui attend d'arriver.

Peek le rend explicite à la place. `sso.password_exempt` nomme les comptes de
secours, et `peek doctor` **échoue** — il n'avertit pas — quand `required` est
posé et que cette liste est vide.

### Le lien à l'annuaire est (émetteur, sujet), pas l'adresse e-mail

Les adresses changent : les gens se marient, les services sont renommés,
quelqu'un corrige une faute. Pire, chez un fournisseur, la même boîte peut être
réattribuée à un autre humain. Un lien d'authentification construit sur
l'adresse suit la boîte plutôt que la personne, ce qui est une prise de contrôle
de compte avec une trace qui a l'air ordinaire.

Le lien est donc l'émetteur et le sujet, et l'adresse les suit. L'émetteur est
stocké à côté du sujet parce qu'un sujet n'est unique qu'au sein de son
émetteur : repointer une instance vers un autre tenant ne doit pas apparier
silencieusement les anciens sujets.

Lier un compte local *existant* à une identité d'annuaire est le seul endroit où
l'adresse est utilisée, et c'est gardé deux fois : le compte ne doit pas être
déjà lié à un autre sujet, et un fournisseur qui marque explicitement l'adresse
comme non vérifiée est refusé. Sans cette seconde garde, n'importe quel
fournisseur qui laisse un utilisateur taper une adresse arbitraire serait une
entrée dans le compte de quelqu'un d'autre.

### Un utilisateur appartient à une organisation, pas à plusieurs

Le cahier des charges esquissait une table `memberships`. Peek garde `org_id`
sur le compte à la place.

« Une instance héberge plusieurs clients » ne veut pas dire qu'une personne
travaille pour deux d'entre eux. Une table d'appartenances mettrait une
organisation dans chaque session, chaque jeton d'API et chaque requête qui la
prend aujourd'hui du compte — beaucoup de surface, et beaucoup d'endroits où
l'oublier — pour un cas que personne n'a demandé. Quelqu'un qui a vraiment
besoin des deux prend deux comptes, ce qui est aussi la trace d'audit honnête :
l'activité de deux personnes sous une seule identité est exactement ce qu'un
auditeur ne veut pas voir.

### Un domaine ne résout qu'après qu'un enregistrement TXT l'a prouvé

L'en-tête Host décide à quelle organisation appartient une requête, et sur une
connexion directe cet en-tête est ce que le client a tapé. N'importe qui pouvant
pointer un nom DNS sur cette instance pourrait sinon réclamer la marque d'un
client, et le destinataire verrait le bon logo au-dessus de la page de la
mauvaise organisation — c'est-à-dire une page d'hameçonnage convaincante que
l'exploitant héberge lui-même.

Un domaine déclaré ne résout donc vers rien jusqu'à ce que
`_peek-challenge.<domaine> IN TXT "peek-verification=<jeton>"` ait été vu. Le
label est dédié plutôt que l'apex, parce qu'un enregistrement TXT à l'apex est
partagé avec SPF, DMARC et une poignée d'autres jetons de vérification, et que
les exploitants s'effacent les uns les autres.

Deux décisions plus petites à l'intérieur de celle-là. Un domaine prouvé une
fois reste prouvé : une revérification en échec consigne ce que le résolveur a
vu et laisse `verified_at` tranquille, parce que retirer sa marque à un client
le temps d'une mauvaise après-midi de son registrar est la mauvaise panne. Et un
hôte inconnu ou non vérifié obtient la marque de l'*instance* plutôt qu'un
refus — un destinataire qui détient un lien doit pouvoir lire son secret même
quand l'exploitant n'a pas fini de monter la marque.

### L'en-tête Host est mis en cache, et le cache est borné

Résoudre un hôte est une requête, et l'en-tête vient du client : un déluge de
valeurs de Host distinctes est donc un déluge de requêtes. Les réponses sont
mises en cache trente secondes — assez longtemps pour qu'un domaine chargé soit
une requête, assez court pour qu'ajouter un domaine prenne effet pendant que
l'exploitant regarde encore son écran — et la table entière est jetée quand elle
passe le millier d'entrées, plutôt qu'évincée intelligemment. Un cache indexé
sur une entrée contrôlée par l'attaquant a davantage besoin d'une borne que
d'une politique d'éviction.

### Un jeton peut franchir les organisations et un cookie non, le contrôle est donc là où les deux passent

Un cookie de session est cantonné à un hôte par le navigateur : un cookie ouvert
sur acme.example.com n'est jamais envoyé à beta.example.com. Un jeton d'API est
un en-tête, et le Host à côté de lui est au choix de l'appelant.

La comparaison — l'organisation du compte contre celle vers laquelle l'adresse
résout — vit donc dans l'unique intergiciel par lequel passent les deux formes
d'authentification, et le refus est audité. L'autre voie, les comparer dans
chaque handler qui lit une organisation depuis le compte, est une règle qui
tient jusqu'à ce que quelqu'un ajoute le vingtième handler.

Un administrateur de plateforme est exempté, parce qu'agir à travers les
organisations est tout ce rôle.

### `platform_admin` est allé sur l'échelle des rôles, ce qui a transformé trois contrôles en escalades

Le rôle au-dessus d'`admin` a été ajouté à la même échelle ordonnée que les
autres utilisent, pour que chaque `requireRole(RoleAdmin)` de la table des
routes l'admette sans être listé. C'est l'intérêt d'une échelle.

Cela a aussi cassé trois gardes qui nommaient chacune `admin` à la main —
`!actor.Can(RoleAdmin) && role == RoleAdmin` et deux variantes. Un
administrateur passe les trois, un administrateur aurait donc pu accorder le
rôle au-dessus du sien. Elles sont maintenant une seule fonction qui lit
l'échelle : personne n'accorde un rôle qu'il ne détient pas lui-même. Une règle
qui porte sur un ordre appartient à un seul endroit qui connaît cet ordre.
