# Modèle de menace

Ce document dit contre quoi Peek protège, contre quoi il ne protège pas, et
quelles décisions en découlent. Il est fait pour être lu avant un déploiement,
et cité honnêtement à un client qui demande « donc vous ne pouvez pas lire nos
secrets ? ».

## Ce qu'il y a à protéger

1. Le contenu d'un secret — la chose pour laquelle tout le reste existe.
2. La passphrase, quand il y en a une.
3. Les métadonnées : qui a partagé quoi, avec qui, quand, depuis quelle
   adresse.
4. L'instance elle-même : disponibilité, configuration, clé maîtresse.

## Qui peut être l'attaquant

| Attaquant | Ce qu'il peut faire |
|---|---|
| Un passant qui a le lien | Il a l'URL, donc la clé. Traité comme le destinataire. |
| Un observateur du réseau | Voit du trafic TLS. Ne voit aucun fragment : il n'est jamais envoyé. |
| Un robot d'aperçu de lien | Charge la page automatiquement (Teams, Slack, Outlook Safe Links, antivirus de messagerie). |
| Un administrateur curieux de la machine | Accès complet à la base, aux fichiers et aux logs. |
| Un voleur de sauvegarde | A l'archive, donc les chiffrés et la clé maîtresse. |
| Un attaquant sur le réseau | Peut atteindre l'écouteur exposé et deviner des identifiants. |
| Un attaquant qui compromet le serveur | Peut modifier le code que Peek sert. |

## Ce qui est protégé

**Une base volée n'apprend rien sur le contenu.** Chaque charge utile est en
AES-256-GCM avec une clé qui n'atteint jamais le serveur. Il n'y a pas de
séquestre de clé, pas de mécanisme de récupération et pas de contournement
administrateur — volontairement.

**Un robot d'aperçu ne détruit jamais un secret.** Charger la page ne renvoie
que des métadonnées. Consommer une lecture demande un POST portant un jeton
dérivé de la clé, que le robot n'a pas. C'est l'étape « cliquer pour
révéler », active par défaut et imposable par politique.

**Deviner une passphrase coûte à l'attaquant, pas au destinataire.** Une
mauvaise passphrase produit un mauvais jeton de lecture, rejeté avant qu'aucune
lecture ne soit consommée. Au-delà de `security.max_passphrase_attempts`
échecs, le secret est détruit. Deviner un identifiant de 128 bits n'est pas
praticable, et deviner la clé encore moins.

**Une lecture est consommée exactement une fois.** Le décompte est un `UPDATE`
conditionnel dans une transaction, contrôlé par le nombre de lignes ; cinquante
lecteurs simultanés d'un secret à lecture unique produisent exactement un
succès. Testé au niveau du store, au niveau HTTP, et à travers un répartiteur
sur deux nœuds.

**Un secret consommé a disparu.** La ligne est supprimée dans la même
transaction, pas marquée. Une tâche passe chaque minute purger ce qui a expiré.
Il ne reste qu'une pierre tombale (statut et compteurs) et le journal d'audit,
et ni l'un ni l'autre ne contient de contenu.

**La surface d'administration peut être rendue injoignable depuis Internet.**
Deux écouteurs plus des filtres CIDR, et `peek doctor --external` vérifie le
résultat au lieu de faire confiance à la configuration.

**Une IP client falsifiée ne marche pas.** Les en-têtes transférés ne sont
honorés que depuis les proxys déclarés ; partout ailleurs l'adresse du pair
gagne. Les limites de débit, les filtres et les entrées d'audit sont donc
écrits contre une adresse que l'attaquant ne choisit pas.

**Le destinataire ne sait pas qui a envoyé.** Le serveur, lui, le sait —
`creator_id` est sur la ligne, c'est ce qui rend possibles le tableau de bord
de l'expéditeur et le journal d'audit — mais aucun des deux points d'entrée
qu'un destinataire appelle ne le dit. La fiche d'un secret renvoie son
identifiant, son type, sa taille, ses compteurs, son expiration et les
paramètres de dérivation ; la révélation renvoie le chiffré, le type, la
taille, les lectures restantes et, s'il y a des pièces jointes, un jeton de
téléchargement. Rien d'autre. L'e-mail de notification, quand l'instance en
envoie un, dit « Un secret vous a été partagé via *le service* » et part de
l'adresse de l'instance, sans `Reply-To` et sans nom. Le seul chemin par
lequel un destinataire apprend l'identité de l'expéditeur, c'est que celui-ci
l'écrive dans le message libre : c'est son choix, affiché tel quel.
`TestRecipientLearnsNothingAboutTheSender` compare la liste complète des
champs des deux réponses, de sorte qu'un champ ajouté sans y penser casse le
test plutôt que la promesse.

**Rien ne quitte la machine par défaut.** Pas de CDN, pas de service de
polices, pas d'analytique, pas de télémétrie. Du trafic sortant, il n'y en a
que pour SMTP, un fournisseur d'identité, les webhooks et la vérification de
mise à jour — chacun que vous configurez, chacun désactivable. Peek fonctionne
sur un réseau isolé.

## Ce qui n'est pas protégé

**Un serveur compromis peut servir un JavaScript modifié.** C'est la limite
structurelle du chiffrement côté navigateur, et aucune conception ne la
supprime : qui contrôle le code que le navigateur exécute peut capturer ce que
le navigateur voit. Ce que Peek fait malgré tout : une CSP stricte sans aucune
origine tierce et sans script en ligne ; des assets immuables, empreintés,
servis depuis le binaire ; une unité systemd durcie avec un système de fichiers
en lecture seule ; et des releases signées pour que le binaire lui-même ne
puisse pas être remplacé sans qu'on le voie. Ce que vous devez faire : traiter
la machine comme un système à forte valeur, la tenir à jour, surveiller le
journal d'audit, et préférer une passphrase pour du matériel réellement
sensible — elle n'est jamais envoyée, et ne peut donc pas être capturée côté
serveur sans une modification de code **ciblée**.

**Qui a le lien a le secret.** La clé est dans l'URL. Un lien partagé dans une
conversation de groupe est un secret partagé avec ce groupe. La réponse est une
passphrase sur un second canal, et c'est pourquoi Peek n'envoie jamais la
passphrase par e-mail, même quand il envoie le lien.

**L'appareil du destinataire est hors périmètre.** Un secret révélé peut être
capturé en image, copié, journalisé par un gestionnaire de mots de passe ou
synchronisé ailleurs. Peek contrôle sa propre page : `no-store`, aucun cache
navigateur, rien d'écrit en stockage local sauf une langue et un thème.

**Les métadonnées sont visibles du serveur, et c'est le compromis.**
L'existence, la taille, les horodatages, les lectures et les adresses IP sont
ce qui fait fonctionner le journal d'audit, l'expiration et la limitation de
débit. `security.anonymize_ips` ne garde qu'un préfixe /24 ou /48 ;
`security.audit_retention` borne la durée de conservation.

**Une sauvegarde est aussi sensible que la base vivante, plus la clé
maîtresse.** Voir [BACKUP.md](BACKUP.md) : chiffrez l'archive, gardez une
rétention courte. `peek doctor` échoue quand les sauvegardes sont actives sans
passphrase, parce que lire le répertoire de sauvegarde suffirait alors à
prendre l'instance.

**Le déni de service est borné, pas éliminé.** Les limites de débit par IP
client réelle, les plafonds de taille de corps et les délais d'attente
augmentent le coût ; dimensionner le lien et le répartiteur devant reste votre
travail.

**Le HTTP simple casse le produit, pas seulement son transport.** WebCrypto
n'est disponible que dans un contexte sécurisé : une instance servie en
`http://` sur autre chose que localhost ne peut pas chiffrer du tout.
L'interface le dit au lieu d'échouer obscurément, et `peek doctor` avertit
pour une URL publique en `http://`.

**Un navigateur ancien peut être incapable de déchiffrer.** WebCrypto,
WebAssembly et le support de `'wasm-unsafe-eval'` sont nécessaires. La page le
dit plutôt que d'échouer en silence.

## Les décisions qui en découlent

| Décision | Pourquoi |
|---|---|
| La clé vit dans le fragment, jamais dans une chaîne de requête | Les chaînes de requête finissent dans les logs des proxys et des serveurs |
| `Referrer-Policy: no-referrer` partout | Empêche l'URL porteuse du fragment de fuiter vers un autre site |
| Preuve de possession avant de libérer un chiffré | Fait qu'une mauvaise passphrase, et un robot, ne coûtent rien |
| Réponse identique pour expiré, consommé et inconnu | Un appelant ne peut pas énumérer ce qui existe |
| 404, pas 403, depuis un filtre CIDR | Un réseau non autorisé n'apprend rien |
| Création désactivée par défaut | Une instance exposée n'est pas un relais ouvert dès le premier jour |
| La signature de release est vérifiée par le updater, avec la clé dans le binaire | Le chemin de mise à jour ne dépend pas de la confiance en un serveur web |
| Les endpoints de webhook vivent dans `peek.toml`, pas dans l'API | Une URL que l'API pourrait fixer ferait du serveur un relais de requêtes pointé vers votre propre réseau |
| Un domaine ne résout qu'après preuve par enregistrement DNS | Sinon n'importe qui pointant un nom sur l'instance porterait la marque d'un autre client |
| Les fonctions à moitié faites refusent au lieu d'approximer | Un repli silencieux casserait la garantie de lecture unique, ou servirait du HTTP simple |

## Signaler un problème

Voir [SECURITY.md](../SECURITY.md).
