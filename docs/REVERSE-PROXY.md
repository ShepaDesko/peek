# Exposer Peek derrière un répartiteur de charge

Le but de ce document est un seul résultat : **les pages destinataire sont
joignables depuis Internet, et rien d'autre ne l'est**.

Peek vous donne deux mécanismes indépendants. Utilisez les deux.

1. **Deux écoutes.** `public_listen` ne sert que les routes destinataire ;
   `internal_listen` sert tout. Publiez la première, gardez la seconde sur le
   LAN. Une erreur de routage ne peut pas exposer l'administration, parce que
   les routes réservées à l'interne sont refusées sur l'écoute publique quel que
   soit le chemin.
2. **Des filtres CIDR.** `security.admin_allowed_cidrs` et
   `security.create_allowed_cidrs` contrôlent la **vraie** IP cliente et
   répondent 404 — pas 403 — pour qu'un scan n'apprenne rien.

```toml
public_url = "https://secrets.acme.com"

[server]
internal_listen = "10.0.0.5:8080"
public_listen   = "10.0.0.5:8081"
# Les en-têtes transmis ne sont crus QUE depuis ces adresses.
trusted_proxies = ["10.0.0.10/32", "10.0.0.11/32"]

[security]
admin_allowed_cidrs  = ["10.0.0.0/8", "192.168.0.0/16"]
create_allowed_cidrs = ["10.0.0.0/8"]
```

## HTTPS est requis, pas recommandé

Les navigateurs n'exposent WebCrypto que dans un contexte sécurisé : une
instance publiée en `http://` (autrement que sur `localhost`) ne peut donc rien
chiffrer ni déchiffrer. L'interface le détecte et le dit, plutôt que d'échouer
avec une erreur énigmatique, mais la correction est toujours la même : publier
en `https://`.

Chaque exemple ci-dessous termine le TLS. Si vous évaluez Peek sur un portable,
`http://127.0.0.1:8080` fonctionne parce que localhost est un contexte
sécurisé.

## Pourquoi `trusted_proxies` compte

Les limites de débit, les filtres CIDR et le journal d'audit sont tous écrits
contre l'IP cliente. Peek lit donc `X-Forwarded-For`, `Forwarded`,
`X-Forwarded-Proto` et `X-Forwarded-Host` **seulement quand la connexion vient
d'un proxy déclaré**. Depuis n'importe où ailleurs, ces en-têtes sont ignorés et
l'adresse du pair est utilisée. Laissez la liste vide et aucun en-tête n'est
jamais cru.

Au sein d'une chaîne de confiance, Peek prend l'adresse la plus à droite qui
n'est pas elle-même un proxy de confiance : les sauts que votre proxy a ajoutés
sont dignes de foi, ce que le client a mis devant ne l'est pas.

Vérifiez-le depuis le serveur :

```bash
curl -s https://secrets.acme.com/api/v1/ip | jq
```

```json
{ "client_ip": "203.0.113.5", "peer_addr": "10.0.0.10:52118",
  "scheme": "https", "listener": "public", "trusted_peer": true }
```

Un `client_ip` égal à l'adresse du proxy veut dire que le proxy ne transmet pas
l'en-tête ; `trusted_peer: false` veut dire que le proxy n'est pas dans votre
liste.

---

## Kemp LoadMaster

Peek est couramment déployé derrière un Kemp, c'est donc l'exemple de référence.

### Service virtuel — déchargement SSL (le cas le plus courant)

1. **Virtual Services → Add New**
   - Virtual Address : la VIP publique
   - Port : `443`, Protocol : `tcp`
   - Service Name : `peek-public`

2. **SSL Properties**
   - SSL Acceleration : **activé**
   - Reencrypt : désactivé (HTTP en clair vers Peek) — voir la section suivante
     pour rechiffrer
   - Certificates : le certificat de `secrets.acme.com`
   - Supported Ciphers : un profil intermédiaire ou mieux, TLS 1.2 au minimum

3. **Standard Options**
   - Transparency : **désactivée** (le Kemp se connecte alors depuis sa propre
     adresse, ce qu'attend `trusted_proxies`)
   - Add HTTP Headers : **X-Forwarded-For** — c'est obligatoire
   - Persistence : **None**. Peek ne garde aucun état de session local, les
     sessions collantes sont donc inutiles même avec plusieurs nœuds.
   - Scheduling Method : `round robin` ou `least connection`

4. **Real Servers**
   - Ajoutez chaque nœud Peek sur le port **public** : `10.0.0.5:8081`
   - Real Server Check Method : `HTTPS/HTTP Protocol`
   - URL : `/readyz`, HTTP Method : `GET`, statut attendu `200`
   - Check Interval 9 s, Timeout 5 s, Retry 2

5. **ESP / règles de contenu (facultatif, ceinture et bretelles)**
   Si vous préférez une seule écoute, publiez `internal_listen` et ajoutez une
   règle de contenu qui jette `/api/v1/audit`, `/api/v1/instance`,
   `/api/v1/policy` et `POST /api/v1/secrets`. La séparation en deux écoutes est
   plus simple et plus sûre : préférez-la, et ne gardez la règle qu'en second
   verrou.

6. **Sous-service virtuel pour l'administration (facultatif)**
   Publiez `internal_listen` sur une VIP qui n'est joignable que depuis le
   réseau interne, avec le même certificat.

Côté Peek :

```toml
public_url = "https://secrets.acme.com"
[server]
internal_listen = "10.0.0.5:8080"
public_listen   = "10.0.0.5:8081"
trusted_proxies = ["10.0.0.10/32"]      # l'adresse de l'interface du Kemp
[tls]
mode = "none"                            # le Kemp termine le TLS
hsts = false                             # laissez le Kemp envoyer HSTS, ou mettez true ici, pas les deux
```

### Rechiffrement (TLS de bout en bout)

Activez **Reencrypt** sur le service virtuel, puis sur Peek :

```toml
[tls]
mode      = "file"
cert_file = "/etc/peek/tls/fullchain.pem"
key_file  = "/etc/peek/tls/privkey.pem"
hsts      = true
```

Pointez le contrôle du Real Server sur `https://…/readyz`. Une autorité de
certification interne convient ; le Kemp doit lui faire confiance.

### Couche 4 (protocole PROXY)

Si vous transmettez du TCP plutôt que du HTTP, activez le protocole PROXY sur le
Real Server et sur Peek :

```toml
[server]
proxy_protocol  = true
trusted_proxies = ["10.0.0.10/32"]   # obligatoire : sans ça, Peek refuse de démarrer
```

Peek n'analyse un en-tête PROXY **que** venant d'un pair de confiance ;
n'importe qui d'autre voit sa vraie adresse utilisée, l'en-tête ne peut donc pas
être forgé.

---

## HAProxy

```haproxy
global
    log stdout format raw local0
    tune.ssl.default-dh-param 2048

defaults
    mode http
    option httplog
    option forwardfor
    timeout connect 5s
    timeout client  120s
    timeout server  120s

frontend peek_public
    bind :443 ssl crt /etc/haproxy/certs/secrets.acme.com.pem alpn h2,http/1.1
    http-request redirect scheme https unless { ssl_fc }
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    # Ne jamais laisser un client injecter sa propre chaîne.
    http-request del-header X-Forwarded-For
    http-request set-header X-Forwarded-Proto https
    default_backend peek_recipients

backend peek_recipients
    balance roundrobin
    option httpchk GET /readyz
    http-check expect status 200
    # Écoute destinataire uniquement : l'administration n'est pas joignable d'ici.
    server peek1 10.0.0.5:8081 check inter 5s fall 3 rise 2
    server peek2 10.0.0.6:8081 check inter 5s fall 3 rise 2

# VIP interne, joignable depuis le LAN seulement.
frontend peek_internal
    bind 10.0.0.2:8443 ssl crt /etc/haproxy/certs/secrets-internal.pem
    http-request del-header X-Forwarded-For
    http-request set-header X-Forwarded-Proto https
    default_backend peek_admin

backend peek_admin
    option httpchk GET /readyz
    server peek1 10.0.0.5:8080 check
```

```toml
[server]
trusted_proxies = ["10.0.0.10/32"]   # l'adresse de HAProxy
```

Pour la couche 4, ajoutez `send-proxy-v2` aux lignes `server` et mettez
`proxy_protocol = true` dans `peek.toml`.

---

## nginx

```nginx
upstream peek_recipients { server 10.0.0.5:8081; keepalive 16; }

server {
    listen 443 ssl;
    http2 on;
    server_name secrets.acme.com;

    ssl_certificate     /etc/nginx/ssl/secrets.acme.com.crt;
    ssl_certificate_key /etc/nginx/ssl/secrets.acme.com.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # De gros envois chiffrés.
    client_max_body_size 128m;
    proxy_request_buffering off;
    proxy_read_timeout 120s;

    location / {
        proxy_pass http://peek_recipients;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $remote_addr;   # pas $proxy_add_x_forwarded_for : ne faites pas confiance à la chaîne du client
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
    }

    location = /readyz { proxy_pass http://peek_recipients; access_log off; }
}
```

---

## F5 BIG-IP

- Virtual Server : `secrets.acme.com:443`, profil Client SSL avec le
  certificat, profil HTTP attaché.
- **X-Forwarded-For : Enabled** sur le profil HTTP.
- Pool : des membres sur le port **public** `10.0.0.5:8081`.
- Moniteur de santé : HTTP, chaîne envoyée
  `GET /readyz HTTP/1.1\r\nHost: secrets.acme.com\r\n\r\n`, chaîne attendue
  `200`.
- SNAT : Auto Map. Peek voit alors l'adresse de SNAT comme le pair, mettez donc
  cette adresse dans `trusted_proxies`.
- Persistance : aucune n'est nécessaire.

---

## Apache httpd

```apache
<VirtualHost *:443>
    ServerName secrets.acme.com
    SSLEngine on
    SSLCertificateFile    /etc/pki/tls/certs/secrets.acme.com.crt
    SSLCertificateKeyFile /etc/pki/tls/private/secrets.acme.com.key

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

    RequestHeader unset X-Forwarded-For
    RequestHeader set X-Forwarded-Proto "https"

    ProxyPreserveHost On
    ProxyPass        / http://10.0.0.5:8081/
    ProxyPassReverse / http://10.0.0.5:8081/
</VirtualHost>
```

`mod_proxy_http` met lui-même `X-Forwarded-For` à la vraie adresse du client ;
le retirer d'abord empêche qu'une chaîne fournie par le client se fasse
compléter.

---

## Traefik (fournisseur fichier)

```yaml
http:
  routers:
    peek:
      rule: "Host(`secrets.acme.com`)"
      entryPoints: [websecure]
      service: peek
      tls:
        certResolver: letsencrypt
  services:
    peek:
      loadBalancer:
        servers:
          - url: "http://10.0.0.5:8081"
        healthCheck:
          path: /readyz
          interval: 10s
          timeout: 3s
```

Traefik pose les en-têtes transmis par défaut ; ajoutez son adresse à
`trusted_proxies`.

---

## Exposition directe avec votre propre certificat

Sans aucun proxy :

```toml
public_url = "https://secrets.acme.com"

[server]
internal_listen = "0.0.0.0:443"
trusted_proxies = []          # rien devant : ne jamais croire un en-tête

[tls]
mode      = "file"
cert_file = "/etc/peek/tls/fullchain.pem"
key_file  = "/etc/peek/tls/privkey.pem"
hsts      = true
```

Écouter sur le port 443 en tant que service non privilégié demande une
capacité — décommentez ces deux lignes dans
`/usr/lib/systemd/system/peek.service` :

```ini
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

Renouvelez avec certbot et rechargez :

```bash
certbot certonly --standalone -d secrets.acme.com \
  --deploy-hook 'install -o peek -g peek -m 0640 \
      /etc/letsencrypt/live/secrets.acme.com/fullchain.pem /etc/peek/tls/fullchain.pem && \
    install -o peek -g peek -m 0600 \
      /etc/letsencrypt/live/secrets.acme.com/privkey.pem /etc/peek/tls/privkey.pem && \
    systemctl restart peek'
```

Ou laissez Peek le faire : `tls.mode = "acme"` obtient et renouvelle lui-même un
certificat Let's Encrypt, par TLS-ALPN-01, donc sans port 80 et sans hook
certbot. Il faut que Peek soit ce qui écoute sur 443 — voir
[`CONFIG.md`](CONFIG.md#acme-quand-peek-est-seul-à-écouter). Derrière un proxy,
le proxy possède le certificat et `tls.mode = "none"` est la bonne réponse.

---

## Vérifier, chaque fois

```bash
sudo peek doctor --external
```

Il vérifie que l'URL publique répond, que le certificat est valide et pour
combien de temps, quelle IP cliente Peek résout à travers le proxy, et — celui
qui compte — si `/api/v1/audit` répond à travers l'URL publique. Un `FAIL` sur
« surface d'administration » veut dire que l'administration est exposée :
corrigez avant la mise en service.

Les équivalents à la main :

```bash
curl -s  https://secrets.acme.com/api/v1/ip | jq        # l'IP cliente résolue
curl -si https://secrets.acme.com/api/v1/audit | head -1 # doit être 404
curl -si https://secrets.acme.com/healthz | head -1      # doit être 200
```
