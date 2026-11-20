# Exposing Peek behind a load balancer

The goal of this document is one outcome: **the recipient pages are reachable
from the internet, and nothing else is**.

Peek gives you two independent mechanisms. Use both.

1. **Two listeners.** `public_listen` serves recipient routes only;
   `internal_listen` serves everything. Publish the first, keep the second on
   the LAN. A routing mistake cannot expose administration, because the
   internal-only routes are refused on the public listener regardless of path.
2. **CIDR gates.** `security.admin_allowed_cidrs` and
   `security.create_allowed_cidrs` check the **real** client IP and answer 404
   — not 403 — so a scan learns nothing.

```toml
public_url = "https://secrets.acme.com"

[server]
internal_listen = "10.0.0.5:8080"
public_listen   = "10.0.0.5:8081"
# Forwarded headers are believed ONLY from these addresses.
trusted_proxies = ["10.0.0.10/32", "10.0.0.11/32"]

[security]
admin_allowed_cidrs  = ["10.0.0.0/8", "192.168.0.0/16"]
create_allowed_cidrs = ["10.0.0.0/8"]
```

## HTTPS is required, not recommended

Browsers expose WebCrypto only in a secure context, so an instance published
over plain `http://` (other than `localhost`) cannot encrypt or decrypt
anything. The interface detects it and says so rather than failing with a
cryptic error, but the fix is always the same: publish `https://`.

Every example below terminates TLS. If you are evaluating Peek on a laptop,
`http://127.0.0.1:8080` works because localhost is a secure context.

## Why `trusted_proxies` matters

Rate limits, CIDR gates and the audit trail are all written against the client
IP. Peek therefore reads `X-Forwarded-For`, `Forwarded`, `X-Forwarded-Proto`
and `X-Forwarded-Host` **only when the connection comes from a declared
proxy**. From anywhere else those headers are ignored and the peer address is
used. Leave the list empty and no header is ever believed.

Within a trusted chain Peek takes the rightmost address that is not itself a
trusted proxy: the hops your proxy appended are trustworthy, whatever the
client prepended is not.

Check it from the server:

```bash
curl -s https://secrets.acme.com/api/v1/ip | jq
```

```json
{ "client_ip": "203.0.113.5", "peer_addr": "10.0.0.10:52118",
  "scheme": "https", "listener": "public", "trusted_peer": true }
```

`client_ip` equal to the proxy address means the proxy is not forwarding the
header; `trusted_peer: false` means the proxy is not in your list.

---

## Kemp LoadMaster

Peek is routinely deployed behind a Kemp, so this is the reference example.

### Virtual Service — SSL offload (most common)

1. **Virtual Services → Add New**
   - Virtual Address: the public VIP
   - Port: `443`, Protocol: `tcp`
   - Service Name: `peek-public`

2. **SSL Properties**
   - SSL Acceleration: **enabled**
   - Reencrypt: off (plain HTTP to Peek) — see the next section to re-encrypt
   - Certificates: the certificate for `secrets.acme.com`
   - Supported Ciphers: an intermediate or better profile, TLS 1.2 minimum

3. **Standard Options**
   - Transparency: **off** (Kemp then connects from its own address, which is
     what `trusted_proxies` expects)
   - Add HTTP Headers: **X-Forwarded-For** — this is required
   - Persistence: **None**. Peek keeps no local session state, so sticky
     sessions are unnecessary even with several nodes.
   - Scheduling Method: `round robin` or `least connection`

4. **Real Servers**
   - Add each Peek node on the **public** port: `10.0.0.5:8081`
   - Real Server Check Method: `HTTPS/HTTP Protocol`
   - URL: `/readyz`, HTTP Method: `GET`, expected status `200`
   - Check Interval 9 s, Timeout 5 s, Retry 2

5. **ESP / content rules (optional, belt and braces)**
   If you prefer a single listener, publish `internal_listen` and add a content
   rule that drops `/api/v1/audit`, `/api/v1/instance`, `/api/v1/policy` and
   `POST /api/v1/secrets`. The two-listener split is simpler and safer: prefer
   it, and keep the rule as a second lock only.

6. **Sub Virtual Service for administration (optional)**
   Publish `internal_listen` on a VIP that is only reachable from the internal
   network, with the same certificate.

Peek side:

```toml
public_url = "https://secrets.acme.com"
[server]
internal_listen = "10.0.0.5:8080"
public_listen   = "10.0.0.5:8081"
trusted_proxies = ["10.0.0.10/32"]      # the Kemp interface address
[tls]
mode = "none"                            # Kemp terminates TLS
hsts = false                             # let the Kemp send HSTS, or set true here, not both
```

### Re-encryption (TLS all the way)

Enable **Reencrypt** on the Virtual Service, then on Peek:

```toml
[tls]
mode      = "file"
cert_file = "/etc/peek/tls/fullchain.pem"
key_file  = "/etc/peek/tls/privkey.pem"
hsts      = true
```

Point the Real Server check at `https://…/readyz`. An internal CA is fine; the
Kemp must trust it.

### Layer 4 (PROXY protocol)

If you forward TCP rather than HTTP, enable PROXY protocol on the Real Server
and on Peek:

```toml
[server]
proxy_protocol  = true
trusted_proxies = ["10.0.0.10/32"]   # required: without it Peek refuses to start
```

Peek parses a PROXY header **only** from a trusted peer; anyone else gets their
real address used, so the header cannot be forged.

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
    # Never let a client inject its own chain.
    http-request del-header X-Forwarded-For
    http-request set-header X-Forwarded-Proto https
    default_backend peek_recipients

backend peek_recipients
    balance roundrobin
    option httpchk GET /readyz
    http-check expect status 200
    # Recipient listener only: administration is not reachable from here.
    server peek1 10.0.0.5:8081 check inter 5s fall 3 rise 2
    server peek2 10.0.0.6:8081 check inter 5s fall 3 rise 2

# Internal VIP, reachable from the LAN only.
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
trusted_proxies = ["10.0.0.10/32"]   # the HAProxy address
```

For layer 4, add `send-proxy-v2` to the `server` lines and set
`proxy_protocol = true` in `peek.toml`.

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

    # Large encrypted uploads (milestone M7).
    client_max_body_size 128m;
    proxy_request_buffering off;
    proxy_read_timeout 120s;

    location / {
        proxy_pass http://peek_recipients;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $remote_addr;   # not $proxy_add_x_forwarded_for: do not trust the client's chain
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
    }

    location = /readyz { proxy_pass http://peek_recipients; access_log off; }
}
```

---

## F5 BIG-IP

- Virtual Server: `secrets.acme.com:443`, Client SSL profile with the
  certificate, HTTP profile attached.
- **X-Forwarded-For: Enabled** on the HTTP profile.
- Pool: members on the **public** port `10.0.0.5:8081`.
- Health monitor: HTTP, send string
  `GET /readyz HTTP/1.1\r\nHost: secrets.acme.com\r\n\r\n`, receive string `200`.
- SNAT: Auto Map. Peek then sees the SNAT address as the peer, so put that
  address in `trusted_proxies`.
- Persistence: none required.

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

`mod_proxy_http` sets `X-Forwarded-For` to the real client address itself;
unsetting it first stops a client-supplied chain being appended to.

---

## Traefik (file provider)

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

Traefik sets the forwarded headers by default; add its address to
`trusted_proxies`.

---

## Direct exposure with your own certificate

No proxy at all:

```toml
public_url = "https://secrets.acme.com"

[server]
internal_listen = "0.0.0.0:443"
trusted_proxies = []          # nothing in front: never believe a header

[tls]
mode      = "file"
cert_file = "/etc/peek/tls/fullchain.pem"
key_file  = "/etc/peek/tls/privkey.pem"
hsts      = true
```

Binding port 443 as an unprivileged service needs one capability — uncomment
these two lines in `/usr/lib/systemd/system/peek.service`:

```ini
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

Renew with certbot and reload:

```bash
certbot certonly --standalone -d secrets.acme.com \
  --deploy-hook 'install -o peek -g peek -m 0640 \
      /etc/letsencrypt/live/secrets.acme.com/fullchain.pem /etc/peek/tls/fullchain.pem && \
    install -o peek -g peek -m 0600 \
      /etc/letsencrypt/live/secrets.acme.com/privkey.pem /etc/peek/tls/privkey.pem && \
    systemctl restart peek'
```

Built-in ACME (`tls.mode = "acme"`) is milestone M4 and currently refuses to
start rather than silently serving plain HTTP.

---

## Verify, every time

```bash
sudo peek doctor --external
```

It checks that the public URL answers, that the certificate is valid and for
how long, which client IP Peek resolves through the proxy, and — the one that
matters — whether `/api/v1/audit` answers through the public URL. A `FAIL` on
"admin surface" means administration is exposed: fix it before going live.

Manual equivalents:

```bash
curl -s  https://secrets.acme.com/api/v1/ip | jq        # resolved client IP
curl -si https://secrets.acme.com/api/v1/audit | head -1 # must be 404
curl -si https://secrets.acme.com/healthz | head -1      # must be 200
```
