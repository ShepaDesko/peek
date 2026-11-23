# Running several nodes

Peek on one node needs nothing from this page. SQLite, one process, one
systemd unit: that is the right answer for almost every installation, and it
handles more traffic than most organisations will ever send it.

Several nodes are for availability, not for throughput. The point is that a
node can be rebooted, patched or lost without the service going with it.

Three things have to be shared, and nothing else does.

| | What | Why |
|---|---|---|
| Database | PostgreSQL 14 or newer | Every node reads and writes the same rows. The single-read guarantee comes from there. |
| File storage | S3-compatible, or NFS | A blob uploaded to one node is downloaded from another. |
| Master key | the same `master.key` on every node | It decrypts what is in the shared database: TOTP seeds, notification addresses. |

There is **no Redis, no message broker and no external scheduler**. Peek
coordinates through the database it already has.

---

## What the cluster does for itself

**One reader per secret.** On one node the guarantee comes from a conditional
`UPDATE` and its row count. On a cluster it comes from the same statement, in
PostgreSQL, which is why that is how it was written rather than as a read
followed by a write. Forty simultaneous reveals of a one-view secret through a
load balancer across two nodes: one gets the ciphertext, thirty-nine get the
answer a link that never existed would get.

**One rate limit, not one per node.** The token bucket lives in the database
and is spent in a single upsert. Two nodes with `burst = 30` give the client
thirty requests, not sixty. Two consequences worth knowing:

- raising a limit in `peek.toml` does not top an exhausted bucket back up. It
  refills at the new rate, from where it is. A bucket emptied by a load test
  stays empty for a while.
- a database that cannot be reached fails *open* and logs it. A limiter that
  takes the service down with it is worse than no limiter.

**One periodic job, not one per node.** The purge, the audit trim and the
webhook drain are each claimed with a lease in `job_locks`. A node that dies
mid-job delays the next run by one tick; it does not block the others. One
webhook delivery leaves the cluster per event, not one per node.

**Any node, any session.** A session is a row, so a cookie issued by one node
is accepted by the next. Sticky sessions are not needed, and configuring them
hides a cluster that is not really one — do not.

---

## The recipe

### 1. PostgreSQL

```sql
CREATE ROLE peek LOGIN PASSWORD '…';
CREATE DATABASE peek OWNER peek;
```

Nothing else. Every node runs the migrations at start, and they are safe to
run concurrently: the first one in applies them, the others find nothing
pending.

```toml
[database]
driver = "postgres"
dsn    = "postgres://peek:…@db.internal:5432/peek?sslmode=verify-full"
```

Use `sslmode=verify-full` on anything but a loopback connection. The database
holds every ciphertext.

### 2. Shared file storage

S3-compatible is the easier of the two:

```toml
[storage]
backend     = "s3"
s3_bucket   = "peek-blobs"
s3_region   = "us-east-1"
s3_endpoint = "https://minio.internal:9000"
s3_access_key = "…"
s3_secret_key = "…"
```

Verified against MinIO and Garage. NFS works too — point `storage.path` at
the mount — but a stale NFS handle during a 100 MiB download is a worse
failure mode than an S3 timeout.

### 3. The same master key everywhere

```bash
# on the first node
sudo peek key rotate --init
sudo install -m 0640 -o root -g peek /etc/peek/master.key /mnt/transfer/master.key
# on every other node
sudo install -m 0640 -o root -g peek /mnt/transfer/master.key /etc/peek/master.key
```

Copy it, do not generate a second one. A node with a different key cannot read
the second factors or notification addresses the others wrote, and the
features that need it refuse with a clear message rather than failing
strangely.

### 4. The load balancer

Round robin, no session affinity, health check on `/readyz`. `/readyz` answers
`503` while the database is unreachable, which is exactly when the node should
be taken out of rotation.

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

The rest — headers, TLS, body size — is in
[`REVERSE-PROXY.md`](REVERSE-PROXY.md). Two points matter more with several
nodes:

- `server.trusted_proxies` must list the load balancer's addresses, or every
  node will log the balancer's IP as the client's and every rate limit will
  apply to the balancer rather than to the caller;
- publish `public_listen` to the outside and keep `internal_listen` on the
  LAN, per node. The split is per process, so it has to be configured on each.

### 5. The unit

Use the packaged unit (`/usr/lib/systemd/system/peek.service`) unchanged. It
scores 1.5 OK under `systemd-analyze security`; a hand-written one for a
second instance usually does not, and a weaker unit on one node is a weaker
cluster.

To run two instances on one host — for a test, not for availability — copy the
packaged unit to a template and change only `ExecStart` and `ReadWritePaths`.

---

## Verifying it

```bash
# every node sees the same schema
sudo peek migrate status

# every node answers
curl -fsS https://node1.internal:8080/readyz
curl -fsS https://node2.internal:8080/readyz

# the single-read guarantee, through the load balancer
#   create a one-view secret, then reveal it from forty clients at once:
#   exactly one must get the ciphertext, the rest must get 404.
```

The repository's own acceptance run, on two nodes against PostgreSQL 17
behind nginx:

- 40 simultaneous reveals × 8 rounds → 1 reader each time, 39 × `404`
- a secret created on node 1, revealed on node 2, and gone on node 1
- a 512 KiB attachment uploaded to node 1, served by node 2 with the grant
  node 2 issued
- a session issued by node 1, accepted by node 2
- one `secret.revealed` webhook delivery for one event, with both nodes
  watching
- `burst = 30` shared: 30 requests allowed and 10 refused out of 40
- 5–7 MB resident per node at rest

---

## Multi-organisation mode on a cluster

Nothing extra to configure. The Host-to-organisation answer is cached per node
for thirty seconds, so adding or verifying a domain takes effect immediately
on the node that did it and within thirty seconds everywhere else. That window
is the only thing a cluster changes about
[multi-organisation mode](CONFIG.md#multi-organisation-mode).

---

## What is not solved here

**The database is a single point of failure.** Peek does not replicate
PostgreSQL for you; use whatever your organisation already runs — Patroni, a
managed service, streaming replication with a VIP. A node that loses the
database answers `503` on `/readyz` and refuses work rather than serving
something wrong.

**There is no cross-site story.** Two data centres sharing one PostgreSQL over
a WAN will work and will be slow, because every reveal is a write. If you need
that, run two instances and give each its own domain.

**Rolling upgrades are safe in one direction.** A new binary applies pending
migrations at start, and the migrations are additive: an older node keeps
working against the newer schema. So upgrade one node at a time, oldest first,
and do not roll *back* a node past a migration that has been applied — see
[`UPGRADE.md`](UPGRADE.md).
