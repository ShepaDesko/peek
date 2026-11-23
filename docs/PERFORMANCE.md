# What it costs to run

Short version: a single core and a quarter of a gigabyte. The numbers below
were measured on a deliberately small machine, because the interesting
question is not how fast Peek can go on good hardware — it is whether the
smallest virtual machine an organisation will give you is enough. It is.

## The budgets

Section 13 of the brief sets three, and `make budget` checks them (CI runs it
on every build, so they cannot drift quietly):

| | Budget | Measured |
|---|---|---|
| Binary, with the interface embedded | < 60 MB | **28.7 MB** |
| Recipient page, JavaScript gzipped | < 150 kB | **131.2 kB** |
| Memory at rest | < 100 MB | **5–7 MB** |

The page budget is the one that matters most: a recipient did not choose to
use Peek, and may be opening the link on a phone on a train. 131 kB is the
whole application — the Argon2id WebAssembly module included — because nothing
is fetched from anywhere else.

## Throughput

One virtual CPU, 2 GB of RAM, Debian 13. Sixteen concurrent clients creating a
secret and immediately revealing it, for twenty seconds, with the rate
limiters lifted so the measurement is of Peek rather than of its own
throttling.

| Deployment | Creates/s | Reveals/s | p50 | p99 | Errors |
|---|---|---|---|---|---|
| One node, SQLite (the default) | **372** | **372** | 13 ms | 66 ms | none |
| One node, PostgreSQL | 182 | 182 | 32 / 48 ms | 104 / 127 ms | none |
| Two nodes, PostgreSQL, through nginx with TLS | 92 | 92 | 81 / 90 ms | 142 / 131 ms | none |

Read those three rows as what they are. SQLite on one node is the fastest
because the database is a function call rather than a socket. PostgreSQL costs
a round trip per query, which is what buys the shared state several nodes need.
The third row is lower again because one vCPU is running nginx, TLS
termination *and* two Peek processes — the box is saturated, not the software.

Memory peaked at **31 MB** on the SQLite node and **15 MB** per node in the
pair, after seven thousand secrets each.

So: 744 requests a second on the smallest sensible machine, with every secret
created, read and destroyed in the database. An organisation of a few thousand
people will not notice Peek is there.

## Where the time actually goes

```
BenchmarkSeal/1KiB                581 ns      1.8 GB/s
BenchmarkSeal/64KiB            13,013 ns      5.0 GB/s
BenchmarkSeal/1MiB            194,949 ns      5.4 GB/s
BenchmarkDeriveKeysNoPassphrase 1,408 ns
BenchmarkDeriveKeys        11,623,939 ns
BenchmarkSealFileStream     1,824,251 ns      4.6 GB/s  (8 MiB, 1 MiB chunks)
BenchmarkOpenFileStream     1,805,487 ns      4.6 GB/s
```

`make bench`, on a desktop Ryzen 9. Two things are worth reading off that
list.

**AES-GCM is free.** 5.4 GB/s means the hardware instruction is doing the
work; encryption is never the bottleneck, in the browser or on the server. The
file path is the same story at 4.6 GB/s, chunk by chunk, so a 100 MiB
attachment is bounded by the disk and the network and nothing else.

**Argon2id is eight thousand times slower than the path without it, and that
is the point.** 11.6 ms for one derivation with the shipped parameters
(19 MiB, two passes, one lane — the OWASP figures) is what makes an offline
guess against a passphrase-protected secret expensive. It runs in the
recipient's browser, so the server pays nothing for it, which is why the
parameters can be generous.

If that benchmark ever reports a tenth of this figure, somebody weakened the
parameters. That is the main reason it exists.

## What a 100 MiB attachment looks like

Measured end to end through nginx on the same virtual machine, with real TLS:

- upload: 106 MB/s, limited by the link
- download: 719 ms
- the SHA-256 of the file that came out matches the one that went in
- the secret was destroyed by the reveal that started the download, and the
  download finished anyway — that is what the grant is for

## Tuning, in the order worth trying

1. **Leave the rate limits alone** unless you have a reason. They are per
   client address and generous: 20 creations and 30 reads in a burst. They are
   what stops one script from filling the disk.
2. **Keep SQLite** unless you need several nodes. It is faster, and one file
   is a much simpler thing to back up than a database cluster.
3. **Put the blobs on S3** before you worry about anything else, if you expect
   large attachments. The database holds only the ciphertext of text secrets;
   files never go through it.
4. **`policy.max_file_bytes`** is the knob that decides your disk, not the
   number of users.
5. If reveals are slow and the box is idle, look at the proxy. A `p50` of
   80 ms where Peek reports 30 ms is TLS termination and a hop, not Peek.

`peek doctor` reports the database size, the blob count and the free space on
each directory, which is usually enough to see what is growing.
