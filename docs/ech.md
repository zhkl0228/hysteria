# Encrypted Client Hello (ECH)

Upstream Hysteria supports ECH (RFC 9849 / draft-ietf-tls-esni-13, version
`0xfe0d`): the client's real SNI travels inside an encrypted inner ClientHello,
and only a cover name — the *public name* — is visible on the wire.

This fork keeps upstream's configuration and key format unchanged and adds four
things on top:

- **`ech.enabled`** with automatic key generation, so a server can turn ECH on
  without running an external tool first.
- **`hysteria ech keygen`**, producing the same key file format as
  `sing-box generate ech-keypair`.
- **`GET /ech`** on the trafficStats API, so clients can fetch the config list
  instead of having it copied out of the server log by hand.
- **`ech.publish`**, which writes the config list into DNS as an HTTPS record,
  for clients that discover ECH configs there.

## What ECH does and does not buy you

ECH replaces the visible SNI with the public name. It does **not** make the
connection invisible — it moves the question to *which* cover name you use, and
the two defensible answers trade off against each other:

- A public name that resolves to **this same server**, with a certificate that
  covers it, is the textbook deployment. Nothing about the handshake is
  anomalous: outer SNI, IP and certificate all agree, and the cover name can be
  rotated without touching the real one. It costs a second name and a second
  certificate.
- A public name belonging to a **large ECH deployment** — `cloudflare-ech.com`,
  the default here — puts the handshake in the biggest crowd available. The cost
  is that the crowd is not at your IP: an observer sees an outer SNI claiming
  Cloudflare while the packets go to a single VPS, and that combination is rarer
  than your real domain was. What it buys is that the name itself says nothing
  about you — "which site is this?" stops having an answer on the wire, even for
  an observer who has your IP.

Neither is right for every threat model. `cloudflare-ech.com` is the default
because it needs no second certificate and leaks no name, but if the mismatch
between the cover name and your IP is what you are worried about, set
`ech.publicName` to a name of your own that points here.

Two consequences of the default worth knowing:

- **ECH rejection cannot degrade into a working plain connection.** Answering a
  rejected handshake means answering under the outer SNI, and there is no
  certificate for `cloudflare-ech.com` here: with ACME the server has none for
  that name at all, and with a local certificate it either refuses on the SNI
  guard or presents a certificate the client rejects, since the rejection path
  verifies against the public name with the system roots. That is the desired
  outcome for a probe, but it also means a client holding a stale config list
  recovers only through the retry configs described below.
- The public name travels in the clear inside every ECHConfig, including the one
  published to DNS. It is not a secret and was never meant to be.

## Server config

```yaml
ech:
  enabled: true                  # default when the ech block is present
  publicName: cover.example.com  # outer (cover) SNI; default cloudflare-ech.com
  keyPath: /etc/hysteria/ech.pem # default: ech.pem next to the config file
```

Every field is optional; an `ech: {}` block is enough to turn ECH on with a
generated key under the default cover name.

On startup:

- If `keyPath` exists, it is loaded. `publicName` is ignored — the file's
  ECHConfig already carries the name clients were handed.
- If `keyPath` does not exist, a fresh X25519 key pair is generated for
  `publicName` and written there (mode `0600`, via temp file + rename). The same
  key is then reused on every restart.
- A key file that exists but cannot be parsed is an error. It is never silently
  regenerated, because that would cut off every client holding the old config
  list.

Omitting the `ech` block, or setting `ech.enabled: false`, disables ECH.

> An `ech` block containing only `keyPath` behaves exactly as it does upstream —
> present means enabled — so upstream configs work unchanged.

### Generating a key manually

```
hysteria ech keygen cover.example.com -o /etc/hysteria/ech.pem
```

The public name argument is optional and defaults to `cloudflare-ech.com`. The
command prints the base64 config list to give to clients. The file is
interchangeable with `sing-box generate ech-keypair <public_name>` in both
directions.

## Client config

```yaml
tls:
  ech: AEv+DQBHAAAgACB3rc0Q...   # base64 ECHConfigList, or a path to a file
```

The value is tried as an inline base64 config list first; failing that, it is
read as a file, which may hold either base64 or a PEM `ECH CONFIGS` block.

ECH also travels in share URIs as `?ech=<base64>`, so `hysteria share` output
carries it automatically.

### ECH turns off the Chrome QUIC fingerprint

Chrome parroting (on by default, `quic.disableChromeParrot` to turn it off) and
ECH are mutually exclusive, and a client configured with `tls.ech` silently
takes the ECH side: the parrot is disabled for that connection.

The parrot replaces `crypto/tls` with uTLS, and the adapter in between drops
`EncryptedClientHelloRejectionVerify`, never reports back whether ECH was
accepted, and reports rejection through uTLS's own error type rather than
`*tls.ECHRejectionError`. Under the parrot, ECH would report as never accepted
and the retry-config recovery below would not fire. ECH hides the SNI outright,
which is the stronger property, so it wins.

The client log line on a successful connection reports whether ECH was accepted:

```
connected to server   {"addr": "...", "udpEnabled": true, "tx": 0, "ech": true, "count": 1}
```

## Distributing the config list

With `trafficStats.listen` configured, the server exposes:

```
GET /ech
Authorization: <trafficStats.secret>

{"config":"AEv+DQBHAAAgACB3rc0Q..."}
```

It returns 404 when ECH is disabled. The same value is printed to the server log
at startup.

## Publishing the config list to DNS

RFC 9460 defines the in-band way to hand out an ECH config: an HTTPS resource
record carrying an `ech` SvcParam. With `ech.publish`, the server writes that
record itself through a DNS provider API.

```yaml
ech:
  publish:
    config:
      cloudflare_api_token: ...
```

That is the whole minimal config — everything else is derived:

| field     | default                                                          |
|-----------|------------------------------------------------------------------|
| `name`    | `cloudflare`, the only supported provider                        |
| `domains` | `acme.domains`                                                   |
| `zone`    | discovered by walking up the labels until a nameserver answers with an SOA |
| `ttl`     | `5m`                                                             |
| `alpn`    | the protocols this server actually serves (see below)            |

The result, for a server with `acme.domains: [your.domain.com]`:

```
your.domain.com.  300  IN  HTTPS  1 . ech="AEv+DQBH..." alpn="h3,h2"
```

`alpn` defaults to what is really answering on that name: `h3` always, because
the QUIC listener runs an HTTP/3 server and hands every request that is not a
hysteria client to the masquerade handler; plus `h2` when
`masquerade.listenHTTPS` is set, because that listener is a `net/http` server on
`ServeTLS` and negotiates it. Advertising a protocol nothing answers would just
break browsers that believe the record, so the default never claims more than
the config delivers. Set `ech.publish.alpn` to override, or to an empty list to
publish no `alpn` at all.

### What it is and is not for

**Hysteria's own client does not read HTTPS records.** It takes the config list
from `tls.ech` or the `ech=` parameter of a share URI, and publishing changes
nothing for it. The record is for everything else that resolves the name:
browsers reaching the masquerade site, and third-party clients that implement
SVCB-based ECH discovery.

That cuts both ways. An HTTPS record is visible to anyone who queries the name,
and a self-hosted site publishing `ech=` is not yet a common sight — it is one
more thing to look at, on a name that previously had only an address record.
Whether that trade is worth making is the same judgement as the cover name
above, and `ech.publish` is off unless configured.

### Operational notes

- Publishing runs **in the background and never fails the server**. A DNS API
  that is down or slow is no reason to refuse connections. Failures are logged
  with the full record that was attempted, so it can be written by hand:

  ```
  ERROR  failed to publish the ECH config list to DNS
         {"zone": "example.com.", "name": "sub", "type": "HTTPS",
          "data": "1 . ech=AEv+DQBH... alpn=h3,h2", "error": "..."}
  ```

  Mistakes that can be caught without touching the network — an unknown provider,
  a missing token, a wildcard domain — are config errors and still fail at
  startup.
- The record is rewritten on every start, so rotating `ech.pem` propagates on the
  next restart. Clients holding the previous list recover through the retry
  configs described below in the meantime.
- The Cloudflare token needs `Zone / DNS / Edit` plus `Zone / Zone / Read` — the
  same permission set as `acme.dns` (see [acme.md](acme.md)), but deliberately
  configured separately: answering an ACME challenge and publishing a record are
  different jobs, and ACME is commonly solved over HTTP-01 with no DNS
  credentials at all.
- The zone must not be proxied through Cloudflare. An orange-cloud record has
  Cloudflare terminating TLS and managing its own ECH parameters, which is not
  the deployment this describes.
- Wildcard entries in `acme.domains` are rejected rather than guessed at; list
  the concrete names in `ech.publish.domains` instead.

## Key rotation and stale clients

`crypto/tls` **aborts the handshake whenever ECH is rejected** — there is no
falling back to a plain connection. It also ignores `insecure` and `pinSHA256`
on the rejection path, verifying the certificate against the public name with
the system roots instead, which would surface as a baffling certificate error
for the self-signed setups Hysteria commonly uses.

To keep a rotated key from locking clients out, this fork:

- marks the server's keys as retry configs, so a server that no longer holds the
  client's key advertises its current one;
- has the client detect the rejection, adopt the advertised config list, and
  reconnect once, automatically;
- applies Hysteria's own certificate policy on the rejection path, so the error
  that does surface is the actionable one.

The result: replacing `ech.pem` on the server is safe. Clients holding the old
config list recover on their next connection without any config change.

The one case that cannot self-heal is a server with **no** ECH keys at all —
there are no retry configs to advertise. A client still configured with `tls.ech`
will fail to connect rather than silently downgrade. Remove `tls.ech` from the
client, or re-enable ECH on the server.

## Masquerade

The masquerade HTTPS listener shares the server's ECH keys, so the cover site is
reachable over ECH too and does not become the odd one out.
