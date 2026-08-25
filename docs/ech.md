# Encrypted Client Hello (ECH)

Upstream Hysteria supports ECH (RFC 9849 / draft-ietf-tls-esni-13, version
`0xfe0d`): the client's real SNI travels inside an encrypted inner ClientHello,
and only a cover name — the *public name* — is visible on the wire.

This fork keeps upstream's configuration and key format unchanged and adds three
things on top:

- **`ech.enabled`** with automatic key generation, so a server can turn ECH on
  without running an external tool first.
- **`hysteria ech keygen`**, producing the same key file format as
  `sing-box generate ech-keypair`.
- **`GET /ech`** on the trafficStats API, so clients can fetch the config list
  instead of having it copied out of the server log by hand.

## What ECH does and does not buy you

ECH replaces the visible SNI with the public name. It does **not** make the
connection invisible. Whether that is an improvement depends entirely on the
public name you pick:

- A public name that resolves to **this same server**, with a certificate that
  covers it, is the intended deployment. Your real domain stops appearing on the
  wire, and you can rotate the cover name without touching the real one.
- A public name belonging to somebody else — `cloudflare-ech.com` is the usual
  suggestion — is **worse than not using ECH**. An observer sees an outer SNI
  claiming to be Cloudflare while the packets go to your VPS, which is a far
  rarer and more distinctive pattern than your real domain was. The "blend into
  the anonymity set" argument only works when the cover name genuinely serves
  large amounts of other traffic *at the same IP*.

There is no safe automatic default here, so `ech.enabled: true` requires you to
name the cover explicitly the first time.

## Server config

```yaml
ech:
  enabled: true                # default when the ech block is present
  publicName: cover.example.com # outer (cover) SNI; required to generate a key
  keyPath: /etc/hysteria/ech.pem # default: ech.pem next to the config file
```

On startup:

- If `keyPath` exists, it is loaded. `publicName` is ignored — the file's
  ECHConfig already carries the name clients were handed.
- If `keyPath` does not exist and `publicName` is set, a fresh X25519 key pair is
  generated and written there (mode `0600`, via temp file + rename). The same key
  is then reused on every restart.
- If `keyPath` does not exist and `publicName` is unset, startup fails with an
  error telling you to set it or to create the file yourself.
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

The command prints the base64 config list to give to clients. The file is
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
