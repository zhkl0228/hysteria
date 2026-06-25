# Encrypted Client Hello (ECH)

This fork ships server- and client-side support for **Encrypted Client Hello**
(RFC 9849 / draft-ietf-tls-esni-13, version `0xfe0d`), so the real SNI the
client wants to reach is encrypted on the wire and only the cover (public) name
is visible to on-path observers.

ECH is **on by default**: set `ech.disable: true` to opt out.

## Server config

```yaml
ech:
  disable: false        # ECH is on by default
  publicName: ""        # outer (cover) SNI; defaults to cloudflare-ech.com
  persist: true         # cache a random key to <configDir>/ech.json
  seed: ""              # only used with persist:false; falls back to
                        # trafficStats.secret
```

### Cover SNI (`publicName`)

The cover SNI is what shows up in cleartext in the outer ClientHello. It should
be an innocuous domain, **different from your real domain**, so the real SNI
stays hidden.

When unset it defaults to `cloudflare-ech.com`, which is the shared public name
every Cloudflare ECH-enabled site uses. Sending that means your traffic blends
into Cloudflare's existing ECH anonymity set. Override it if you want a
different cover.

### Key lifecycle

There are two modes, controlled by `ech.persist` (default `true`):

| Mode | What it does |
|---|---|
| `persist: true` *(default)* | First start: generate a random X25519 key, write `<configDir>/ech.json` (mode `0600`, atomic temp+rename). Subsequent starts: reload from the file. The key stays stable across restarts. The `publicName` recorded in the file wins over the one in config. |
| `persist: false` | Derive the key deterministically via HKDF-SHA256 from `ech.seed` (or `trafficStats.secret` if unset). No file is written. Useful for read-only / ephemeral environments where you can supply a stable secret. |

If saving `ech.json` fails (read-only filesystem, no permission, …), the server
falls back to a seed-derived key when a seed is available, or an ephemeral key
that rotates on restart otherwise. A warning is logged in both cases — startup
is not blocked.

> **Note.** With `persist:false`, the ECH key is tied to `trafficStats.secret`
> by default. Rotating that secret silently rotates the ECH key, which will
> break any client that cached the old `ECHConfigList`. Either set an explicit
> `ech.seed` independent of `trafficStats.secret`, or stay on the default
> `persist:true` and back up `ech.json`.

## Client config

```yaml
tls:
  ech:
    config: ""          # base64-encoded ECHConfigList
    configFile: ""      # path to a file containing the same
```

`config` takes precedence. The base64 string is the same one served by the
server's `/ech` endpoint (see below).

## Distributing the config

The server's `trafficStats` HTTP API exposes a new endpoint:

```
GET /ech
```

Response when ECH is enabled:

```json
{
  "config": "<base64 ECHConfigList>",
  "publicName": "cloudflare-ech.com"
}
```

`404` when ECH is disabled. `publicName` is informational — the cover SNI is
already baked into the `ECHConfigList`, so clients only need `config`.

The `/ech` endpoint is on the trafficStats listener, which is guarded by the
trafficStats secret. The expected workflow is: operator fetches once with the
admin secret, then ships the resulting base64 string to clients out of band.

Quick fetch:

```bash
curl -H "Authorization: <trafficStats.secret>" http://127.0.0.1:9999/ech
```

## End-to-end example

Server:

```yaml
listen: :443

acme:
  domains: [real.example.com]
  email: you@example.com

ech:
  # All defaults are fine — cloudflare-ech.com cover SNI + persistent random key.

trafficStats:
  listen: 127.0.0.1:9999
  secret: your-secret

auth:
  type: password
  password: hunter2
```

Fetch the config:

```bash
$ curl -s -H "Authorization: your-secret" http://127.0.0.1:9999/ech
{"config":"AED+DQA8AQAgACAAA...","publicName":"cloudflare-ech.com"}
```

Client:

```yaml
server: real.example.com:443

auth: hunter2

tls:
  sni: real.example.com
  ech:
    config: AED+DQA8AQAgACAAA...
```

The outer ClientHello now advertises SNI `cloudflare-ech.com` while the inner
(encrypted) ClientHello carries `real.example.com`.
