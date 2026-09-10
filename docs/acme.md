# ACME

Upstream Hysteria gets its certificate from an ACME CA through
[certmagic](https://github.com/caddyserver/certmagic). This fork keeps that
configuration unchanged and fixes the parts that break when the server also runs
a masquerade site:

- **HTTP-01 and TLS-ALPN-01 now work behind the masquerade servers.** Upstream,
  a server with `masquerade.listenHTTP` / `listenHTTPS` could only ever obtain a
  certificate during the startup window, and silently failed to renew afterwards.
- **`acme.ca` accepts an ACME directory URL**, so a staging endpoint or a local
  test CA can be used to verify renewal end to end.

## Config

```yaml
acme:
  domains:
    - your.domain.com
  email: you@example.com
  ca: letsencrypt          # letsencrypt | zerossl | https://... directory URL
  dir: /etc/hysteria/acme   # certificate/account storage
  listenHost: 0.0.0.0       # address the challenge listeners bind to

  type: http                # http | tls | dns
  http:
    altPort: 0              # only useful behind a port forward
  tls:
    altPort: 0
  dns:
    name: cloudflare
    config:
      cloudflare_api_token: ...
```

`type` selects exactly one challenge and disables the others. Leaving it empty
keeps upstream's legacy behaviour, where `disableHTTP`, `disableTLSALPN`,
`altHTTPPort` and `altTLSALPNPort` apply instead.

### `acme.ca`

- `letsencrypt` / `le` / empty — Let's Encrypt production.
- `zerossl` / `zero` — ZeroSSL, with EAB credentials fetched automatically from
  the address in `acme.email`.
- Anything starting with `https://` is taken as an ACME directory URL. That is
  what reaching any other CA requires, including Let's Encrypt's staging
  endpoint and a local [Pebble](https://github.com/letsencrypt/pebble) instance:

  ```yaml
  acme:
    ca: https://acme-staging-v02.api.letsencrypt.org/directory
  ```

  Staging issues untrusted certificates but shares the production rate limits'
  code paths, so it is the right place to debug a challenge before burning a
  production quota. Any other value is rejected at startup rather than silently
  falling back to Let's Encrypt.

## Challenges and the masquerade site

The three challenge types differ in what they need to be reachable:

| type  | needs                        | works behind NAT | wildcards |
|-------|------------------------------|------------------|-----------|
| `http`| inbound TCP 80               | no               | no        |
| `tls` | inbound TCP 443              | no               | no        |
| `dns` | credentials for your DNS API | yes              | yes       |

With `masquerade.listenHTTP` / `listenHTTPS` set, the masquerade servers already
hold ports 80 and 443, and both port-based challenges need help from them.

### HTTP-01

certmagic's own challenge server cannot bind port 80 while the masquerade server
is on it. certmagic does not treat that as an error — it assumes whatever holds
the port can answer the challenge. Nothing did, so the CA reached the decoy site
instead and validation failed. The practical symptom: the certificate could only
be obtained in the startup window before the masquerade server took the port,
and every renewal after that failed.

The masquerade HTTP server now gets the first look at every plain-HTTP request
and hands ACME challenges to certmagic. Two details matter:

- It runs **before** the `forceHTTPS` redirect. A CA does follow a 301 to HTTPS,
  but it would land on the masquerade handler, which knows nothing about
  challenge tokens.
- It stays **shut except while a challenge is actually in flight**. certmagic
  records a challenge when the solver presents it and drops it during cleanup;
  outside that window every request falls through to the masquerade handler
  untouched. So `/.well-known/acme-challenge/` on the decoy site behaves exactly
  as it would on a site that never uses ACME, and scanner traffic does not fill
  the log.

### TLS-ALPN-01

Serving the challenge certificate needs no special handling — the masquerade TLS
config already gets its certificate from certmagic, which returns the key
authentication certificate when it sees an `acme-tls/1` handshake. What blocked
the challenge was ALPN negotiation happening first: `http.Server` puts `h2` and
`http/1.1` in `NextProtos`, the CA offers only `acme-tls/1`, and Go rejects the
handshake for want of a shared protocol before any certificate is chosen.

A `GetConfigForClient` hook now swaps in a config that speaks `acme-tls/1`, and
only when the handshake really is a challenge: RFC 8737 requires the CA to send
exactly one ALPN protocol and an SNI naming the domain being validated, and
there must be a live challenge for that name. Outside that window an
`acme-tls/1` handshake is refused for no shared protocol, exactly as an ordinary
web server would refuse it.

### DNS-01

DNS-01 needs no inbound port at all, which makes it the option for a server
behind NAT, on a non-standard port, or one that would rather not expose 80/443.
It is also the only type that can issue wildcard certificates.

```yaml
acme:
  type: dns
  dns:
    name: cloudflare
    config:
      cloudflare_api_token: ...
```

Supported providers and their config keys:

| `name`       | keys                                                                          |
|--------------|-------------------------------------------------------------------------------|
| `cloudflare` | `cloudflare_api_token`                                                        |
| `duckdns`    | `duckdns_api_token`, `duckdns_override_domain`                                |
| `gandi`      | `gandi_api_token`                                                             |
| `godaddy`    | `godaddy_api_token`                                                           |
| `namecheap`  | `namecheap_api_key`, `namecheap_api_user`, `namecheap_api_endpoint`, `namecheap_client_ip` |
| `njalla`     | `njalla_api_token`                                                            |
| `porkbun`    | `porkbun_api_key`, `porkbun_api_secret_key`                                   |
| `vultr`      | `vultr_api_token`                                                             |

A Cloudflare token needs `Zone / DNS / Edit` plus `Zone / Zone / Read`, scoped to
the zone in question. It is an API token, not a Global API Key and not anything
from Cloudflare Access.

`namedotcom` was dropped: upstream never released a libdns v1 compatible version,
which the current certmagic requires. Configuring it is an error rather than a
silent fallback.

> The ECH config list can be published to DNS with a provider of its own, see
> [ech.md](ech.md). It is deliberately configured separately from `acme.dns`,
> because answering a challenge and publishing a record are different jobs and
> ACME is commonly solved over HTTP-01 with no DNS credentials at all.
