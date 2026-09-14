package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/extras/v2/trafficlogger"
)

// Publishing the ECH config list to DNS.
//
// A client that only knows the server's domain has no way to learn its ECH
// config unless we hand it over out of band (tls.ech in the client config, or
// the ech= parameter of a hy2:// URI). RFC 9460 defines the in-band way: an
// HTTPS resource record carrying an "ech" SvcParam. Publishing one lets any
// client that resolves HTTPS records - browsers reaching the masquerade site,
// and third-party clients that implement SVCB-based ECH discovery - pick the
// config up from DNS.
//
// Note that hysteria's own client does NOT read HTTPS records; it still needs
// tls.ech. This publishes the record, nothing more.

// echPublishDefaultTTL is the TTL of the published HTTPS record when
// ech.publish.ttl is unset. Short enough that a key rotation propagates
// quickly, long enough not to look like a dynamic-DNS endpoint.
const echPublishDefaultTTL = 5 * time.Minute

// echPublishTimeout bounds one domain's publishing attempt (zone lookup plus
// the API call), so a wedged DNS API cannot leak goroutines forever.
const echPublishTimeout = 30 * time.Second

// providerCloudflare is the only DNS provider ech.publish accepts. The libdns
// providers differ in whether they implement HTTPS/SVCB records at all, and
// Cloudflare is the one whose write path we have actually exercised against
// the live API. Anything else is rejected rather than attempted blindly.
const providerCloudflare = "cloudflare"

// validateECHPublish checks everything about ech.publish that can be decided
// without touching the network, and returns the domains to publish for. A
// mistake here is a config mistake, so it is reported at startup rather than
// buried in a log line an hour later.
func (c *serverConfig) validateECHPublish() ([]string, error) {
	p := c.ECH.Publish

	name := strings.ToLower(p.Name)
	if name == "" {
		// The provider name is optional precisely because there is only one.
		name = providerCloudflare
	}
	if name != providerCloudflare {
		return nil, configError{Field: "ech.publish.name", Err: fmt.Errorf("unsupported DNS provider %q: only %q is implemented", p.Name, providerCloudflare)}
	}
	if p.Config["cloudflare_api_token"] == "" {
		return nil, configError{Field: "ech.publish.config", Err: errors.New("missing cloudflare_api_token")}
	}
	return c.echPublishDomains()
}

// publishECHConfig writes an HTTPS record carrying configList to the DNS
// provider configured under ech.publish, one record per domain, and records
// each outcome in status for the /ech endpoint.
//
// It runs in the background and never fails the server: the record is a
// convenience for clients that discover ECH configs over DNS, and a DNS API
// that is down or slow is no reason to refuse connections. Every failure is
// logged with the record we tried to write, so it can be published by hand.
// Domains are independent - one failing does not skip the rest.
func (c *serverConfig) publishECHConfig(status *trafficlogger.ECHPublishStatus, domains []string, configList []byte) {
	provider := &cloudflare.Provider{APIToken: c.ECH.Publish.Config["cloudflare_api_token"]}
	for _, domain := range domains {
		c.publishECHConfigForDomain(status, provider, domain, configList)
	}
}

func (c *serverConfig) publishECHConfigForDomain(status *trafficlogger.ECHPublishStatus, provider *cloudflare.Provider, domain string, configList []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), echPublishTimeout)
	defer cancel()

	zone, err := c.echPublishZone(ctx, domain)
	if err != nil {
		logger.Error("failed to publish the ECH config list to DNS",
			zap.String("domain", domain),
			zap.Error(err))
		status.Failed(domain)
		return
	}
	rec := c.echPublishRecord(domain, zone, configList)
	rr := rec.RR()
	if _, err := provider.SetRecords(ctx, zone, []libdns.Record{rec}); err != nil {
		logger.Error("failed to publish the ECH config list to DNS",
			zap.String("zone", zone),
			zap.String("name", rr.Name),
			zap.String("type", rr.Type),
			zap.String("data", rr.Data),
			zap.Error(err))
		status.Failed(domain)
		return
	}
	logger.Info("published the ECH config list to DNS",
		zap.String("zone", zone),
		zap.String("name", rr.Name),
		zap.String("type", rr.Type),
		zap.String("data", rr.Data))
	status.Published(domain)
}

// echPublishRecord builds the HTTPS record that carries configList for domain.
func (c *serverConfig) echPublishRecord(domain, zone string, configList []byte) libdns.ServiceBinding {
	p := c.ECH.Publish
	ttl := p.TTL
	if ttl == 0 {
		ttl = echPublishDefaultTTL
	}
	params := libdns.SvcParams{
		"ech": []string{base64.StdEncoding.EncodeToString(configList)},
	}
	if alpn := c.echPublishALPN(); len(alpn) > 0 {
		params["alpn"] = alpn
	}
	return libdns.ServiceBinding{
		Scheme:   "https",
		Name:     libdns.RelativeName(fqdn(domain), zone),
		TTL:      ttl,
		Priority: 1,
		// "." means "this same name", i.e. keep using the A/AAAA records of
		// the domain itself; we are only attaching parameters to it.
		Target: ".",
		Params: params,
	}
}

// echPublishALPN returns the alpn= SvcParam values, which must name the
// protocols this server really answers with - a browser that believes the
// record and finds nothing there just fails to load the site.
//
// An explicit ech.publish.alpn wins, including an empty list, which publishes
// no alpn= at all.
func (c *serverConfig) echPublishALPN() []string {
	if p := c.ECH.Publish.ALPN; p != nil {
		return p
	}
	// The QUIC listener runs an HTTP/3 server and hands every request that is
	// not a hysteria client to the masquerade handler, so h3 always holds.
	alpn := []string{"h3"}
	// The masquerade TCP server is a net/http server on ServeTLS, which
	// negotiates h2. Without it there is nothing listening on TCP 443.
	if c.Masquerade.ListenHTTPS != "" {
		alpn = append(alpn, "h2")
	}
	return alpn
}

// echPublishDomains resolves which names get an HTTPS record: ech.publish.domains
// when set, otherwise the ACME domains, since those are the names this server
// actually answers for.
func (c *serverConfig) echPublishDomains() ([]string, error) {
	domains := c.ECH.Publish.Domains
	field := "ech.publish.domains"
	if len(domains) == 0 {
		if c.ACME == nil || len(c.ACME.Domains) == 0 {
			return nil, configError{Field: field, Err: errors.New("empty domains, and there is no acme.domains to fall back on")}
		}
		domains = c.ACME.Domains
		field = "acme.domains"
	}
	for _, d := range domains {
		// A wildcard certificate covers names we cannot enumerate, and an
		// HTTPS record at "*.example.com" is not what anyone means by this.
		// Make the user spell out the names instead of guessing for them.
		if strings.HasPrefix(d, "*.") {
			return nil, configError{Field: field, Err: fmt.Errorf("cannot publish an HTTPS record for the wildcard %q: list the concrete names in ech.publish.domains", d)}
		}
	}
	return domains, nil
}

// echPublishZone returns the zone apex that owns domain, either as configured
// or by walking up the labels until a nameserver answers with an SOA record.
func (c *serverConfig) echPublishZone(ctx context.Context, domain string) (string, error) {
	if z := c.ECH.Publish.Zone; z != "" {
		return fqdn(z), nil
	}
	zone, err := certmagic.FindZoneByFQDN(ctx, logger, fqdn(domain), certmagic.RecursiveNameservers(nil))
	if err != nil {
		return "", fmt.Errorf("could not determine the DNS zone of %q, set ech.publish.zone to skip this lookup: %w", domain, err)
	}
	return zone, nil
}

// fqdn appends the root label to name if it is missing.
func fqdn(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}
