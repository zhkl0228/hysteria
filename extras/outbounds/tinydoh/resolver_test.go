package tinydoh

import (
	"fmt"
	"testing"
)

func TestResolver(t *testing.T) {
	r := &Resolver{
		// Addressed by IP, not by name: resolving the resolver's own hostname
		// first would mean using DNS to test DNS. The certificate carries
		// 1.1.1.1 as an IP SAN, so ordinary verification still applies.
		//
		// Cloudflare rather than a CN resolver, because this test runs in CI
		// from a US network: AliDNS answers SERVFAIL for this name from there,
		// and returns poisoned addresses when asked from a CN source. The
		// trade is that a developer on a bare CN link, with no tunnel, cannot
		// reach 1.1.1.1 at all.
		URL: "https://1.1.1.1/dns-query",
	}
	ipv4, err := r.LookupA("www.wikipedia.org")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(ipv4)
	ipv6, err := r.LookupAAAA("www.wikipedia.org")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(ipv6)
}
