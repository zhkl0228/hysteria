package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECHPublishDomains(t *testing.T) {
	tests := []struct {
		name    string
		publish serverConfigECHPublish
		acme    *serverConfigACME
		want    []string
		wantErr string
	}{
		{
			name:    "explicit domains win",
			publish: serverConfigECHPublish{Domains: []string{"a.example.com"}},
			acme:    &serverConfigACME{Domains: []string{"b.example.com"}},
			want:    []string{"a.example.com"},
		},
		{
			name:    "falls back to the ACME domains",
			publish: serverConfigECHPublish{},
			acme:    &serverConfigACME{Domains: []string{"b.example.com", "c.example.com"}},
			want:    []string{"b.example.com", "c.example.com"},
		},
		{
			name:    "no domains anywhere",
			publish: serverConfigECHPublish{},
			acme:    nil,
			wantErr: "ech.publish.domains",
		},
		{
			name:    "wildcard is rejected",
			publish: serverConfigECHPublish{Domains: []string{"*.example.com"}},
			wantErr: "wildcard",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &serverConfig{
				ECH:  &serverConfigECH{Publish: &tt.publish},
				ACME: tt.acme,
			}
			got, err := c.echPublishDomains()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestECHPublishALPN(t *testing.T) {
	tests := []struct {
		name        string
		alpn        []string
		listenHTTPS string
		want        []string
	}{
		{
			name:        "defaults to what is actually served",
			listenHTTPS: ":443",
			want:        []string{"h3", "h2"},
		},
		{
			name: "no TCP masquerade means no h2",
			want: []string{"h3"},
		},
		{
			name:        "explicit list wins",
			alpn:        []string{"h2"},
			listenHTTPS: ":443",
			want:        []string{"h2"},
		},
		{
			name:        "explicit empty list publishes no alpn",
			alpn:        []string{},
			listenHTTPS: ":443",
			want:        []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &serverConfig{
				ECH:        &serverConfigECH{Publish: &serverConfigECHPublish{ALPN: tt.alpn}},
				Masquerade: serverConfigMasquerade{ListenHTTPS: tt.listenHTTPS},
			}
			assert.Equal(t, tt.want, c.echPublishALPN())
		})
	}
}

func TestECHPublishRecord(t *testing.T) {
	// A one-byte config list stands in for the real thing; the record only
	// carries its base64 form.
	configList := []byte{0x00, 0x01, 0x02}

	tests := []struct {
		name        string
		publish     serverConfigECHPublish
		listenHTTPS string
		domain      string
		zone        string
		wantName    string
		wantParams  libdns.SvcParams
		wantTTL     time.Duration
	}{
		{
			name:       "subdomain",
			publish:    serverConfigECHPublish{ALPN: []string{}},
			domain:     "jp.example.com",
			zone:       "example.com.",
			wantName:   "jp",
			wantParams: libdns.SvcParams{"ech": {"AAEC"}},
			wantTTL:    echPublishDefaultTTL,
		},
		{
			name:       "zone apex",
			publish:    serverConfigECHPublish{ALPN: []string{}},
			domain:     "example.com",
			zone:       "example.com.",
			wantName:   "@",
			wantParams: libdns.SvcParams{"ech": {"AAEC"}},
			wantTTL:    echPublishDefaultTTL,
		},
		{
			name:        "default alpn follows the masquerade",
			listenHTTPS: ":443",
			domain:      "jp.example.com",
			zone:        "example.com.",
			wantName:    "jp",
			wantParams:  libdns.SvcParams{"ech": {"AAEC"}, "alpn": {"h3", "h2"}},
			wantTTL:     echPublishDefaultTTL,
		},
		{
			name:       "custom ttl and alpn",
			publish:    serverConfigECHPublish{TTL: time.Minute, ALPN: []string{"h3"}},
			domain:     "jp.example.com",
			zone:       "example.com.",
			wantName:   "jp",
			wantParams: libdns.SvcParams{"ech": {"AAEC"}, "alpn": {"h3"}},
			wantTTL:    time.Minute,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &serverConfig{
				ECH:        &serverConfigECH{Publish: &tt.publish},
				Masquerade: serverConfigMasquerade{ListenHTTPS: tt.listenHTTPS},
			}
			rr := c.echPublishRecord(tt.domain, tt.zone, configList).RR()
			assert.Equal(t, "HTTPS", rr.Type)
			assert.Equal(t, tt.wantName, rr.Name)
			assert.Equal(t, tt.wantTTL, rr.TTL)
			// SvcParams is a map, so the presentation order is not stable;
			// compare the parsed parameters instead of the raw string.
			prefix, params, found := strings.Cut(rr.Data, " . ")
			require.True(t, found, "unexpected record data %q", rr.Data)
			assert.Equal(t, "1", prefix)
			gotParams, err := libdns.ParseSvcParams(params)
			require.NoError(t, err)
			assert.Equal(t, tt.wantParams, gotParams)
		})
	}
}

func TestValidateECHPublish(t *testing.T) {
	tests := []struct {
		name    string
		publish serverConfigECHPublish
		wantErr string
	}{
		{
			name: "unknown provider",
			publish: serverConfigECHPublish{
				Name:    "route53",
				Config:  map[string]string{"cloudflare_api_token": "x"},
				Domains: []string{"jp.example.com"},
			},
			wantErr: "route53",
		},
		{
			name:    "missing token",
			publish: serverConfigECHPublish{Domains: []string{"jp.example.com"}},
			wantErr: "cloudflare_api_token",
		},
		{
			name: "provider name is optional",
			publish: serverConfigECHPublish{
				Config:  map[string]string{"cloudflare_api_token": "x"},
				Domains: []string{"jp.example.com"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &serverConfig{ECH: &serverConfigECH{Publish: &tt.publish}}
			domains, err := c.validateECHPublish()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.publish.Domains, domains)
		})
	}
}
