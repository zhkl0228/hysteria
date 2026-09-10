package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// newTestACMEIssuer builds an issuer backed by throwaway storage, plus an
// observer over its log output. The observer is what makes the gate testable:
// when the gate declines, certmagic is never entered and stays silent; when it
// is entered without an active challenge, it logs a warning.
func newTestACMEIssuer(t *testing.T) (*certmagic.ACMEIssuer, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zapcore.WarnLevel)
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return nil, nil
		},
		Logger: zap.NewNop(),
	})
	t.Cleanup(cache.Stop)
	cfg := certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: t.TempDir()},
		Logger:  zap.NewNop(),
	})
	return certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{Logger: zap.New(core)}), logs
}

// Without ACME there is nothing to solve, so no hook is installed at all and
// the masquerade server keeps its original behavior.
func TestACMEHTTPChallengeNilWithoutACME(t *testing.T) {
	c := &serverConfig{}
	assert.Nil(t, c.acmeHTTPChallenge())
}

// The gate is the point of this hook: between renewals no challenge is active,
// so even a well-formed challenge request must be declined without certmagic
// being consulted at all. Asserting only on the false return would not catch a
// removed gate — certmagic also returns false when it finds no challenge — so
// this asserts on the silence, which only holds if the gate short-circuits.
func TestACMEHTTPChallengeGateClosedBetweenRenewals(t *testing.T) {
	issuer, logs := newTestACMEIssuer(t)
	c := &serverConfig{acmeIssuer: issuer}
	hook := c.acmeHTTPChallenge()
	require.NotNil(t, hook)

	for _, path := range []string{
		"/.well-known/acme-challenge/tok3n",
		"/.well-known/acme-challenge/",
		"/index.html",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "example.com"
		rec := httptest.NewRecorder()

		assert.False(t, hook(rec, req), "path %q must be declined with no challenge in flight", path)
		assert.Zero(t, rec.Body.Len(), "path %q must not have been written to", path)
	}

	assert.Zero(t, logs.Len(),
		"certmagic must not be consulted while no challenge is in flight; got %v", logs.All())
}

// A request that is not a challenge at all is declined before the issuer is
// consulted, whatever the challenge state happens to be.
func TestACMEHTTPChallengeIgnoresNonChallengeRequests(t *testing.T) {
	issuer, logs := newTestACMEIssuer(t)
	c := &serverConfig{acmeIssuer: issuer}
	hook := c.acmeHTTPChallenge()
	require.NotNil(t, hook)

	// POST to the challenge path: LooksLikeHTTPChallenge requires GET.
	req := httptest.NewRequest(http.MethodPost, "/.well-known/acme-challenge/tok3n", nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	assert.False(t, hook(rec, req))
	assert.Zero(t, rec.Body.Len())
	assert.Zero(t, logs.Len())
}

func tlsALPNHello(serverName string, protos ...string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{ServerName: serverName, SupportedProtos: protos}
}

// Without ACME there is nothing to solve, so no hook is installed and the
// masquerade TLS config keeps its original behavior.
func TestACMETLSALPNNilWithoutACME(t *testing.T) {
	c := &serverConfig{}
	assert.Nil(t, c.acmeTLSALPNChallenge(&tls.Config{}))
}

// Between renewals no challenge is active, so even a textbook RFC 8737 hello
// must be declined. A nil config leaves the base config in force, which does
// not speak acme-tls/1 — so the handshake is refused for want of a shared
// protocol, exactly as an ordinary web server would refuse it.
func TestACMETLSALPNGateClosedBetweenRenewals(t *testing.T) {
	issuer, _ := newTestACMEIssuer(t)
	c := &serverConfig{acmeIssuer: issuer}
	hook := c.acmeTLSALPNChallenge(&tls.Config{})
	require.NotNil(t, hook)

	cfg, err := hook(tlsALPNHello("example.com", acmez.ACMETLS1Protocol))
	require.NoError(t, err)
	assert.Nil(t, cfg, "no challenge in flight, so the base config must stay in force")
}

// Handshakes that are not TLS-ALPN-01 challenges are left alone regardless of
// challenge state. RFC 8737 requires an SNI and exactly one ALPN protocol.
func TestACMETLSALPNIgnoresNonChallengeHandshakes(t *testing.T) {
	issuer, _ := newTestACMEIssuer(t)
	c := &serverConfig{acmeIssuer: issuer}
	hook := c.acmeTLSALPNChallenge(&tls.Config{})
	require.NotNil(t, hook)

	for name, hello := range map[string]*tls.ClientHelloInfo{
		"ordinary browser":        tlsALPNHello("example.com", "h2", "http/1.1"),
		"no ALPN at all":          tlsALPNHello("example.com"),
		"no SNI":                  tlsALPNHello("", acmez.ACMETLS1Protocol),
		"acme-tls/1 among others": tlsALPNHello("example.com", acmez.ACMETLS1Protocol, "h2"),
	} {
		cfg, err := hook(hello)
		require.NoError(t, err, name)
		assert.Nil(t, cfg, name)
	}
}

func selfSignedCert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// dialALPN performs a real TLS handshake against ln offering exactly protos,
// and reports the negotiated protocol or the handshake error.
func dialALPN(t *testing.T, addr string, protos ...string) (string, error) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         "example.com",
		NextProtos:         protos,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.ConnectionState().NegotiatedProtocol, nil
}

// The claim the gate rests on, verified against a real handshake rather than
// asserted: with the gate shut, an acme-tls/1 hello is refused for want of a
// shared protocol — the same refusal any ordinary web server gives — so the
// masquerade server does not stand out when no renewal is in progress.
func TestACMETLSALPNHandshakeRefusedOutsideWindow(t *testing.T) {
	cert := selfSignedCert(t, "example.com")
	base := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
	}
	issuer, _ := newTestACMEIssuer(t)
	c := &serverConfig{acmeIssuer: issuer}
	base.GetConfigForClient = c.acmeTLSALPNChallenge(base)
	// http.Server.ServeTLS puts these on the config it serves with; mirror that
	// so this exercises the same negotiation production does.
	base.NextProtos = []string{"h2", "http/1.1"}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", base)
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = conn.(*tls.Conn).Handshake()
				conn.Close()
			}()
		}
	}()

	_, err = dialALPN(t, ln.Addr().String(), acmez.ACMETLS1Protocol)
	require.Error(t, err, "acme-tls/1 must be refused while no challenge is in flight")
	assert.Contains(t, err.Error(), "no application protocol")

	// Control: the server is otherwise perfectly functional for real clients.
	proto, err := dialALPN(t, ln.Addr().String(), "h2", "http/1.1")
	require.NoError(t, err)
	assert.Equal(t, "h2", proto)
}
