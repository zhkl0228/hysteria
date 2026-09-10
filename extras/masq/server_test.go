package masq

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const challengePath = "/.well-known/acme-challenge/tok3n"

func newDecoyServer(t *testing.T, hook func(http.ResponseWriter, *http.Request) bool) *MasqTCPServer {
	t.Helper()
	return &MasqTCPServer{
		QUICPort:  443,
		HTTPSPort: 443,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("decoy site"))
		}),
		ForceHTTPS:    true,
		ACMEChallenge: hook,
	}
}

func serveHTTP(t *testing.T, s *MasqTCPServer, path string) *http.Response {
	t.Helper()
	// Origin-form target, as a real server receives it: RequestURI is the path,
	// which is what the ForceHTTPS redirect builds its Location from.
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	s.httpHandler().ServeHTTP(rec, req)
	return rec.Result()
}

// An answered challenge must win over ForceHTTPS. Redirecting instead would
// send the CA to the decoy site, which has no token to serve.
func TestMasqHTTPACMEChallengeBeatsForceHTTPS(t *testing.T) {
	called := 0
	s := newDecoyServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		called++
		require.Equal(t, challengePath, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("key-authorization"))
		return true
	})

	resp := serveHTTP(t, s, challengePath)
	defer resp.Body.Close()

	assert.Equal(t, 1, called)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
}

// A hook that declines must leave the request exactly as it was before: still
// redirected by ForceHTTPS, with nothing written by the hook.
func TestMasqHTTPACMEChallengeDeclinedFallsThrough(t *testing.T) {
	called := 0
	s := newDecoyServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		called++
		return false
	})

	resp := serveHTTP(t, s, challengePath)
	defer resp.Body.Close()

	assert.Equal(t, 1, called)
	assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
	assert.Equal(t, "https://example.com"+challengePath, resp.Header.Get("Location"))
}

// The hook is consulted for every plain-HTTP request, not just challenge-looking
// ones; deciding what is a challenge is the hook's job, not this package's.
func TestMasqHTTPACMEChallengeConsultedForOrdinaryPath(t *testing.T) {
	called := 0
	s := newDecoyServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		called++
		return false
	})

	resp := serveHTTP(t, s, "/index.html")
	defer resp.Body.Close()

	assert.Equal(t, 1, called)
	assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
}

// Without ACME configured the hook is nil, and the server must behave exactly
// as it did before the hook existed.
func TestMasqHTTPNoACMEHookRedirects(t *testing.T) {
	s := newDecoyServer(t, nil)

	resp := serveHTTP(t, s, challengePath)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
	assert.Equal(t, "https://example.com"+challengePath, resp.Header.Get("Location"))
}

// With ForceHTTPS off, a declined challenge still reaches the decoy handler.
func TestMasqHTTPDeclinedChallengeReachesDecoyWithoutForceHTTPS(t *testing.T) {
	s := newDecoyServer(t, func(w http.ResponseWriter, r *http.Request) bool { return false })
	s.ForceHTTPS = false

	resp := serveHTTP(t, s, challengePath)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, `h3=":443"; ma=2592000`, resp.Header.Get("Alt-Svc"))
}
