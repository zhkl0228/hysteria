package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/core/v2/server"
)

func boolPtr(b bool) *bool { return &b }

func TestServerConfigECHEnabled(t *testing.T) {
	tests := []struct {
		name string
		ech  *serverConfigECH
		want bool
	}{
		{"no ech block", nil, false},
		// Upstream semantics: an ech block with only keyPath means enabled.
		{"block without enabled", &serverConfigECH{KeyPath: "x.pem"}, true},
		{"enabled true", &serverConfigECH{Enabled: boolPtr(true)}, true},
		{"enabled false", &serverConfigECH{Enabled: boolPtr(false), KeyPath: "x.pem"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &serverConfig{ECH: tt.ech}
			assert.Equal(t, tt.want, c.echEnabled())
		})
	}
}

func TestServerConfigECHKeyPath(t *testing.T) {
	tests := []struct {
		name      string
		ech       *serverConfigECH
		configDir string
		want      string
	}{
		{"explicit path wins", &serverConfigECH{KeyPath: "/etc/custom/k.pem"}, "/etc/hysteria", "/etc/custom/k.pem"},
		{"defaults next to config", &serverConfigECH{}, "/etc/hysteria", filepath.Join("/etc/hysteria", defaultECHKeyFile)},
		{"defaults to working dir", &serverConfigECH{}, "", defaultECHKeyFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &serverConfig{ECH: tt.ech, configDir: tt.configDir}
			assert.Equal(t, tt.want, c.echKeyPath())
		})
	}
}

func TestFillECHKeys(t *testing.T) {
	logger = zap.NewNop()

	dir := t.TempDir()
	c := &serverConfig{
		ECH:       &serverConfigECH{Enabled: boolPtr(true), PublicName: "cover.example.com"},
		configDir: dir,
	}

	// First run generates and persists the key next to the config file.
	hyConfig := &server.Config{}
	require.NoError(t, c.fillECHKeys(hyConfig))
	require.Len(t, hyConfig.TLSConfig.ECHKeys, 1)
	assert.NotEmpty(t, c.echConfigList)
	assert.FileExists(t, filepath.Join(dir, defaultECHKeyFile))

	// Restarting must reuse the same key, so clients keep working.
	c2 := &serverConfig{
		ECH:       &serverConfigECH{Enabled: boolPtr(true), PublicName: "cover.example.com"},
		configDir: dir,
	}
	hyConfig2 := &server.Config{}
	require.NoError(t, c2.fillECHKeys(hyConfig2))
	assert.Equal(t, c.echConfigList, c2.echConfigList, "config list must be stable across restarts")
}

func TestFillECHKeysDisabled(t *testing.T) {
	logger = zap.NewNop()

	dir := t.TempDir()
	c := &serverConfig{
		ECH:       &serverConfigECH{Enabled: boolPtr(false), PublicName: "cover.example.com"},
		configDir: dir,
	}
	hyConfig := &server.Config{}
	require.NoError(t, c.fillECHKeys(hyConfig))
	assert.Nil(t, hyConfig.TLSConfig.ECHKeys)
	assert.Empty(t, c.echConfigList)
	// Nothing should be written to disk when ECH is off.
	_, err := os.Stat(filepath.Join(dir, defaultECHKeyFile))
	assert.True(t, os.IsNotExist(err))
}

func TestFillECHKeysRequiresPublicName(t *testing.T) {
	logger = zap.NewNop()

	dir := t.TempDir()
	c := &serverConfig{
		ECH:       &serverConfigECH{Enabled: boolPtr(true)},
		configDir: dir,
	}
	// Enabling ECH without a key file and without a public name must fail rather
	// than pick a cover name on the user's behalf.
	err := c.fillECHKeys(&server.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ech")
}

func TestFillECHKeysExistingFileNeedsNoPublicName(t *testing.T) {
	logger = zap.NewNop()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ech.pem")

	// Simulate a key file created out of band (hysteria ech keygen / sing-box).
	seed := &serverConfig{
		ECH:       &serverConfigECH{Enabled: boolPtr(true), PublicName: "cover.example.com", KeyPath: keyPath},
		configDir: dir,
	}
	require.NoError(t, seed.fillECHKeys(&server.Config{}))

	c := &serverConfig{
		ECH:       &serverConfigECH{Enabled: boolPtr(true), KeyPath: keyPath},
		configDir: dir,
	}
	hyConfig := &server.Config{}
	require.NoError(t, c.fillECHKeys(hyConfig))
	assert.Len(t, hyConfig.TLSConfig.ECHKeys, 1)
	assert.Equal(t, seed.echConfigList, c.echConfigList)
}
