package cmd

// Server-side ECH configuration: ech.enabled with automatic key generation,
// the default public name, and publishing. The `hysteria ech` key generation
// command itself is upstream code and lives in ech.go untouched.

import (
	"encoding/base64"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/apernet/hysteria/app/v2/internal/utils"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/trafficlogger"
)

// defaultECHKeyFile is the ECH key file name used when ech.keyPath is unset.
const defaultECHKeyFile = "ech.pem"

// defaultECHPublicName is the outer (cover) SNI used when ech.publicName is
// unset. It is the public name Cloudflare puts in the ECH configs of every zone
// it serves, so a handshake carrying it looks like any of the many sites behind
// Cloudflare - the largest crowd there is to blend into.
//
// Note that this is a name we do not own: when ECH is rejected the server has
// no certificate for it and the handshake fails. That is the desired outcome
// for a probe, but it does mean a client with a stale config list only
// recovers through the retry_configs the server sends, not by falling back to
// a plain handshake.
const defaultECHPublicName = "cloudflare-ech.com"

// echEnabled reports whether the ech config block asks for ECH. Enabled is
// nil-as-true so that a block setting only keyPath behaves as upstream does,
// where the presence of the block is what turns ECH on.
func (c *serverConfig) echEnabled() bool {
	return c.ECH != nil && (c.ECH.Enabled == nil || *c.ECH.Enabled)
}

// echPublicName resolves ech.publicName, which is optional because a cover SNI
// is only useful if it belongs to a large crowd, and defaultECHPublicName is
// the largest one available.
func (c *serverConfig) echPublicName() string {
	if c.ECH != nil && c.ECH.PublicName != "" {
		return c.ECH.PublicName
	}
	return defaultECHPublicName
}

// echKeyPath resolves ech.keyPath, defaulting to ech.pem alongside the config
// file (or in the working directory when the config did not come from a file).
func (c *serverConfig) echKeyPath() string {
	if c.ECH != nil && c.ECH.KeyPath != "" {
		return c.ECH.KeyPath
	}
	if c.configDir != "" {
		return filepath.Join(c.configDir, defaultECHKeyFile)
	}
	return defaultECHKeyFile
}

// fillECHKeys installs the server's ECH keys, generating and persisting a key
// pair on first run. It also records the config list, and the status of
// publishing it to DNS, so fillTrafficLogger can serve both from /ech.
func (c *serverConfig) fillECHKeys(hyConfig *server.Config) error {
	if !c.echEnabled() {
		return nil
	}
	keyPath := c.echKeyPath()
	publicName := c.echPublicName()
	keys, configList, generated, err := utils.EnsureECHKeys(keyPath, publicName)
	if err != nil {
		return configError{Field: "ech", Err: err}
	}
	if generated {
		logger.Info("generated a new ECH key pair",
			zap.String("keyPath", keyPath),
			zap.String("publicName", publicName))
	}
	hyConfig.TLSConfig.ECHKeys = keys
	c.echConfigList = base64.StdEncoding.EncodeToString(configList)
	logger.Info("ECH enabled, set the following config list on clients (tls.ech)",
		zap.String("configList", c.echConfigList))
	if c.ECH.Publish != nil {
		domains, err := c.validateECHPublish()
		if err != nil {
			return err
		}
		// Publishing is a side errand: it talks to a third-party DNS API and
		// only helps clients that look ECH configs up in DNS, so it must not
		// hold up - or take down - the server. Its outcome is still worth
		// knowing without grepping the log, so it reports into a status
		// that /ech serves.
		c.echPublishStatus = trafficlogger.NewECHPublishStatus(domains)
		go c.publishECHConfig(c.echPublishStatus, domains, configList)
	}
	return nil
}
