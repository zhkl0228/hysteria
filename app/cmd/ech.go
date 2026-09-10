package cmd

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/app/v2/internal/utils"
	"github.com/apernet/hysteria/core/v2/server"
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
// pair on first run. It also records the config list so fillTrafficLogger can
// serve it from /ech.
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
		// hold up - or take down - the server.
		go c.publishECHConfig(domains, configList)
	}
	return nil
}

var (
	echKeyOutFile   string
	echKeyOverwrite bool
)

// echCmd groups the ECH helper subcommands.
var echCmd = &cobra.Command{
	Use:   "ech",
	Short: "ECH (Encrypted Client Hello) utilities",
}

var echKeygenCmd = &cobra.Command{
	Use:   "keygen [public_name]",
	Short: "Generate an ECH key pair",
	Long: "Generate an ECH key pair for the given public name (the outer/cover SNI),\n" +
		"defaulting to " + defaultECHPublicName + ".\n" +
		"The output file is compatible with `sing-box generate ech-keypair`, and is\n" +
		"what the server's ech.keyPath points at.",
	Run: runECHKeygenCmd,
}

func init() {
	echKeygenCmd.Flags().StringVarP(&echKeyOutFile, "out", "o", "ech.pem", "output key file")
	echKeygenCmd.Flags().BoolVar(&echKeyOverwrite, "overwrite", false, "overwrite an existing key file")
	echCmd.AddCommand(echKeygenCmd)
	rootCmd.AddCommand(echCmd)
}

func runECHKeygenCmd(cmd *cobra.Command, args []string) {
	if len(args) > 1 {
		logger.Fatal("expected at most one public name argument")
	}
	publicName := defaultECHPublicName
	if len(args) == 1 {
		publicName = args[0]
	}

	if !echKeyOverwrite {
		if _, err := os.Stat(echKeyOutFile); err == nil {
			logger.Fatal("key file already exists, use --overwrite to replace it",
				zap.String("file", echKeyOutFile))
		} else if !errors.Is(err, os.ErrNotExist) {
			logger.Fatal("failed to check key file", zap.Error(err))
		}
	}

	data, err := utils.GenerateECHKeyPEM(publicName)
	if err != nil {
		logger.Fatal("failed to generate ECH key pair", zap.Error(err))
	}
	if err := os.WriteFile(echKeyOutFile, data, 0o600); err != nil {
		logger.Fatal("failed to write key file", zap.Error(err))
	}

	_, configList, err := utils.LoadECHKeys(echKeyOutFile)
	if err != nil {
		logger.Fatal("failed to read back generated key file", zap.Error(err))
	}
	logger.Info("ECH key pair generated",
		zap.String("file", echKeyOutFile),
		zap.String("publicName", publicName),
		zap.String("configList", base64.StdEncoding.EncodeToString(configList)))
	logger.Info("set ech.keyPath to this file on the server, and tls.ech to the config list above on clients")
}
