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

// echEnabled reports whether the ech config block asks for ECH. Enabled is
// nil-as-true so that a block setting only keyPath behaves as upstream does,
// where the presence of the block is what turns ECH on.
func (c *serverConfig) echEnabled() bool {
	return c.ECH != nil && (c.ECH.Enabled == nil || *c.ECH.Enabled)
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
// pair on first run when ech.publicName is set. It also records the config list
// so fillTrafficLogger can serve it from /ech.
func (c *serverConfig) fillECHKeys(hyConfig *server.Config) error {
	if !c.echEnabled() {
		return nil
	}
	keyPath := c.echKeyPath()
	keys, configList, generated, err := utils.EnsureECHKeys(keyPath, c.ECH.PublicName)
	if err != nil {
		return configError{Field: "ech", Err: err}
	}
	if generated {
		logger.Info("generated a new ECH key pair",
			zap.String("keyPath", keyPath),
			zap.String("publicName", c.ECH.PublicName))
	}
	hyConfig.TLSConfig.ECHKeys = keys
	c.echConfigList = base64.StdEncoding.EncodeToString(configList)
	logger.Info("ECH enabled, set the following config list on clients (tls.ech)",
		zap.String("configList", c.echConfigList))
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
	Use:   "keygen <public_name>",
	Short: "Generate an ECH key pair",
	Long: "Generate an ECH key pair for the given public name (the outer/cover SNI).\n" +
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
	if len(args) != 1 {
		logger.Fatal("expected exactly one public name argument")
	}
	publicName := args[0]

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
