package utils

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Automatic ECH key provisioning.
//
// This is a fork-only addition on top of ech.go and ech_generate.go: upstream
// generates keys only through the `hysteria ech` command, while the server
// here can create its own key file on first start (ech.enabled).

// EnsureECHKeys loads the ECH key file at path, generating and persisting a new
// key pair for publicName if the file does not exist yet. generated reports
// whether a new key pair was written.
//
// publicName is only consulted when generating; an existing file always wins,
// since its ECHConfig already carries the public name clients have been given.
func EnsureECHKeys(path, publicName string) (keys []tls.EncryptedClientHelloKey, configList []byte, generated bool, err error) {
	keys, configList, err = LoadECHKeys(path)
	if err == nil {
		return keys, configList, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, err
	}
	if publicName == "" {
		return nil, nil, false, fmt.Errorf("ECH key file %q does not exist and no public name is set to generate one; set ech.publicName or create the file with `hysteria ech --public-name <public_name>`", path)
	}
	data, _, err := GenerateECHKeys(ECHKeyOptions{PublicName: publicName})
	if err != nil {
		return nil, nil, false, err
	}
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return nil, nil, false, fmt.Errorf("failed to save generated ECH key to %q: %w", path, err)
	}
	keys, configList, err = LoadECHKeys(path)
	if err != nil {
		return nil, nil, false, err
	}
	return keys, configList, true, nil
}

// writeFileAtomic writes data to path via a temp file + rename, so a crash
// mid-write cannot leave a truncated key file behind.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename below succeeds
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
