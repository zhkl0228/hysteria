package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureECHKeys(t *testing.T) {
	const publicName = "cover.example.com"

	dir := t.TempDir()
	path := filepath.Join(dir, "ech.pem")

	// First call generates and persists.
	keys, configList, generated, err := EnsureECHKeys(path, publicName)
	if err != nil {
		t.Fatalf("EnsureECHKeys (generate): %v", err)
	}
	if !generated {
		t.Error("expected generated to be true on first call")
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("key file not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}

	// Second call must reuse the exact same key, so clients that already have
	// the config list keep working across restarts.
	keys2, configList2, generated2, err := EnsureECHKeys(path, publicName)
	if err != nil {
		t.Fatalf("EnsureECHKeys (reload): %v", err)
	}
	if generated2 {
		t.Error("expected generated to be false when the file already exists")
	}
	if !equalBytes(configList, configList2) {
		t.Error("config list changed across reload")
	}
	if !equalBytes(keys[0].PrivateKey, keys2[0].PrivateKey) {
		t.Error("private key changed across reload")
	}

	// An existing file wins over publicName, since its ECHConfig already carries
	// the name clients were given.
	_, configList3, _, err := EnsureECHKeys(path, "something.else.com")
	if err != nil {
		t.Fatalf("EnsureECHKeys (different public name): %v", err)
	}
	if !equalBytes(configList, configList3) {
		t.Error("existing key file should not be regenerated for a different public name")
	}
}

func TestEnsureECHKeysNoPublicName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ech.pem")

	if _, _, _, err := EnsureECHKeys(path, ""); err == nil {
		t.Fatal("expected error when the file is missing and no public name is set")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("no key file should have been written")
	}
}

func TestEnsureECHKeysCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ech.pem")
	if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A corrupt file must be an error, never silently overwritten: regenerating
	// would cut off every client holding the old config list.
	if _, _, _, err := EnsureECHKeys(path, "cover.example.com"); err == nil {
		t.Error("expected error for a corrupt key file")
	}
}
