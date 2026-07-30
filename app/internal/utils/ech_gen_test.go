package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateECHKeyPEM(t *testing.T) {
	const publicName = "cover.example.com"

	dir := t.TempDir()
	path := filepath.Join(dir, "ech.pem")

	data, err := GenerateECHKeyPEM(publicName)
	if err != nil {
		t.Fatalf("GenerateECHKeyPEM: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// The generated file must be readable by the loader that upstream uses for
	// sing-box keys, which is the whole point of matching its format.
	keys, configList, err := LoadECHKeys(path)
	if err != nil {
		t.Fatalf("LoadECHKeys on generated file: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if !keys[0].SendAsRetry {
		t.Error("expected SendAsRetry to be set")
	}
	// The ECH CONFIGS block we wrote must match the list derived from the keys.
	if blob := findPEMBlock(data, pemBlockECHConfigs); !equalBytes(blob, configList) {
		t.Errorf("CONFIGS block and derived config list differ:\n got %x\nwant %x", blob, configList)
	}

	// End-to-end against crypto/tls: a real handshake must accept ECH.
	assertECHHandshake(t, keys, configList, true)
}

func TestGenerateECHKeyPEMErrors(t *testing.T) {
	if _, err := GenerateECHKeyPEM(""); err == nil {
		t.Error("expected error for empty public name")
	}
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := GenerateECHKeyPEM(string(long)); err == nil {
		t.Error("expected error for over-long public name")
	}
}

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
