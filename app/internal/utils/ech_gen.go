package utils

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ECH key generation.
//
// This is a fork-only addition on top of ech.go, which only knows how to *load*
// keys produced by `sing-box generate ech-keypair`. The output here is
// byte-compatible with that format, so keys stay interchangeable in both
// directions and ech.go needs no changes.

// GenerateECHKeyPEM creates a fresh X25519 ECH key pair for publicName and
// returns a PEM document holding an "ECH KEYS" block (private, for the server)
// followed by an "ECH CONFIGS" block (public, for clients).
func GenerateECHKeyPEM(publicName string) ([]byte, error) {
	if publicName == "" {
		return nil, errors.New("empty ECH public name")
	}
	if len(publicName) > 255 {
		return nil, errors.New("ECH public name too long (max 255 bytes)")
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var configID [1]byte
	if _, err := rand.Read(configID[:]); err != nil {
		return nil, err
	}
	config := marshalECHConfig(configID[0], priv.PublicKey().Bytes(), publicName)

	// ECH KEYS entry: uint16 len | private key, uint16 len | ECHConfig.
	var keyBlob []byte
	keyBlob = binary.BigEndian.AppendUint16(keyBlob, uint16(len(priv.Bytes())))
	keyBlob = append(keyBlob, priv.Bytes()...)
	keyBlob = binary.BigEndian.AppendUint16(keyBlob, uint16(len(config)))
	keyBlob = append(keyBlob, config...)

	// ECHConfigList: uint16 total length | ECHConfig(s).
	configList := binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	configList = append(configList, config...)

	out := pem.EncodeToMemory(&pem.Block{Type: pemBlockECHKeys, Bytes: keyBlob})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: pemBlockECHConfigs, Bytes: configList})...)
	return out, nil
}

// marshalECHConfig builds a single ECHConfig (version 0xfe0d, draft-ietf-tls-esni-13
// / RFC 9849) for an X25519 public key.
func marshalECHConfig(configID byte, publicKey []byte, publicName string) []byte {
	var contents []byte
	contents = append(contents, configID)
	contents = binary.BigEndian.AppendUint16(contents, 0x0020) // kem_id: DHKEM(X25519, HKDF-SHA256)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(publicKey)))
	contents = append(contents, publicKey...)
	// cipher_suites: HKDF-SHA256 paired with AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305.
	suites := []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03}
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(suites)))
	contents = append(contents, suites...)
	// maximum_name_length: 0, matching sing-box. It only tunes inner ClientHello
	// padding, and 0 lets crypto/tls fall back to its own padding scheme.
	contents = append(contents, 0x00)
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = binary.BigEndian.AppendUint16(contents, 0) // extensions (none)

	config := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	config = binary.BigEndian.AppendUint16(config, uint16(len(contents)))
	return append(config, contents...)
}

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
		return nil, nil, false, fmt.Errorf("ECH key file %q does not exist and no public name is set to generate one; set ech.publicName or create the file with `hysteria ech keygen <public_name>`", path)
	}
	data, err := GenerateECHKeyPEM(publicName)
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
