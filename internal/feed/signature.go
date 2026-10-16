package feed

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	signatureFormat        = "psirtmap-feed-signature"
	signatureFormatVersion = 1
	signatureAlgorithm     = "Ed25519"
	signatureDomain        = "PSIRTMap offline feed manifest signature v1\n"

	privateKeyPEMType = "PRIVATE KEY"
	publicKeyPEMType  = "PUBLIC KEY"
)

// SigningKey is an Ed25519 private key loaded from a PSIRTMap signing-key
// file. Its key material is intentionally not exposed through JSON or public
// fields.
type SigningKey struct {
	privateKey ed25519.PrivateKey
	keyID      string
}

// TrustedKey is an Ed25519 public key accepted by a feed verification policy.
type TrustedKey struct {
	publicKey ed25519.PublicKey
	keyID     string
}

// VerificationPolicy controls whether a bundle signature must be present and
// which public keys may authenticate it.
type VerificationPolicy struct {
	TrustedKeys      []TrustedKey
	RequireSignature bool
}

type signatureDocument struct {
	Format         string `json:"format"`
	FormatVersion  int    `json:"format_version"`
	Algorithm      string `json:"algorithm"`
	KeyID          string `json:"key_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Signature      string `json:"signature"`
}

// KeyID returns the stable SHA-256 fingerprint of the signing public key.
func (key SigningKey) KeyID() string {
	return key.keyID
}

// KeyID returns the stable SHA-256 fingerprint of a trusted public key.
func (key TrustedKey) KeyID() string {
	return key.keyID
}

// GenerateKeyPair creates a new Ed25519 private/public key pair without
// replacing existing files. The private key is written with mode 0600.
func GenerateKeyPair(privatePath, publicPath string) (string, error) {
	privatePath = strings.TrimSpace(privatePath)
	publicPath = strings.TrimSpace(publicPath)
	if privatePath == "" || publicPath == "" {
		return "", errors.New("private and public key paths are required")
	}
	privateAbsolute, err := filepath.Abs(privatePath)
	if err != nil {
		return "", fmt.Errorf("resolve private key path: %w", err)
	}
	publicAbsolute, err := filepath.Abs(publicPath)
	if err != nil {
		return "", fmt.Errorf("resolve public key path: %w", err)
	}
	if privateAbsolute == publicAbsolute {
		return "", errors.New("private and public key paths must be different")
	}
	for _, path := range []string{privatePath, publicPath} {
		if _, err := os.Lstat(path); err == nil {
			return "", fmt.Errorf("key file %q already exists", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect key file %q: %w", path, err)
		}
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate Ed25519 key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("encode private key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("encode public key: %w", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: publicDER})
	if err := writeNewFile(privatePath, privatePEM, 0o600); err != nil {
		return "", fmt.Errorf("write private signing key: %w", err)
	}
	if err := writeNewFile(publicPath, publicPEM, 0o644); err != nil {
		if removeErr := os.Remove(privatePath); removeErr != nil {
			return "", fmt.Errorf("write public verification key: %v; remove incomplete private key: %w", err, removeErr)
		}
		return "", fmt.Errorf("write public verification key: %w", err)
	}
	return publicKeyID(publicKey), nil
}

// LoadSigningKey loads an Ed25519 PKCS#8 private key. On Unix-like systems,
// group or other permissions are rejected before key material is read.
func LoadSigningKey(path string) (SigningKey, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return SigningKey{}, errors.New("signing key path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return SigningKey{}, fmt.Errorf("inspect signing key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return SigningKey{}, errors.New("signing key must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return SigningKey{}, fmt.Errorf("signing key permissions %o are too broad; require 0600 or stricter", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return SigningKey{}, fmt.Errorf("read signing key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != privateKeyPEMType || len(strings.TrimSpace(string(rest))) != 0 {
		return SigningKey{}, errors.New("signing key must contain exactly one PKCS#8 private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return SigningKey{}, fmt.Errorf("parse signing key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return SigningKey{}, errors.New("signing key must be Ed25519")
	}
	privateCopy := append(ed25519.PrivateKey(nil), privateKey...)
	publicKey := privateCopy.Public().(ed25519.PublicKey)
	return SigningKey{privateKey: privateCopy, keyID: publicKeyID(publicKey)}, nil
}

// LoadTrustedKey loads an Ed25519 PKIX public key used to authenticate signed
// bundles.
func LoadTrustedKey(path string) (TrustedKey, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return TrustedKey{}, errors.New("trusted key path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return TrustedKey{}, fmt.Errorf("inspect trusted key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return TrustedKey{}, errors.New("trusted key must be a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return TrustedKey{}, fmt.Errorf("read trusted key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != publicKeyPEMType || len(strings.TrimSpace(string(rest))) != 0 {
		return TrustedKey{}, errors.New("trusted key must contain exactly one PKIX public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return TrustedKey{}, fmt.Errorf("parse trusted key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return TrustedKey{}, errors.New("trusted key must be Ed25519")
	}
	publicCopy := append(ed25519.PublicKey(nil), publicKey...)
	return TrustedKey{publicKey: publicCopy, keyID: publicKeyID(publicCopy)}, nil
}

func createSignature(manifestBytes []byte, key SigningKey) (signatureDocument, error) {
	if len(key.privateKey) != ed25519.PrivateKeySize || key.keyID == "" {
		return signatureDocument{}, errors.New("valid Ed25519 signing key is required")
	}
	signature := ed25519.Sign(key.privateKey, signatureMessage(manifestBytes))
	return signatureDocument{
		Format: signatureFormat, FormatVersion: signatureFormatVersion,
		Algorithm: signatureAlgorithm, KeyID: key.keyID,
		ManifestSHA256: digest(manifestBytes),
		Signature:      base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func validateSignatureDocument(document signatureDocument, manifestBytes []byte) ([]byte, error) {
	if document.Format != signatureFormat || document.FormatVersion != signatureFormatVersion {
		return nil, errors.New("unsupported feed signature format")
	}
	if document.Algorithm != signatureAlgorithm {
		return nil, fmt.Errorf("unsupported feed signature algorithm %q", document.Algorithm)
	}
	if document.ManifestSHA256 != digest(manifestBytes) {
		return nil, errors.New("feed signature manifest digest mismatch")
	}
	if !validKeyID(document.KeyID) {
		return nil, errors.New("feed signature key ID is invalid")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(document.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("feed signature value is invalid")
	}
	return signature, nil
}

func verifySignature(document signatureDocument, manifestBytes []byte, policy VerificationPolicy) (bool, error) {
	signature, err := validateSignatureDocument(document, manifestBytes)
	if err != nil {
		return false, err
	}
	if len(policy.TrustedKeys) == 0 {
		return false, nil
	}
	for _, trusted := range policy.TrustedKeys {
		if trusted.keyID != document.KeyID {
			continue
		}
		if len(trusted.publicKey) != ed25519.PublicKeySize || !ed25519.Verify(trusted.publicKey, signatureMessage(manifestBytes), signature) {
			return false, errors.New("feed signature verification failed")
		}
		return true, nil
	}
	return false, fmt.Errorf("feed signer %s is not trusted", document.KeyID)
}

func signatureMessage(manifestBytes []byte) []byte {
	message := make([]byte, 0, len(signatureDomain)+len(manifestBytes))
	message = append(message, signatureDomain...)
	return append(message, manifestBytes...)
}

func publicKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validKeyID(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && value == strings.ToLower(value)
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}
