package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
)

type ED25519Key struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func NewED25519Key(_ hash.Hash) *ED25519Key {
	return &ED25519Key{}
}

func (key *ED25519Key) GenerateKeyFromSeed(seed []byte) error {
	reader := NewDeterministicReader(seed, []byte(DEFAULT_SALT))
	publicKey, privateKey, err := ed25519.GenerateKey(reader)
	if err != nil {
		return fmt.Errorf("unable to generate private key, %w", err)
	}
	key.publicKey = publicKey
	key.privateKey = privateKey
	return nil
}

func (key *ED25519Key) SignData(data []byte) ([]byte, error) {
	if key.privateKey == nil {
		return nil, fmt.Errorf("private key is not set")
	}
	signature := ed25519.Sign(key.privateKey, data)
	if ok, err := key.VerifySignature(data, signature); err != nil || !ok {
		return nil, errSignatureSelfCheck
	}
	return signature, nil
}

func (key *ED25519Key) VerifySignature(data []byte, signature []byte) (bool, error) {
	if err := key.checkPublicKey(); err != nil {
		return false, err
	}
	return ed25519.Verify(key.publicKey, data, signature), nil
}

func (key *ED25519Key) SignWithContext(domain SigningDomain, data []byte) ([]byte, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	if key.privateKey == nil {
		return nil, fmt.Errorf("private key is not set")
	}
	signature, err := key.privateKey.Sign(nil, data, &ed25519.Options{Context: string(domain)})
	if err != nil {
		return nil, fmt.Errorf("unable to sign data, %w", err)
	}
	if ok, err := key.VerifyWithContext(domain, data, signature); err != nil || !ok {
		return nil, errSignatureSelfCheck
	}
	return signature, nil
}

func (key *ED25519Key) VerifyWithContext(domain SigningDomain, data, signature []byte) (bool, error) {
	if err := validateDomain(domain); err != nil {
		return false, err
	}
	if err := key.checkPublicKey(); err != nil {
		return false, err
	}
	return ed25519.VerifyWithOptions(key.publicKey, data, signature, &ed25519.Options{Context: string(domain)}) == nil, nil
}

func (key *ED25519Key) checkPublicKey() error {
	if key.publicKey == nil {
		return fmt.Errorf("public key is not set")
	}
	if len(key.publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key length %d", len(key.publicKey))
	}
	return nil
}

func (key *ED25519Key) GetPublicKeyHex(compressed bool) string {
	if key.publicKey == nil {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(key.publicKey))
}

func (key *ED25519Key) GetPrivateKeyHex() string {
	if key.privateKey == nil {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(key.privateKey))
}

func (key *ED25519Key) GetType() KeyType {
	return KeyTypeED25519
}

func (key *ED25519Key) GeneratePublicKeyFromHex(compressed bool, hex string) error {
	if key.publicKey != nil {
		return fmt.Errorf("public key is already set")
	}

	publicKey, err := HexToBytes(hex)
	if err != nil {
		return fmt.Errorf("unable to decode public key, %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key length %d", len(publicKey))
	}
	key.publicKey = publicKey
	return nil
}

func (key *ED25519Key) GeneratePrivateKeyFromHex(hex string) error {
	if key.privateKey != nil {
		return fmt.Errorf("private key is already set")
	}

	privateKey, err := HexToBytes(hex)
	if err != nil {
		return fmt.Errorf("unable to decode private key, %w", err)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid ed25519 private key length %d", len(privateKey))
	}
	key.privateKey = privateKey
	if key.publicKey == nil {
		key.publicKey = key.privateKey.Public().(ed25519.PublicKey)
	}
	return nil
}

func (key *ED25519Key) RegenerateKeyFromSeed(seed []byte, salt []byte) error {
	reader := NewDeterministicReader(seed, salt)
	publicKey, privateKey, err := ed25519.GenerateKey(reader)
	if err != nil {
		return fmt.Errorf("unable to generate private key, %w", err)
	}
	key.publicKey = publicKey
	key.privateKey = privateKey
	return nil
}
