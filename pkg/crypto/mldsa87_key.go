package crypto

import (
	"fmt"
	"hash"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

type MLDSA87Key struct {
	privateKey *mldsa87.PrivateKey
	publicKey  *mldsa87.PublicKey
}

func NewMLDSA87Key(_ hash.Hash) *MLDSA87Key {
	return &MLDSA87Key{}
}

func (key *MLDSA87Key) GenerateKeyFromSeed(seed []byte) error {
	reader := NewDeterministicReader(seed, []byte(DEFAULT_SALT))
	publicKey, privateKey, err := mldsa87.GenerateKey(reader)
	if err != nil {
		return fmt.Errorf("unable to generate private key, %w", err)
	}
	key.publicKey = publicKey
	key.privateKey = privateKey
	return nil
}

func (key *MLDSA87Key) SignData(data []byte) ([]byte, error) {
	return key.sign(data, nil)
}

func (key *MLDSA87Key) VerifySignature(data []byte, signature []byte) (bool, error) {
	return key.verify(data, nil, signature)
}

func (key *MLDSA87Key) SignWithContext(domain SigningDomain, data []byte) ([]byte, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	return key.sign(data, []byte(domain))
}

func (key *MLDSA87Key) VerifyWithContext(domain SigningDomain, data, signature []byte) (bool, error) {
	if err := validateDomain(domain); err != nil {
		return false, err
	}
	return key.verify(data, []byte(domain), signature)
}

func (key *MLDSA87Key) sign(data, ctx []byte) ([]byte, error) {
	if key.privateKey == nil {
		return nil, fmt.Errorf("private key is not set")
	}

	sig := make([]byte, mldsa87.SignatureSize)
	err := mldsa87.SignTo(key.privateKey, data, ctx, true, sig)
	if err != nil {
		return nil, fmt.Errorf("unable to sign data, %w", err)
	}
	if ok, err := key.verify(data, ctx, sig); err != nil || !ok {
		return nil, errSignatureSelfCheck
	}
	return sig, nil
}

func (key *MLDSA87Key) verify(data, ctx, signature []byte) (bool, error) {
	if key.publicKey == nil {
		return false, fmt.Errorf("public key is not set")
	}
	return mldsa87.Verify(key.publicKey, data, ctx, signature), nil
}

func (key *MLDSA87Key) GetPublicKeyHex(compressed bool) string {
	if key.publicKey == nil {
		return ""
	}

	pubKeyBytes, err := key.publicKey.MarshalBinary()
	if err != nil {
		return ""
	}
	return BytesToHex(pubKeyBytes)
}

func (key *MLDSA87Key) GetPrivateKeyHex() string {
	if key.privateKey == nil {
		return ""
	}
	privKeyBytes, err := key.privateKey.MarshalBinary()
	if err != nil {
		return ""
	}
	return BytesToHex(privKeyBytes)
}

func (key *MLDSA87Key) GetType() KeyType {
	return KeyTypeMlDSA87
}

func (key *MLDSA87Key) GeneratePublicKeyFromHex(compressed bool, hex string) error {
	if key.publicKey != nil {
		return fmt.Errorf("public key is already set")
	}

	key.publicKey = &mldsa87.PublicKey{}

	pubKeyBytes, err := HexToBytes(hex)
	if err != nil {
		return fmt.Errorf("unable to convert hex to bytes, %w", err)
	}

	err = key.publicKey.UnmarshalBinary(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("unable to unmarshal public key, %w", err)
	}
	return nil
}

func (key *MLDSA87Key) GeneratePrivateKeyFromHex(hex string) error {
	if key.privateKey != nil {
		return fmt.Errorf("private key is already set")
	}

	key.privateKey = &mldsa87.PrivateKey{}

	privKeyBytes, err := HexToBytes(hex)
	if err != nil {
		return fmt.Errorf("unable to convert hex to bytes, %w", err)
	}

	err = key.privateKey.UnmarshalBinary(privKeyBytes)
	if err != nil {
		return fmt.Errorf("unable to unmarshal private key, %w", err)
	}
	if key.publicKey == nil {
		key.publicKey = key.privateKey.Public().(*mldsa87.PublicKey)
	}
	return nil
}

func (key *MLDSA87Key) RegenerateKeyFromSeed(seed []byte, salt []byte) error {
	reader := NewDeterministicReader(seed, salt)
	publicKey, privateKey, err := mldsa87.GenerateKey(reader)
	if err != nil {
		return fmt.Errorf("unable to generate private key, %w", err)
	}
	key.publicKey = publicKey
	key.privateKey = privateKey
	return nil
}
