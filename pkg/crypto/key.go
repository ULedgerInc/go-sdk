package crypto

import (
	"encoding/json"
	"fmt"
	"hash"
	"strings"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	mimc_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	fr_bw6_761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	mimc_bw6_761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
)

type KeyType int

const (
	KeyTypeSecp256k1 KeyType = iota
	KeyTypeMlDSA87
	KeyTypeED25519
	KeyTypeBLS12377
)

// The default key type to use if no other is specified!
const DEFAULT_KEY_TYPE = KeyTypeSecp256k1

func (k KeyType) String() string {
	switch k {
	case KeyTypeBLS12377:
		return "bls12377"
	case KeyTypeED25519:
		return "ed25519"
	case KeyTypeMlDSA87:
		return "mldsa87"
	case KeyTypeSecp256k1:
		return "secp256k1"
	default:
		return DEFAULT_KEY_TYPE.String()
	}
}

func ParseCryptoKeyType(key string) KeyType {
	switch strings.ToLower(key) {
	case KeyTypeBLS12377.String():
		return KeyTypeBLS12377
	case KeyTypeED25519.String():
		return KeyTypeED25519
	case KeyTypeMlDSA87.String():
		return KeyTypeMlDSA87
	case KeyTypeSecp256k1.String():
		return KeyTypeSecp256k1
	default:
		return DEFAULT_KEY_TYPE
	}
}

func (k KeyType) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

func (k *KeyType) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*k = KeyType(int(value))
		return nil
	case string:
		*k = ParseCryptoKeyType(value)
		return nil
	default:
		return fmt.Errorf("invalid key type, got: %T", value)
	}
}

type ULKey interface {
	// Key management methods
	GetPublicKeyHex(compressed bool) string
	GetPrivateKeyHex() string
	GeneratePublicKeyFromHex(compressed bool, hex string) error
	GeneratePrivateKeyFromHex(hex string) error
	GenerateKeyFromSeed(seed []byte) error
	RegenerateKeyFromSeed(seed []byte, salt []byte) error
	// Cryptographic operations
	SignData(data []byte) ([]byte, error)
	VerifySignature(message []byte, signature []byte) (bool, error)
	GetType() KeyType
}

func GetKeyByType(keyType KeyType, hasher hash.Hash) (ULKey, error) {
	switch keyType {
	case KeyTypeSecp256k1:
		return NewSecp256k1Key(hasher), nil
	case KeyTypeMlDSA87:
		return NewMLDSA87Key(hasher), nil
	case KeyTypeED25519:
		return NewED25519Key(hasher), nil
	case KeyTypeBLS12377:
		return NewBLS12377Key(hasher), nil
	default:
		return nil, fmt.Errorf("invalid key type: %d", keyType)
	}
}

func GetHasherByType(keyType KeyType) hash.Hash {
	switch keyType {
	case KeyTypeSecp256k1:
		return mimc_bn254.NewMiMC(mimc_bn254.WithByteOrder(fr_bn254.BigEndian))
	case KeyTypeBLS12377:
		return mimc_bw6_761.NewMiMC(mimc_bw6_761.WithByteOrder(fr_bw6_761.BigEndian))
	default:
		return mimc_bn254.NewMiMC(mimc_bn254.WithByteOrder(fr_bn254.BigEndian))
	}
}
