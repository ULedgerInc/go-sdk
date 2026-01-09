package crypto

import (
	"fmt"
	"hash"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
)

type Secp256k1Key struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

func NewSecp256k1Key(_ hash.Hash) *Secp256k1Key {
	return &Secp256k1Key{}
}

func (key *Secp256k1Key) GenerateKeyFromSeed(seed []byte) error {
	reader := NewDeterministicReader(seed, []byte(DEFAULT_SALT))
	privateKey, err := ecdsa.GenerateKey(reader)
	if err != nil {
		return fmt.Errorf("unable to generate private key, %w", err)
	}
	key.privateKey = privateKey
	key.publicKey = &privateKey.PublicKey
	return nil
}

func (key *Secp256k1Key) SignData(data []byte) ([]byte, error) {
	if key.privateKey == nil {
		return nil, fmt.Errorf("private key is not set")
	}
	hasher := GetHasherByType(KeyTypeSecp256k1)
	return key.privateKey.Sign(data, hasher)
}

func (key *Secp256k1Key) VerifySignature(message []byte, signature []byte) (bool, error) {
	if key.publicKey == nil {
		return false, fmt.Errorf("public key is not set")
	}
	hasher := GetHasherByType(KeyTypeSecp256k1)
	return key.publicKey.Verify(signature, message, hasher)
}

func (key *Secp256k1Key) GetPublicKeyHex(compressed bool) string {
	if key.publicKey == nil {
		return ""
	}
	if compressed {
		// If the public key is compressed, it will be 32 bytes
		// Return only the x coordinate
		// The first byte is the prefix, which is 0x02 for even y and 0x03 for odd y
		compressed := make([]byte, 33)
		// Careful with the order of the bytes, this is Big Endian
		compressed[0] = byte(0x02) + byte(key.publicKey.A.Y.Bytes()[31]&1)
		xBytes := key.publicKey.A.X.Bytes()
		copy(compressed[1:], xBytes[:])
		return BytesToHex(compressed)
	}
	// If the public key is uncompressed, it will be 65 bytes
	// Return the x and y coordinates
	uncompressed := make([]byte, 65)
	uncompressed[0] = byte(0x04)
	xBytes := key.publicKey.A.X.Bytes()
	copy(uncompressed[1:33], xBytes[:])
	yBytes := key.publicKey.A.Y.Bytes()
	copy(uncompressed[33:], yBytes[:])
	return BytesToHex(uncompressed)
}

func (key *Secp256k1Key) GetPrivateKeyHex() string {
	if key.privateKey == nil {
		return ""
	}
	// The form of this key is 96 bytes, the first 64 bytes are the public key, the last 32 bytes are the private key
	return BytesToHex(key.privateKey.Bytes()[64:])
}

func (key *Secp256k1Key) GeneratePrivateKeyFromHex(hex string) error {
	// The expected format is the private key
	hexBytes, err := HexToBytes(hex)
	if err != nil {
		return fmt.Errorf("unable to convert hex to bytes: %w", err)
	}
	if len(hexBytes) != 32 {
		return fmt.Errorf("expected 32 bytes, got %d", len(hexBytes))
	}
	// Get the public key bytes
	publicKeyBytes := make([]byte, 96)
	copy(publicKeyBytes[0:64], key.publicKey.Bytes())
	// Append the private key bytes
	copy(publicKeyBytes[64:], hexBytes)
	key.privateKey = new(ecdsa.PrivateKey)
	_, err = key.privateKey.SetBytes(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("unable to set private key bytes: %w", err)
	}
	key.publicKey = &key.privateKey.PublicKey
	return nil
}

func (key *Secp256k1Key) GeneratePublicKeyFromHex(compressed bool, hex string) error {
	hexBytes, err := HexToBytes(hex)
	if err != nil {
		return fmt.Errorf("unable to convert hex to bytes: %w", err)
	}
	// If the public key is not compressed, it will be 65 bytes!
	if !compressed {
		if len(hexBytes) != 65 {
			return fmt.Errorf("expected 65 bytes, got %d", len(hexBytes))
		}
		// The first byte is the prefix, which is 0x04 for uncompressed
		if hexBytes[0] != 0x04 {
			return fmt.Errorf("expected 0x04, got 0x%02x", hexBytes[0])
		}
		// Get X coordinate
		var xBytes [32]byte
		copy(xBytes[:], hexBytes[1:33])
		// Get Y coordinate
		var yBytes [32]byte
		copy(yBytes[:], hexBytes[33:65])

		// X is an element of the field for SECP256K1
		x := new(fp.Element)
		x.SetBytes(xBytes[:])
		// Y is an element of the field for SECP256K1
		y := new(fp.Element)
		y.SetBytes(yBytes[:])

		// Create the point
		point := new(secp256k1.G1Affine)
		point.X = *x
		point.Y = *y

		key.publicKey = &ecdsa.PublicKey{
			A: *point,
		}
		return nil
	}
	// The expected format from this point is the compressed public key
	if len(hexBytes) != 33 {
		return fmt.Errorf("expected 33 bytes, got %d", len(hexBytes))
	}
	prefix := hexBytes[0]
	// The first byte is the prefix, which is 0x02 for even y and 0x03 for odd y
	if prefix != 0x02 && prefix != 0x03 {
		return fmt.Errorf("expected 0x02 or 0x03, got 0x%02x", prefix)
	}

	// Get X coordinate
	var xBytes [32]byte
	copy(xBytes[:], hexBytes[1:])

	// X is an element of the field for SECP256K1
	x := new(fp.Element)
	x.SetBytes(xBytes[:])

	// Get Y, y^2 = x^3 + 7 according to SECP256K1 curve equation
	y := new(fp.Element)
	// x^2
	x3 := new(fp.Element).Square(x)
	// x^3
	x3.Mul(x3, x)
	// x^3 + 7
	x3.Add(x3, new(fp.Element).SetUint64(7))
	//y = ±sqrt(x^3 + 7)
	y.Sqrt(x3)

	// Check if we need to negate y based on the prefix
	yBytes := y.Bytes()
	yIsOdd := yBytes[31]&1 == 1
	shouldBeOdd := prefix == 0x03

	if yIsOdd != shouldBeOdd {
		y.Neg(y)
	}

	// Create the point
	point := new(secp256k1.G1Affine)
	point.X = *x
	point.Y = *y

	key.publicKey = &ecdsa.PublicKey{
		A: *point,
	}
	return nil
}

// Methods for this implementation

func (key *Secp256k1Key) GetPublicKey() *ecdsa.PublicKey {
	return key.publicKey
}

func (key *Secp256k1Key) GetCommitmentIntHash(commitment []byte) *big.Int {
	dataToHash := make([]byte, len(commitment))
	copy(dataToHash, commitment[:])
	hasher := GetHasherByType(KeyTypeSecp256k1)
	hasher.Write(dataToHash[:])
	hramBin := hasher.Sum(nil)
	return ecdsa.HashToInt(hramBin)
}

func (key *Secp256k1Key) GetRSFromSignature(signature []byte) (*big.Int, *big.Int, error) {
	if len(signature) != 64 {
		return nil, nil, fmt.Errorf("expected 64 bytes, got %d", len(signature))
	}
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	return r, s, nil
}

func (key *Secp256k1Key) GetType() KeyType {
	return KeyTypeSecp256k1
}

func (key *Secp256k1Key) RegenerateKeyFromSeed(seed []byte, salt []byte) error {
	reader := NewDeterministicReader(seed, salt)
	privateKey, err := ecdsa.GenerateKey(reader)
	if err != nil {
		return fmt.Errorf("unable to generate private key, %w", err)
	}
	key.privateKey = privateKey
	key.publicKey = &privateKey.PublicKey
	return nil
}
