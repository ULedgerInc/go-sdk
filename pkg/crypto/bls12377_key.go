package crypto

import (
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

const (
	sizeFr         = fr.Bytes
	sizeFp         = fp.Bytes
	sizePublicKey  = sizeFp
	sizePrivateKey = sizeFr + sizePublicKey
	sizeSignature  = 2 * sizeFp
)

var one = new(big.Int).SetInt64(1)

var order = fr.Modulus()

// Domain separation tag for hash-to-field
const DST = "0x01"

type BLS12377PublicKey struct {
	A bls12377.G1Affine
}

func (pk *BLS12377PublicKey) Bytes() []byte {
	var res [sizePublicKey]byte
	pkBin := pk.A.Bytes()
	subtle.ConstantTimeCopy(1, res[:sizePublicKey], pkBin[:])
	return res[:]
}

func (pk *BLS12377PublicKey) SetBytes(buf []byte) (int, error) {
	n := 0
	if len(buf) < sizePublicKey {
		return n, io.ErrShortBuffer
	}
	if _, err := pk.A.SetBytes(buf[:sizePublicKey]); err != nil {
		return 0, err
	}
	n += sizeFp
	return n, nil
}

type BLS12377Signature struct {
	S bls12377.G2Affine
}

func (sig *BLS12377Signature) Bytes() []byte {
	res := sig.S.Bytes()
	return res[:sizeSignature]
}

func (sig *BLS12377Signature) SetBytes(buf []byte) (int, error) {
	n := 0
	if len(buf) < sizeSignature {
		return n, io.ErrShortBuffer
	}
	sig.S.SetBytes(buf)
	n += sizeFr
	return n, nil
}

type BLS12377PrivateKey struct {
	PublicKey BLS12377PublicKey
	scalar    [fr.Bytes]byte
}

func (privKey *BLS12377PrivateKey) Bytes() []byte {
	var res [sizePrivateKey]byte
	pubkBin := privKey.PublicKey.A.Bytes()
	subtle.ConstantTimeCopy(1, res[:sizePublicKey], pubkBin[:])
	subtle.ConstantTimeCopy(1, res[sizePublicKey:sizePrivateKey], privKey.scalar[:])
	return res[:]
}

func (privKey *BLS12377PrivateKey) SetBytes(buf []byte) (int, error) {
	n := 0
	if len(buf) < sizePrivateKey {
		return n, io.ErrShortBuffer
	}
	if _, err := privKey.PublicKey.A.SetBytes(buf[:sizePublicKey]); err != nil {
		return 0, err
	}
	n += sizePublicKey
	subtle.ConstantTimeCopy(1, privKey.scalar[:], buf[sizePublicKey:sizePrivateKey])
	n += sizeFr
	return n, nil
}

// Optimized for Minimal Signature Size
// Public Key is in G1
// Signatures are in G2
type BLS12377Key struct {
	privateKey BLS12377PrivateKey
	publicKey  BLS12377PublicKey
}

func NewBLS12377Key(_ hash.Hash) *BLS12377Key {
	return &BLS12377Key{}
}

func (key *BLS12377Key) GenerateKeyFromSeed(seed []byte) error {
	reader := NewDeterministicReader(seed, []byte(DEFAULT_SALT))
	k, err := randFieldElement(reader)
	if err != nil {
		return fmt.Errorf("unable to generate private key, %w", err)
	}

	_, _, g1, _ := bls12377.Generators()

	privateKey := new(BLS12377PrivateKey)
	k.FillBytes(privateKey.scalar[:sizeFr])
	privateKey.PublicKey.A.ScalarMultiplication(&g1, k)

	key.privateKey = *privateKey
	key.publicKey = privateKey.PublicKey

	return nil
}

// The hash must be done in G1
func HashBLS12377Message(message []byte) (bls12377.G2Affine, error) {
	return bls12377.HashToG2(message, []byte(DST))
}

func (key *BLS12377Key) SignData(message []byte) ([]byte, error) {
	if key.privateKey == (BLS12377PrivateKey{}) {
		return nil, fmt.Errorf("private key is not set")
	}

	hashedMessage, err := HashBLS12377Message(message)
	if err != nil {
		return nil, fmt.Errorf("unable to hash message, %w", err)
	}

	var sig BLS12377Signature
	scalar := new(big.Int)
	scalar.SetBytes(key.privateKey.scalar[:sizeFr])
	sig.S.ScalarMultiplication(&hashedMessage, scalar)

	if !sig.S.IsOnCurve() {
		return nil, fmt.Errorf("invalid signature")
	}

	return sig.Bytes(), nil

}

// The validation is defined as:
//
//	e(G1, sig.S) ?= e(pk, G2)
func (key *BLS12377Key) VerifySignature(message []byte, signature []byte) (bool, error) {

	if key.publicKey.A.IsInfinity() {
		return false, fmt.Errorf("public key is not set")
	}

	var sig BLS12377Signature
	if _, err := sig.SetBytes(signature); err != nil {
		return false, fmt.Errorf("unable to set signature, %w", err)
	}

	hashedMessage, err := HashBLS12377Message(message)
	if err != nil {
		return false, fmt.Errorf("unable to hash message, %w", err)
	}

	_, _, g1, _ := bls12377.Generators()
	g1.Neg(&g1)
	f, err := bls12377.PairingCheck([]bls12377.G1Affine{g1, key.publicKey.A}, []bls12377.G2Affine{sig.S, hashedMessage})
	if err != nil {
		return false, err
	}

	return f, nil
}

func (key *BLS12377Key) GetPublicKeyHex(compressed bool) string {
	if key.publicKey.A.IsInfinity() {
		return ""
	}

	return BytesToHex(key.publicKey.Bytes())
}

func (key *BLS12377Key) GetType() KeyType {
	return KeyTypeBLS12377
}

func (key *BLS12377Key) GetPrivateKeyHex() string {
	if key.privateKey.scalar == [fr.Bytes]byte{} {
		return ""
	}

	return BytesToHex(key.privateKey.Bytes())
}

func (key *BLS12377Key) GeneratePublicKeyFromHex(compressed bool, hex string) error {
	hexBytes, err := HexToBytes(hex)
	if err != nil {
		return fmt.Errorf("unable to convert hex to bytes: %w", err)
	}

	key.publicKey.SetBytes(hexBytes)

	return nil
}

func (key *BLS12377Key) GeneratePrivateKeyFromHex(hex string) error {
	hexBytes, err := HexToBytes(hex)
	if err != nil {
		return fmt.Errorf("unable to convert hex to bytes: %w", err)
	}

	_, err = key.privateKey.SetBytes(hexBytes)
	if err != nil {
		return fmt.Errorf("unable to set private key, %w", err)
	}

	return nil
}

func randFieldElement(rand io.Reader) (k *big.Int, err error) {
	b := make([]byte, fr.Bits/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(order, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func (key *BLS12377Key) GetBLSSignatureParameters(signature []byte, message []byte) (bls12377.G1Affine, bls12377.G1Affine, bls12377.G2Affine, bls12377.G2Affine, error) {
	// This method is used to get the parameters for the BLS signature to be used in the circuits
	if key.publicKey.A.IsInfinity() {
		return bls12377.G1Affine{}, bls12377.G1Affine{}, bls12377.G2Affine{}, bls12377.G2Affine{}, fmt.Errorf("public key is not set")
	}

	var g1 bls12377.G1Affine
	var sig BLS12377Signature
	if _, err := sig.SetBytes(signature); err != nil {
		return bls12377.G1Affine{}, bls12377.G1Affine{}, bls12377.G2Affine{}, bls12377.G2Affine{}, fmt.Errorf("unable to set signature, %w", err)
	}

	hashedMessage, err := HashBLS12377Message(message)
	if err != nil {
		return bls12377.G1Affine{}, bls12377.G1Affine{}, bls12377.G2Affine{}, bls12377.G2Affine{}, fmt.Errorf("unable to hash message, %w", err)
	}

	_, _, g1, _ = bls12377.Generators()
	g1.Neg(&g1)

	return g1, key.publicKey.A, hashedMessage, sig.S, nil

}

func (key *BLS12377Key) RegenerateKeyFromSeed(seed []byte, salt []byte) error {
	reader := NewDeterministicReader(seed, salt)
	k, err := randFieldElement(reader)
	if err != nil {
		return fmt.Errorf("unable to generate private key, %w", err)
	}

	_, _, g1, _ := bls12377.Generators()

	privateKey := new(BLS12377PrivateKey)
	k.FillBytes(privateKey.scalar[:sizeFr])
	privateKey.PublicKey.A.ScalarMultiplication(&g1, k)

	key.privateKey = *privateKey
	key.publicKey = privateKey.PublicKey

	return nil
}
