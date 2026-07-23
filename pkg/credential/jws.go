package credential

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
)

const (
	AlgES256K  = "ES256K"
	AlgEdDSA   = "EdDSA"
	AlgMLDSA87 = "ML-DSA-87"
	TypVCJWT   = "vc+jwt"
)

type Header struct {
	Alg            string                    `json:"alg"`
	Typ            string                    `json:"typ"`
	Kid            string                    `json:"kid,omitempty"`
	Jwk            *transaction.PublicKeyJwk `json:"jwk,omitempty"`
	UlKeyType      string                    `json:"ulKeyType,omitempty"`
	UlPublicKeyHex string                    `json:"ulPublicKeyHex,omitempty"`
}

func AlgForKeyType(kt crypto.KeyType) (string, error) {
	switch kt {
	case crypto.KeyTypeSecp256k1:
		return AlgES256K, nil
	case crypto.KeyTypeED25519:
		return AlgEdDSA, nil
	case crypto.KeyTypeMlDSA87:
		return AlgMLDSA87, nil
	case crypto.KeyTypeBLS12377:
		return "", fmt.Errorf("no JOSE algorithm for bls12377 chains")
	default:
		return "", fmt.Errorf("unsupported key type %d", kt)
	}
}

func ParseCompactJWS(token string) (Header, []byte, []byte, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Header{}, nil, nil, nil, fmt.Errorf("not a compact jws")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Header{}, nil, nil, nil, fmt.Errorf("invalid jws header encoding: %w", err)
	}
	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Header{}, nil, nil, nil, fmt.Errorf("invalid jws header: %w", err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Header{}, nil, nil, nil, fmt.Errorf("invalid jws payload encoding: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Header{}, nil, nil, nil, fmt.Errorf("invalid jws signature encoding: %w", err)
	}
	return header, payloadJSON, sig, []byte(parts[0] + "." + parts[1]), nil
}

// VerifyJWS verifies a compact JWS offline against a known signer key:
// tamper-evident under operator honesty, not a trust root by itself.
func VerifyJWS(token string, kt crypto.KeyType, publicKeyHex string) ([]byte, error) {
	expectedAlg, err := AlgForKeyType(kt)
	if err != nil {
		return nil, err
	}
	header, payloadJSON, sig, signingInput, err := ParseCompactJWS(token)
	if err != nil {
		return nil, err
	}
	if header.Alg != expectedAlg {
		return nil, fmt.Errorf("alg mismatch: token %q, expected %q", header.Alg, expectedAlg)
	}
	if header.Typ != TypVCJWT {
		return nil, fmt.Errorf("typ mismatch: token %q, expected %q", header.Typ, TypVCJWT)
	}
	ok, err := crypto.IsSignatureValid(publicKeyHex, signingInput, sig, kt)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("jws signature invalid")
	}
	return payloadJSON, nil
}
