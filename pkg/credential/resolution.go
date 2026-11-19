package credential

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
)

func resolutionSigningInput(freshnessJSON []byte, payloadB64 string) []byte {
	f := base64.RawURLEncoding.EncodeToString(freshnessJSON)
	input := make([]byte, 0, len(f)+1+len(payloadB64))
	input = append(input, f...)
	input = append(input, '.')
	input = append(input, payloadB64...)
	return input
}

// VerifySignedResolution verifies a SignedResolutionEnvelope entirely
// offline, self-sourcing the signer key carried in the envelope: it is
// tamper-evident under operator honesty, not an independent trust root.
// Without a pinned key the envelope self-sources its signer, so the caller
// must pin or cross-check env.Signer.PublicKey out of band, for example
// against the block-signer key from an audit-verified tx inclusion proof.
// Passing a non-empty pinnedSignerKey requires env.Signer.PublicKey to match
// it before the signature is even checked.
func VerifySignedResolution(env transaction.SignedResolutionEnvelope, expectedChainId string, pinnedSignerKey ...string) ([]byte, error) {
	if len(pinnedSignerKey) > 0 && pinnedSignerKey[0] != "" && env.Signer.PublicKey != pinnedSignerKey[0] {
		return nil, fmt.Errorf("signer key does not match pinned key")
	}
	freshnessJSON, err := json.Marshal(env.Freshness)
	if err != nil {
		return nil, err
	}
	sig, err := crypto.HexToBytes(env.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}
	ok, err := crypto.IsSignatureValid(crypto.DomainDIDResolution, env.Signer.PublicKey, resolutionSigningInput(freshnessJSON, env.Payload), sig, env.Signer.KeyType)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("resolution signature invalid")
	}
	if env.Freshness.ChainId != expectedChainId {
		return nil, fmt.Errorf("chain id mismatch: got %q want %q", env.Freshness.ChainId, expectedChainId)
	}
	return base64.RawURLEncoding.DecodeString(env.Payload)
}
