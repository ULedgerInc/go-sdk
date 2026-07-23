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

// VerifySignedResolution verifies an envelope offline. Without a pinned key it
// self-sources the signer from env.Signer.PublicKey, so callers must pin or
// cross-check that key out of band (e.g. against an audit-verified block signer):
// tamper-evident under operator honesty, not a trust root by itself.
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
	ok, err := crypto.IsSignatureValid(env.Signer.PublicKey, resolutionSigningInput(freshnessJSON, env.Payload), sig, env.Signer.KeyType)
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
