package credential

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
)

type VerifyOptions struct {
	KeyType            crypto.KeyType
	SignerPublicKeyHex string
	// ProofPackage, if set, cross-checks the issuer key against the proof
	// block's proposer key (fails closed on multi-node councils).
	ProofPackage  *transaction.TxInclusionProofPackage
	StatusListJWS string
	Now           time.Time
}

// VerifyCredentialJWT verifies a ULedger credential JWT offline: tamper-evident
// under operator honesty. The signer key is pinned by the caller or self-sourced
// from the JWS header; a ProofPackage additionally cross-checks the issuer key
// against the block signer (assumes the package was already audit-verified).
func VerifyCredentialJWT(token string, opts VerifyOptions) (*CredentialPayload, error) {
	header, _, _, _, err := ParseCompactJWS(token)
	if err != nil {
		return nil, err
	}
	if _, err := AlgForKeyType(opts.KeyType); err != nil {
		return nil, err
	}
	signerKey := opts.SignerPublicKeyHex
	if signerKey == "" {
		signerKey = header.UlPublicKeyHex
	}
	if signerKey == "" {
		return nil, fmt.Errorf("no signer public key available: pin SignerPublicKeyHex or supply a header with ulPublicKeyHex")
	}

	payloadJSON, err := VerifyJWS(token, opts.KeyType, signerKey)
	if err != nil {
		return nil, err
	}

	if opts.ProofPackage != nil {
		b := opts.ProofPackage.Block
		if b == nil || len(b.InstanceId) <= len(b.BlockchainId) || b.InstanceId[len(b.BlockchainId):] != signerKey {
			return nil, fmt.Errorf("issuer key does not match block signer key")
		}
	}

	var cred CredentialPayload
	if err := json.Unmarshal(payloadJSON, &cred); err != nil {
		return nil, fmt.Errorf("invalid credential payload: %w", err)
	}

	if opts.ProofPackage != nil {
		expectedIss := "did:ulnet:" + opts.ProofPackage.Block.BlockchainId
		if cred.Iss != expectedIss {
			return nil, fmt.Errorf("issuer mismatch: got %q want %q", cred.Iss, expectedIss)
		}
	}

	if len(cred.Context) == 0 || cred.Context[0] != ContextCredentialsV2 {
		return nil, fmt.Errorf("unexpected credential context")
	}
	if !slices.Contains(cred.Type, TypeVerifiableCredential) {
		return nil, fmt.Errorf("unexpected credential type")
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if now.Unix() < cred.Iat || now.Unix() > cred.Exp {
		return nil, fmt.Errorf("credential not valid at %s", now.UTC().Format(time.RFC3339))
	}

	if opts.StatusListJWS != "" {
		if cred.CredentialStatus == nil {
			return nil, fmt.Errorf("credential has no status entry")
		}
		statusPayloadJSON, err := VerifyJWS(opts.StatusListJWS, opts.KeyType, signerKey)
		if err != nil {
			return nil, fmt.Errorf("status list jws: %w", err)
		}
		var statusCred CredentialPayload
		if err := json.Unmarshal(statusPayloadJSON, &statusCred); err != nil {
			return nil, fmt.Errorf("invalid status list payload: %w", err)
		}
		if now.Unix() < statusCred.Iat {
			return nil, fmt.Errorf("status list not yet valid")
		}
		if now.Unix() > statusCred.Exp {
			return nil, fmt.Errorf("status list expired")
		}
		if statusCred.Id != cred.CredentialStatus.StatusListCredential {
			return nil, fmt.Errorf("status list does not match credential status entry")
		}
		bits, err := DecodeList(statusCred.CredentialSubject.EncodedList)
		if err != nil {
			return nil, fmt.Errorf("status list decode: %w", err)
		}
		index, err := strconv.ParseUint(cred.CredentialStatus.StatusListIndex, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid status list index: %w", err)
		}
		revoked, err := GetBit(bits, index)
		if err != nil {
			return nil, err
		}
		if revoked {
			return nil, fmt.Errorf("credential revoked")
		}
	}

	return &cred, nil
}
