package credential

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
)

type goldenVector struct {
	KeyType                  string                               `json:"keyType"`
	PublicKeyHex             string                               `json:"publicKeyHex"`
	ChainId                  string                               `json:"chainId"`
	IdentityCredentialJws    string                               `json:"identityCredentialJws"`
	StatusListCleanJws       string                               `json:"statusListCleanJws"`
	StatusListRevokedJws     string                               `json:"statusListRevokedJws"`
	SignedResolutionEnvelope transaction.SignedResolutionEnvelope `json:"signedResolutionEnvelope"`
}

var goldenKeyTypes = map[string]crypto.KeyType{
	"secp256k1": crypto.KeyTypeSecp256k1,
	"ed25519":   crypto.KeyTypeED25519,
	"mldsa87":   crypto.KeyTypeMlDSA87,
}

func loadVector(t *testing.T, name string) goldenVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "golden", name+".json"))
	if err != nil {
		t.Fatalf("golden vector %s missing (copy from node repo): %v", name, err)
	}
	var v goldenVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

var fixedNow = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

func TestVerifyGoldenCredentialsAllKeyTypes(t *testing.T) {
	for name, kt := range goldenKeyTypes {
		v := loadVector(t, name)
		cred, err := VerifyCredentialJWT(v.IdentityCredentialJws, VerifyOptions{
			KeyType: kt, SignerPublicKeyHex: v.PublicKeyHex,
			StatusListJWS: v.StatusListCleanJws, Now: fixedNow,
		})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if cred.Iss != "did:ulnet:chain-1" || cred.Sub != "did:ulnet:chain-1:aa11" {
			t.Errorf("%s: iss/sub %q %q", name, cred.Iss, cred.Sub)
		}
	}
}

func TestVerifyDetectsRevocation(t *testing.T) {
	v := loadVector(t, "ed25519")
	_, err := VerifyCredentialJWT(v.IdentityCredentialJws, VerifyOptions{
		KeyType: crypto.KeyTypeED25519, SignerPublicKeyHex: v.PublicKeyHex,
		StatusListJWS: v.StatusListRevokedJws, Now: fixedNow,
	})
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected revoked error, got %v", err)
	}
}

func TestVerifyDetectsExpiry(t *testing.T) {
	v := loadVector(t, "ed25519")
	_, err := VerifyCredentialJWT(v.IdentityCredentialJws, VerifyOptions{
		KeyType: crypto.KeyTypeED25519, SignerPublicKeyHex: v.PublicKeyHex,
		Now: time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestVerifyRejectsTamperAndAlgConfusion(t *testing.T) {
	v := loadVector(t, "ed25519")
	parts := strings.Split(v.IdentityCredentialJws, ".")
	tampered := parts[0] + "." + strings.Replace(parts[1], "a", "b", 1) + "." + parts[2]
	if _, err := VerifyCredentialJWT(tampered, VerifyOptions{KeyType: crypto.KeyTypeED25519, SignerPublicKeyHex: v.PublicKeyHex, Now: fixedNow}); err == nil {
		t.Error("tampered payload accepted")
	}
	if _, err := VerifyCredentialJWT(v.IdentityCredentialJws, VerifyOptions{KeyType: crypto.KeyTypeSecp256k1, SignerPublicKeyHex: v.PublicKeyHex, Now: fixedNow}); err == nil {
		t.Error("alg substitution accepted")
	}
}

func buildLocalCredential(statusURL string, iat, exp int64) CredentialPayload {
	return CredentialPayload{
		VerifiableCredential: VerifiableCredential{
			Context:    []string{ContextCredentialsV2, ContextULedgerV1},
			Id:         "urn:uledger:cred:chain-1:1:0",
			Type:       []string{TypeVerifiableCredential, TypeULedgerIdentityCredential},
			Issuer:     "did:ulnet:chain-1",
			ValidFrom:  time.Unix(iat, 0).UTC().Format(time.RFC3339),
			ValidUntil: time.Unix(exp, 0).UTC().Format(time.RFC3339),
			CredentialSubject: CredentialSubject{
				Id: "did:ulnet:chain-1:aa11", Role: "admin",
			},
			CredentialStatus: &CredentialStatus{
				Type: TypeBitstringStatusListEntry, StatusPurpose: StatusPurposeRevocation,
				StatusListIndex: "0", StatusListCredential: statusURL,
			},
		},
		Iss: "did:ulnet:chain-1", Sub: "did:ulnet:chain-1:aa11", Jti: "urn:uledger:cred:chain-1:1:0",
		Iat: iat, Exp: exp,
	}
}

func buildLocalStatusList(id string, iat, exp int64) CredentialPayload {
	return CredentialPayload{
		VerifiableCredential: VerifiableCredential{
			Context:    []string{ContextCredentialsV2, ContextULedgerV1},
			Id:         id,
			Type:       []string{TypeVerifiableCredential, TypeBitstringStatusListCredential},
			Issuer:     "did:ulnet:chain-1",
			ValidFrom:  time.Unix(iat, 0).UTC().Format(time.RFC3339),
			ValidUntil: time.Unix(exp, 0).UTC().Format(time.RFC3339),
			CredentialSubject: CredentialSubject{
				Id: id + "#list", StatusPurpose: StatusPurposeRevocation,
			},
		},
		Iss: "did:ulnet:chain-1", Sub: id + "#list", Jti: id,
		Iat: iat, Exp: exp,
	}
}

func TestVerifyRejectsExpiredStatusList(t *testing.T) {
	key := seededKey(t, crypto.KeyTypeED25519)
	pub := key.GetPublicKeyHex(true)
	statusURL := "https://node.example/identity/credentials/status/chain-1/1"

	credIat := fixedNow.Add(-24 * time.Hour).Unix()
	credExp := fixedNow.Add(24 * time.Hour).Unix()
	credJws := buildToken(t, key, AlgEdDSA, TypVCJWT, buildLocalCredential(statusURL, credIat, credExp))

	pastIat := fixedNow.Add(-2 * 365 * 24 * time.Hour).Unix()
	pastExp := fixedNow.Add(-24 * time.Hour).Unix()
	expiredList := buildToken(t, key, AlgEdDSA, TypVCJWT, buildLocalStatusList(statusURL, pastIat, pastExp))

	_, err := VerifyCredentialJWT(credJws, VerifyOptions{
		KeyType: crypto.KeyTypeED25519, SignerPublicKeyHex: pub,
		StatusListJWS: expiredList, Now: fixedNow,
	})
	if err == nil || !strings.Contains(err.Error(), "status list expired") {
		t.Fatalf("expected status list expired error, got %v", err)
	}
}

func TestVerifyRejectsMismatchedStatusListBinding(t *testing.T) {
	key := seededKey(t, crypto.KeyTypeED25519)
	pub := key.GetPublicKeyHex(true)
	statusURL := "https://node.example/identity/credentials/status/chain-1/1"
	wrongURL := "https://node.example/identity/credentials/status/chain-1/other-list"

	credIat := fixedNow.Add(-24 * time.Hour).Unix()
	credExp := fixedNow.Add(24 * time.Hour).Unix()
	credJws := buildToken(t, key, AlgEdDSA, TypVCJWT, buildLocalCredential(statusURL, credIat, credExp))

	listIat := fixedNow.Add(-24 * time.Hour).Unix()
	listExp := fixedNow.Add(24 * time.Hour).Unix()
	mismatchedList := buildToken(t, key, AlgEdDSA, TypVCJWT, buildLocalStatusList(wrongURL, listIat, listExp))

	_, err := VerifyCredentialJWT(credJws, VerifyOptions{
		KeyType: crypto.KeyTypeED25519, SignerPublicKeyHex: pub,
		StatusListJWS: mismatchedList, Now: fixedNow,
	})
	if err == nil || !strings.Contains(err.Error(), "status list does not match credential status entry") {
		t.Fatalf("expected status list binding error, got %v", err)
	}
}

func TestVerifySignedResolutionGolden(t *testing.T) {
	for name := range goldenKeyTypes {
		v := loadVector(t, name)
		payload, err := VerifySignedResolution(v.SignedResolutionEnvelope, "chain-1")
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !strings.Contains(string(payload), "did:ulnet:chain-1:aa11") {
			t.Errorf("%s payload = %s", name, payload)
		}
		if _, err := VerifySignedResolution(v.SignedResolutionEnvelope, "other-chain"); err == nil {
			t.Errorf("%s: wrong chain accepted", name)
		}
	}
}

func TestVerifySignedResolutionPinnedSignerKey(t *testing.T) {
	v := loadVector(t, "ed25519")
	if _, err := VerifySignedResolution(v.SignedResolutionEnvelope, "chain-1", v.PublicKeyHex); err != nil {
		t.Fatalf("matching pinned key must pass: %v", err)
	}
	if _, err := VerifySignedResolution(v.SignedResolutionEnvelope, "chain-1", "AB12CD"); err == nil {
		t.Error("wrong pinned key must fail")
	} else if !strings.Contains(err.Error(), "signer key does not match pinned key") {
		t.Errorf("unexpected error for wrong pinned key: %v", err)
	}
}

func TestVerifyCrossChecksIssuerKeyAgainstBlockSigner(t *testing.T) {
	v := loadVector(t, "ed25519")
	good := &transaction.TxInclusionProofPackage{Block: &transaction.UL_Block{
		BlockchainId: "chain-1",
		InstanceId:   "chain-1" + v.PublicKeyHex,
	}}
	if _, err := VerifyCredentialJWT(v.IdentityCredentialJws, VerifyOptions{
		KeyType: crypto.KeyTypeED25519, SignerPublicKeyHex: v.PublicKeyHex,
		ProofPackage: good, Now: fixedNow,
	}); err != nil {
		t.Fatalf("matching block signer must pass: %v", err)
	}

	wrongKey := &transaction.TxInclusionProofPackage{Block: &transaction.UL_Block{
		BlockchainId: "chain-1",
		InstanceId:   "chain-1" + "AB12CD",
	}}
	if _, err := VerifyCredentialJWT(v.IdentityCredentialJws, VerifyOptions{
		KeyType: crypto.KeyTypeED25519, SignerPublicKeyHex: v.PublicKeyHex,
		ProofPackage: wrongKey, Now: fixedNow,
	}); err == nil {
		t.Error("mismatched block signer key must fail")
	}

	wrongChain := &transaction.TxInclusionProofPackage{Block: &transaction.UL_Block{
		BlockchainId: "other-chain",
		InstanceId:   "other-chain" + v.PublicKeyHex,
	}}
	if _, err := VerifyCredentialJWT(v.IdentityCredentialJws, VerifyOptions{
		KeyType: crypto.KeyTypeED25519, SignerPublicKeyHex: v.PublicKeyHex,
		ProofPackage: wrongChain, Now: fixedNow,
	}); err == nil {
		t.Error("issuer chain mismatch must fail")
	}
}
