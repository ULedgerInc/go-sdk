package identity

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ULedgerInc/go-sdk/pkg/credential"
	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
)

func seedCredentialKey(t *testing.T) crypto.ULKey {
	t.Helper()
	key, err := crypto.GetKeyByType(crypto.KeyTypeED25519, crypto.GetHasherByType(crypto.KeyTypeED25519))
	if err != nil {
		t.Fatalf("GetKeyByType: %v", err)
	}
	if err := key.GenerateKeyFromSeed(bytes.Repeat([]byte{9}, 32)); err != nil {
		t.Fatalf("GenerateKeyFromSeed: %v", err)
	}
	return key
}

func signCompactJWS(t *testing.T, key crypto.ULKey, payload any) string {
	t.Helper()
	headerJSON, err := json.Marshal(credential.Header{Alg: credential.AlgEdDSA, Typ: credential.TypVCJWT})
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig, err := key.SignData([]byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func encodeStatusBits(t *testing.T, bits []byte) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(bits); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return "u" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func signResolutionEnvelope(t *testing.T, key crypto.ULKey, chainId string, payload []byte) transaction.SignedResolutionEnvelope {
	t.Helper()
	freshness := transaction.ResolutionFreshness{
		ChainId:       chainId,
		HeadHeight:    5,
		HeadBlockHash: "block-hash-5",
		SignedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	freshnessJSON, err := json.Marshal(freshness)
	if err != nil {
		t.Fatal(err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(freshnessJSON) + "." + payloadB64
	sig, err := key.SignData([]byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	return transaction.SignedResolutionEnvelope{
		Payload:   payloadB64,
		Freshness: freshness,
		Signer:    transaction.ResolutionSigner{PublicKey: key.GetPublicKeyHex(true), KeyType: crypto.KeyTypeED25519},
		Signature: crypto.BytesToHex(sig),
	}
}

func buildCredentialPayload(chainId, credType string, subject credential.CredentialSubject, jti, statusURL, statusIndex string, iat, exp time.Time) credential.CredentialPayload {
	return credential.CredentialPayload{
		VerifiableCredential: credential.VerifiableCredential{
			Context:           []string{credential.ContextCredentialsV2, credential.ContextULedgerV1},
			Id:                jti,
			Type:              []string{credential.TypeVerifiableCredential, credType},
			Issuer:            credential.ChainIssuer(chainId),
			ValidFrom:         iat.UTC().Format(time.RFC3339),
			ValidUntil:        exp.UTC().Format(time.RFC3339),
			CredentialSubject: subject,
			CredentialStatus: &credential.CredentialStatus{
				Type:                 credential.TypeBitstringStatusListEntry,
				StatusPurpose:        credential.StatusPurposeRevocation,
				StatusListIndex:      statusIndex,
				StatusListCredential: statusURL,
			},
		},
		Iss: credential.ChainIssuer(chainId),
		Sub: subject.Id,
		Jti: jti,
		Iat: iat.Unix(),
		Exp: exp.Unix(),
	}
}

func buildStatusListPayload(chainId, listURL, encodedList string, iat, exp time.Time) credential.CredentialPayload {
	return credential.CredentialPayload{
		VerifiableCredential: credential.VerifiableCredential{
			Context:    []string{credential.ContextCredentialsV2, credential.ContextULedgerV1},
			Id:         listURL,
			Type:       []string{credential.TypeVerifiableCredential, credential.TypeBitstringStatusListCredential},
			Issuer:     credential.ChainIssuer(chainId),
			ValidFrom:  iat.UTC().Format(time.RFC3339),
			ValidUntil: exp.UTC().Format(time.RFC3339),
			CredentialSubject: credential.CredentialSubject{
				Id: listURL + "#list", StatusPurpose: credential.StatusPurposeRevocation, EncodedList: encodedList,
			},
		},
		Iss: credential.ChainIssuer(chainId),
		Sub: listURL + "#list",
		Jti: listURL,
		Iat: iat.Unix(),
		Exp: exp.Unix(),
	}
}

func TestRunner_CredentialsPhase_Disabled(t *testing.T) {
	f := &fakeClient{}
	r := testRunner(f)
	r.cfg.Credentials.Enabled = false
	r.agentEntityAddr = "agent-entity-addr"

	if err := r.runCredentialsPhase(); err != nil {
		t.Fatalf("expected no error when disabled, got %v", err)
	}
	if r.report != nil && len(r.report.Steps) != 0 {
		t.Fatalf("expected no steps recorded when disabled, got %+v", r.report.Steps)
	}
}

func TestRunner_CredentialsPhase_HappyPath(t *testing.T) {
	key := seedCredentialKey(t)
	chainId := "test-chain"
	ownerAddr := "owner-addr"
	rootEntityAddr := "root-entity-addr"
	subjectDID := buildDID(chainId, ownerAddr)
	statusURL := fmt.Sprintf("http://fake-node/identity/credentials/status/%s/1", chainId)
	now := time.Now().UTC()

	identityJTI := "urn:uledger:cred:" + chainId + ":1:0"
	identityJWS := signCompactJWS(t, key, buildCredentialPayload(chainId, credential.TypeULedgerIdentityCredential,
		credential.CredentialSubject{Id: subjectDID, Entity: rootEntityAddr, Role: transaction.EntityRoleAdmin},
		identityJTI, statusURL, "0", now.Add(-time.Hour), now.Add(24*time.Hour)))

	authJTI := "urn:uledger:cred:" + chainId + ":1:1"
	authJWS := signCompactJWS(t, key, buildCredentialPayload(chainId, credential.TypeULedgerAuthenticationCredential,
		credential.CredentialSubject{Id: subjectDID, TxId: "auth-internal-tx"},
		authJTI, statusURL, "1", now.Add(-time.Hour), now.Add(24*time.Hour)))

	cleanListJWS := signCompactJWS(t, key, buildStatusListPayload(chainId, statusURL,
		encodeStatusBits(t, []byte{0x00}), now.Add(-time.Hour), now.Add(24*time.Hour)))

	envelopePayload, err := json.Marshal(transaction.DIDResolutionResult{DIDDocument: transaction.DIDDocument{Id: subjectDID}})
	if err != nil {
		t.Fatal(err)
	}
	env := signResolutionEnvelope(t, key, chainId, envelopePayload)

	f := &fakeClient{
		resolveDIDSigned: func(did string) (transaction.SignedResolutionEnvelope, error) {
			if did != subjectDID {
				return transaction.SignedResolutionEnvelope{}, fmt.Errorf("unexpected did %q", did)
			}
			return env, nil
		},
		fetchStatusList: func(blockchainId, listId string) (string, error) {
			return cleanListJWS, nil
		},
		issueIdentityCred: func(claim transaction.IdentityClaim, evidenceTxId string) (string, string, error) {
			return identityJWS, identityJTI, nil
		},
		issueAuthCred: func(blockchainId, txId string) (string, string, error) {
			if txId != "auth-internal-tx" {
				return "", "", fmt.Errorf("unexpected txId %q", txId)
			}
			return authJWS, authJTI, nil
		},
	}

	r := testRunner(f)
	r.cfg.BlockchainId = chainId
	r.cfg.ChainKeyType = "ed25519"
	r.cfg.Credentials = CredentialsScenarioConfig{Enabled: true}
	r.rootEntityAddr = rootEntityAddr
	r.authInternalTxId = "auth-internal-tx"

	if err := r.runCredentialsPhase(); err != nil {
		t.Fatalf("credentials phase failed: %v", err)
	}

	wantSteps := []string{
		"credential-issue",
		"credential-verify-offline",
		"credential-dedup",
		"credential-issue-authentication",
	}
	if r.report == nil || len(r.report.Steps) != len(wantSteps) {
		t.Fatalf("expected %d steps, got %+v", len(wantSteps), r.report)
	}
	for i, name := range wantSteps {
		step := r.report.Steps[i]
		if step.Name != name {
			t.Fatalf("step %d: expected %q, got %q", i, name, step.Name)
		}
		if step.Error != "" {
			t.Fatalf("step %d (%s): unexpected error: %s", i, name, step.Error)
		}
	}
	if len(f.issuedClaims) == 0 {
		t.Fatalf("expected the fake client to capture at least one issued claim")
	}
	issued := f.issuedClaims[0]
	if issued.EntityAddress != rootEntityAddr {
		t.Fatalf("expected issued claim entityAddress %q, got %q", rootEntityAddr, issued.EntityAddress)
	}
	if issued.Role != transaction.EntityRoleAdmin {
		t.Fatalf("expected issued claim role %q, got %q", transaction.EntityRoleAdmin, issued.Role)
	}
	if issued.SubjectDID != subjectDID {
		t.Fatalf("expected issued claim subjectDID %q, got %q", subjectDID, issued.SubjectDID)
	}
}

func TestRunner_CredentialsPhase_AuthCredentialSkippedWithoutTxId(t *testing.T) {
	key := seedCredentialKey(t)
	chainId := "test-chain"
	ownerAddr := "owner-addr"
	rootEntityAddr := "root-entity-addr"
	subjectDID := buildDID(chainId, ownerAddr)
	statusURL := fmt.Sprintf("http://fake-node/identity/credentials/status/%s/1", chainId)
	now := time.Now().UTC()

	identityJTI := "urn:uledger:cred:" + chainId + ":1:0"
	identityJWS := signCompactJWS(t, key, buildCredentialPayload(chainId, credential.TypeULedgerIdentityCredential,
		credential.CredentialSubject{Id: subjectDID, Entity: rootEntityAddr, Role: transaction.EntityRoleAdmin},
		identityJTI, statusURL, "0", now.Add(-time.Hour), now.Add(24*time.Hour)))
	cleanListJWS := signCompactJWS(t, key, buildStatusListPayload(chainId, statusURL,
		encodeStatusBits(t, []byte{0x00}), now.Add(-time.Hour), now.Add(24*time.Hour)))

	envelopePayload, err := json.Marshal(transaction.DIDResolutionResult{DIDDocument: transaction.DIDDocument{Id: subjectDID}})
	if err != nil {
		t.Fatal(err)
	}
	env := signResolutionEnvelope(t, key, chainId, envelopePayload)

	f := &fakeClient{
		resolveDIDSigned: func(did string) (transaction.SignedResolutionEnvelope, error) { return env, nil },
		fetchStatusList:  func(blockchainId, listId string) (string, error) { return cleanListJWS, nil },
		issueIdentityCred: func(claim transaction.IdentityClaim, evidenceTxId string) (string, string, error) {
			return identityJWS, identityJTI, nil
		},
	}

	r := testRunner(f)
	r.cfg.BlockchainId = chainId
	r.cfg.ChainKeyType = "ed25519"
	r.cfg.Credentials = CredentialsScenarioConfig{Enabled: true}
	r.rootEntityAddr = rootEntityAddr

	if err := r.runCredentialsPhase(); err != nil {
		t.Fatalf("credentials phase failed: %v", err)
	}

	wantSteps := []string{
		"credential-issue",
		"credential-verify-offline",
		"credential-dedup",
		"credential-issue-authentication",
	}
	if r.report == nil || len(r.report.Steps) != len(wantSteps) {
		t.Fatalf("expected %d steps, got %+v", len(wantSteps), r.report)
	}
	for i, name := range wantSteps {
		if r.report.Steps[i].Name != name {
			t.Fatalf("step %d: expected %q, got %q", i, name, r.report.Steps[i].Name)
		}
	}
	if step := r.report.Steps[3]; step.Error != "" || !strings.Contains(step.Output, "skipped") {
		t.Fatalf("expected credential-issue-authentication skipped (no retained txId), got %+v", step)
	}
}
