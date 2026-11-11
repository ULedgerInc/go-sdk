package transaction

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

func TestDIDResolutionResultUnmarshalsNewShape(t *testing.T) {
	body := `{
	  "didResolutionMetadata": {"contentType": "application/did+ld+json", "retrieved": "2026-07-20T00:00:00Z"},
	  "didDocument": {
	    "@context": ["https://www.w3.org/ns/did/v1"],
	    "id": "did:ulnet:chain-1:aa11",
	    "verificationMethod": [{"id": "did:ulnet:chain-1:aa11#key-1", "type": "Ed25519VerificationKey2020",
	      "controller": "did:ulnet:chain-1:aa11", "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "abc"}}],
	    "capabilityInvocation": ["did:ulnet:chain-1:aa11#key-1"]
	  },
	  "didDocumentMetadata": {"deactivated": false, "resolvedAtHeight": 5, "entityType": "ORGANIZATION",
	    "name": "acme", "capabilities": [{"action": "token:transfer"}]}
	}`
	var result DIDResolutionResult
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.DIDResolutionMetadata.ContentType != "application/did+ld+json" {
		t.Errorf("contentType = %q", result.DIDResolutionMetadata.ContentType)
	}
	vm := result.DIDDocument.VerificationMethod[0]
	if vm.PublicKeyJwk == nil || vm.PublicKeyJwk.Crv != "Ed25519" {
		t.Errorf("jwk = %+v", vm.PublicKeyJwk)
	}
	if len(result.DIDDocument.CapabilityInvocation) != 1 {
		t.Errorf("capabilityInvocation = %v", result.DIDDocument.CapabilityInvocation)
	}
	if result.DIDDocumentMetadata.EntityType != "ORGANIZATION" || result.DIDDocumentMetadata.Name != "acme" {
		t.Errorf("metadata = %+v", result.DIDDocumentMetadata)
	}
	if len(result.DIDDocumentMetadata.Capabilities) != 1 {
		t.Errorf("capabilities = %+v", result.DIDDocumentMetadata.Capabilities)
	}
}

func TestResolveDIDSigned(t *testing.T) {
	const did = "did:ulnet:chain-1:aa11"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			w.Write([]byte(`{"nodeVersion":"v1","chainsInfo":{},"nodeId":"node-1","peerId":"peer-1"}`))
		case "/blockchains":
			w.Write([]byte(`["chain-1"]`))
		case "/did/" + did:
			if r.URL.Query().Get("signed") != "1" {
				http.Error(w, "expected signed=1", http.StatusBadRequest)
				return
			}
			w.Write([]byte(`{
			  "payload": "eyJmb28iOiJiYXIifQ",
			  "freshness": {"chainId": "chain-1", "headHeight": 5, "headBlockHash": "deadbeef", "signedAt": "2026-07-20T00:00:00Z"},
			  "signer": {"publicKey": "04abcd", "keyType": "ed25519"},
			  "signature": "aabbcc"
			}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	session, err := NewUL_TransactionSession(t.Context(), srv.URL, wallet.UL_Wallet{}, SessionOptions{})
	if err != nil {
		t.Fatalf("NewUL_TransactionSession: %v", err)
	}

	env, err := session.ResolveDIDSigned(did)
	if err != nil {
		t.Fatalf("ResolveDIDSigned: %v", err)
	}
	if env.Freshness.ChainId != "chain-1" || env.Freshness.HeadHeight != 5 || env.Freshness.HeadBlockHash != "deadbeef" {
		t.Errorf("freshness = %+v", env.Freshness)
	}
	if env.Signer.PublicKey != "04abcd" || env.Signer.KeyType.String() != "ed25519" {
		t.Errorf("signer = %+v", env.Signer)
	}
	if env.Signature != "aabbcc" {
		t.Errorf("signature = %q", env.Signature)
	}
	if env.Payload == "" {
		t.Errorf("expected non-empty payload")
	}
}
