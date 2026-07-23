package credential

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
)

func seededKey(t *testing.T, kt crypto.KeyType) crypto.ULKey {
	t.Helper()
	key, err := crypto.GetKeyByType(kt, crypto.GetHasherByType(kt))
	if err != nil {
		t.Fatalf("GetKeyByType: %v", err)
	}
	if err := key.GenerateKeyFromSeed(bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatalf("GenerateKeyFromSeed: %v", err)
	}
	return key
}

func buildToken(t *testing.T, key crypto.ULKey, alg, typ string, payload any) string {
	t.Helper()
	headerJSON, err := json.Marshal(Header{Alg: alg, Typ: typ})
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

func TestAlgForKeyType(t *testing.T) {
	cases := map[crypto.KeyType]string{
		crypto.KeyTypeSecp256k1: "ES256K",
		crypto.KeyTypeED25519:   "EdDSA",
		crypto.KeyTypeMlDSA87:   "ML-DSA-87",
	}
	for kt, want := range cases {
		got, err := AlgForKeyType(kt)
		if err != nil || got != want {
			t.Errorf("AlgForKeyType(%v) = %q, %v; want %q", kt, got, err, want)
		}
	}
	if _, err := AlgForKeyType(crypto.KeyTypeBLS12377); err == nil {
		t.Error("bls12377 must be refused")
	}
}

func TestParseCompactJWSRejectsMalformed(t *testing.T) {
	if _, _, _, _, err := ParseCompactJWS("not-a-jws"); err == nil {
		t.Error("expected error for malformed token")
	}
}

func TestVerifyJWSRoundTrip(t *testing.T) {
	key := seededKey(t, crypto.KeyTypeED25519)
	pub := key.GetPublicKeyHex(true)
	token := buildToken(t, key, AlgEdDSA, TypVCJWT, map[string]string{"hello": "world"})
	payload, err := VerifyJWS(token, crypto.KeyTypeED25519, pub)
	if err != nil {
		t.Fatalf("VerifyJWS: %v", err)
	}
	var out map[string]string
	if err := json.Unmarshal(payload, &out); err != nil || out["hello"] != "world" {
		t.Errorf("payload roundtrip: %v %v", out, err)
	}
}

func TestVerifyJWSRejectsWrongTyp(t *testing.T) {
	key := seededKey(t, crypto.KeyTypeED25519)
	pub := key.GetPublicKeyHex(true)
	token := buildToken(t, key, AlgEdDSA, "JWT", map[string]int{"n": 1})
	_, err := VerifyJWS(token, crypto.KeyTypeED25519, pub)
	if err == nil || !strings.Contains(err.Error(), "typ") {
		t.Errorf("expected typ mismatch error, got %v", err)
	}
}

func TestVerifyJWSRejectsAlgSubstitution(t *testing.T) {
	key := seededKey(t, crypto.KeyTypeED25519)
	pub := key.GetPublicKeyHex(true)
	token := buildToken(t, key, AlgEdDSA, TypVCJWT, map[string]int{"n": 1})
	if _, err := VerifyJWS(token, crypto.KeyTypeSecp256k1, pub); err == nil {
		t.Error("verifying an EdDSA token as ES256K must fail alg pinning")
	}
}

func TestVerifyJWSRejectsTamperedPayload(t *testing.T) {
	key := seededKey(t, crypto.KeyTypeED25519)
	pub := key.GetPublicKeyHex(true)
	token := buildToken(t, key, AlgEdDSA, TypVCJWT, map[string]int{"n": 1})
	parts := strings.Split(token, ".")
	tampered := base64.RawURLEncoding.EncodeToString([]byte(`{"n":2}`))
	if _, err := VerifyJWS(parts[0]+"."+tampered+"."+parts[2], crypto.KeyTypeED25519, pub); err == nil {
		t.Error("tampered payload must fail")
	}
}

func TestVerifyJWSGolden(t *testing.T) {
	v := loadVector(t, "secp256k1")
	payload, err := VerifyJWS(v.IdentityCredentialJws, crypto.KeyTypeSecp256k1, v.PublicKeyHex)
	if err != nil {
		t.Fatalf("VerifyJWS golden: %v", err)
	}
	if !strings.Contains(string(payload), "did:ulnet:chain-1:aa11") {
		t.Errorf("payload = %s", payload)
	}
}
