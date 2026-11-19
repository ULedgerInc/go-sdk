package crypto

import (
	"errors"
	"strings"
	"testing"
)

var domainTestKeyTypes = []KeyType{KeyTypeSecp256k1, KeyTypeMlDSA87, KeyTypeED25519, KeyTypeBLS12377}

func newDomainTestKey(t *testing.T, kt KeyType) ULKey {
	t.Helper()
	key, err := GetKeyByType(kt, GetHasherByType(kt))
	if err != nil {
		t.Fatalf("GetKeyByType(%s): %v", kt, err)
	}
	return key
}

func deriveDomainTestKeys(t *testing.T, seed string) map[KeyType]ULKey {
	t.Helper()
	keys := make(map[KeyType]ULKey, len(domainTestKeyTypes))
	for _, kt := range domainTestKeyTypes {
		key := newDomainTestKey(t, kt)
		if err := key.RegenerateKeyFromSeed([]byte(seed), []byte("domain-test-salt")); err != nil {
			t.Fatalf("RegenerateKeyFromSeed(%s): %v", kt, err)
		}
		keys[kt] = key
	}
	return keys
}

func TestDomainSeparatedMessageDomainBounds(t *testing.T) {
	for _, d := range []SigningDomain{"", SigningDomain(strings.Repeat("d", 256))} {
		if _, err := DomainSeparatedMessage(d, []byte("m")); err == nil {
			t.Fatalf("accepted a %d-byte domain", len(d))
		}
	}
	longest := SigningDomain(strings.Repeat("d", 255))
	got, err := DomainSeparatedMessage(longest, []byte("m"))
	if err != nil {
		t.Fatalf("rejected a 255-byte domain: %v", err)
	}
	if got[8] != 255 || string(got[9:9+255]) != string(longest) || string(got[9+255:]) != "m" {
		t.Fatalf("255-byte domain encoded wrongly: % x", got[:10])
	}
}

func TestSignWithContextSeparatesDomains(t *testing.T) {
	keys := deriveDomainTestKeys(t, "domain-seed-a")
	msg := []byte("block hash")
	for _, kt := range domainTestKeyTypes {
		t.Run(kt.String(), func(t *testing.T) {
			key := keys[kt]
			for _, signed := range domainVectorDomainValues {
				sig, err := key.SignWithContext(signed.domain, msg)
				if err != nil {
					t.Fatalf("SignWithContext(%s): %v", signed.domain, err)
				}
				for _, other := range domainVectorDomainValues {
					ok, err := key.VerifyWithContext(other.domain, msg, sig)
					if err != nil {
						t.Fatalf("VerifyWithContext(%s): %v", other.domain, err)
					}
					if ok != (other.domain == signed.domain) {
						t.Fatalf("signed under %s, VerifyWithContext(%s) = %v", signed.domain, other.domain, ok)
					}
				}
				if ok, _ := key.VerifySignature(msg, sig); ok {
					t.Fatalf("signature under %s verified under the empty context", signed.domain)
				}
				if ok, _ := IsSignatureValid(signed.domain, key.GetPublicKeyHex(true), msg, sig, kt); !ok {
					t.Fatalf("IsSignatureValid(%s) rejected a signature made under it", signed.domain)
				}
			}

			rawSig, err := key.SignData(msg)
			if err != nil {
				t.Fatalf("SignData: %v", err)
			}
			for _, d := range domainVectorDomainValues {
				if ok, _ := key.VerifyWithContext(d.domain, msg, rawSig); ok {
					t.Fatalf("empty-context signature verified under %s", d.domain)
				}
				if ok, _ := IsSignatureValid(d.domain, key.GetPublicKeyHex(true), msg, rawSig, kt); ok {
					t.Fatalf("IsSignatureValid(%s) accepted an empty-context signature", d.domain)
				}
			}

			if _, err := key.SignWithContext("", msg); err == nil {
				t.Fatal("SignWithContext accepted the empty domain")
			}
			if _, err := key.SignWithContext(SigningDomain(strings.Repeat("d", 256)), msg); err == nil {
				t.Fatal("SignWithContext accepted a 256-byte domain")
			}
			sig, err := key.SignWithContext(DomainBlock, msg)
			if err != nil {
				t.Fatalf("SignWithContext: %v", err)
			}
			if ok, err := key.VerifyWithContext("", msg, sig); ok || err == nil {
				t.Fatalf("VerifyWithContext with the empty domain = (%v, %v), want (false, error)", ok, err)
			}
		})
	}
}

func TestSignRefusesMismatchedPublicKey(t *testing.T) {
	keysA := deriveDomainTestKeys(t, "domain-seed-a")
	keysB := deriveDomainTestKeys(t, "domain-seed-b")
	msg := []byte("checkpoint receipt")
	for _, kt := range domainTestKeyTypes {
		t.Run(kt.String(), func(t *testing.T) {
			key := newDomainTestKey(t, kt)
			if err := key.GeneratePublicKeyFromHex(true, keysB[kt].GetPublicKeyHex(true)); err != nil {
				t.Fatalf("GeneratePublicKeyFromHex: %v", err)
			}
			if err := key.GeneratePrivateKeyFromHex(keysA[kt].GetPrivateKeyHex()); err != nil {
				t.Fatalf("GeneratePrivateKeyFromHex: %v", err)
			}
			if sig, err := key.SignData(msg); !errors.Is(err, errSignatureSelfCheck) {
				t.Fatalf("SignData = (%x, %v), want the self-check error", sig, err)
			}
			if sig, err := key.SignWithContext(DomainCheckpointReceipt, msg); !errors.Is(err, errSignatureSelfCheck) {
				t.Fatalf("SignWithContext = (%x, %v), want the self-check error", sig, err)
			}
		})
	}
}

func TestPrivateKeyFromHexAloneCanSign(t *testing.T) {
	source := deriveDomainTestKeys(t, "domain-seed-a")
	msg := []byte("operator challenge")
	for _, kt := range []KeyType{KeyTypeMlDSA87, KeyTypeED25519, KeyTypeBLS12377} {
		t.Run(kt.String(), func(t *testing.T) {
			key := newDomainTestKey(t, kt)
			if err := key.GeneratePrivateKeyFromHex(source[kt].GetPrivateKeyHex()); err != nil {
				t.Fatalf("GeneratePrivateKeyFromHex: %v", err)
			}
			if got, want := key.GetPublicKeyHex(true), source[kt].GetPublicKeyHex(true); got != want {
				t.Fatalf("derived public key %s, want %s", got, want)
			}
			sig, err := key.SignWithContext(DomainOperatorLogin, msg)
			if err != nil {
				t.Fatalf("SignWithContext: %v", err)
			}
			if ok, err := source[kt].VerifyWithContext(DomainOperatorLogin, msg, sig); err != nil || !ok {
				t.Fatalf("VerifyWithContext = (%v, %v), want (true, nil)", ok, err)
			}
			if _, err := key.SignData(msg); err != nil {
				t.Fatalf("SignData: %v", err)
			}
		})
	}
}

func TestED25519KeyFromHexRejectsWrongLength(t *testing.T) {
	for _, h := range []string{"ab", strings.Repeat("ab", 32), strings.Repeat("ab", 65)} {
		if err := NewED25519Key(nil).GeneratePrivateKeyFromHex(h); err == nil {
			t.Fatalf("accepted a %d-byte ed25519 private key", len(h)/2)
		}
	}
	for _, h := range []string{"", "ab", strings.Repeat("ab", 31), strings.Repeat("ab", 33)} {
		if err := NewED25519Key(nil).GeneratePublicKeyFromHex(true, h); err == nil {
			t.Fatalf("accepted a %d-byte ed25519 public key", len(h)/2)
		}
	}
}

func TestED25519VerifyShortPublicKeyDoesNotPanic(t *testing.T) {
	key := &ED25519Key{publicKey: []byte{0xab}}
	if ok, err := key.VerifySignature([]byte("m"), make([]byte, 64)); ok || err == nil {
		t.Fatalf("VerifySignature = (%v, %v), want (false, error)", ok, err)
	}
	if ok, err := key.VerifyWithContext(DomainBlock, []byte("m"), make([]byte, 64)); ok || err == nil {
		t.Fatalf("VerifyWithContext = (%v, %v), want (false, error)", ok, err)
	}
}

func TestRawSignatureCannotPoseAsDomainSignature(t *testing.T) {
	keys := deriveDomainTestKeys(t, "domain-seed-a")
	msg := []byte("checkpoint receipt")
	tagged, err := DomainSeparatedMessage(DomainCheckpointReceipt, msg)
	if err != nil {
		t.Fatalf("DomainSeparatedMessage: %v", err)
	}
	for _, kt := range domainTestKeyTypes {
		t.Run(kt.String(), func(t *testing.T) {
			key := keys[kt]
			rawSig, err := key.SignData(tagged)
			switch kt {
			case KeyTypeSecp256k1, KeyTypeBLS12377:
				if !errors.Is(err, errDomainTaggedRawMessage) {
					t.Fatalf("SignData(tagged) = (%x, %v), want the tagged-input error", rawSig, err)
				}
				if _, err := key.SignData([]byte(domainSeparationTag)); !errors.Is(err, errDomainTaggedRawMessage) {
					t.Fatalf("SignData(tag alone) = %v, want the tagged-input error", err)
				}
				sig, err := key.SignWithContext(DomainCheckpointReceipt, msg)
				if err != nil {
					t.Fatalf("SignWithContext: %v", err)
				}
				if ok, err := key.VerifyWithContext(DomainCheckpointReceipt, msg, sig); err != nil || !ok {
					t.Fatalf("VerifyWithContext = (%v, %v), want (true, nil)", ok, err)
				}
				if ok, err := key.VerifySignature(tagged, sig); ok || !errors.Is(err, errDomainTaggedRawMessage) {
					t.Fatalf("VerifySignature(tagged) = (%v, %v), want (false, tagged-input error)", ok, err)
				}
			default:
				if err != nil {
					t.Fatalf("SignData(tagged): %v", err)
				}
				if ok, _ := key.VerifyWithContext(DomainCheckpointReceipt, msg, rawSig); ok {
					t.Fatal("raw signature over the tagged bytes verified as a domain signature")
				}
			}
		})
	}
}
