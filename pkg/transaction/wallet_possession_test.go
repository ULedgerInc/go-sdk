package transaction

import (
	"encoding/hex"
	"testing"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

func TestWalletPossessionSigningBytesVector(t *testing.T) {
	got := hex.EncodeToString(WalletPossessionSigningBytes("chain-1", "parent-addr", "04ABCD", crypto.KeyTypeSecp256k1))
	want := "554c57414c4c4554504f50" +
		"7c000000077c" + hex.EncodeToString([]byte("chain-1")) +
		"7c0000000b7c" + hex.EncodeToString([]byte("parent-addr")) +
		"7c000000067c" + hex.EncodeToString([]byte("04abcd")) +
		"7c000000097c" + hex.EncodeToString([]byte("secp256k1"))
	if got != want {
		t.Fatalf("signing bytes = %s, want %s", got, want)
	}
}

func TestProveWalletPossessionVerifies(t *testing.T) {
	for _, kt := range []crypto.KeyType{crypto.KeyTypeSecp256k1, crypto.KeyTypeMlDSA87} {
		w, _, err := wallet.GenerateNewWallet("pw", kt, "parent-addr", nil, wallet.DefaultEntropy)
		if err != nil {
			t.Fatalf("GenerateNewWallet: %v", err)
		}
		proof, err := ProveWalletPossession(&w, "chain-1", "parent-addr")
		if err != nil {
			t.Fatalf("ProveWalletPossession: %v", err)
		}
		sig, err := hex.DecodeString(proof)
		if err != nil {
			t.Fatalf("proof is not hex: %v", err)
		}
		msg := WalletPossessionSigningBytes("chain-1", "parent-addr", w.GetKey().GetPublicKeyHex(false), w.GetKey().GetType())
		ok, err := w.GetKey().VerifyWithContext(crypto.DomainWalletPossession, msg, sig)
		if err != nil || !ok {
			t.Fatalf("%s: proof does not verify: ok=%v err=%v", kt, ok, err)
		}
		other := WalletPossessionSigningBytes("chain-2", "parent-addr", w.GetKey().GetPublicKeyHex(false), w.GetKey().GetType())
		if ok, _ := w.GetKey().VerifyWithContext(crypto.DomainWalletPossession, other, sig); ok {
			t.Fatalf("%s: proof verifies over a different chain id", kt)
		}
		if ok, _ := w.GetKey().VerifyWithContext(crypto.DomainTransaction, msg, sig); ok {
			t.Fatalf("%s: proof verifies under the transaction domain", kt)
		}
		if ok, _ := w.GetKey().VerifySignature(msg, sig); ok {
			t.Fatalf("%s: proof verifies under the empty context", kt)
		}
	}
}
