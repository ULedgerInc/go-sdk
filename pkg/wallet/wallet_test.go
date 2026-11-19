package wallet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
)

func TestGetWalletFromPrivateKey(t *testing.T) {
	tests := []struct {
		name          string
		publicKeyHex  string
		privateKeyHex string
		wantErr       bool
	}{
		{
			name:          "valid private key",
			privateKeyHex: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			publicKeyHex:  "04f2f0fd15ba3a7f4ba62cd705c4df8094917e7e85cab345beaf0b378f84a3422ced9a9cf925c05ded76c63ab677207287a5b64b2fb683803abef934259fa37c5d",
			wantErr:       false,
		},
		{
			name:          "invalid private key",
			privateKeyHex: "invalid",
			publicKeyHex:  "invalid",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetWalletFromHex(tt.publicKeyHex, tt.privateKeyHex, crypto.KeyTypeSecp256k1)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetWalletFromPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.Address == "" {
				t.Error("GetWalletFromPrivateKey() returned empty address for valid key")
			}
		})
	}
}

func TestGetAddressFromWallet(t *testing.T) {
	privateKeyHex := "63f6062f2034bcbcc08bae2eaabee8dd780d352cd76c595dce3a631ce8877934"
	publicKeyHex := "04f2f0fd15ba3a7f4ba62cd705c4df8094917e7e85cab345beaf0b378f84a3422ced9a9cf925c05ded76c63ab677207287a5b64b2fb683803abef934259fa37c5d"
	wallet, err := GetWalletFromHex(publicKeyHex, privateKeyHex, 0)
	if err != nil {
		t.Errorf("GetWalletFromPrivateKey() error = %v", err)
	}

	if !strings.EqualFold(wallet.key.GetPrivateKeyHex(), privateKeyHex) {
		t.Errorf("GetPrivateKeyHex() returned %s, want %s", wallet.key.GetPrivateKeyHex(), privateKeyHex)
	}

	expectedAddress := "56dda682a1ae8b3bd2104dac92769458eccc9475158559396d3744e366d99200"
	if !strings.EqualFold(wallet.Address, expectedAddress) {
		t.Errorf("GetAddressFromWallet() returned %s, want %s", wallet.Address, expectedAddress)
	}
}

var signingKeyTypes = []crypto.KeyType{crypto.KeyTypeSecp256k1, crypto.KeyTypeMlDSA87, crypto.KeyTypeED25519, crypto.KeyTypeBLS12377}

func TestEveryWalletConstructionSignsUnderDomains(t *testing.T) {
	msg := []byte("tx digest")
	for _, kt := range signingKeyTypes {
		t.Run(kt.String(), func(t *testing.T) {
			generated, mnemonic, err := GenerateNewWallet("pw", kt, "", nil, DefaultEntropy)
			if err != nil {
				t.Fatalf("GenerateNewWallet: %v", err)
			}
			pub := generated.key.GetPublicKeyHex(false)
			priv := generated.key.GetPrivateKeyHex()

			fromMnemonic, err := GenerateFromMnemonic(mnemonic, "pw", kt)
			if err != nil {
				t.Fatalf("GenerateFromMnemonic: %v", err)
			}
			fromHex, err := GetWalletFromHex(pub, priv, kt)
			if err != nil {
				t.Fatalf("GetWalletFromHex: %v", err)
			}
			raw, err := json.Marshal(WalletData{KeyType: kt, PublicKeyHex: pub, PrivateKeyHex: priv})
			if err != nil {
				t.Fatalf("marshal wallet data: %v", err)
			}
			fromJson, err := FromJson(string(raw), "pw")
			if err != nil {
				t.Fatalf("FromJson: %v", err)
			}
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "with-key")
			if err := generated.SaveToFile(keyPath, "", true); err != nil {
				t.Fatalf("SaveToFile: %v", err)
			}
			fromKeyFile, err := LoadFromFile(keyPath+".ukey", "pw")
			if err != nil {
				t.Fatalf("LoadFromFile (private key): %v", err)
			}
			mnemonicPath := filepath.Join(dir, "with-mnemonic")
			if err := generated.SaveToFile(mnemonicPath, mnemonic, false); err != nil {
				t.Fatalf("SaveToFile: %v", err)
			}
			fromMnemonicFile, err := LoadFromFile(mnemonicPath+".ukey", "pw")
			if err != nil {
				t.Fatalf("LoadFromFile (mnemonic): %v", err)
			}

			for name, w := range map[string]*UL_Wallet{
				"GenerateNewWallet":     &generated,
				"GenerateFromMnemonic":  &fromMnemonic,
				"GetWalletFromHex":      &fromHex,
				"FromJson":              fromJson,
				"LoadFromFile private":  &fromKeyFile,
				"LoadFromFile mnemonic": &fromMnemonicFile,
			} {
				sig, err := w.GetKey().SignWithContext(crypto.DomainTransaction, msg)
				if err != nil {
					t.Fatalf("%s: SignWithContext: %v", name, err)
				}
				if ok, err := crypto.IsSignatureValid(crypto.DomainTransaction, generated.key.GetPublicKeyHex(true), msg, sig, kt); err != nil || !ok {
					t.Fatalf("%s: IsSignatureValid = (%v, %v), want (true, nil)", name, ok, err)
				}
				if _, err := w.GetKey().SignData(msg); err != nil {
					t.Fatalf("%s: SignData: %v", name, err)
				}
			}
		})
	}
}

func TestWalletWithMismatchedKeyHalvesCannotSign(t *testing.T) {
	for _, kt := range signingKeyTypes {
		t.Run(kt.String(), func(t *testing.T) {
			a, _, err := GenerateNewWallet("pw", kt, "", nil, DefaultEntropy)
			if err != nil {
				t.Fatalf("GenerateNewWallet: %v", err)
			}
			b, _, err := GenerateNewWallet("pw", kt, "", nil, DefaultEntropy)
			if err != nil {
				t.Fatalf("GenerateNewWallet: %v", err)
			}
			mixed, err := GetWalletFromHex(b.key.GetPublicKeyHex(false), a.key.GetPrivateKeyHex(), kt)
			if err != nil {
				t.Fatalf("GetWalletFromHex: %v", err)
			}
			if sig, err := mixed.GetKey().SignWithContext(crypto.DomainTransaction, []byte("tx digest")); err == nil {
				t.Fatalf("SignWithContext with mismatched key halves = %x, want the self-check error", sig)
			}
			if sig, err := mixed.GetKey().SignData([]byte("tx digest")); err == nil {
				t.Fatalf("SignData with mismatched key halves = %x, want the self-check error", sig)
			}
		})
	}
}

// Both loaders must accept or reject the same file the same way, and agree
// on the resulting key and metadata.
//
//	.ukey ──┬─ FromJson(contents)  ─┐
//	        └─ LoadFromFile(path)  ─┴─ same wallet, or both error

const (
	testPassphrase  = "correct-pass"
	wrongPassphrase = "wrong-pass"
	probeMessage    = "probe digest"
)

type loadResult struct {
	name   string
	wallet *UL_Wallet
	err    error
}

// loadBoth writes wd to disk and loads it through both entry points,
// converting a panic into a test failure so a bad file never crashes a caller.
func loadBoth(t *testing.T, wd WalletData, passphrase string) []loadResult {
	t.Helper()

	raw, err := json.Marshal(wd)
	if err != nil {
		t.Fatalf("marshal wallet data: %v", err)
	}

	path := filepath.Join(t.TempDir(), "w.ukey")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write wallet file: %v", err)
	}

	results := []loadResult{{name: "FromJson"}, {name: "LoadFromFile"}}
	for i := range results {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s panicked: %v", results[i].name, r)
				}
			}()

			if i == 0 {
				results[i].wallet, results[i].err = FromJson(string(raw), passphrase)
				return
			}
			w, err := LoadFromFile(path, passphrase)
			results[i].wallet, results[i].err = &w, err
		}()
	}

	return results
}

func newTestWallet(t *testing.T, kt crypto.KeyType) (UL_Wallet, string) {
	t.Helper()

	auth := map[string]UL_AuthPermission{WALLET_GROUP_NAME: {Create: true, Read: true}}
	w, mnemonic, err := GenerateNewWallet(testPassphrase, kt, "parent-address", auth, DefaultEntropy)
	if err != nil {
		t.Fatalf("GenerateNewWallet: %v", err)
	}

	return w, mnemonic
}

// toData mirrors SaveToFile so tests can build tampered files field by field.
func toData(w UL_Wallet, mnemonic string, privateKey bool) WalletData {
	wd := WalletData{
		Address:      w.Address,
		Enabled:      w.Enabled,
		Parent:       w.Parent,
		AuthGroups:   w.AuthGroups,
		Mnemonic:     mnemonic,
		KeyType:      w.key.GetType(),
		PublicKeyHex: w.key.GetPublicKeyHex(false),
	}
	if privateKey {
		wd.PrivateKeyHex = w.key.GetPrivateKeyHex()
	}

	return wd
}

func requireSigns(t *testing.T, r loadResult) {
	t.Helper()

	sig, err := r.wallet.key.SignData([]byte(probeMessage))
	if err != nil {
		t.Fatalf("%s: SignData: %v", r.name, err)
	}

	ok, err := r.wallet.key.VerifySignature([]byte(probeMessage), sig)
	if err != nil || !ok {
		t.Fatalf("%s: VerifySignature = (%v, %v), want (true, nil)", r.name, ok, err)
	}
}

func TestLoadersKeepKeyAndMetadata(t *testing.T) {
	for _, kt := range signingKeyTypes {
		t.Run(kt.String(), func(t *testing.T) {
			want, mnemonic := newTestWallet(t, kt)

			for _, file := range []struct {
				name string
				data WalletData
			}{
				{"mnemonic and private key", toData(want, mnemonic, true)},
				{"mnemonic only", toData(want, mnemonic, false)},
				{"private key only", toData(want, "", true)},
			} {
				for _, r := range loadBoth(t, file.data, testPassphrase) {
					if r.err != nil {
						t.Fatalf("%s %s: %v", file.name, r.name, r.err)
					}

					got := r.wallet
					if got.Address != want.Address || got.key.GetPublicKeyHex(false) != want.key.GetPublicKeyHex(false) {
						t.Errorf("%s %s: address %s, want %s", file.name, r.name, got.Address, want.Address)
					}
					if got.Parent != want.Parent || got.Enabled != want.Enabled || !reflect.DeepEqual(got.AuthGroups, want.AuthGroups) {
						t.Errorf("%s %s: metadata (%q, %v, %v), want (%q, %v, %v)", file.name, r.name, got.Parent, got.Enabled, got.AuthGroups, want.Parent, want.Enabled, want.AuthGroups)
					}
					requireSigns(t, r)
				}
			}
		})
	}
}

func TestLoadersAcceptPublicOnlyFile(t *testing.T) {
	for _, kt := range signingKeyTypes {
		t.Run(kt.String(), func(t *testing.T) {
			w, _ := newTestWallet(t, kt)

			for _, r := range loadBoth(t, toData(w, "", false), testPassphrase) {
				if r.err != nil {
					t.Fatalf("%s: %v", r.name, r.err)
				}
				if r.wallet.Address != w.Address || r.wallet.key.GetPrivateKeyHex() != "" {
					t.Errorf("%s: got address %s with private key %t, want watch-only %s", r.name, r.wallet.Address, r.wallet.key.GetPrivateKeyHex() != "", w.Address)
				}
			}
		})
	}
}

func TestLoadersRejectInconsistentFile(t *testing.T) {
	for _, kt := range signingKeyTypes {
		t.Run(kt.String(), func(t *testing.T) {
			a, mnemonicA := newTestWallet(t, kt)
			b, _ := newTestWallet(t, kt)

			// Mnemonic belongs to A; keys and address belong to B.
			conflicting := toData(b, mnemonicA, true)

			// Keys belong to A; the address field names B.
			wrongAddress := toData(a, "", true)
			wrongAddress.Address = b.Address

			// Public half from B, private half from A.
			mixedHalves := toData(a, "", true)
			mixedHalves.PublicKeyHex = b.key.GetPublicKeyHex(false)

			// Mnemonic-derived key differs from the stored public key.
			mnemonicWrongPub := toData(a, mnemonicA, false)
			mnemonicWrongPub.PublicKeyHex = b.key.GetPublicKeyHex(false)

			truncated := toData(a, "", true)
			truncated.PrivateKeyHex = truncated.PrivateKeyHex[:len(truncated.PrivateKeyHex)-2]

			for _, file := range []struct {
				name       string
				data       WalletData
				passphrase string
			}{
				{"mnemonic and private key, wrong passphrase", toData(a, mnemonicA, true), wrongPassphrase},
				{"mnemonic only, wrong passphrase", toData(a, mnemonicA, false), wrongPassphrase},
				{"mnemonic disagrees with private key", conflicting, testPassphrase},
				{"address does not match key", wrongAddress, testPassphrase},
				{"public and private halves differ", mixedHalves, testPassphrase},
				{"mnemonic disagrees with public key", mnemonicWrongPub, testPassphrase},
				{"truncated private key", truncated, testPassphrase},
			} {
				for _, r := range loadBoth(t, file.data, file.passphrase) {
					if r.err == nil {
						t.Errorf("%s %s: loaded address %s, want an error", file.name, r.name, r.wallet.Address)
					}
				}
			}
		})
	}
}
