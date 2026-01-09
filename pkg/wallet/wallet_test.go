package wallet

import (
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
