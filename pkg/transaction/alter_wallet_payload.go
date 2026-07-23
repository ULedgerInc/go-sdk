package transaction

import "github.com/ULedgerInc/go-sdk/pkg/wallet"

type AlterWalletPayload struct {
	Target       string                              `json:"target"`
	Enabled      bool                                `json:"enabled"`
	AuthGroups   map[string]wallet.UL_AuthPermission `json:"authGroups,omitempty"`
	Capabilities []Capability                        `json:"capabilities,omitempty"`
}
