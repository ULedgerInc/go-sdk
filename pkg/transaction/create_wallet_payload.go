package transaction

import (
	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

// CreateWalletPayload is the payload of a CREATE_WALLET transaction. PublicKey
// is the uncompressed hex form, and Parent must match the transaction's From.
type CreateWalletPayload struct {
	PublicKey         string                              `json:"publicKey"`
	Parent            string                              `json:"parent"`
	KeyType           crypto.KeyType                      `json:"keyType"`
	AuthGroups        map[string]wallet.UL_AuthPermission `json:"authGroups,omitempty"`
	Capabilities      []Capability                        `json:"capabilities,omitempty"`
	ProofOfPossession string                              `json:"proofOfPossession,omitempty"`
}
