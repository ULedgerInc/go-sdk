package transaction

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

// WalletPossessionSigningBytes must stay byte-identical to the node's
// function of the same name.
func WalletPossessionSigningBytes(blockchainId, parent, publicKey string, keyType crypto.KeyType) []byte {
	buf := bytes.Buffer{}
	buf.WriteString("ULWALLETPOP")
	for _, field := range []string{blockchainId, parent, strings.ToLower(publicKey), keyType.String()} {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(field)))
		buf.WriteByte('|')
		buf.Write(lenBuf[:])
		buf.WriteByte('|')
		buf.WriteString(field)
	}
	return buf.Bytes()
}

func ProveWalletPossession(w *wallet.UL_Wallet, blockchainId, parent string) (string, error) {
	key := w.GetKey()
	sig, err := key.SignWithContext(crypto.DomainWalletPossession, WalletPossessionSigningBytes(blockchainId, parent, key.GetPublicKeyHex(false), key.GetType()))
	if err != nil {
		return "", fmt.Errorf("signing proof of possession: %w", err)
	}
	return hex.EncodeToString(sig), nil
}
