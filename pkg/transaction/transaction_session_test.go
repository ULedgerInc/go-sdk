package transaction

import (
	"fmt"
	"testing"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

func TestNewTransactionSession(t *testing.T) {
	privateKeyHex := "63f6062f2034bcbcc08bae2eaabee8dd780d352cd76c595dce3a631ce8877934"
	publicKeyHex := "04f2f0fd15ba3a7f4ba62cd705c4df8094917e7e85cab345beaf0b378f84a3422ced9a9cf925c05ded76c63ab677207287a5b64b2fb683803abef934259fa37c5d"
	wallet, err := wallet.GetWalletFromHex(publicKeyHex, privateKeyHex, crypto.KeyTypeSecp256k1)
	if err != nil {
		t.Errorf("GetWalletFromPrivateKey() error = %v", err)
	}

	input := ULTransactionInput{
		Payload:      "test",
		From:         wallet.Address,
		To:           wallet.Address,
		BlockchainId: "MyBlockchain1",
		PayloadType:  TX_DATA.String(),
	}

	// Make sure the node is running!
	testNodeEndpoint := "http://localhost:8080"

	transactionSession, err := NewUL_TransactionSession(testNodeEndpoint, wallet)
	if err != nil {
		t.Errorf("NewUL_TransactionSession() error = %v", err)
		return
	}

	transaction, err := transactionSession.GenerateTransaction(input)
	if err != nil {
		t.Errorf("GenerateTransaction() error = %v", err)
	}

	if transaction.TransactionId == "" {
		t.Error("GenerateTransaction() returned empty transaction id")
	}

	fmt.Printf("Transaction: %+v\n", transaction)
}
