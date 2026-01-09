package main

import (
	"fmt"
	"os"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

func main() {
	privateKeyHex := "46871FC92D83F41BEC1BE9C820BEBAF1DF906CDA4E11A5E66784B09C3C6B1F76"
	// Uncompressed public key
	publicKeyHex := "042D14822C75648ACCC0E44BAE5312D11000351A302AE047A2D0B55984F6D9D392178B12427749ACB67E3A15F4C0EBDD23BE7DBCFAC82826A5FD3055F81B4ACC82"
	wallet, err := wallet.GetWalletFromHex(publicKeyHex, privateKeyHex, crypto.KeyTypeSecp256k1)
	if err != nil {
		fmt.Printf("GetWalletFromPrivateKey() error = %v", err)
		return
	}

	// Read the contract source code from the file
	contractSourceCode, err := os.ReadFile("./contract.wat")
	if err != nil {
		fmt.Printf("os.ReadFile() error = %v", err)
		return
	}

	// Convert the contract source code to a string
	contractSourceCodeString := string(contractSourceCode)

	nodeEndpoint := os.Args[1] // "https://node.testnet.uledger.com"
	blockchainId := os.Args[2] // "Testnet"

	input := transaction.ULTransactionInput{
		Payload:      contractSourceCodeString,
		From:         wallet.Address,
		BlockchainId: blockchainId,
		PayloadType:  transaction.DEPLOY_SMART_CONTRACT.String(),
	}

	session, err := transaction.NewUL_TransactionSession(nodeEndpoint, wallet)
	if err != nil {
		fmt.Printf("NewUL_TransactionSession() error = %v\n", err)
		return
	}

	transaction, err := session.GenerateTransaction(input)
	if err != nil {
		fmt.Printf("GenerateTransaction() error = %v\n", err)
		return
	}

	if transaction.TransactionId == "" {
		fmt.Printf("GenerateTransaction() returned empty transaction id\n")
		return
	}

	fmt.Printf("Contract Address: %+v\n", transaction.TransactionId)
}
