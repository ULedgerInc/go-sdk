package main

import (
	"encoding/json"
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
	operation := os.Args[3]    // "upgrade" or "rollback"
	contractAddress := os.Args[4]

	if contractAddress == "" {
		fmt.Printf("contract address cannot be empty")
		return
	}

	var payloadBytes []byte
	var payloadType string

	if operation == "upgrade" {
		payloadBytes, err = getUpgradePayloadBytes(contractSourceCodeString)
		payloadType = transaction.UPGRADE_SMART_CONTRACT.String()
		if err != nil {
			fmt.Printf("getUpgradePayloadBytes() error = %v", err)
			return
		}
	} else if operation == "rollback" {
		payloadBytes, err = getRollbackPayloadBytes(1)
		payloadType = transaction.ROLLBACK_SMART_CONTRACT.String()
		if err != nil {
			fmt.Printf("getRollbackPayloadBytes() error = %v", err)
			return
		}
	}

	input := transaction.ULTransactionInput{
		Payload:      string(payloadBytes),
		From:         wallet.Address,
		BlockchainId: blockchainId,
		PayloadType:  payloadType,
		To:           contractAddress,
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

	fmt.Printf("Transaction Id: %+v\n", transaction.TransactionId)
}

func getUpgradePayloadBytes(contractSourceCodeString string) ([]byte, error) {
	payload := transaction.UpgradeContractPayload{
		NewSourceCode: contractSourceCodeString,
		UpgradeReason: "Upgrade contract to support emit event on transfer",
	}

	return json.Marshal(payload)
}

func getRollbackPayloadBytes(targetVersion uint64) ([]byte, error) {
	payload := transaction.RollbackContractPayload{
		TargetVersion:  targetVersion,
		RollbackReason: "Rollback contract for testing purposes",
	}

	return json.Marshal(payload)
}
