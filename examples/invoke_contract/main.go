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

	// Make sure the node is running!
	testNodeEndpoint := os.Args[1] // "https://node.testnet.uledger.com"
	blockchainId := os.Args[2]     // "Testnet"
	method := os.Args[3]           // "transfer" or "initialize"
	contractAddress := os.Args[4]
	if contractAddress == "" {
		fmt.Printf("contract address cannot be empty")
		return
	}
	var payloadBytes []byte

	if method == "transfer" {
		payloadBytes, err = getTransferPayloadBytes(1000, "c99d74279e6b5d17aa21fe99a1e9021a731ec9945c9eb294a9095529151759de")
	} else if method == "initialize" {
		payloadBytes, err = getInitializePayloadBytes()
	} else if method == "emit" {
		payloadBytes, err = getEmitPayloadBytes()
	} else if method == "log" {
		payloadBytes, err = getLogPayloadBytes()
	}

	if err != nil {
		fmt.Printf("getPayloadBytes() error = %v", err)
		return
	}

	input := transaction.ULTransactionInput{
		Payload:      string(payloadBytes),
		From:         wallet.Address,
		To:           contractAddress,
		BlockchainId: blockchainId,
		PayloadType:  transaction.INVOKE_SMART_CONTRACT.String(),
	}

	session, err := transaction.NewUL_TransactionSession(testNodeEndpoint, wallet)
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

	fmt.Printf("Transaction: %+v\n", transaction)
}

func getEmitPayloadBytes() ([]byte, error) {
	contractPayload := transaction.InvokeContractPayload{
		FunctionName: "emit",
		Args:         []transaction.ContractArgs{},
		GasLimit:     100000,
	}

	contractPayloadBytes, err := json.Marshal(contractPayload)
	if err != nil {
		fmt.Printf("Marshal() error = %v", err)
		return nil, err
	}

	return contractPayloadBytes, nil
}

func getLogPayloadBytes() ([]byte, error) {
	contractPayload := transaction.InvokeContractPayload{
		FunctionName: "log",
		Args:         []transaction.ContractArgs{},
		GasLimit:     100000,
	}

	contractPayloadBytes, err := json.Marshal(contractPayload)
	if err != nil {
		fmt.Printf("Marshal() error = %v", err)
		return nil, err
	}

	return contractPayloadBytes, nil
}

func getInitializePayloadBytes() ([]byte, error) {
	inititalSupply := int32(1000000)
	initialSupplyEncoded, err := transaction.Encode(inititalSupply)
	if err != nil {
		fmt.Printf("Encode() error = %v", err)
		return nil, err
	}

	initializeArgs := []transaction.ContractArgs{
		{
			Value: initialSupplyEncoded,
		},
	}

	contractPayload := transaction.InvokeContractPayload{
		FunctionName: "initialize",
		Args:         initializeArgs,
		GasLimit:     100000,
	}

	initializePayloadBytes, err := json.Marshal(contractPayload)
	if err != nil {
		fmt.Printf("Marshal() error = %v", err)
		return nil, err
	}

	return initializePayloadBytes, nil
}

func getTransferPayloadBytes(amount int32, address string) ([]byte, error) {
	// Transfer 100 tokens to the recipient address
	recipientAddressEncoded, err := transaction.Encode(address)
	if err != nil {
		fmt.Printf("Encode() error = %v", err)
		return nil, err
	}

	tokensToTransferEncoded, err := transaction.Encode(amount)
	if err != nil {
		fmt.Printf("Encode() error = %v", err)
		return nil, err
	}

	transferArgs := []transaction.ContractArgs{
		{
			Value: recipientAddressEncoded,
		},
		{
			Value: tokensToTransferEncoded,
		},
	}

	transferPayload := transaction.InvokeContractPayload{
		FunctionName: "transfer",
		Args:         transferArgs,
		GasLimit:     100000,
	}

	transferPayloadBytes, err := json.Marshal(transferPayload)
	if err != nil {
		fmt.Printf("Marshal() error = %v", err)
		return nil, err
	}

	return transferPayloadBytes, nil
}
