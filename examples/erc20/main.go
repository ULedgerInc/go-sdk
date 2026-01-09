package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ULedgerInc/golang-sdk/pkg/crypto"
	"github.com/ULedgerInc/golang-sdk/pkg/transaction"
	"github.com/ULedgerInc/golang-sdk/pkg/wallet"
)

func main() {
	nodeEndpoint := os.Args[1] // "https://node.testnet.uledger.com"
	blockchainId := os.Args[2] // "Testnet"
	operation := os.Args[3]    // "create", "transfer", "approve", "mint", "burn", "transfer_approval"
	tokenAddress := ""         // "0x1234567890123456789012345678901234567890"

	privateKeyHex := "46871FC92D83F41BEC1BE9C820BEBAF1DF906CDA4E11A5E66784B09C3C6B1F76"
	// Uncompressed public key
	publicKeyHex := "042D14822C75648ACCC0E44BAE5312D11000351A302AE047A2D0B55984F6D9D392178B12427749ACB67E3A15F4C0EBDD23BE7DBCFAC82826A5FD3055F81B4ACC82"
	firstWallet, err := wallet.GetWalletFromHex(publicKeyHex, privateKeyHex, crypto.KeyTypeSecp256k1)
	if err != nil {
		fmt.Printf("GetWalletFromPrivateKey() error = %v", err)
		return
	}

	privateKeyHex2 := "8511885EE2FFBACE539EA454C5C1FEC54F04EE57F8820F910E9AE842C7F71972"
	publicKeyHex2 := "04CB435FDF7D9AE78F4D6A6CCE3CC4AB9E21B8577EFAE2DD628D4093230010FF3394D9D3F14E8665D927ABB93E09835AD4A1565446A4F173CC03061D0467C469A3"

	secondWallet, err := wallet.GetWalletFromHex(publicKeyHex2, privateKeyHex2, crypto.KeyTypeSecp256k1)
	if err != nil {
		fmt.Printf("GetWalletFromPrivateKey() error = %v", err)
		return
	}

	sourceWallet := firstWallet
	destinationWallet := secondWallet

	amount := uint64(5000)

	input := transaction.ULTransactionInput{
		From:         sourceWallet.Address,
		BlockchainId: blockchainId,
	}

	switch operation {
	case "create":
		payloadBytes, err := createERC20Token()
		if err != nil {
			fmt.Printf("createERC20Token() error = %v", err)
			return
		}
		input.Payload = string(payloadBytes)
		input.PayloadType = transaction.CREATE_TOKEN.String()

	case "transfer":
		tokenAddress = os.Args[4]
		payloadBytes, err := transferERC20Token(tokenAddress, destinationWallet.Address, amount)
		if err != nil {
			fmt.Printf("transferERC20Token() error = %v", err)
			return
		}
		input.Payload = string(payloadBytes)
		input.PayloadType = transaction.TRANSFER_TOKEN.String()

	case "burn":
		tokenAddress = os.Args[4]
		payloadBytes, err := burnERC20Token(tokenAddress, amount)
		if err != nil {
			fmt.Printf("burnERC20Token() error = %v", err)
			return
		}
		input.Payload = string(payloadBytes)
		input.PayloadType = transaction.BURN_TOKEN.String()

	case "approve":
		tokenAddress = os.Args[4]
		payloadBytes, err := approveERC20Token(tokenAddress, destinationWallet.Address, amount)
		if err != nil {
			fmt.Printf("approveERC20Token() error = %v", err)
			return
		}
		input.Payload = string(payloadBytes)
		input.PayloadType = transaction.APPROVE_TOKEN.String()

	case "transfer_approval":
		// Transfer on behalf of another wallet or account
		tokenAddress = os.Args[4]
		transferAmount := uint64(2000)
		// The two wallets are:
		sourceWallet = secondWallet // The first transaction with the allowance is coming from the first wallet
		destinationWallet = firstWallet
		// Not the destination or the source wallet
		thirdWalletAddress := "0aa5890b691d2676627874ec20f57882c735e07c86efe64ebab86c46cf9dc53f"
		// It will transfer the tokens from the destination wallet to the third wallet using the allowance from the source wallet
		payloadBytes, err := transferApprovalERC20Token(tokenAddress, thirdWalletAddress, destinationWallet.Address, transferAmount)
		if err != nil {
			fmt.Printf("transferApprovalERC20Token() error = %v", err)
			return
		}
		input.From = sourceWallet.Address
		input.Payload = string(payloadBytes)
		input.PayloadType = transaction.TRANSFER_TOKEN.String()
	}

	session, err := transaction.NewUL_TransactionSession(nodeEndpoint, sourceWallet)
	if err != nil {
		fmt.Printf("NewUL_TransactionSession() error = %v\n", err)
		return
	}

	transaction, err := session.GenerateTransaction(input)
	if err != nil {
		fmt.Printf("GenerateTransaction() error = %v\n", err)
		return
	}

	switch operation {
	case "create":
		fmt.Printf("Transaction Created for ERC20 Token with token address: %s \n %+v\n", transaction.TransactionId, transaction)
	case "transfer":
		fmt.Printf("Transfer ERC20 Token Created for ERC20 Token with transaction id: %s \n %+v\n", transaction.TransactionId, transaction)
	case "burn":
		fmt.Printf("Burn ERC20 Token Created for ERC20 Token with transaction id: %s \n %+v\n", transaction.TransactionId, transaction)
	case "approve":
		fmt.Printf("Approve ERC20 Token Created for ERC20 Token with transaction id: %s \n %+v\n", transaction.TransactionId, transaction)
	case "transfer_approval":
		fmt.Printf("Transfer Approval ERC20 Token Created for ERC20 Token with transaction id: %s \n %+v\n", transaction.TransactionId, transaction)
	}
}

func createERC20Token() ([]byte, error) {
	payloadBytes, err := json.Marshal(transaction.CreateTokenPayload{
		TokenType:     transaction.ERC20_TOKEN_TYPE,
		Name:          "ULedger Token Test",
		Symbol:        "ULTT",
		Decimals:      18,
		InitialSupply: 1000000000000000000,
		Mintable:      true,
		Burnable:      true,
	})
	if err != nil {
		return nil, err
	}
	return payloadBytes, nil
}

func transferERC20Token(tokenAddress string, to string, amount uint64) ([]byte, error) {
	payloadBytes, err := json.Marshal(transaction.TransferTokenPayload{
		TokenAddress: tokenAddress,
		To:           to,
		Amount:       amount,
	})
	if err != nil {
		return nil, err
	}
	return payloadBytes, nil
}

func burnERC20Token(tokenAddress string, tokenId uint64) ([]byte, error) {
	payloadBytes, err := json.Marshal(transaction.BurnTokenPayload{
		TokenAddress: tokenAddress,
		TokenId:      tokenId,
	})
	if err != nil {
		return nil, err
	}
	return payloadBytes, nil
}

func approveERC20Token(tokenAddress string, to string, amount uint64) ([]byte, error) {
	payloadBytes, err := json.Marshal(transaction.ApproveTokenPayload{
		TokenAddress: tokenAddress,
		Spender:      to,
		Amount:       amount,
	})
	if err != nil {
		return nil, err
	}
	return payloadBytes, nil
}

func transferApprovalERC20Token(tokenAddress string, to string, from string, amount uint64) ([]byte, error) {
	payloadBytes, err := json.Marshal(transaction.TransferTokenPayload{
		TokenAddress: tokenAddress,
		To:           to,
		Amount:       amount,
		From:         from,
	})
	if err != nil {
		return nil, err
	}
	return payloadBytes, nil
}
