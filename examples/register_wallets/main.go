package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ULedgerInc/golang-sdk/pkg/crypto"
	"github.com/ULedgerInc/golang-sdk/pkg/transaction"
	"github.com/ULedgerInc/golang-sdk/pkg/wallet"
	"github.com/urfave/cli/v3"
)

func main() {
	nodeAddress := ""
	input := ""
	blockchainId := ""
	password := ""

	command := &cli.Command{
		Name:                  "Generate Wallet",
		Usage:                 "Generate one or more new wallets and save them to files",
		EnableShellCompletion: true,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			// Prevent help menu from being shown be default even when flags are present that are not the help flag
			return nil
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "node",
				Aliases:  []string{"n"},
				Usage:    "The node endpoint address",
				Required: true,
				Action: func(ctx context.Context, cmd *cli.Command, str string) error {
					if str == "" {
						return fmt.Errorf("node address cannot be empty")
					}
					nodeAddress = str
					return nil
				},
			},
			&cli.StringFlag{
				Name:        "input",
				Aliases:     []string{"i"},
				Usage:       "The path to the folder containing the wallets, or the json string of a single wallet",
				Value:       "./wallets",
				DefaultText: "./wallets",
				Action: func(ctx context.Context, cmd *cli.Command, str string) error {
					if str == "" {
						return fmt.Errorf("input cannot be empty")
					}
					input = str
					return nil
				},
			},
			&cli.StringFlag{
				Name:        "password",
				Aliases:     []string{"p"},
				Usage:       "The password to decrypt the wallets",
				Value:       "",
				DefaultText: "",
				Action: func(ctx context.Context, cmd *cli.Command, str string) error {
					password = str
					return nil
				},
			},
			&cli.StringFlag{
				Name:        "blockchain",
				Aliases:     []string{"b"},
				Usage:       "The blockchain to register the wallet to",
				DefaultText: "",
				Required:    true,
				Action: func(ctx context.Context, cmd *cli.Command, str string) error {
					if str == "" {
						return fmt.Errorf("blockchain ID cannot be empty")
					}
					blockchainId = str
					return nil
				},
			},
		},
		After: func(ctx context.Context, cmd *cli.Command) error {
			rawWallets := make([]string, 0)

			// Determine if input is a folder or a json string
			if strings.Contains(input, "{") && strings.Contains(input, "}") {
				rawWallets = append(rawWallets, input)
			} else {
				allWallets := false
				// Parse if this is getting all of the wallets or a specific one
				dot := strings.LastIndex(input, ".")
				if dot > 0 {
					// Get the character before the dot, if its a * then we are getting all wallets
					if input[dot-1] == '*' {
						allWallets = true
						input = input[:dot-1] // Remove the *.json from the input
					}
				}
				if allWallets {
					// Get the number of files in the folder
					files, err := os.ReadDir(input)
					if err != nil {
						return fmt.Errorf("error reading folder: %w", err)
					}
					if len(files) == 0 {
						return fmt.Errorf("no files found in the specified folder")
					}
					for _, file := range files {
						if file.IsDir() {
							continue // Skip directories
						}
						content, err := os.ReadFile(filepath.Join(input, file.Name()))
						if err != nil {
							panic("Error reading file: " + err.Error())
						}
						rawWallets = append(rawWallets, string(content))
					}
				} else {
					// Just get the single wallet file
					content, err := os.ReadFile(input)
					if err != nil {
						return fmt.Errorf("error reading wallet file: %w", err)
					}
					rawWallets = append(rawWallets, string(content))
				}
			}
			if len(rawWallets) == 0 {
				return fmt.Errorf("no wallets found in the specified input")
			}

			for _, rawWallet := range rawWallets {
				// Parse the w
				w, err := wallet.FromJson(rawWallet, password)
				if err != nil {
					panic(fmt.Sprintf("Error parsing wallet from JSON: %s\n", err))
				}
				fmt.Printf("Parsed wallet: %+v\n", w)

				type UL_CreateWalletPaylod struct {
					PublicKey  string                              `json:"publicKey"`
					Parent     string                              `json:"parent"`
					KeyType    crypto.KeyType                      `json:"keyType"`
					AuthGroups map[string]wallet.UL_AuthPermission `json:"authGroups,omitempty"`
				}

				payload, err := json.Marshal(UL_CreateWalletPaylod{
					PublicKey:  w.GetKey().GetPublicKeyHex(false),
					Parent:     w.Parent,
					KeyType:    w.GetKey().GetType(),
					AuthGroups: w.AuthGroups,
				})
				if err != nil {
					return fmt.Errorf("error marshalling payload: %w", err)
				}

				input := transaction.ULTransactionInput{
					Payload: string(payload),
					// This would be where wallet create delegation is implemented
					From:         w.Parent,  // Parent is the author of the new wallet
					To:           w.Address, // To address is always self
					BlockchainId: blockchainId,
					PayloadType:  transaction.TX_CREATE_WALLET.String(),
				}

				session, err := transaction.NewUL_TransactionSession(nodeAddress, *w)
				if err != nil {
					return fmt.Errorf("error creating transaction session: %w", err)
				}

				transaction, err := session.GenerateTransaction(input)
				if err != nil {
					return fmt.Errorf("error generating transaction: %w", err)
				}

				if transaction.TransactionId == "" {
					return fmt.Errorf("empty transaction id")
				}

				fmt.Printf("Transaction: %+v\n", transaction)
			}

			// Prevent help menu from being shown be default even when flags are present that are not the help flag
			return nil
		},
	}

	err := command.Run(context.Background(), os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
