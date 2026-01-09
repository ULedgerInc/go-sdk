package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ULedgerInc/go-sdk/pkg/transaction"
	"github.com/ULedgerInc/go-sdk/pkg/utils"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
	"github.com/urfave/cli/v3"
)

func main() {
	nodeAddress := ""
	input := ""
	targetAddress := ""
	blockchainId := ""
	password := ""
	auth := make(map[string]wallet.UL_AuthPermission)
	enabled := true

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
			&cli.StringFlag{
				Name:        "target",
				Aliases:     []string{"t"},
				Usage:       "The target address to alter (if empty, will use the wallet's own address)",
				DefaultText: "",
				Required:    true,
				Action: func(ctx context.Context, cmd *cli.Command, str string) error {
					if str == "" {
						return fmt.Errorf("target address cannot be empty")
					}
					targetAddress = str
					return nil
				},
			},
			&cli.StringFlag{
				Name:    "auth",
				Aliases: []string{"a"},
				Usage:   "JSON string representing the auth groups and permissions",
				Value:   "{}",
				Action: func(ctx context.Context, cmd *cli.Command, str string) error {
					// Validate that the input is a valid JSON string
					err := json.Unmarshal([]byte(str), &auth)
					if err != nil {
						return fmt.Errorf("invalid JSON string for auth: %s", utils.HandleJsonError(err))
					}
					return nil
				},
			},
			&cli.BoolFlag{
				Name:    "enabled",
				Aliases: []string{"e"},
				Usage:   "Whether the wallet should be enabled or disabled.",
				Value:   true,
				Action: func(ctx context.Context, cmd *cli.Command, val bool) error {
					enabled = val
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
							return fmt.Errorf("error reading wallet file: %w", err)
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
				// Parse the wallet
				w, err := wallet.FromJson(rawWallet, password)
				if err != nil {
					panic(fmt.Sprintf("Error parsing wallet from JSON: %s\n", err))
				}

				type UL_AlterWalletPaylod struct {
					Target     string                              `json:"target"`
					Enabled    bool                                `json:"enabled"`
					AuthGroups map[string]wallet.UL_AuthPermission `json:"authGroups"`
				}

				payload, err := json.Marshal(UL_AlterWalletPaylod{
					Target:     targetAddress,
					Enabled:    enabled,
					AuthGroups: auth,
				})
				if err != nil {
					return fmt.Errorf("error marshalling payload: %w", err)
				}

				// empty to should use the wallet's own address as a self alter
				to := targetAddress
				if to == "" {
					to = w.Address
				}
				input := transaction.ULTransactionInput{
					Payload:      string(payload),
					From:         w.Address,
					To:           to,
					BlockchainId: blockchainId,
					PayloadType:  transaction.TX_ALTER_WALLET.String(),
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
					return fmt.Errorf("generated transaction has empty transaction ID")
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
