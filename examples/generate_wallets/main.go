package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ULedgerInc/golang-sdk/pkg/crypto"
	"github.com/ULedgerInc/golang-sdk/pkg/wallet"
	"github.com/urfave/cli/v3"
)

func getKeyType(keyTypeStr string) (crypto.KeyType, error) {
	switch keyTypeStr {
	case "secp256k1":
		return crypto.KeyTypeSecp256k1, nil
	case "mldsa87":
		return crypto.KeyTypeMlDSA87, nil
	case "ed25519":
		return crypto.KeyTypeED25519, nil
	case "bls12377":
		return crypto.KeyTypeBLS12377, nil
	default:
		return 0, fmt.Errorf("invalid key type: %s", keyTypeStr)
	}
}

func sanitizeString(input string) string {
	if len(input) >= 2 && input[0] == '\'' && input[len(input)-1] == '\'' {
		return input[1 : len(input)-1]
	}
	return input
}

func main() {
	outputDir := ""
	parentAddress := ""
	password := ""
	outputCount := 1
	keyType := crypto.KeyTypeSecp256k1
	entropy := wallet.MakeEntropy(256)
	auth := make(map[string]wallet.UL_AuthPermission, 0)

	// CLI app for generating wallets
	app := &cli.Command{
		Name:                  "Generate Wallet",
		Usage:                 "Generate one or more new wallets and save them to files",
		EnableShellCompletion: true,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			// Prevent help menu from being shown be default even when flags are present that are not the help flag
			return nil
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "output",
				Aliases:     []string{"o"},
				Usage:       "Output directory for wallet file(s)",
				Value:       "",
				DefaultText: "",
				Action: func(ctx context.Context, cmd *cli.Command, str string) error {
					// Trim any single quotes from the string
					str = sanitizeString(str)
					outputDir = str
					return nil
				},
			},
			&cli.IntFlag{
				Name:    "count",
				Aliases: []string{"n"},
				Usage:   "Number of wallets to generate",
				Value:   1,
				Action: func(ctx context.Context, cmd *cli.Command, n int) error {
					outputCount = n
					return nil
				},
			},
			&cli.StringFlag{
				Name:        "keyType",
				Aliases:     []string{"k"},
				Usage:       "Key type (secp256k1, mldsa87, ed25519, bls12377)",
				Value:       "secp256k1",
				DefaultText: "secp256k1",
				Action: func(ctx context.Context, cmd *cli.Command, str string) error {
					var err error
					keyType, err = getKeyType(str)
					return err
				},
			},
			&cli.StringFlag{
				Name:        "parent",
				Aliases:     []string{"p"},
				Usage:       "Parent wallet address (optional, for child wallets)",
				Value:       "",
				DefaultText: "",
				Action: func(ctx context.Context, cmd *cli.Command, s string) error {
					parentAddress = s
					return nil
				},
			},
			&cli.IntFlag{
				Name:        "entropy",
				Aliases:     []string{"e"},
				Usage:       "Entropy size in bits (128, 160, 192, 224, 256)",
				Value:       256,
				DefaultText: "256",
				Action: func(ctx context.Context, cmd *cli.Command, i int) error {
					entropy = wallet.MakeEntropy(i)
					return nil
				},
			},
			&cli.StringFlag{
				Name:        "password",
				Aliases:     []string{"w"},
				Usage:       "Password to protect the wallet(s)",
				Value:       "myPassword",
				DefaultText: "myPassword",
				Action: func(ctx context.Context, cmd *cli.Command, s string) error {
					s = sanitizeString(s)
					password = s
					return nil
				},
			},
			&cli.StringFlag{
				Name:        "auth",
				Aliases:     []string{"a"},
				Usage:       "Custom auth groups in JSON format (optional)",
				Value:       "",
				DefaultText: "",
				Action: func(ctx context.Context, cmd *cli.Command, s string) error {
					s = sanitizeString(s)
					if s != "" {
						err := json.Unmarshal([]byte(s), &auth)
						if err != nil {
							return fmt.Errorf("error parsing custom auth groups: %w", err)
						}
					}
					return nil
				},
			},
		},
		After: func(ctx context.Context, cmd *cli.Command) error {
			// Create output directory if it doesn't exist
			if outputDir != "" {
				outputDir = filepath.Clean(outputDir)
				outputDir, err := filepath.Abs(outputDir)
				if err != nil {
					return fmt.Errorf("error getting absolute path of output directory: %w", err)
				}
				err = os.MkdirAll(outputDir, 0755)
				if err != nil {
					return fmt.Errorf("error creating output directory: %w", err)
				}
			}

			// Generate wallets
			for i := 0; i < outputCount; i++ {
				myWallet, mnemonic, err := wallet.GenerateNewWallet(password, keyType, parentAddress, auth, entropy)
				if err != nil {
					return fmt.Errorf("error generating wallet: %w", err)
				}

				if outputDir != "" {
					// Save wallet using address as filename
					outputPath := filepath.Join(outputDir, myWallet.Address+".ukey")
					err = myWallet.SaveToFile(outputPath, mnemonic, true)
					if err != nil {
						return fmt.Errorf("error saving wallet to file: %w", err)
					}
				}

				// Print wallet details to console as json
				walletData := wallet.WalletData{
					Address:       myWallet.Address,
					Enabled:       myWallet.Enabled,
					Parent:        myWallet.Parent,
					AuthGroups:    myWallet.AuthGroups,
					Mnemonic:      mnemonic,
					KeyType:       myWallet.GetKey().GetType(),
					PublicKeyHex:  myWallet.GetKey().GetPublicKeyHex(false), // Uncompressed
					PrivateKeyHex: myWallet.GetKey().GetPrivateKeyHex(),
				}
				walletJSON, err := json.Marshal(walletData)
				if err != nil {
					return fmt.Errorf("error marshaling wallet to JSON: %w", err)
				}
				escapedJson := string(walletJSON)
				escapedJson = strings.ReplaceAll(escapedJson, "\"", "\\\"")
				// This has to be the only thing that prints here as commands like xargs rely on it
				fmt.Printf("%s\n", escapedJson)
			}
			return nil
		},
	}

	ctx := context.Background()
	err := app.Run(ctx, os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
