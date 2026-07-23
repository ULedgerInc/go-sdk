package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ULedgerInc/go-sdk/pkg/identity"
	"github.com/urfave/cli/v3"
)

func main() {
	configPath := ""

	cmd := &cli.Command{
		Name:                  "identity",
		Usage:                 "Run the ULedger identity-services lifecycle end-to-end",
		EnableShellCompletion: true,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			// Real work happens in After so a populated flag does not trigger the help menu.
			return nil
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "config",
				Aliases:  []string{"c"},
				Usage:    "Path to the identity run config JSON",
				Required: true,
				Action: func(ctx context.Context, cmd *cli.Command, s string) error {
					if s == "" {
						return fmt.Errorf("config path cannot be empty")
					}
					configPath = s
					return nil
				},
			},
		},
		After: func(ctx context.Context, cmd *cli.Command) error {
			if configPath == "" {
				return nil
			}
			cfg, err := identity.Load(configPath)
			if err != nil {
				return err
			}
			runner, err := identity.NewRunner(cfg)
			if err != nil {
				return err
			}
			report, runErr := runner.Run()
			if path, saveErr := report.Save(cfg.OutputDir); saveErr != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to save report: %v\n", saveErr)
			} else {
				fmt.Printf("Report saved to %s\n", path)
			}
			identity.PrintSummary(os.Stdout, report)
			return runErr
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
