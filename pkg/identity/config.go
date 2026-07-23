package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
)

type PollConfig struct {
	IntervalSeconds int `json:"intervalSeconds"`
	TimeoutSeconds  int `json:"timeoutSeconds"`
}

type WalletsConfig struct {
	Owner    string   `json:"owner"`
	Admin    string   `json:"admin"`
	Agent    string   `json:"agent"`
	NewOwner string   `json:"newOwner"`
	Recovery []string `json:"recovery"`
}

type EntityConfig struct {
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type RecoveryConfig struct {
	Threshold int `json:"threshold"`
}

type AccessListConfig struct {
	Operation     string `json:"operation"`
	TargetAddress string `json:"targetAddress"`
}

// CredentialsScenarioConfig gates the optional Verifiable Credential phase.
type CredentialsScenarioConfig struct {
	Enabled bool `json:"enabled"`
}

type Config struct {
	NodeEndpoints      []string                  `json:"nodeEndpoints"`
	InsecureSkipVerify bool                      `json:"insecureSkipVerify"`
	BlockchainId       string                    `json:"blockchainId"`
	Passphrase         string                    `json:"passphrase"`
	OutputDir          string                    `json:"outputDir"`
	Poll               PollConfig                `json:"poll"`
	Wallets            WalletsConfig             `json:"wallets"`
	Entity             EntityConfig              `json:"entity"`
	Child              EntityConfig              `json:"child"`
	AlterMetadata      map[string]string         `json:"alterMetadata"`
	Recovery           RecoveryConfig            `json:"recovery"`
	AccessList         AccessListConfig          `json:"accessList"`
	Audience           string                    `json:"audience"`
	ChainKeyType       string                    `json:"chainKeyType"`
	Credentials        CredentialsScenarioConfig `json:"credentials,omitempty"`
}

// ChainKeyTypeValue parses ChainKeyType to a crypto.KeyType, defaulting to
// secp256k1 — the key type the offline proof verifier checks block signatures with.
func (c Config) ChainKeyTypeValue() crypto.KeyType {
	return crypto.ParseCryptoKeyType(c.ChainKeyType)
}

// Load reads and parses a config file and applies defaults.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("parsing config: %w", err)
	}
	if c.Poll.IntervalSeconds <= 0 {
		c.Poll.IntervalSeconds = 1
	}
	if c.Poll.TimeoutSeconds <= 0 {
		c.Poll.TimeoutSeconds = 30
	}
	if c.OutputDir == "" {
		c.OutputDir = "."
	}
	if c.Audience == "" {
		c.Audience = "uledger-demo-verifier"
	}
	if c.ChainKeyType == "" {
		c.ChainKeyType = "secp256k1"
	}
	return c, nil
}

func (c Config) Validate() error {
	if len(c.NodeEndpoints) == 0 {
		return fmt.Errorf("at least one nodeEndpoint is required")
	}
	if c.BlockchainId == "" {
		return fmt.Errorf("blockchainId is required")
	}
	if c.Wallets.Owner == "" {
		return fmt.Errorf("wallets.owner is required")
	}
	if c.Wallets.Admin == "" {
		return fmt.Errorf("wallets.admin is required")
	}
	if c.Wallets.Agent == "" {
		return fmt.Errorf("wallets.agent is required")
	}
	if c.Wallets.NewOwner == "" {
		return fmt.Errorf("wallets.newOwner is required")
	}
	if len(c.Wallets.Recovery) == 0 {
		return fmt.Errorf("at least one recovery wallet is required")
	}
	if c.Recovery.Threshold <= 0 || c.Recovery.Threshold > len(c.Wallets.Recovery) {
		return fmt.Errorf("recovery.threshold must be between 1 and %d", len(c.Wallets.Recovery))
	}
	if !validEntityType(c.Entity.Type) {
		return fmt.Errorf("invalid entity.type: %s", c.Entity.Type)
	}
	if !validEntityType(c.Child.Type) {
		return fmt.Errorf("invalid child.type: %s", c.Child.Type)
	}
	if !transaction.ValidateEntityName(c.Entity.Name) {
		return fmt.Errorf("invalid entity.name %q: must be 3-64 chars, lowercase alphanumerics and hyphens, no spaces", c.Entity.Name)
	}
	if !transaction.ValidateEntityName(c.Child.Name) {
		return fmt.Errorf("invalid child.name %q: must be 3-64 chars, lowercase alphanumerics and hyphens, no spaces", c.Child.Name)
	}
	if _, ok := transaction.ParseAccessListOperation(c.AccessList.Operation); !ok {
		return fmt.Errorf("invalid accessList.operation: %s", c.AccessList.Operation)
	}
	if !validChainKeyType(c.ChainKeyType) {
		return fmt.Errorf("invalid chainKeyType: %s", c.ChainKeyType)
	}
	return nil
}

func validChainKeyType(t string) bool {
	if t == "" {
		return true
	}
	switch strings.ToLower(t) {
	case crypto.KeyTypeSecp256k1.String(), crypto.KeyTypeED25519.String(),
		crypto.KeyTypeBLS12377.String(), crypto.KeyTypeMlDSA87.String():
		return true
	default:
		return false
	}
}

func validEntityType(t string) bool {
	switch transaction.EntityType(t) {
	case transaction.EntityTypeOrganization, transaction.EntityTypeDepartment,
		transaction.EntityTypePersonal, transaction.EntityTypeService,
		transaction.EntityTypeDevice, transaction.EntityTypeAgent:
		return true
	default:
		return false
	}
}
