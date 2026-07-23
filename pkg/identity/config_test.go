package identity

import (
	"os"
	"testing"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
)

func validConfig() Config {
	return Config{
		NodeEndpoints: []string{"http://localhost:8090"},
		BlockchainId:  "test-chain",
		Wallets: WalletsConfig{
			Owner:    "owner.ukey",
			Admin:    "admin.ukey",
			Agent:    "agent.ukey",
			NewOwner: "new.ukey",
			Recovery: []string{"r1.ukey", "r2.ukey", "r3.ukey"},
		},
		Entity:     EntityConfig{Name: "test-org", Type: "ORGANIZATION"},
		Child:      EntityConfig{Name: "test-agent", Type: "AGENT"},
		Recovery:   RecoveryConfig{Threshold: 2},
		AccessList: AccessListConfig{Operation: "ADD_TRUSTED"},
	}
}

func TestValidate_OK(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}
}

func TestValidate_MissingOwner(t *testing.T) {
	c := validConfig()
	c.Wallets.Owner = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing owner")
	}
}

func TestValidate_MissingAgent(t *testing.T) {
	c := validConfig()
	c.Wallets.Agent = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing agent")
	}
}

func TestValidate_BadThreshold(t *testing.T) {
	c := validConfig()
	c.Recovery.Threshold = 4 // only 3 recovery wallets
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for threshold > recovery count")
	}
}

func TestValidate_BadEntityType(t *testing.T) {
	c := validConfig()
	c.Entity.Type = "NOPE"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for invalid entity type")
	}
}

func TestValidate_BadAccessListOp(t *testing.T) {
	c := validConfig()
	c.AccessList.Operation = "NONSENSE"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for invalid access list operation")
	}
}

func TestValidate_BadEntityName(t *testing.T) {
	// Internal space is rejected (the node would silently drop it on-chain).
	c := validConfig()
	c.Entity.Name = "Acme Org"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for entity name with a space")
	}
}

func TestValidate_BadChildName(t *testing.T) {
	c := validConfig()
	c.Child.Name = "ab" // too short (min 3)
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for too-short child name")
	}
}

func TestValidate_EmptyChainKeyTypeOK(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("expected empty chainKeyType to be valid (defaulted at Load), got: %v", err)
	}
}

func TestValidate_BadChainKeyType(t *testing.T) {
	c := validConfig()
	c.ChainKeyType = "rsa2048"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for invalid chainKeyType")
	}
}

func TestValidate_ChainKeyTypeCaseInsensitive(t *testing.T) {
	c := validConfig()
	c.ChainKeyType = "ED25519"
	if err := c.Validate(); err != nil {
		t.Fatalf("expected case-insensitive chainKeyType to be valid, got: %v", err)
	}
}

func TestLoad_DefaultsAudienceAndChainKeyType(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.json"
	data := []byte(`{
		"nodeEndpoints": ["http://localhost:8090"],
		"blockchainId": "test-chain",
		"wallets": {
			"owner": "owner.ukey", "admin": "admin.ukey", "agent": "agent.ukey",
			"newOwner": "new.ukey", "recovery": ["r1.ukey", "r2.ukey"]
		},
		"entity": {"name": "test-org", "type": "ORGANIZATION"},
		"child": {"name": "test-agent", "type": "AGENT"},
		"recovery": {"threshold": 1},
		"accessList": {"operation": "ADD_TRUSTED"}
	}`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audience != "uledger-demo-verifier" {
		t.Fatalf("expected default audience, got %q", cfg.Audience)
	}
	if cfg.ChainKeyType != "secp256k1" {
		t.Fatalf("expected default chainKeyType, got %q", cfg.ChainKeyType)
	}
}

func TestLoad_PreservesExplicitAudienceAndChainKeyType(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.json"
	data := []byte(`{
		"nodeEndpoints": ["http://localhost:8090"],
		"blockchainId": "test-chain",
		"audience": "my-verifier",
		"chainKeyType": "ed25519",
		"wallets": {
			"owner": "owner.ukey", "admin": "admin.ukey", "agent": "agent.ukey",
			"newOwner": "new.ukey", "recovery": ["r1.ukey", "r2.ukey"]
		},
		"entity": {"name": "test-org", "type": "ORGANIZATION"},
		"child": {"name": "test-agent", "type": "AGENT"},
		"recovery": {"threshold": 1},
		"accessList": {"operation": "ADD_TRUSTED"}
	}`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audience != "my-verifier" {
		t.Fatalf("expected explicit audience preserved, got %q", cfg.Audience)
	}
	if cfg.ChainKeyType != "ed25519" {
		t.Fatalf("expected explicit chainKeyType preserved, got %q", cfg.ChainKeyType)
	}
	if cfg.ChainKeyTypeValue() != crypto.KeyTypeED25519 {
		t.Fatalf("expected ChainKeyTypeValue() to parse to ED25519, got %v", cfg.ChainKeyTypeValue())
	}
}
