package identity

import (
	"encoding/json"
	"testing"

	"github.com/ULedgerInc/go-sdk/pkg/transaction"
)

func TestBuildCreateEntity_WithParent(t *testing.T) {
	s, err := buildCreateEntity("alice", transaction.EntityTypeAgent, "parent-addr", map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	var p transaction.CreateEntityPayload
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		t.Fatal(err)
	}
	if p.Name != "alice" || p.EntityType != transaction.EntityTypeAgent || p.Parent != "parent-addr" || p.Metadata["k"] != "v" {
		t.Fatalf("unexpected payload: %+v", p)
	}
}

func TestBuildConfigureRecovery(t *testing.T) {
	s, err := buildConfigureRecovery("e-addr", []string{"r1", "r2"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	var p transaction.ConfigureEntityRecoveryPayload
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		t.Fatal(err)
	}
	if p.EntityAddress != "e-addr" || p.Threshold != 2 || len(p.RecoveryWallets) != 2 {
		t.Fatalf("unexpected payload: %+v", p)
	}
}

func TestBuildApproveRecovery(t *testing.T) {
	s, err := buildApproveRecovery("req-1")
	if err != nil {
		t.Fatal(err)
	}
	var p transaction.ApproveEntityRecoveryPayload
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		t.Fatal(err)
	}
	if p.RequestId != "req-1" {
		t.Fatalf("unexpected payload: %+v", p)
	}
}

func TestBuildAuthenticateInternal(t *testing.T) {
	s, err := buildAuthenticateInternal("subj-addr", 42, "block-hash")
	if err != nil {
		t.Fatal(err)
	}
	var p transaction.AuthenticateInternalPayload
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		t.Fatal(err)
	}
	if p.Type != transaction.AUTHENTICATE_INTERNAL.String() {
		t.Fatalf("expected type AUTHENTICATE_INTERNAL, got %q", p.Type)
	}
	if p.Subject != "subj-addr" || p.ReferenceHeight != 42 || p.ReferenceBlockHash != "block-hash" {
		t.Fatalf("unexpected payload: %+v", p)
	}
}

func TestBuildAuthenticateExternal(t *testing.T) {
	s, err := buildAuthenticateExternal("subj-addr", "aud", "nonce-1", map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	var p transaction.AuthenticateExternalPayload
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		t.Fatal(err)
	}
	if p.Type != transaction.AUTHENTICATE_EXTERNAL.String() {
		t.Fatalf("expected type AUTHENTICATE_EXTERNAL, got %q", p.Type)
	}
	if p.Subject != "subj-addr" || p.Audience != "aud" || p.Nonce != "nonce-1" || p.Metadata["k"] != "v" {
		t.Fatalf("unexpected payload: %+v", p)
	}
}

func TestBuildDisableEntity(t *testing.T) {
	s, err := buildDisableEntity("entity-addr")
	if err != nil {
		t.Fatal(err)
	}
	var p transaction.AlterEntityPayload
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		t.Fatal(err)
	}
	if p.EntityAddress != "entity-addr" {
		t.Fatalf("unexpected entityAddress: %+v", p)
	}
	if p.Enabled == nil || *p.Enabled {
		t.Fatalf("expected enabled=false, got %+v", p.Enabled)
	}
	if p.Metadata != nil {
		t.Fatalf("expected no metadata, got %+v", p.Metadata)
	}
}

func TestBuildTransferEntity(t *testing.T) {
	s, err := buildTransferEntity("entity-addr", "new-owner-addr")
	if err != nil {
		t.Fatal(err)
	}
	var p transaction.TransferEntityPayload
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		t.Fatal(err)
	}
	if p.EntityAddress != "entity-addr" || p.NewOwner != "new-owner-addr" {
		t.Fatalf("unexpected payload: %+v", p)
	}
}

func TestRandomNonceHex(t *testing.T) {
	a, err := randomNonceHex(16)
	if err != nil {
		t.Fatal(err)
	}
	b, err := randomNonceHex(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 || len(b) != 32 {
		t.Fatalf("expected 32 hex chars for 16 bytes, got %d and %d", len(a), len(b))
	}
	if a == b {
		t.Fatal("expected two independent nonces to differ")
	}
}
