package identity

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

type fakeCall struct {
	signerAddr  string
	payloadType string
	payload     string
}

type fakeClient struct {
	calls             []fakeCall
	counter           int
	statusFor         func(txid string) string // returns Output; default SUCCESS
	submitErr         func(input transaction.ULTransactionInput) error
	txID              func(counter int) string // overrides the default "tx-%d" id format
	getTransactionErr func(txid string) error

	chainHead        ChainHead
	chainHeadErr     error
	resolveDID       func(did string) (transaction.DIDResolutionResult, error)
	resolveDIDChain  func(did string) ([]transaction.DIDResolutionResult, error)
	resolveDIDSigned func(did string) (transaction.SignedResolutionEnvelope, error)
	verifyClaim      func(claim transaction.IdentityClaim) (transaction.VerifyResult, error)
	txProof          func(blockchainId, txId string) (transaction.TxInclusionProofPackage, error)

	issueIdentityCred func(claim transaction.IdentityClaim, evidenceTxId string) (string, string, error)
	issueAuthCred     func(blockchainId, txId string) (string, string, error)
	fetchStatusList   func(blockchainId, listId string) (string, error)

	issuedClaims []transaction.IdentityClaim
}

func (f *fakeClient) Submit(signer *wallet.UL_Wallet, input transaction.ULTransactionInput) (transaction.ULTransaction, error) {
	if f.submitErr != nil {
		if err := f.submitErr(input); err != nil {
			return transaction.ULTransaction{}, err
		}
	}
	f.counter++
	txid := fmt.Sprintf("tx-%d", f.counter)
	if f.txID != nil {
		txid = f.txID(f.counter)
	}
	f.calls = append(f.calls, fakeCall{
		signerAddr:  signer.Address,
		payloadType: input.PayloadType,
		payload:     input.Payload,
	})
	var tx transaction.ULTransaction
	tx.TransactionId = txid
	return tx, nil
}

func (f *fakeClient) GetTransaction(blockchainId, txid string) (transaction.ULTransaction, error) {
	if f.getTransactionErr != nil {
		if err := f.getTransactionErr(txid); err != nil {
			return transaction.ULTransaction{}, err
		}
	}
	out := "SUCCESS"
	if f.statusFor != nil {
		out = f.statusFor(txid)
	}
	var tx transaction.ULTransaction
	tx.TransactionId = txid
	tx.Status = "ACCEPTED"
	tx.Output = out
	return tx, nil
}

func (f *fakeClient) GetChainHead(blockchainId string) (ChainHead, error) {
	if f.chainHeadErr != nil {
		return ChainHead{}, f.chainHeadErr
	}
	return f.chainHead, nil
}

func (f *fakeClient) ResolveDID(signer *wallet.UL_Wallet, did string) (transaction.DIDResolutionResult, error) {
	if f.resolveDID != nil {
		return f.resolveDID(did)
	}
	return transaction.DIDResolutionResult{}, nil
}

func (f *fakeClient) ResolveDIDChain(signer *wallet.UL_Wallet, did string) ([]transaction.DIDResolutionResult, error) {
	if f.resolveDIDChain != nil {
		return f.resolveDIDChain(did)
	}
	return nil, nil
}

func (f *fakeClient) VerifyIdentityClaim(signer *wallet.UL_Wallet, claim transaction.IdentityClaim) (transaction.VerifyResult, error) {
	if f.verifyClaim != nil {
		return f.verifyClaim(claim)
	}
	return transaction.VerifyResult{Valid: true}, nil
}

func (f *fakeClient) GetTransactionProof(signer *wallet.UL_Wallet, blockchainId, txId string) (transaction.TxInclusionProofPackage, error) {
	if f.txProof != nil {
		return f.txProof(blockchainId, txId)
	}
	return transaction.TxInclusionProofPackage{}, nil
}

func (f *fakeClient) ResolveDIDSigned(signer *wallet.UL_Wallet, did string) (transaction.SignedResolutionEnvelope, error) {
	if f.resolveDIDSigned != nil {
		return f.resolveDIDSigned(did)
	}
	return transaction.SignedResolutionEnvelope{}, nil
}

func (f *fakeClient) IssueIdentityCredential(claim transaction.IdentityClaim, evidenceTxId string) (string, string, error) {
	f.issuedClaims = append(f.issuedClaims, claim)
	if f.issueIdentityCred != nil {
		return f.issueIdentityCred(claim, evidenceTxId)
	}
	return "", "", nil
}

func (f *fakeClient) IssueAuthenticationCredential(blockchainId, txId string) (string, string, error) {
	if f.issueAuthCred != nil {
		return f.issueAuthCred(blockchainId, txId)
	}
	return "", "", nil
}

func (f *fakeClient) FetchStatusList(blockchainId, listId string) (string, error) {
	if f.fetchStatusList != nil {
		return f.fetchStatusList(blockchainId, listId)
	}
	return "", nil
}

func testRunner(client chainClient) *Runner {
	cfg := validConfig()
	cfg.Poll.IntervalSeconds = 0 // tight loop in tests
	cfg.Poll.TimeoutSeconds = 0
	owner := &wallet.UL_Wallet{Address: "owner-addr"}
	admin := &wallet.UL_Wallet{Address: "admin-addr"}
	agent := &wallet.UL_Wallet{Address: "agent-addr"}
	newOwner := &wallet.UL_Wallet{Address: "newowner-addr"}
	recovery := []*wallet.UL_Wallet{
		{Address: "rec-0"}, {Address: "rec-1"}, {Address: "rec-2"},
	}
	return newRunner(cfg, client, owner, admin, agent, newOwner, recovery)
}

func TestRunner_HappyPathChainsEntityAddress(t *testing.T) {
	f := &fakeClient{}
	r := testRunner(f)
	if _, err := r.runHappyPath(); err != nil {
		t.Fatalf("happy path failed: %v", err)
	}
	// call[0] creates the org entity -> tx-1; the child (call[1]) must use tx-1 as parent.
	if f.calls[0].payloadType != transaction.CREATE_ENTITY.String() {
		t.Fatalf("expected first call CREATE_ENTITY, got %s", f.calls[0].payloadType)
	}
	var child transaction.CreateEntityPayload
	if err := json.Unmarshal([]byte(f.calls[1].payload), &child); err != nil {
		t.Fatal(err)
	}
	if child.Parent != "tx-1" {
		t.Fatalf("expected child parent tx-1, got %q", child.Parent)
	}
	// call[2] links the agent's own wallet to the agent entity (tx-2), as a member.
	if f.calls[2].payloadType != transaction.LINK_WALLET_TO_ENTITY.String() {
		t.Fatalf("expected call[2] LINK_WALLET_TO_ENTITY, got %s", f.calls[2].payloadType)
	}
	var agentLink transaction.LinkWalletPayload
	if err := json.Unmarshal([]byte(f.calls[2].payload), &agentLink); err != nil {
		t.Fatal(err)
	}
	if agentLink.EntityAddress != "tx-2" || agentLink.WalletAddress != "agent-addr" || agentLink.Role != transaction.EntityRoleMember {
		t.Fatalf("expected agent wallet linked to tx-2 as member, got %+v", agentLink)
	}
	if agentLink.Permissions == nil || agentLink.Permissions.TransferOwnership || agentLink.Permissions.ManageWallets {
		t.Fatalf("delegated agent must not have transferOwnership/manageWallets, got %+v", agentLink.Permissions)
	}
	// call[3] sets the agent's metadata on the agent entity (tx-2), not the org (tx-1).
	var alter transaction.AlterEntityPayload
	if err := json.Unmarshal([]byte(f.calls[3].payload), &alter); err != nil {
		t.Fatal(err)
	}
	if alter.EntityAddress != "tx-2" {
		t.Fatalf("expected alter entityAddress tx-2 (agent), got %q", alter.EntityAddress)
	}
	// All happy-path steps are signed by the owner (the governing parent).
	for i, c := range f.calls {
		if c.signerAddr != "owner-addr" {
			t.Fatalf("call %d signed by %s, expected owner-addr", i, c.signerAddr)
		}
	}
}

func TestRunner_RecoveryExecuteThresholdApprovals(t *testing.T) {
	f := &fakeClient{}
	r := testRunner(f)
	if err := r.runRecoveryExecuteBranch("parent-e1"); err != nil {
		t.Fatalf("recovery-execute branch failed: %v", err)
	}
	// The request counts as recovery[0]'s approval, so expect threshold-1 approvals,
	// none signed by rec-0.
	approvals := 0
	for _, c := range f.calls {
		if c.payloadType == transaction.APPROVE_ENTITY_RECOVERY.String() {
			approvals++
			if c.signerAddr == "rec-0" {
				t.Fatal("approval signed by requester rec-0; the request already counts as its approval")
			}
		}
	}
	if want := r.cfg.Recovery.Threshold - 1; approvals != want {
		t.Fatalf("expected %d explicit approvals, got %d", want, approvals)
	}
	// request is signed by recovery[0] = "rec-0".
	for _, c := range f.calls {
		if c.payloadType == transaction.REQUEST_ENTITY_RECOVERY.String() && c.signerAddr != "rec-0" {
			t.Fatalf("request signed by %s, expected rec-0", c.signerAddr)
		}
	}
}

func TestRunner_RecoveryCancelSignedByInitiator(t *testing.T) {
	f := &fakeClient{}
	r := testRunner(f)
	if err := r.runRecoveryCancelBranch("parent-e1"); err != nil {
		t.Fatalf("recovery-cancel branch failed: %v", err)
	}
	found := false
	for _, c := range f.calls {
		if c.payloadType == transaction.CANCEL_ENTITY_RECOVERY.String() {
			found = true
			if c.signerAddr != "rec-0" {
				t.Fatalf("cancel signed by %s, expected rec-0 (the request initiator)", c.signerAddr)
			}
		}
	}
	if !found {
		t.Fatal("expected a CANCEL_ENTITY_RECOVERY call")
	}
}

func TestRunner_StopsOnRejection(t *testing.T) {
	f := &fakeClient{statusFor: func(txid string) string {
		if txid == "tx-1" {
			return "REJECTED_BY_UNAUTHORIZED"
		}
		return "SUCCESS"
	}}
	r := testRunner(f)
	_, err := r.runHappyPath()
	if err == nil {
		t.Fatal("expected error when first tx is rejected")
	}
	// Only the first step should have been submitted before the failure.
	if len(f.calls) != 1 {
		t.Fatalf("expected 1 submission before stop, got %d", len(f.calls))
	}
}

func TestRunner_TimesOut(t *testing.T) {
	f := &fakeClient{statusFor: func(txid string) string { return "TO_BE_PROCESSED" }}
	r := testRunner(f)
	_, err := r.runHappyPath()
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func buildVerifiableProof(t *testing.T, blockchainId, txId string) *transaction.TxInclusionProofPackage {
	t.Helper()
	tx := &transaction.ULTransaction{}
	tx.TransactionId = txId
	txs := []*transaction.ULTransaction{tx}
	root, err := transaction.GenerateMerkleRoot(txs, nil, nil)
	if err != nil {
		t.Fatalf("merkle root: %v", err)
	}
	block := &transaction.UL_Block{
		BlockchainId:    blockchainId,
		Height:          1,
		Version:         "v1",
		HashingStrategy: crypto.HASH_SHA3_512.String(),
		Transactions:    txs,
		ProofMerkleRoot: hex.EncodeToString(root),
		MerkleRoot:      hex.EncodeToString(crypto.Hash(root, crypto.HASH_SHA3_512)),
	}
	block.Hash = hex.EncodeToString(crypto.Hash(block.GetHashData(), crypto.HASH_SHA3_512))

	key := crypto.NewSecp256k1Key(nil)
	seed := make([]byte, 32)
	seed[0] = 7
	if err := key.GenerateKeyFromSeed(seed); err != nil {
		t.Fatalf("key: %v", err)
	}
	sig, err := key.SignData([]byte(block.Hash))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	block.NodeSignature = hex.EncodeToString(sig)
	block.InstanceId = block.BlockchainId + key.GetPublicKeyHex(true)

	pkg, err := transaction.AssembleTxInclusionPackage(block, nil, txId)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	return pkg
}

func TestRunner_IdentityServicesPhase_HappyPath(t *testing.T) {
	cfg := validConfig()
	agentWalletDID := buildDID(cfg.BlockchainId, "agent-addr")
	agentEntityDID := buildDID(cfg.BlockchainId, "agent-entity-addr")
	entityDisabled := false

	proofPkg := buildVerifiableProof(t, cfg.BlockchainId, "01")

	f := &fakeClient{
		txID:      func(counter int) string { return fmt.Sprintf("%02x", counter) },
		chainHead: ChainHead{Height: 5, Hash: "block-hash-5"},
		resolveDID: func(did string) (transaction.DIDResolutionResult, error) {
			switch did {
			case agentWalletDID:
				return transaction.DIDResolutionResult{
					DIDDocument:         transaction.DIDDocument{Id: agentWalletDID},
					DIDDocumentMetadata: transaction.DIDDocumentMetadata{Deactivated: false},
				}, nil
			case agentEntityDID:
				return transaction.DIDResolutionResult{
					DIDDocument:         transaction.DIDDocument{Id: agentEntityDID},
					DIDDocumentMetadata: transaction.DIDDocumentMetadata{Deactivated: entityDisabled, EntityType: cfg.Child.Type},
				}, nil
			}
			return transaction.DIDResolutionResult{}, fmt.Errorf("unexpected did %q", did)
		},
		resolveDIDChain: func(did string) ([]transaction.DIDResolutionResult, error) {
			if did != agentWalletDID {
				return nil, fmt.Errorf("unexpected did %q", did)
			}
			return []transaction.DIDResolutionResult{
				{DIDDocument: transaction.DIDDocument{Id: "did:ulnet:test-chain:root-wallet"}},
				{DIDDocument: transaction.DIDDocument{Id: agentWalletDID}},
			}, nil
		},
		verifyClaim: func(claim transaction.IdentityClaim) (transaction.VerifyResult, error) {
			if entityDisabled {
				return transaction.VerifyResult{Valid: false, Reasons: []string{"entity is disabled"}}, nil
			}
			if claim.Role == transaction.EntityRoleMember {
				return transaction.VerifyResult{Valid: true}, nil
			}
			return transaction.VerifyResult{Valid: false, Reasons: []string{"subject does not hold the claimed role"}}, nil
		},
		txProof: func(blockchainId, txId string) (transaction.TxInclusionProofPackage, error) {
			if txId != "01" {
				return transaction.TxInclusionProofPackage{}, fmt.Errorf("unexpected txId %q", txId)
			}
			return *proofPkg, nil
		},
	}
	f.submitErr = func(input transaction.ULTransactionInput) error {
		if input.PayloadType == transaction.ALTER_ENTITY.String() {
			var p transaction.AlterEntityPayload
			if err := json.Unmarshal([]byte(input.Payload), &p); err == nil && p.Enabled != nil && !*p.Enabled {
				entityDisabled = true
			}
			return nil
		}
		if input.PayloadType != transaction.AUTHENTICATE_EXTERNAL.String() {
			return nil
		}
		var p transaction.AuthenticateExternalPayload
		if err := json.Unmarshal([]byte(input.Payload), &p); err != nil {
			return err
		}
		switch p.Subject {
		case "":
			return nil
		case "agent-entity-addr":
			return fmt.Errorf("sender does not control the asserted subject")
		default:
			return fmt.Errorf("personal entities are not identity subjects")
		}
	}

	r := testRunner(f)
	r.agentEntityAddr = "agent-entity-addr"

	if err := r.runIdentityServicesPhase("root-entity-addr"); err != nil {
		t.Fatalf("identity services phase failed: %v", err)
	}

	wantSteps := []string{
		"authenticate_internal[agent]",
		"authenticate_external[agent]",
		"resolve_did[agent-wallet]",
		"resolve_did[agent-entity]",
		"resolve_did_chain[agent-wallet]",
		"verify_claims[true]",
		"verify_claims[false]",
		"transaction_proof[authenticate_internal]",
		"authenticate_subject_denied[agent]",
		"create_personal_entity",
		"authenticate_personal_denied",
		"kill_switch[disable-agent-entity]",
		"resolve_did[agent-entity-deactivated]",
		"verify_claims[after-kill]",
		"proof_still_verifies",
	}
	if r.report == nil || len(r.report.Steps) != len(wantSteps) {
		t.Fatalf("expected %d steps, got %+v", len(wantSteps), r.report)
	}
	for i, name := range wantSteps {
		step := r.report.Steps[i]
		if step.Name != name {
			t.Fatalf("step %d: expected %q, got %q", i, name, step.Name)
		}
		if step.Error != "" {
			t.Fatalf("step %d (%s): unexpected error: %s", i, name, step.Error)
		}
	}
	if r.report.Steps[0].TxId != "01" {
		t.Fatalf("expected authenticate_internal txid 01, got %q", r.report.Steps[0].TxId)
	}
}

func TestRunner_RecoveryHardeningPhase_HappyPath(t *testing.T) {
	orig := denialWindowSeconds
	denialWindowSeconds = 0
	defer func() { denialWindowSeconds = orig }()

	f := &fakeClient{}
	r := testRunner(f)
	rec0, rec1 := r.recovery[0].Address, r.recovery[1].Address

	// Denial is keyed off the recorded signer for that txid (matching the node's
	// initiator-only cancel / stale-council rules); same-shape payloads from different
	// signers can't be told apart by payload type alone.
	f.getTransactionErr = func(txid string) error {
		idx, err := strconv.Atoi(strings.TrimPrefix(txid, "tx-"))
		if err != nil || idx < 1 || idx > len(f.calls) {
			return nil
		}
		call := f.calls[idx-1]
		switch call.payloadType {
		case transaction.CANCEL_ENTITY_RECOVERY.String():
			if call.signerAddr != rec0 {
				return fmt.Errorf("unable to gather transaction")
			}
		case transaction.REQUEST_ENTITY_RECOVERY.String():
			if call.signerAddr == rec1 {
				return fmt.Errorf("unable to gather transaction")
			}
		case transaction.TRANSFER_ENTITY.String():
			return fmt.Errorf("unable to gather transaction")
		}
		return nil
	}

	if err := r.runRecoveryHardeningPhase("root-entity-addr"); err != nil {
		t.Fatalf("recovery hardening phase failed: %v", err)
	}

	wantSteps := []string{
		"create_entity[rh-cancel]",
		"configure_entity_recovery[rh-cancel]",
		"request_entity_recovery[rh-cancel]",
		"cancel_denied[owner]",
		"cancel_denied[recovery[1]]",
		"cancel_entity_recovery[rh]",
		"create_entity[rh-disabled]",
		"configure_entity_recovery[rh-disabled]",
		"disable_entity[rh]",
		"request_entity_recovery[rh-disabled]",
		"create_entity[rh-timelock]",
		"configure_entity_recovery[rh-timelock]",
		"reconfigure_entity_recovery[rh-timelock]",
		"request_denied[new-council]",
		"request_entity_recovery[rh-timelock-oldcouncil]",
		"create_entity[rh-selftransfer]",
		"selftransfer_denied",
	}
	if r.report == nil || len(r.report.Steps) != len(wantSteps) {
		t.Fatalf("expected %d steps, got %+v", len(wantSteps), r.report)
	}
	for i, name := range wantSteps {
		step := r.report.Steps[i]
		if step.Name != name {
			t.Fatalf("step %d: expected %q, got %q", i, name, step.Name)
		}
		if step.Error != "" {
			t.Fatalf("step %d (%s): unexpected error: %s", i, name, step.Error)
		}
	}
	if got := r.report.Steps[3].SignerRole; got != "owner" {
		t.Fatalf("cancel_denied[owner] signer role = %q, want owner", got)
	}
	if got := r.report.Steps[4].SignerRole; got != "recovery[1]" {
		t.Fatalf("cancel_denied[recovery[1]] signer role = %q, want recovery[1]", got)
	}
	if got := r.report.Steps[5].SignerRole; got != "recovery[0]" {
		t.Fatalf("cancel_entity_recovery[rh] signer role = %q, want recovery[0]", got)
	}
	if got := r.report.Steps[13].SignerRole; got != "recovery[1]" {
		t.Fatalf("request_denied[new-council] signer role = %q, want recovery[1]", got)
	}
	if got := r.report.Steps[14].SignerRole; got != "recovery[0]" {
		t.Fatalf("request_entity_recovery[rh-timelock-oldcouncil] signer role = %q, want recovery[0]", got)
	}
}

func TestRunner_SubmitExpectDenied_PassesOnMatchingDenial(t *testing.T) {
	f := &fakeClient{submitErr: func(transaction.ULTransactionInput) error {
		return fmt.Errorf("sender does not control the asserted subject")
	}}
	r := testRunner(f)
	err := r.submitExpectDenied("test_step", "agent", r.agent, transaction.AUTHENTICATE_EXTERNAL.String(), "{}", "control")
	if err != nil {
		t.Fatalf("expected success when denial matches, got %v", err)
	}
	if len(r.report.Steps) != 1 || r.report.Steps[0].Error != "" {
		t.Fatalf("expected 1 step recorded with no error, got %+v", r.report.Steps)
	}
}

func TestRunner_SubmitExpectDenied_FailsWhenAccepted(t *testing.T) {
	f := &fakeClient{}
	r := testRunner(f)
	err := r.submitExpectDenied("test_step", "agent", r.agent, transaction.AUTHENTICATE_EXTERNAL.String(), "{}", "control")
	if err == nil {
		t.Fatal("expected failure when the node unexpectedly accepts the transaction")
	}
	if len(r.report.Steps) != 1 || r.report.Steps[0].Error == "" {
		t.Fatalf("expected 1 step recorded with an error, got %+v", r.report.Steps)
	}
}

func TestRunner_SubmitExpectDenied_FailsOnWrongReason(t *testing.T) {
	f := &fakeClient{submitErr: func(transaction.ULTransactionInput) error {
		return fmt.Errorf("some unrelated validation error")
	}}
	r := testRunner(f)
	err := r.submitExpectDenied("test_step", "agent", r.agent, transaction.AUTHENTICATE_EXTERNAL.String(), "{}", "control")
	if err == nil {
		t.Fatal("expected failure when the denial reason does not match")
	}
}

func TestRunner_SubmitExpectDenied_AsyncDenialNeverStoredPasses(t *testing.T) {
	orig := denialWindowSeconds
	denialWindowSeconds = 0
	defer func() { denialWindowSeconds = orig }()

	f := &fakeClient{
		getTransactionErr: func(string) error { return fmt.Errorf("unable to gather transaction") },
	}
	r := testRunner(f)
	err := r.submitExpectDenied("test_step", "owner", r.owner, transaction.AUTHENTICATE_EXTERNAL.String(), "{}", "personal entities")
	if err != nil {
		t.Fatalf("expected pass when the tx is never stored, got %v", err)
	}
	if len(r.report.Steps) != 1 {
		t.Fatalf("expected 1 step recorded, got %+v", r.report.Steps)
	}
	step := r.report.Steps[0]
	if step.Error != "" {
		t.Fatalf("expected no error, got %q", step.Error)
	}
	const wantOutput = "denied (rejected by async validation, never stored)"
	if step.Output != wantOutput {
		t.Fatalf("expected output %q, got %q", wantOutput, step.Output)
	}
	if step.TxId == "" {
		t.Fatal("expected txId to be recorded for forensics")
	}
}

func TestRunner_SubmitExpectDenied_AsyncAcceptanceFails(t *testing.T) {
	f := &fakeClient{
		statusFor: func(string) string { return "SUCCESS" },
	}
	r := testRunner(f)
	err := r.submitExpectDenied("test_step", "owner", r.owner, transaction.AUTHENTICATE_EXTERNAL.String(), "{}", "personal entities")
	if err == nil {
		t.Fatal("expected failure when the transaction ends up stored")
	}
	if !strings.Contains(err.Error(), "was stored") {
		t.Fatalf("expected error to mention 'was stored', got %v", err)
	}
	if len(r.report.Steps) != 1 || r.report.Steps[0].Error == "" {
		t.Fatalf("expected 1 step recorded with an error, got %+v", r.report.Steps)
	}
}
