package identity

import (
	"fmt"
	"strings"
	"time"

	"github.com/ULedgerInc/go-sdk/pkg/audit"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
	"github.com/google/uuid"
)

type Runner struct {
	cfg      Config
	client   chainClient
	owner    *wallet.UL_Wallet
	admin    *wallet.UL_Wallet
	agent    *wallet.UL_Wallet
	newOwner *wallet.UL_Wallet
	recovery []*wallet.UL_Wallet
	report   *RunReport

	rootEntityAddr   string
	agentEntityAddr  string
	savedProof       transaction.TxInclusionProofPackage
	authInternalTxId string
}

// NewRunner validates the config, loads the role wallets from disk, and wires
// the real HTTP chain client.
func NewRunner(cfg Config) (*Runner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	owner, err := loadWallet(cfg.Wallets.Owner, cfg.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("owner wallet: %w", err)
	}
	admin, err := loadWallet(cfg.Wallets.Admin, cfg.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("admin wallet: %w", err)
	}
	agent, err := loadWallet(cfg.Wallets.Agent, cfg.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("agent wallet: %w", err)
	}
	newOwner, err := loadWallet(cfg.Wallets.NewOwner, cfg.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("newOwner wallet: %w", err)
	}
	recovery := make([]*wallet.UL_Wallet, 0, len(cfg.Wallets.Recovery))
	for i, path := range cfg.Wallets.Recovery {
		w, err := loadWallet(path, cfg.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("recovery[%d] wallet: %w", i, err)
		}
		recovery = append(recovery, w)
	}
	client := newHTTPChainClient(cfg.NodeEndpoints[0], cfg.InsecureSkipVerify)
	return newRunner(cfg, client, owner, admin, agent, newOwner, recovery), nil
}

// newRunner wires a Runner with an explicit client and wallets (used by tests).
func newRunner(cfg Config, client chainClient, owner, admin, agent, newOwner *wallet.UL_Wallet, recovery []*wallet.UL_Wallet) *Runner {
	return &Runner{
		cfg:      cfg,
		client:   client,
		owner:    owner,
		admin:    admin,
		agent:    agent,
		newOwner: newOwner,
		recovery: recovery,
	}
}

func loadWallet(path, passphrase string) (*wallet.UL_Wallet, error) {
	w, err := wallet.LoadFromFile(path, passphrase)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

// Run executes the full lifecycle and returns the report; any error is also
// recorded on it (Failed=true).
func (r *Runner) Run() (*RunReport, error) {
	r.report = &RunReport{
		RunnerId:     uuid.New().String(),
		BlockchainId: r.cfg.BlockchainId,
		StartTime:    time.Now(),
	}
	err := r.run()
	r.report.EndTime = time.Now()
	if err != nil {
		r.report.Failed = true
	}
	return r.report, err
}

func (r *Runner) run() error {
	// A wallet can only belong to one entity, so the recovery/unlink branches reuse
	// the happy-path entity (child entities under it, tearing down its existing link)
	// rather than creating new top-level entities.
	rootEntity, err := r.runHappyPath()
	if err != nil {
		return fmt.Errorf("happy path: %w", err)
	}
	if err := r.runRecoveryExecuteBranch(rootEntity); err != nil {
		return fmt.Errorf("recovery-execute branch: %w", err)
	}
	if err := r.runRecoveryCancelBranch(rootEntity); err != nil {
		return fmt.Errorf("recovery-cancel branch: %w", err)
	}
	if err := r.runUnlinkBranch(rootEntity); err != nil {
		return fmt.Errorf("unlink branch: %w", err)
	}
	if err := r.runIdentityServicesPhase(rootEntity); err != nil {
		return fmt.Errorf("identity services phase: %w", err)
	}
	if err := r.runRecoveryHardeningPhase(rootEntity); err != nil {
		return fmt.Errorf("recovery hardening phase: %w", err)
	}
	if err := r.runCredentialsPhase(); err != nil {
		return fmt.Errorf("credentials phase: %w", err)
	}
	return nil
}

func (r *Runner) recoveryAddresses() []string {
	addrs := make([]string, len(r.recovery))
	for i, w := range r.recovery {
		addrs[i] = w.Address
	}
	return addrs
}

// submitAndWait submits the tx with the given signer, polls until it commits,
// records the step, and returns the committed txid.
func (r *Runner) submitAndWait(name, signerRole string, signer *wallet.UL_Wallet, payloadType, payload string) (string, error) {
	sr := StepResult{Name: name, SignerRole: signerRole, PayloadType: payloadType}

	input := transaction.ULTransactionInput{
		BlockchainId: r.cfg.BlockchainId,
		Payload:      payload,
		PayloadType:  payloadType,
	}
	tx, err := r.client.Submit(signer, input)
	if err != nil {
		sr.Error = err.Error()
		r.recordStep(sr)
		return "", err
	}
	sr.TxId = tx.TransactionId
	if tx.TransactionId == "" {
		sr.Error = "node returned empty transaction id"
		r.recordStep(sr)
		return "", fmt.Errorf("%s: empty transaction id", name)
	}

	final, err := r.waitForCommit(tx.TransactionId)
	sr.Status = final.Status
	sr.Output = final.Output
	if err != nil {
		sr.Error = err.Error()
		r.recordStep(sr)
		return "", err
	}
	r.recordStep(sr)
	return tx.TransactionId, nil
}

func (r *Runner) recordStep(sr StepResult) {
	if r.report == nil {
		r.report = &RunReport{}
	}
	r.report.Steps = append(r.report.Steps, sr)
}

// waitForCommit polls until the tx output is SUCCESS, fails fast on any terminal
// rejection, or times out (TO_BE_PROCESSED / empty output keep polling).
func (r *Runner) waitForCommit(txid string) (transaction.ULTransaction, error) {
	interval := time.Duration(r.cfg.Poll.IntervalSeconds) * time.Second
	timeout := time.Duration(r.cfg.Poll.TimeoutSeconds) * time.Second
	deadline := time.Now().Add(timeout)
	var last transaction.ULTransaction
	var lastErr error
	for {
		tx, err := r.client.GetTransaction(r.cfg.BlockchainId, txid)
		if err == nil {
			last = tx
			lastErr = nil
			switch tx.Output {
			case transaction.TX_SUCCESS.String():
				return tx, nil
			case "", transaction.TO_BE_PROCESSED.String():
				// not committed yet; keep polling
			default:
				return tx, fmt.Errorf("transaction %s not successful: output=%s status=%s", txid, tx.Output, tx.Status)
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return last, fmt.Errorf("timed out after %s waiting for tx %s to commit; last fetch error: %w", timeout, txid, lastErr)
			}
			return last, fmt.Errorf("timed out after %s waiting for tx %s to commit (last output=%q status=%q)", timeout, txid, last.Output, last.Status)
		}
		time.Sleep(interval)
	}
}

// runHappyPath creates the primary top-level entity, exercises the non-destructive
// owner-signed operations on it, and returns its address so the isolated branches
// can attach their entities as children.
func (r *Runner) runHappyPath() (string, error) {
	p, err := buildCreateEntity(r.cfg.Entity.Name, transaction.EntityType(r.cfg.Entity.Type), "", r.cfg.Entity.Metadata)
	if err != nil {
		return "", err
	}
	e1, err := r.submitAndWait("create_entity", "owner", r.owner, transaction.CREATE_ENTITY.String(), p)
	if err != nil {
		return "", err
	}
	r.rootEntityAddr = e1

	p, err = buildCreateEntity(r.cfg.Child.Name, transaction.EntityType(r.cfg.Child.Type), e1, r.cfg.Child.Metadata)
	if err != nil {
		return "", err
	}
	agentEntity, err := r.submitAndWait("create_child_entity", "owner", r.owner, transaction.CREATE_ENTITY.String(), p)
	if err != nil {
		return "", err
	}
	r.agentEntityAddr = agentEntity

	// Delegated-operator model: the owner owns the agent entity, but the agent runs on
	// its own wallet. Link that wallet as a member with no management rights so the
	// parent keeps governance. The agent wallet must be otherwise unassociated to link.
	agentPerms := &transaction.EntityPermission{ManageMetadata: false}
	p, err = buildLinkWallet(agentEntity, r.agent.Address, transaction.EntityRoleMember, agentPerms)
	if err != nil {
		return "", err
	}
	if _, err = r.submitAndWait("link_wallet_to_entity[agent]", "owner", r.owner, transaction.LINK_WALLET_TO_ENTITY.String(), p); err != nil {
		return "", err
	}

	// Parent sets the agent's budget/preferences on the agent entity it governs.
	p, err = buildAlterEntity(agentEntity, r.cfg.AlterMetadata)
	if err != nil {
		return "", err
	}
	if _, err = r.submitAndWait("update_metadata_entity", "owner", r.owner, transaction.ALTER_ENTITY.String(), p); err != nil {
		return "", err
	}

	perms := &transaction.EntityPermission{
		ManageWallets:    true,
		ManageChildren:   true,
		ManageAccessList: true,
		ManageMetadata:   true,
	}
	p, err = buildLinkWallet(e1, r.admin.Address, transaction.EntityRoleAdmin, perms)
	if err != nil {
		return "", err
	}
	if _, err = r.submitAndWait("link_wallet_to_entity", "owner", r.owner, transaction.LINK_WALLET_TO_ENTITY.String(), p); err != nil {
		return "", err
	}

	target := r.cfg.AccessList.TargetAddress
	if target == "" {
		target = r.admin.Address
	}
	p, err = buildSetAccessList(e1, r.cfg.AccessList.Operation, target)
	if err != nil {
		return "", err
	}
	if _, err = r.submitAndWait("add_access_list_entity", "owner", r.owner, transaction.SET_ENTITY_ACCESS_LIST.String(), p); err != nil {
		return "", err
	}

	p, err = buildConfigureRecovery(e1, r.recoveryAddresses(), r.cfg.Recovery.Threshold)
	if err != nil {
		return "", err
	}
	if _, err = r.submitAndWait("configure_entity_recovery", "owner", r.owner, transaction.CONFIGURE_ENTITY_RECOVERY.String(), p); err != nil {
		return "", err
	}
	return e1, nil
}

func (r *Runner) runRecoveryExecuteBranch(parent string) error {
	p, err := buildCreateEntity(r.cfg.Entity.Name+"-recovery-exec", transaction.EntityType(r.cfg.Entity.Type), parent, nil)
	if err != nil {
		return err
	}
	e2, err := r.submitAndWait("create_entity[recovery-exec]", "owner", r.owner, transaction.CREATE_ENTITY.String(), p)
	if err != nil {
		return err
	}

	p, err = buildConfigureRecovery(e2, r.recoveryAddresses(), r.cfg.Recovery.Threshold)
	if err != nil {
		return err
	}
	if _, err = r.submitAndWait("configure_entity_recovery[recovery-exec]", "owner", r.owner, transaction.CONFIGURE_ENTITY_RECOVERY.String(), p); err != nil {
		return err
	}

	p, err = buildRequestRecovery(e2, r.newOwner.Address)
	if err != nil {
		return err
	}
	reqId, err := r.submitAndWait("request_entity_recovery", "recovery[0]", r.recovery[0], transaction.REQUEST_ENTITY_RECOVERY.String(), p)
	if err != nil {
		return err
	}

	// The request counts as recovery[0]'s approval, so collect the remaining
	// threshold-1 approvals from the other recovery wallets.
	for i := 1; i < r.cfg.Recovery.Threshold; i++ {
		p, err = buildApproveRecovery(reqId)
		if err != nil {
			return err
		}
		name := fmt.Sprintf("approve_entity_recovery[%d]", i)
		role := fmt.Sprintf("recovery[%d]", i)
		if _, err = r.submitAndWait(name, role, r.recovery[i], transaction.APPROVE_ENTITY_RECOVERY.String(), p); err != nil {
			return err
		}
	}

	p, err = buildExecuteRecovery(reqId)
	if err != nil {
		return err
	}
	if _, err = r.submitAndWait("execute_entity_recovery", "recovery[0]", r.recovery[0], transaction.EXECUTE_ENTITY_RECOVERY.String(), p); err != nil {
		return err
	}
	return nil
}

func (r *Runner) runRecoveryCancelBranch(parent string) error {
	p, err := buildCreateEntity(r.cfg.Entity.Name+"-recovery-cancel", transaction.EntityType(r.cfg.Entity.Type), parent, nil)
	if err != nil {
		return err
	}
	e3, err := r.submitAndWait("create_entity[recovery-cancel]", "owner", r.owner, transaction.CREATE_ENTITY.String(), p)
	if err != nil {
		return err
	}

	p, err = buildConfigureRecovery(e3, r.recoveryAddresses(), r.cfg.Recovery.Threshold)
	if err != nil {
		return err
	}
	if _, err = r.submitAndWait("configure_entity_recovery[recovery-cancel]", "owner", r.owner, transaction.CONFIGURE_ENTITY_RECOVERY.String(), p); err != nil {
		return err
	}

	// r.newOwner is already bound to the recovery-execute entity, and the node rejects a
	// recovery whose new owner already owns another entity. This branch only cancels, so
	// the last (never-executed-to, still unbound) recovery wallet is a valid stand-in.
	cancelNewOwner := r.recovery[len(r.recovery)-1]
	p, err = buildRequestRecovery(e3, cancelNewOwner.Address)
	if err != nil {
		return err
	}
	reqId, err := r.submitAndWait("request_entity_recovery[cancel]", "recovery[0]", r.recovery[0], transaction.REQUEST_ENTITY_RECOVERY.String(), p)
	if err != nil {
		return err
	}

	p, err = buildCancelRecovery(reqId)
	if err != nil {
		return err
	}
	if _, err = r.submitAndWait("cancel_entity_recovery", "recovery[0]", r.recovery[0], transaction.CANCEL_ENTITY_RECOVERY.String(), p); err != nil {
		return err
	}
	return nil
}

// runUnlinkBranch tears down the admin link the happy path established. A wallet can
// only belong to one entity, so we unlink the existing E1<->admin association rather
// than create a fresh entity+link; this exercises UNLINK against a real link.
func (r *Runner) runUnlinkBranch(entity string) error {
	p, err := buildUnlinkWallet(entity, r.admin.Address)
	if err != nil {
		return err
	}
	if _, err = r.submitAndWait("unlink_wallet_from_entity", "owner", r.owner, transaction.UNLINK_WALLET_FROM_ENTITY.String(), p); err != nil {
		return err
	}
	return nil
}

func buildDID(chainId, address string) string {
	return fmt.Sprintf("did:ulnet:%s:%s", chainId, address)
}

func (r *Runner) runIdentityServicesPhase(rootEntity string) error {
	agentWalletDID := buildDID(r.cfg.BlockchainId, r.agent.Address)
	agentEntityDID := buildDID(r.cfg.BlockchainId, r.agentEntityAddr)

	head, err := r.client.GetChainHead(r.cfg.BlockchainId)
	if err != nil {
		return r.recordCheck("authenticate_internal[agent]", "", fmt.Errorf("fetching chain head: %w", err))
	}
	p, err := buildAuthenticateInternal("", head.Height, head.Hash)
	if err != nil {
		return err
	}
	authInternalTx, err := r.submitAndWait("authenticate_internal[agent]", "agent", r.agent, transaction.AUTHENTICATE_INTERNAL.String(), p)
	if err != nil {
		return err
	}
	r.authInternalTxId = authInternalTx

	nonce, err := randomNonceHex(16)
	if err != nil {
		return err
	}
	p, err = buildAuthenticateExternal("", r.cfg.Audience, nonce, nil)
	if err != nil {
		return err
	}
	if _, err = r.submitAndWait("authenticate_external[agent]", "agent", r.agent, transaction.AUTHENTICATE_EXTERNAL.String(), p); err != nil {
		return err
	}

	err = r.checkResolveDID("resolve_did[agent-wallet]", agentWalletDID, func(res transaction.DIDResolutionResult) error {
		if res.DIDDocumentMetadata.Deactivated {
			return fmt.Errorf("expected agent wallet to be active, resolver reports deactivated")
		}
		if res.DIDDocument.Id != agentWalletDID {
			return fmt.Errorf("resolved document id %q does not match requested did %q", res.DIDDocument.Id, agentWalletDID)
		}
		return nil
	})
	if err != nil {
		return err
	}

	err = r.checkResolveDID("resolve_did[agent-entity]", agentEntityDID, func(res transaction.DIDResolutionResult) error {
		if res.DIDDocumentMetadata.Deactivated {
			return fmt.Errorf("expected agent entity to be active, resolver reports deactivated")
		}
		if res.DIDDocumentMetadata.EntityType != r.cfg.Child.Type {
			return fmt.Errorf("expected entityType %q, got %q", r.cfg.Child.Type, res.DIDDocumentMetadata.EntityType)
		}
		return nil
	})
	if err != nil {
		return err
	}

	err = r.checkResolveDIDChain("resolve_did_chain[agent-wallet]", agentWalletDID, func(res []transaction.DIDResolutionResult) error {
		if len(res) == 0 {
			return fmt.Errorf("expected at least 1 result in the did chain, got 0")
		}
		if res[len(res)-1].DIDDocument.Id != agentWalletDID {
			return fmt.Errorf("expected %q last (leaf) in root-first order, got %q", agentWalletDID, res[len(res)-1].DIDDocument.Id)
		}
		return nil
	})
	if err != nil {
		return err
	}

	memberClaim := transaction.IdentityClaim{
		SubjectDID:    agentWalletDID,
		EntityAddress: r.agentEntityAddr,
		Role:          transaction.EntityRoleMember,
	}
	if err = r.checkVerifyClaim("verify_claims[true]", memberClaim, true); err != nil {
		return err
	}

	adminClaim := memberClaim
	adminClaim.Role = transaction.EntityRoleAdmin
	if err = r.checkVerifyClaim("verify_claims[false]", adminClaim, false); err != nil {
		return err
	}

	proofPkg, err := r.client.GetTransactionProof(r.owner, r.cfg.BlockchainId, authInternalTx)
	if err == nil {
		err = audit.VerifyTxInclusionProof(&proofPkg, authInternalTx, r.cfg.ChainKeyTypeValue(), r.cfg.BlockchainId)
	}
	if err = r.recordCheck("transaction_proof[authenticate_internal]", "verified", err); err != nil {
		return err
	}
	r.savedProof = proofPkg

	nonce, err = randomNonceHex(16)
	if err != nil {
		return err
	}
	p, err = buildAuthenticateExternal(r.agentEntityAddr, r.cfg.Audience, nonce, nil)
	if err != nil {
		return err
	}
	if err = r.submitExpectDenied("authenticate_subject_denied[agent]", "agent", r.agent, transaction.AUTHENTICATE_EXTERNAL.String(), p, "control"); err != nil {
		return err
	}

	p, err = buildCreateEntity(r.cfg.Entity.Name+"-personal", transaction.EntityTypePersonal, rootEntity, nil)
	if err != nil {
		return err
	}
	personalEntity, err := r.submitAndWait("create_personal_entity", "owner", r.owner, transaction.CREATE_ENTITY.String(), p)
	if err != nil {
		return err
	}

	nonce, err = randomNonceHex(16)
	if err != nil {
		return err
	}
	p, err = buildAuthenticateExternal(personalEntity, r.cfg.Audience, nonce, nil)
	if err != nil {
		return err
	}
	if err = r.submitExpectDenied("authenticate_personal_denied", "owner", r.owner, transaction.AUTHENTICATE_EXTERNAL.String(), p, "personal entities"); err != nil {
		return err
	}

	p, err = buildDisableEntity(r.agentEntityAddr)
	if err != nil {
		return err
	}
	if _, err = r.submitAndWait("kill_switch[disable-agent-entity]", "owner", r.owner, transaction.ALTER_ENTITY.String(), p); err != nil {
		return err
	}

	err = r.checkResolveDID("resolve_did[agent-entity-deactivated]", agentEntityDID, func(res transaction.DIDResolutionResult) error {
		if !res.DIDDocumentMetadata.Deactivated {
			return fmt.Errorf("expected agent entity to be deactivated after the kill switch")
		}
		return nil
	})
	if err != nil {
		return err
	}

	if err = r.checkVerifyClaim("verify_claims[after-kill]", memberClaim, false); err != nil {
		return err
	}

	verifyErr := audit.VerifyTxInclusionProof(&r.savedProof, authInternalTx, r.cfg.ChainKeyTypeValue(), r.cfg.BlockchainId)
	return r.recordCheck("proof_still_verifies", "verified", verifyErr)
}

// recoveryHardeningWallets picks the active council and a NewOwner for this phase.
// r.newOwner is already bound to an entity, so it can't be reused; recovery wallets
// stay unbound as long as no recovery is executed to them, which this phase avoids.
func (r *Runner) recoveryHardeningWallets() ([]*wallet.UL_Wallet, *wallet.UL_Wallet) {
	n := len(r.recovery)
	if n >= 3 {
		return r.recovery[:2], r.recovery[2]
	}
	return r.recovery[:n-1], r.recovery[n-1]
}

// runRecoveryHardeningPhase exercises the recovery-authority hardening rules:
// initiator-only cancel, requests allowed on disabled entities, timelocked
// reconfiguration, and self-transfer rejection. Each sub-demo uses a fresh child entity.
func (r *Runner) runRecoveryHardeningPhase(rootEntity string) error {
	council, newOwnerWallet := r.recoveryHardeningWallets()
	rec0 := council[0]
	rec1 := rec0
	if len(council) > 1 {
		rec1 = council[1]
	}
	councilAddrs := []string{rec0.Address, rec1.Address}

	p, err := buildCreateEntity(r.cfg.Entity.Name+"-rh-cancel", transaction.EntityType(r.cfg.Entity.Type), rootEntity, nil)
	if err != nil {
		return err
	}
	entA, err := r.submitAndWait("create_entity[rh-cancel]", "owner", r.owner, transaction.CREATE_ENTITY.String(), p)
	if err != nil {
		return err
	}

	p, err = buildConfigureRecovery(entA, councilAddrs, 2)
	if err != nil {
		return err
	}
	if _, err = r.submitAndWait("configure_entity_recovery[rh-cancel]", "owner", r.owner, transaction.CONFIGURE_ENTITY_RECOVERY.String(), p); err != nil {
		return err
	}

	p, err = buildRequestRecovery(entA, newOwnerWallet.Address)
	if err != nil {
		return err
	}
	reqIdA, err := r.submitAndWait("request_entity_recovery[rh-cancel]", "recovery[0]", rec0, transaction.REQUEST_ENTITY_RECOVERY.String(), p)
	if err != nil {
		return err
	}

	p, err = buildCancelRecovery(reqIdA)
	if err != nil {
		return err
	}
	if err = r.submitExpectDenied("cancel_denied[owner]", "owner", r.owner, transaction.CANCEL_ENTITY_RECOVERY.String(), p, "only the request initiator"); err != nil {
		return err
	}
	if err = r.submitExpectDenied("cancel_denied[recovery[1]]", "recovery[1]", rec1, transaction.CANCEL_ENTITY_RECOVERY.String(), p, "only the request initiator"); err != nil {
		return err
	}
	if _, err = r.submitAndWait("cancel_entity_recovery[rh]", "recovery[0]", rec0, transaction.CANCEL_ENTITY_RECOVERY.String(), p); err != nil {
		return err
	}

	p, err = buildCreateEntity(r.cfg.Entity.Name+"-rh-disabled", transaction.EntityType(r.cfg.Entity.Type), rootEntity, nil)
	if err != nil {
		return err
	}
	entB, err := r.submitAndWait("create_entity[rh-disabled]", "owner", r.owner, transaction.CREATE_ENTITY.String(), p)
	if err != nil {
		return err
	}

	p, err = buildConfigureRecovery(entB, councilAddrs, 2)
	if err != nil {
		return err
	}
	if _, err = r.submitAndWait("configure_entity_recovery[rh-disabled]", "owner", r.owner, transaction.CONFIGURE_ENTITY_RECOVERY.String(), p); err != nil {
		return err
	}

	p, err = buildDisableEntity(entB)
	if err != nil {
		return err
	}
	if _, err = r.submitAndWait("disable_entity[rh]", "owner", r.owner, transaction.ALTER_ENTITY.String(), p); err != nil {
		return err
	}

	p, err = buildRequestRecovery(entB, newOwnerWallet.Address)
	if err != nil {
		return err
	}
	if _, err = r.submitAndWait("request_entity_recovery[rh-disabled]", "recovery[0]", rec0, transaction.REQUEST_ENTITY_RECOVERY.String(), p); err != nil {
		return err
	}

	p, err = buildCreateEntity(r.cfg.Entity.Name+"-rh-timelock", transaction.EntityType(r.cfg.Entity.Type), rootEntity, nil)
	if err != nil {
		return err
	}
	entC, err := r.submitAndWait("create_entity[rh-timelock]", "owner", r.owner, transaction.CREATE_ENTITY.String(), p)
	if err != nil {
		return err
	}

	p, err = buildConfigureRecovery(entC, []string{rec0.Address}, 1)
	if err != nil {
		return err
	}
	if _, err = r.submitAndWait("configure_entity_recovery[rh-timelock]", "owner", r.owner, transaction.CONFIGURE_ENTITY_RECOVERY.String(), p); err != nil {
		return err
	}

	p, err = buildConfigureRecovery(entC, []string{rec1.Address}, 1)
	if err != nil {
		return err
	}
	if _, err = r.submitAndWait("reconfigure_entity_recovery[rh-timelock]", "owner", r.owner, transaction.CONFIGURE_ENTITY_RECOVERY.String(), p); err != nil {
		return err
	}

	p, err = buildRequestRecovery(entC, newOwnerWallet.Address)
	if err != nil {
		return err
	}
	if err = r.submitExpectDenied("request_denied[new-council]", "recovery[1]", rec1, transaction.REQUEST_ENTITY_RECOVERY.String(), p, "recovery wallet"); err != nil {
		return err
	}
	if _, err = r.submitAndWait("request_entity_recovery[rh-timelock-oldcouncil]", "recovery[0]", rec0, transaction.REQUEST_ENTITY_RECOVERY.String(), p); err != nil {
		return err
	}

	p, err = buildCreateEntity(r.cfg.Entity.Name+"-rh-selftransfer", transaction.EntityType(r.cfg.Entity.Type), rootEntity, nil)
	if err != nil {
		return err
	}
	entD, err := r.submitAndWait("create_entity[rh-selftransfer]", "owner", r.owner, transaction.CREATE_ENTITY.String(), p)
	if err != nil {
		return err
	}

	p, err = buildTransferEntity(entD, r.owner.Address)
	if err != nil {
		return err
	}
	if err = r.submitExpectDenied("selftransfer_denied", "owner", r.owner, transaction.TRANSFER_ENTITY.String(), p, "current owner"); err != nil {
		return err
	}

	return nil
}

func (r *Runner) recordCheck(name, successOutput string, err error) error {
	sr := StepResult{Name: name}
	if err != nil {
		sr.Error = err.Error()
		r.recordStep(sr)
		return err
	}
	sr.Output = successOutput
	r.recordStep(sr)
	return nil
}

func (r *Runner) checkResolveDID(name, did string, assert func(transaction.DIDResolutionResult) error) error {
	res, err := r.client.ResolveDID(r.owner, did)
	if err == nil {
		err = assert(res)
	}
	return r.recordCheck(name, "resolved", err)
}

func (r *Runner) checkResolveDIDChain(name, did string, assert func([]transaction.DIDResolutionResult) error) error {
	res, err := r.client.ResolveDIDChain(r.owner, did)
	if err == nil {
		err = assert(res)
	}
	return r.recordCheck(name, fmt.Sprintf("chain length %d", len(res)), err)
}

func (r *Runner) checkVerifyClaim(name string, claim transaction.IdentityClaim, wantValid bool) error {
	res, err := r.client.VerifyIdentityClaim(r.owner, claim)
	if err == nil {
		if res.Valid != wantValid {
			err = fmt.Errorf("expected valid=%v, got valid=%v reasons=%v", wantValid, res.Valid, res.Reasons)
		} else if !wantValid && len(res.Reasons) == 0 {
			err = fmt.Errorf("expected non-empty reasons when valid=false")
		}
	}
	return r.recordCheck(name, fmt.Sprintf("valid=%v", wantValid), err)
}

// denialWindowSeconds is how long submitExpectDenied waits for an accepted tx to stay
// absent from the ledger before declaring the async denial confirmed. A var so tests can shrink it.
var denialWindowSeconds = 10

func (r *Runner) submitExpectDenied(name, signerRole string, signer *wallet.UL_Wallet, payloadType, payload, expectedSubstring string) error {
	sr := StepResult{Name: name, SignerRole: signerRole, PayloadType: payloadType}
	input := transaction.ULTransactionInput{
		BlockchainId: r.cfg.BlockchainId,
		Payload:      payload,
		PayloadType:  payloadType,
	}
	tx, err := r.client.Submit(signer, input)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(expectedSubstring)) {
			sr.Output = "denied as expected: " + err.Error()
			r.recordStep(sr)
			return nil
		}
		sr.Error = fmt.Sprintf("expected denial containing %q, got: %v", expectedSubstring, err)
		r.recordStep(sr)
		return fmt.Errorf("%s", sr.Error)
	}
	sr.TxId = tx.TransactionId

	// The node pre-validates synchronously but runs full validation (and any denial) in a
	// detached goroutine. A denied tx is never stored, so absence for the whole window confirms denial.
	stored, found := r.waitForAbsence(tx.TransactionId)
	if found {
		sr.Error = fmt.Sprintf("expected %q denial but transaction was stored (status=%s output=%s)", expectedSubstring, stored.Status, stored.Output)
		r.recordStep(sr)
		return fmt.Errorf("%s", sr.Error)
	}
	sr.Output = "denied (rejected by async validation, never stored)"
	r.recordStep(sr)
	return nil
}

// waitForAbsence polls for txid until denialWindowSeconds elapses. found=true as soon as
// the node returns the tx in any state; any fetch error (e.g. unknown id) counts as not-found.
func (r *Runner) waitForAbsence(txid string) (transaction.ULTransaction, bool) {
	interval := time.Duration(r.cfg.Poll.IntervalSeconds) * time.Second
	deadline := time.Now().Add(time.Duration(denialWindowSeconds) * time.Second)
	for {
		tx, err := r.client.GetTransaction(r.cfg.BlockchainId, txid)
		if err == nil {
			return tx, true
		}
		if time.Now().After(deadline) {
			return transaction.ULTransaction{}, false
		}
		time.Sleep(interval)
	}
}
