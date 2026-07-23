package identity

import (
	"fmt"

	"github.com/ULedgerInc/go-sdk/pkg/credential"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
)

const credentialsStatusListId = "1"

// runCredentialsPhase exercises the Verifiable Credential surface using a claim
// that stays true for the whole run — the owner's admin standing on the root
// entity — since the agent entity is later disabled by the kill-switch step.
func (r *Runner) runCredentialsPhase() error {
	if !r.cfg.Credentials.Enabled {
		return nil
	}
	subjectDID := buildDID(r.cfg.BlockchainId, r.owner.Address)
	claim := transaction.IdentityClaim{
		SubjectDID:    subjectDID,
		EntityAddress: r.rootEntityAddr,
		Role:          transaction.EntityRoleAdmin,
	}

	jws, jti, err := r.issueIdentityCredentialStep(claim)
	if err != nil {
		return err
	}
	if err := r.verifyCredentialOfflineStep(jws, subjectDID); err != nil {
		return err
	}
	if err := r.dedupCredentialStep(claim, jti); err != nil {
		return err
	}
	return r.issueAuthenticationCredentialStep(subjectDID)
}

// offlineVerifyCredential resolves and verifies the subject DID's signed
// envelope, pins its signer key, fetches a fresh status list, and verifies
// the credential JWT against all three.
func (r *Runner) offlineVerifyCredential(jws, subjectDID string) (*credential.CredentialPayload, error) {
	env, err := r.client.ResolveDIDSigned(r.owner, subjectDID)
	if err != nil {
		return nil, fmt.Errorf("resolve did signed: %w", err)
	}
	if _, err := credential.VerifySignedResolution(env, r.cfg.BlockchainId); err != nil {
		return nil, fmt.Errorf("verify signed resolution: %w", err)
	}
	statusListJWS, err := r.client.FetchStatusList(r.cfg.BlockchainId, credentialsStatusListId)
	if err != nil {
		return nil, fmt.Errorf("fetch status list: %w", err)
	}
	return credential.VerifyCredentialJWT(jws, credential.VerifyOptions{
		KeyType:            r.cfg.ChainKeyTypeValue(),
		SignerPublicKeyHex: env.Signer.PublicKey,
		StatusListJWS:      statusListJWS,
	})
}

func (r *Runner) issueIdentityCredentialStep(claim transaction.IdentityClaim) (string, string, error) {
	jws, jti, err := r.client.IssueIdentityCredential(claim, "")
	if err := r.recordCheck("credential-issue", fmt.Sprintf("jti=%s no evidence", jti), err); err != nil {
		return "", "", err
	}
	return jws, jti, nil
}

func (r *Runner) verifyCredentialOfflineStep(jws, subjectDID string) error {
	_, err := r.offlineVerifyCredential(jws, subjectDID)
	return r.recordCheck("credential-verify-offline", "verified", err)
}

func (r *Runner) dedupCredentialStep(claim transaction.IdentityClaim, jti string) error {
	_, jti2, err := r.client.IssueIdentityCredential(claim, "")
	if err == nil && jti2 != jti {
		err = fmt.Errorf("expected dedup jti %q, got %q", jti, jti2)
	}
	return r.recordCheck("credential-dedup", fmt.Sprintf("jti=%s", jti2), err)
}

func (r *Runner) issueAuthenticationCredentialStep(subjectDID string) error {
	const name = "credential-issue-authentication"
	if r.authInternalTxId == "" {
		r.recordStep(StepResult{Name: name, Output: "skipped: no authenticate transaction id retained"})
		return nil
	}
	jws, _, err := r.client.IssueAuthenticationCredential(r.cfg.BlockchainId, r.authInternalTxId)
	if err == nil {
		_, err = r.offlineVerifyCredential(jws, subjectDID)
	}
	return r.recordCheck(name, "issued and verified", err)
}
