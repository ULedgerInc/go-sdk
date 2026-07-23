package identity

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"

	"github.com/ULedgerInc/go-sdk/pkg/transaction"
)

func randomNonceHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func marshal(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func buildCreateEntity(name string, etype transaction.EntityType, parent string, metadata map[string]string) (string, error) {
	return marshal(transaction.CreateEntityPayload{
		Name:       name,
		EntityType: etype,
		Parent:     parent,
		Metadata:   metadata,
	})
}

func buildAlterEntity(entityAddr string, metadata map[string]string) (string, error) {
	return marshal(transaction.AlterEntityPayload{
		EntityAddress: entityAddr,
		Metadata:      metadata,
	})
}

func buildLinkWallet(entityAddr, walletAddr, role string, perms *transaction.EntityPermission) (string, error) {
	return marshal(transaction.LinkWalletPayload{
		EntityAddress: entityAddr,
		WalletAddress: walletAddr,
		Role:          role,
		Permissions:   perms,
	})
}

func buildUnlinkWallet(entityAddr, walletAddr string) (string, error) {
	return marshal(transaction.UnlinkWalletPayload{
		EntityAddress: entityAddr,
		WalletAddress: walletAddr,
	})
}

func buildSetAccessList(entityAddr, operation, target string) (string, error) {
	return marshal(transaction.SetEntityAccessListPayload{
		EntityAddress: entityAddr,
		Operation:     operation,
		TargetAddress: target,
	})
}

func buildConfigureRecovery(entityAddr string, recoveryWallets []string, threshold int) (string, error) {
	return marshal(transaction.ConfigureEntityRecoveryPayload{
		EntityAddress:   entityAddr,
		RecoveryWallets: recoveryWallets,
		Threshold:       threshold,
	})
}

func buildRequestRecovery(entityAddr, newOwner string) (string, error) {
	return marshal(transaction.RequestEntityRecoveryPayload{
		EntityAddress: entityAddr,
		NewOwner:      newOwner,
	})
}

func buildApproveRecovery(requestId string) (string, error) {
	return marshal(transaction.ApproveEntityRecoveryPayload{RequestId: requestId})
}

func buildExecuteRecovery(requestId string) (string, error) {
	return marshal(transaction.ExecuteEntityRecoveryPayload{RequestId: requestId})
}

func buildCancelRecovery(requestId string) (string, error) {
	return marshal(transaction.CancelEntityRecoveryPayload{RequestId: requestId})
}

func buildAuthenticateInternal(subject string, referenceHeight uint64, referenceBlockHash string) (string, error) {
	return marshal(transaction.NewAuthenticateInternalPayload(subject, referenceHeight, referenceBlockHash))
}

func buildAuthenticateExternal(subject, audience, nonce string, metadata map[string]string) (string, error) {
	return marshal(transaction.NewAuthenticateExternalPayload(subject, audience, nonce, metadata))
}

func buildDisableEntity(entityAddr string) (string, error) {
	disabled := false
	return marshal(transaction.AlterEntityPayload{
		EntityAddress: entityAddr,
		Enabled:       &disabled,
	})
}

func buildTransferEntity(entityAddr, newOwner string) (string, error) {
	return marshal(transaction.TransferEntityPayload{
		EntityAddress: entityAddr,
		NewOwner:      newOwner,
	})
}
