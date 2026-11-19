package audit

import (
	"bytes"
	"fmt"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
)

// VerifyTxInclusionProof mirrors node's internal/audit.VerifyTxInclusionProof:
// given a proof package served by GetTransactionProof, it checks, entirely
// offline, that the proof covers expectedTxId, that the block belongs to
// expectedBlockchainId, that the inclusion proof binds to the block's
// declared merkle root, that the merkle root and block hash bindings match
// the block's declared hashing strategy, and that the block's node signature
// verifies against the signer key embedded in InstanceId.
func VerifyTxInclusionProof(pkg *transaction.TxInclusionProofPackage, expectedTxId string, keyType crypto.KeyType, expectedBlockchainId string) error {
	if pkg == nil || pkg.Proof == nil || pkg.Block == nil {
		return fmt.Errorf("incomplete proof package")
	}
	if pkg.Proof.TxId != expectedTxId {
		return fmt.Errorf("transaction id mismatch: got %q want %q", pkg.Proof.TxId, expectedTxId)
	}
	b := pkg.Block

	if b.BlockchainId != expectedBlockchainId {
		return fmt.Errorf("blockchain id mismatch: got %q want %q", b.BlockchainId, expectedBlockchainId)
	}

	if err := transaction.VerifyTxInclusion(pkg.Proof, b.ProofMerkleRoot); err != nil {
		return fmt.Errorf("inclusion: %w", err)
	}

	strat, err := crypto.ParseHashingStrategy(b.HashingStrategy)
	if err != nil {
		return fmt.Errorf("hashing strategy: %w", err)
	}

	rawRoot, err := crypto.HexToBytes(b.ProofMerkleRoot)
	if err != nil {
		return fmt.Errorf("proof merkle root decode: %w", err)
	}
	merkleRootBytes, err := crypto.HexToBytes(b.MerkleRoot)
	if err != nil {
		return fmt.Errorf("block merkle root decode: %w", err)
	}
	if !bytes.Equal(crypto.Hash(rawRoot, strat), merkleRootBytes) {
		return fmt.Errorf("merkle root binding mismatch")
	}

	hashBytes, err := crypto.HexToBytes(b.Hash)
	if err != nil {
		return fmt.Errorf("block hash decode: %w", err)
	}
	if !bytes.Equal(crypto.Hash(b.GetHashData(), strat), hashBytes) {
		return fmt.Errorf("block hash mismatch")
	}

	if len(b.InstanceId) <= len(b.BlockchainId) {
		return fmt.Errorf("block instance id missing signer key")
	}
	signerKey := b.InstanceId[len(b.BlockchainId):]
	sig, err := crypto.HexToBytes(b.NodeSignature)
	if err != nil {
		return fmt.Errorf("node signature decode: %w", err)
	}
	valid, err := crypto.IsSignatureValid(crypto.DomainBlock, signerKey, []byte(b.Hash), sig, keyType)
	if err != nil {
		return fmt.Errorf("node signature verify: %w", err)
	}
	if !valid {
		return fmt.Errorf("node signature invalid")
	}
	return nil
}
