package audit

import (
	"bytes"
	"fmt"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
)

// VerifyTxInclusionProof checks, entirely offline, that a served proof package
// covers expectedTxId in a block of expectedBlockchainId whose merkle root,
// block hash, and node signature all verify under the block's hashing strategy.
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
	valid, err := crypto.IsSignatureValid(signerKey, []byte(b.Hash), sig, keyType)
	if err != nil {
		return fmt.Errorf("node signature verify: %w", err)
	}
	if !valid {
		return fmt.Errorf("node signature invalid")
	}
	return nil
}
