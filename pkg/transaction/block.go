package transaction

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"golang.org/x/crypto/sha3"
)

type BlockProofSystem string

const BlockProofSystemStark BlockProofSystem = "stark"

func (system BlockProofSystem) Normalize() BlockProofSystem {
	if system == BlockProofSystemStark {
		return BlockProofSystemStark
	}
	return ""
}

// BlockCrossReference is the subset of a block's cross-reference needed to verify
// a served tx-inclusion proof offline: BlockHash feeds GetHashData, MerkleRoot
// feeds the tx-merkle-tree leaves.
type BlockCrossReference struct {
	BlockHash  string `json:"blockHash"`
	MerkleRoot string `json:"merkleRoot"`
}

// BlockCheckpoint is a block's checkpoint header.
type BlockCheckpoint struct {
	RootOfRoots      []string `json:"rootOfRoots"`
	Epoch            uint64   `json:"epoch"`
	RosterGenesisIds []string `json:"rosterGenesisIds"`
}

// UL_Block carries the fields that feed the block hash, plus
// ProofMerkleRoot/InstanceId/NodeSignature/HashingStrategy needed to verify a
// served tx-inclusion proof package offline.
type UL_Block struct {
	BlockchainId      string                `json:"blockchainId"`
	PreviousBlockHash string                `json:"previousBlockHash"`
	NodeSignature     string                `json:"nodeSignature"`
	InstanceId        string                `json:"instanceId"`
	Hash              string                `json:"blockHash"`
	Version           string                `json:"version"`
	NodeVersion       string                `json:"nodeVersion"`
	Height            uint64                `json:"height"`
	HashingStrategy   string                `json:"hashingStrategy"`
	Transactions      []*ULTransaction      `json:"transactions"`
	MerkleRoot        string                `json:"merkleRoot"`
	ProofMerkleRoot   string                `json:"proofMerkleRoot"`
	ProofSystem       BlockProofSystem      `json:"proofSystem,omitempty"`
	CrossReferences   []BlockCrossReference `json:"crossReferences"`
	Checkpoint        *BlockCheckpoint      `json:"checkpoint,omitempty"`
}

// GetHashData returns the block's canonical hash preimage; the block hash is
// Hash(GetHashData(), HashingStrategy).
func (b UL_Block) GetHashData() []byte {
	var buf bytes.Buffer

	writeField := func(s string) {
		var sz [8]byte
		binary.BigEndian.PutUint64(sz[:], uint64(len(s)))
		buf.WriteByte('|')
		buf.Write(sz[:])
		buf.WriteByte('|')
		buf.WriteString(s)
	}

	writeField(b.Version)
	writeField(b.NodeVersion)
	writeField(b.BlockchainId)
	writeField(b.PreviousBlockHash)

	var h [8]byte
	binary.BigEndian.PutUint64(h[:], b.Height)
	buf.WriteByte('|')
	buf.Write(h[:])

	writeField(b.MerkleRoot)

	for _, t := range b.Transactions {
		writeField(t.GetTransactionId())
		buf.WriteByte('|')
	}

	var xr [8]byte
	binary.BigEndian.PutUint64(xr[:], uint64(len(b.CrossReferences)))
	buf.Write(xr[:])
	buf.WriteByte('|')

	for _, crossReference := range b.CrossReferences {
		buf.WriteString(crossReference.BlockHash)
		buf.WriteByte('|')
	}

	if b.Checkpoint != nil {
		buf.WriteString("|checkpoint|")
		var ep [8]byte
		binary.BigEndian.PutUint64(ep[:], b.Checkpoint.Epoch)
		buf.Write(ep[:])
		for _, limb := range b.Checkpoint.RootOfRoots {
			writeField(limb)
		}
		for _, gid := range b.Checkpoint.RosterGenesisIds {
			writeField(gid)
		}
	}

	if b.ProofSystem.Normalize() == BlockProofSystemStark {
		buf.WriteString("|proofSystem|")
		buf.WriteString(string(BlockProofSystemStark))
	}

	return buf.Bytes()
}

// Merkle tree

const (
	merkleLeafPrefix = 0x00
	merkleNodePrefix = 0x01
)

func merkleHash(prefix byte, parts ...[]byte) []byte {
	hasher := sha3.New512()
	hasher.Write([]byte{prefix})
	for _, part := range parts {
		hasher.Write(part)
	}
	return hasher.Sum(nil)
}

func buildMerkleLeaves(transactions []*ULTransaction, previousMerkleRoot []byte, crossReferences []BlockCrossReference) ([][]byte, error) {
	leaves := make([][]byte, 0, len(transactions)+1+len(crossReferences))
	for _, tx := range transactions {
		txIdBytes, err := crypto.HexToBytes(tx.TransactionId)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, merkleHash(merkleLeafPrefix, txIdBytes))
	}
	leaves = append(leaves, merkleHash(merkleLeafPrefix, previousMerkleRoot))
	for _, ref := range crossReferences {
		refBytes, err := crypto.HexToBytes(ref.MerkleRoot)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, merkleHash(merkleLeafPrefix, refBytes))
	}
	return leaves, nil
}

func padMerkleLeaves(leaves [][]byte) [][]byte {
	depth := bits.Len(uint(len(leaves) - 1))
	emptyLeaf := merkleHash(merkleLeafPrefix)
	for len(leaves) < 1<<depth {
		leaves = append(leaves, emptyLeaf)
	}
	return leaves
}

// GenerateMerkleRoot computes the SHA3-512 merkle root over transaction ids, the
// previous merkle root, and cross-reference roots.
func GenerateMerkleRoot(transactions []*ULTransaction, previousMerkleRoot []byte, crossReferences []BlockCrossReference) ([]byte, error) {
	leaves, err := buildMerkleLeaves(transactions, previousMerkleRoot, crossReferences)
	if err != nil {
		return nil, err
	}
	leaves = padMerkleLeaves(leaves)

	level := leaves
	for len(level) > 1 {
		next := make([][]byte, len(level)/2)
		for i := range next {
			next[i] = merkleHash(merkleNodePrefix, level[2*i], level[2*i+1])
		}
		level = next
	}

	return level[0], nil
}

// Tx inclusion proof

type MerkleSibling struct {
	Hash           []byte `json:"hash"`
	IsRightSibling bool   `json:"isRightSibling"`
}

type TxInclusionProof struct {
	TxId      string          `json:"txId"`
	LeafIndex int             `json:"leafIndex"`
	Siblings  []MerkleSibling `json:"siblings"`
}

type TxInclusionProofPackage struct {
	Proof *TxInclusionProof `json:"proof"`
	Block *UL_Block         `json:"block"`
}

func BuildTxInclusionProof(transactions []*ULTransaction, previousMerkleRoot []byte, crossReferences []BlockCrossReference, txId string) (*TxInclusionProof, error) {
	index := -1
	for i, tx := range transactions {
		if tx.TransactionId == txId {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, fmt.Errorf("transaction %s not found in block", txId)
	}

	leaves, err := buildMerkleLeaves(transactions, previousMerkleRoot, crossReferences)
	if err != nil {
		return nil, err
	}
	leaves = padMerkleLeaves(leaves)

	siblings := make([]MerkleSibling, 0)
	idx := index
	level := leaves
	for len(level) > 1 {
		if idx%2 == 0 {
			siblings = append(siblings, MerkleSibling{Hash: level[idx+1], IsRightSibling: true})
		} else {
			siblings = append(siblings, MerkleSibling{Hash: level[idx-1], IsRightSibling: false})
		}
		next := make([][]byte, len(level)/2)
		for i := range next {
			next[i] = merkleHash(merkleNodePrefix, level[2*i], level[2*i+1])
		}
		level = next
		idx /= 2
	}

	return &TxInclusionProof{TxId: txId, LeafIndex: index, Siblings: siblings}, nil
}

func AssembleTxInclusionPackage(block *UL_Block, previousMerkleRoot []byte, txId string) (*TxInclusionProofPackage, error) {
	if block == nil {
		return nil, fmt.Errorf("nil block")
	}
	proof, err := BuildTxInclusionProof(block.Transactions, previousMerkleRoot, block.CrossReferences, txId)
	if err != nil {
		return nil, err
	}
	return &TxInclusionProofPackage{Proof: proof, Block: block}, nil
}

// VerifyTxInclusion walks the sibling path from the leaf and checks the result
// against ProofMerkleRoot.
func VerifyTxInclusion(proof *TxInclusionProof, expectedMerkleRoot string) error {
	if proof == nil {
		return fmt.Errorf("nil inclusion proof")
	}
	txIdBytes, err := crypto.HexToBytes(proof.TxId)
	if err != nil {
		return fmt.Errorf("invalid transaction id: %w", err)
	}
	current := merkleHash(merkleLeafPrefix, txIdBytes)
	for _, sib := range proof.Siblings {
		if sib.IsRightSibling {
			current = merkleHash(merkleNodePrefix, current, sib.Hash)
		} else {
			current = merkleHash(merkleNodePrefix, sib.Hash, current)
		}
	}
	expectedBytes, err := crypto.HexToBytes(expectedMerkleRoot)
	if err != nil {
		return fmt.Errorf("invalid merkle root: %w", err)
	}
	if !bytes.Equal(current, expectedBytes) {
		return fmt.Errorf("merkle root mismatch")
	}
	return nil
}
