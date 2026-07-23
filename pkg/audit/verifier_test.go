package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
)

func signedBlock(t *testing.T) (*transaction.TxInclusionProofPackage, crypto.KeyType) {
	return signedBlockWithHexEncoder(t, hex.EncodeToString)
}

func signedBlockWithHexEncoder(t *testing.T, encodeHex func([]byte) string) (*transaction.TxInclusionProofPackage, crypto.KeyType) {
	t.Helper()
	txs := make([]*transaction.ULTransaction, 0, 3)
	for _, id := range []string{"aa", "bb", "cc"} {
		tx := &transaction.ULTransaction{}
		tx.TransactionId = id
		txs = append(txs, tx)
	}
	root, err := transaction.GenerateMerkleRoot(txs, nil, nil)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	block := &transaction.UL_Block{
		BlockchainId:    "chain-1",
		Height:          1,
		Version:         "v1",
		HashingStrategy: crypto.HASH_SHA3_512.String(),
		Transactions:    txs,
		ProofMerkleRoot: encodeHex(root),
		MerkleRoot:      encodeHex(crypto.Hash(root, crypto.HASH_SHA3_512)),
	}
	block.Hash = encodeHex(crypto.Hash(block.GetHashData(), crypto.HASH_SHA3_512))

	key := crypto.NewED25519Key(sha256.New())
	seed := make([]byte, 32)
	if err := key.GenerateKeyFromSeed(seed); err != nil {
		t.Fatalf("key: %v", err)
	}
	sig, err := key.SignData([]byte(block.Hash))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	block.NodeSignature = encodeHex(sig)
	block.InstanceId = block.BlockchainId + key.GetPublicKeyHex(true)

	pkg, err := transaction.AssembleTxInclusionPackage(block, nil, "bb")
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	return pkg, crypto.KeyTypeED25519
}

func TestVerifyTxInclusionProof_Valid(t *testing.T) {
	pkg, kt := signedBlock(t)
	if err := VerifyTxInclusionProof(pkg, "bb", kt, "chain-1"); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestVerifyTxInclusionProof_UppercaseCasingStillValid(t *testing.T) {
	pkg, kt := signedBlockWithHexEncoder(t, crypto.BytesToHex)
	if err := VerifyTxInclusionProof(pkg, "bb", kt, "chain-1"); err != nil {
		t.Fatalf("expected uppercase hex fields to still verify, got %v", err)
	}
}

func TestVerifyTxInclusionProof_WrongChain(t *testing.T) {
	pkg, kt := signedBlock(t)
	if err := VerifyTxInclusionProof(pkg, "bb", kt, "wrong-chain"); err == nil {
		t.Fatal("expected chain-id mismatch")
	}
}

func TestVerifyTxInclusionProof_WrongSigner(t *testing.T) {
	pkg, kt := signedBlock(t)
	other := crypto.NewED25519Key(sha256.New())
	seed := make([]byte, 32)
	seed[0] = 9
	if err := other.GenerateKeyFromSeed(seed); err != nil {
		t.Fatalf("key: %v", err)
	}
	pkg.Block.InstanceId = pkg.Block.BlockchainId + other.GetPublicKeyHex(true)
	if err := VerifyTxInclusionProof(pkg, "bb", kt, "chain-1"); err == nil {
		t.Fatal("expected signature failure when the block's declared signer key does not match who signed it")
	}
}

func TestVerifyTxInclusionProof_TamperedProof(t *testing.T) {
	pkg, kt := signedBlock(t)
	pkg.Proof.Siblings[0].Hash[0] ^= 0xff
	if err := VerifyTxInclusionProof(pkg, "bb", kt, "chain-1"); err == nil {
		t.Fatal("expected inclusion failure after tampering the proof")
	}
}

func TestVerifyTxInclusionProof_TamperedRoot(t *testing.T) {
	pkg, kt := signedBlock(t)
	pkg.Block.MerkleRoot = "deadbeef"
	if err := VerifyTxInclusionProof(pkg, "bb", kt, "chain-1"); err == nil {
		t.Fatal("expected failure after tampering the merkle root")
	}
}

func TestVerifyTxInclusionProof_WrongTxId(t *testing.T) {
	pkg, kt := signedBlock(t)
	if err := VerifyTxInclusionProof(pkg, "aa", kt, "chain-1"); err == nil {
		t.Fatal("expected tx-id mismatch when asking for a different transaction than the proof covers")
	}
}

func TestVerifyTxInclusionProof_JSONRoundTrip(t *testing.T) {
	pkg, kt := signedBlock(t)
	data, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got transaction.TxInclusionProofPackage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := VerifyTxInclusionProof(&got, "bb", kt, "chain-1"); err != nil {
		t.Fatalf("expected a JSON round-tripped served proof to verify, got %v", err)
	}
}
