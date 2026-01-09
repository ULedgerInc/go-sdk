package transaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/ULedgerInc/golang-sdk/pkg/crypto"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
)

// ===================
// TRANSACTION PARSING
// ===================

const (
	SEPARATOR           = "|"
	TIMESTAMP_SIZE      = 8 // Golang uses 64 bits for timestamps in the Unix Format
	TRANSACTION_VERSION = "2.0.0"
	CHUNK_SIZE          = 16
	DEPTH               = 6
)

var (
	ECDSA_CURVE = ecc.BN254.ScalarField()
	BLS_CURVE   = ecc.BW6_761.ScalarField()
)

type ErrParsingTransactionStatus struct {
	Msg string
}

func (e *ErrParsingTransactionStatus) Error() string {
	return fmt.Sprintf("invalid transaction status, %s", e.Msg)
}

type UL_TransactionStatus int

const (
	INVALID_TX_STATUS UL_TransactionStatus = 0
	TX_SUBMITTED      UL_TransactionStatus = 1
	TX_ACCEPTED       UL_TransactionStatus = 2
	TX_REJECTED       UL_TransactionStatus = 3
)

func (ts UL_TransactionStatus) String() string {
	switch ts {
	case TX_SUBMITTED:
		return "SUBMITTED"
	case TX_ACCEPTED:
		return "ACCEPTED"
	case TX_REJECTED:
		return "REJECTED"
	default:
		return ""
	}
}

func ParseTransactionStatus(str string) (UL_TransactionStatus, error) {
	switch strings.ToUpper(str) {
	case TX_SUBMITTED.String():
		return TX_SUBMITTED, nil
	case TX_ACCEPTED.String():
		return TX_ACCEPTED, nil
	case TX_REJECTED.String():
		return TX_REJECTED, nil
	default:
		return INVALID_TX_STATUS, &ErrParsingTransactionStatus{Msg: str}
	}
}

type ErrParsingTransactionType struct {
	Msg string
}

func (e *ErrParsingTransactionType) Error() string {
	return fmt.Sprintf("invalid transaction type, %s", e.Msg)
}

type ULTransactionType int

const (
	INVALID_TX_TYPE ULTransactionType = iota
	TX_DATA
	TX_CREATE_WALLET
	TX_ALTER_WALLET
	DEPLOY_SMART_CONTRACT
	INVOKE_SMART_CONTRACT
	UPGRADE_SMART_CONTRACT
	ROLLBACK_SMART_CONTRACT
	CREATE_TOKEN
	TRANSFER_TOKEN
	APPROVE_TOKEN
	MINT_TOKEN
	BURN_TOKEN
	MINT_NFT
	TRANSFER_NFT
	APPROVE_NFT
	SET_APPROVAL_FOR_ALL
	TRANSFER_MULTI_TOKEN
	MINT_MULTI_TOKEN
	CONVERT_TOKEN
)

func (tt ULTransactionType) String() string {
	switch tt {
	case TX_DATA:
		return "DATA"
	case TX_CREATE_WALLET:
		return "CREATE_WALLET"
	case TX_ALTER_WALLET:
		return "ALTER_WALLET"
	case DEPLOY_SMART_CONTRACT:
		return "DEPLOY_SMART_CONTRACT"
	case INVOKE_SMART_CONTRACT:
		return "INVOKE_SMART_CONTRACT"
	case UPGRADE_SMART_CONTRACT:
		return "UPGRADE_SMART_CONTRACT"
	case ROLLBACK_SMART_CONTRACT:
		return "ROLLBACK_SMART_CONTRACT"
	case CREATE_TOKEN:
		return "CREATE_TOKEN"
	case TRANSFER_TOKEN:
		return "TRANSFER_TOKEN"
	case APPROVE_TOKEN:
		return "APPROVE_TOKEN"
	case MINT_TOKEN:
		return "MINT_TOKEN"
	case BURN_TOKEN:
		return "BURN_TOKEN"
	case MINT_NFT:
		return "MINT_NFT"
	case TRANSFER_NFT:
		return "TRANSFER_NFT"
	case APPROVE_NFT:
		return "APPROVE_NFT"
	case SET_APPROVAL_FOR_ALL:
		return "SET_APPROVAL_FOR_ALL"
	case TRANSFER_MULTI_TOKEN:
		return "TRANSFER_MULTI_TOKEN"
	case MINT_MULTI_TOKEN:
		return "MINT_MULTI_TOKEN"
	case CONVERT_TOKEN:
		return "CONVERT_TOKEN"
	default:
		return ""
	}
}

func ParseTransactionType(str string) (ULTransactionType, error) {
	switch strings.ToUpper(str) {
	case TX_DATA.String():
		return TX_DATA, nil
	case DEPLOY_SMART_CONTRACT.String():
		return DEPLOY_SMART_CONTRACT, nil
	case INVOKE_SMART_CONTRACT.String():
		return INVOKE_SMART_CONTRACT, nil
	case UPGRADE_SMART_CONTRACT.String():
		return UPGRADE_SMART_CONTRACT, nil
	case ROLLBACK_SMART_CONTRACT.String():
		return ROLLBACK_SMART_CONTRACT, nil
	case CREATE_TOKEN.String():
		return CREATE_TOKEN, nil
	case TRANSFER_TOKEN.String():
		return TRANSFER_TOKEN, nil
	case APPROVE_TOKEN.String():
		return APPROVE_TOKEN, nil
	case MINT_TOKEN.String():
		return MINT_TOKEN, nil
	case BURN_TOKEN.String():
		return BURN_TOKEN, nil
	case MINT_NFT.String():
		return MINT_NFT, nil
	case TRANSFER_NFT.String():
		return TRANSFER_NFT, nil
	case APPROVE_NFT.String():
		return APPROVE_NFT, nil
	case SET_APPROVAL_FOR_ALL.String():
		return SET_APPROVAL_FOR_ALL, nil
	case TRANSFER_MULTI_TOKEN.String():
		return TRANSFER_MULTI_TOKEN, nil
	case MINT_MULTI_TOKEN.String():
		return MINT_MULTI_TOKEN, nil
	case CONVERT_TOKEN.String():
		return CONVERT_TOKEN, nil
	default:
		return INVALID_TX_TYPE, &ErrParsingTransactionType{Msg: str}
	}
}

type ErrParsingTransactionOutput struct {
	Msg string
}

func (e *ErrParsingTransactionOutput) Error() string {
	return fmt.Sprintf("invalid transaction output, %s", e.Msg)
}

type UL_TransactionOutput int

const (
	INVALID_TX_OUTPUT                UL_TransactionOutput = 0
	TO_BE_PROCESSED                  UL_TransactionOutput = 1
	TX_SUCCESS                       UL_TransactionOutput = 2
	TX_REJECTED_BY_DUPLICATE         UL_TransactionOutput = 3
	TX_REJECTED_BY_UNEXISTING        UL_TransactionOutput = 4
	TX_REJECTED_BY_DISABLED          UL_TransactionOutput = 5
	TX_REJECTED_BY_UNAUTHORIZED      UL_TransactionOutput = 6
	TX_REJECTED_BY_INVALID_SIGNATURE UL_TransactionOutput = 7
	TX_TRANSACTION_ERROR             UL_TransactionOutput = 8
	TX_REJECTED_BY_INVALID_KEY_TYPE  UL_TransactionOutput = 9
)

func (tt UL_TransactionOutput) String() string {
	switch tt {
	case TO_BE_PROCESSED:
		return "TO_BE_PROCESSED"
	case TX_SUCCESS:
		return "SUCCESS"
	case TX_REJECTED_BY_DUPLICATE:
		return "REJECTED_BY_DUPLICATE"
	case TX_REJECTED_BY_UNEXISTING:
		return "REJECTED_BY_UNEXISTING"
	case TX_REJECTED_BY_DISABLED:
		return "REJECTED_BY_DISABLED"
	case TX_REJECTED_BY_UNAUTHORIZED:
		return "REJECTED_BY_UNAUTHORIZED"
	case TX_REJECTED_BY_INVALID_SIGNATURE:
		return "REJECTED_BY_INVALID_SIGNATURE"
	case TX_TRANSACTION_ERROR:
		return "TRANSACTION_ERROR"
	case TX_REJECTED_BY_INVALID_KEY_TYPE:
		return "REJECTED_BY_INVALID_KEY_TYPE"
	default:
		return ""
	}
}

func ParseTransactionOutput(str string) (UL_TransactionOutput, error) {
	switch strings.ToUpper(str) {
	case TO_BE_PROCESSED.String():
		return TO_BE_PROCESSED, nil
	case TX_SUCCESS.String():
		return TX_SUCCESS, nil
	case TX_REJECTED_BY_DUPLICATE.String():
		return TX_REJECTED_BY_DUPLICATE, nil
	case TX_REJECTED_BY_UNEXISTING.String():
		return TX_REJECTED_BY_UNEXISTING, nil
	case TX_REJECTED_BY_DISABLED.String():
		return TX_REJECTED_BY_DISABLED, nil
	case TX_REJECTED_BY_UNAUTHORIZED.String():
		return TX_REJECTED_BY_UNAUTHORIZED, nil
	case TX_REJECTED_BY_INVALID_SIGNATURE.String():
		return TX_REJECTED_BY_INVALID_SIGNATURE, nil
	case TX_TRANSACTION_ERROR.String():
		return TX_TRANSACTION_ERROR, nil
	case TX_REJECTED_BY_INVALID_KEY_TYPE.String():
		return TX_REJECTED_BY_INVALID_KEY_TYPE, nil
	default:
		return INVALID_TX_OUTPUT, &ErrParsingTransactionOutput{Msg: str}
	}
}

type VectorClock map[string]uint64

type Timestamp struct {
	ExactTime       time.Time
	ApproximateTime time.Time
}

// ===========
// TRANSACTION
// ===========

type Transaction interface {
	GetVectorClock() VectorClock
	GetTimestamp() Timestamp
	GetTransactionId() string
	GetTransactionSignatureBody() string
	SetTransactionWeight()
}

type TransactionCommitment struct {
	BlockchainIdHigh []byte
	BlockchainIdLow  []byte
	FromHigh         []byte
	FromLow          []byte
	ToHigh           []byte
	ToLow            []byte
	PayloadRoot      []byte
	Timestamp        uint64
	SuggestorHigh    []byte
	SuggestorLow     []byte
	ProofElements    [][]byte
	ChunkIndex       int64
	NumLeaves        uint64
	ChunkSize        int
	ProofChunk       []byte
	Depth            int
}

// Helper to hash the data! Using SHA256
func splitHash32(data string) ([]byte, []byte, error) {
	hash := sha256.Sum256([]byte(data))
	if len(hash) != 32 {
		return nil, nil, fmt.Errorf("expected 32 byte hash, got %d", len(hash))
	}
	return hash[:16], hash[16:], nil
}

func (t *ULTransactionInput) GetSignatureCommitment(hasher hash.Hash, computeRoot bool) (TransactionCommitment, error) {
	// Split BlockchainId hash
	blockchainIdHigh, blockchainIdLow, err := splitHash32(t.BlockchainId)
	if err != nil {
		return TransactionCommitment{}, err
	}

	// Split From address hash
	fromHigh, fromLow, err := splitHash32(t.From)
	if err != nil {
		return TransactionCommitment{}, err
	}

	// Split To address hash
	toHigh, toLow, err := splitHash32(t.To)
	if err != nil {
		return TransactionCommitment{}, err
	}

	// Split Suggestor hash
	suggestorHigh, suggestorLow, err := splitHash32(t.Suggestor)
	if err != nil {
		return TransactionCommitment{}, err
	}

	var field *big.Int

	switch t.KeyType {
	case crypto.KeyTypeBLS12377:
		field = BLS_CURVE
	default:
		field = ECDSA_CURVE
	}

	payloadRoot, proofElements, proofChunk, numLeaves, err := GenerateMerkleTreeWithHardBound([]byte(t.Payload), field, CHUNK_SIZE, DEPTH, hasher, uint64(0))
	if err != nil {
		return TransactionCommitment{}, err
	}

	return TransactionCommitment{
		BlockchainIdHigh: blockchainIdHigh,
		BlockchainIdLow:  blockchainIdLow,
		FromHigh:         fromHigh,
		FromLow:          fromLow,
		ToHigh:           toHigh,
		ToLow:            toLow,
		Timestamp:        uint64(t.SenderTimestamp.Unix()),
		SuggestorHigh:    suggestorHigh,
		SuggestorLow:     suggestorLow,
		ChunkIndex:       0, // Merkle Root
		ChunkSize:        CHUNK_SIZE,
		Depth:            DEPTH,
		PayloadRoot:      payloadRoot,
		ProofElements:    proofElements,
		NumLeaves:        numLeaves,
		ProofChunk:       proofChunk,
	}, nil
}

func (t *ULTransactionInput) GetUnboundCommitment(hasher hash.Hash) ([]byte, error) {
	var field *big.Int

	switch t.KeyType {
	case crypto.KeyTypeBLS12377:
		field = BLS_CURVE
	default:
		field = ECDSA_CURVE
	}

	payloadRoot, _, _, _, _, err := GenerateMerkleTree([]byte(t.Payload), field, CHUNK_SIZE, hasher, uint64(0))
	if err != nil {
		return nil, err
	}

	return payloadRoot, nil
}

func (t *ULTransactionInput) HashSignatureCommitment(hasher hash.Hash, commitment TransactionCommitment) ([]byte, error) {
	hasher.Reset()
	hasher.Write(commitment.BlockchainIdHigh)
	hasher.Write(commitment.BlockchainIdLow)
	hasher.Write(commitment.FromHigh)
	hasher.Write(commitment.FromLow)
	hasher.Write(commitment.ToHigh)
	hasher.Write(commitment.ToLow)
	hasher.Write(commitment.PayloadRoot)
	binary.Write(hasher, binary.BigEndian, commitment.Timestamp)
	hasher.Write(commitment.SuggestorHigh)
	hasher.Write(commitment.SuggestorLow)

	return hasher.Sum(nil), nil
}

type ULBlock struct {
	Hash              string            `json:"blockHash"`
	PreviousBlockHash string            `json:"previousBlockHash"`
	Height            int               `json:"height"`
	Transactions      []ULTransaction   `json:"transactions"`
	MerkleRoot        string            `json:"merkleRoot"`
	Voters            map[string]string `json:"voters"`
}

// These are the fields that are used to create a transaction!
type ULTransactionInput struct {
	BlockchainId    string         `json:"blockchainId"`
	To              string         `json:"to"`
	From            string         `json:"from"`
	Payload         string         `json:"payload"`
	SenderSignature string         `json:"senderSignature"`
	PayloadType     string         `json:"payloadType"`
	Suggestor       string         `json:"suggestor"`
	SenderTimestamp time.Time      `json:"senderTimestamp"`
	PayloadRoot     string         `json:"payloadRoot"`
	KeyType         crypto.KeyType `json:"keyType"`
}

// These fields are generated by the node!
type ULTransactionOutput struct {
	TransactionId string      `json:"transactionId"`
	BlockHeight   int         `json:"blockHeight"`
	Clock         VectorClock `json:"vectorClock"`
	Timestamp     Timestamp   `json:"timestamp"`
	Version       string      `json:"version"`
	Weight        int         `json:"weight"`
	Status        string      `json:"status"`
	Output        string      `json:"output"`
	Proof         string      `json:"proof"`
	ProofVersion  string      `json:"proofVersion"`
}

type ULTransaction struct {
	ULTransactionInput
	ULTransactionOutput
}

func (t *ULTransaction) GetVectorClock() VectorClock { return t.Clock }
func (t *ULTransaction) GetTimestamp() Timestamp     { return t.Timestamp }
func (t *ULTransaction) GetTransactionId() string    { return t.TransactionId }

func (t *ULTransaction) SetTransactionWeight() {
	weight := 0

	weight += len(t.BlockchainId)
	weight += len(t.TransactionId)
	weight += len(t.To)
	weight += len(t.From)
	weight += len(t.Payload)
	weight += len(t.SenderSignature)
	weight += len(t.Version)
	weight += len(t.Suggestor)

	// Add the size of the int fields
	weight += 16

	t.Weight = weight
}

func (t *ULTransaction) ToBytes() ([]byte, error) {
	// Convert the transaction to a byte slice
	return json.Marshal(t)
}

func TransactionFromBytes(data []byte) (*ULTransaction, error) {
	// Convert the byte slice to a transaction
	tx := &ULTransaction{}
	err := json.Unmarshal(data, tx)
	if err != nil {
		return nil, err
	}

	return tx, nil
}

func GenerateMerkleTreeWithHardBound(payload []byte, modulus *big.Int, chunkSize int, depth int, hasher hash.Hash, proofIndex uint64) ([]byte, [][]byte, []byte, uint64, error) {
	maxSize := chunkSize * (1 << depth) // Maximum size of the payload in bytes
	if len(payload) > maxSize {
		return nil, nil, nil, 0, fmt.Errorf("payload is too large, max size is %d bytes, got %d bytes", maxSize, len(payload))
	}

	modulusSizeBytes := len(modulus.Bytes())
	var proofChunk []byte
	var buf bytes.Buffer

	for i := 0; i < (1 << depth); i++ {
		chunk := make([]byte, chunkSize)

		// Only copy payload data if we haven't reached the end
		if i*chunkSize < len(payload) {
			start := i * chunkSize
			end := start + chunkSize
			if end > len(payload) {
				end = len(payload)
			}
			chunk = append(chunk, payload[start:end]...)
			// Padd with zeros to make sure it's a field element!
			chunk = append(chunk, make([]byte, modulusSizeBytes-len(chunk))...)
		}

		// Store proof chunk if this is the index we're proving
		if i == int(proofIndex) {
			proofChunk = make([]byte, len(chunk))
			copy(proofChunk, chunk)
		}

		// Ensure chunk fits in field
		if len(chunk) < modulusSizeBytes {
			// Pad with zeros to make it a valid field element
			chunk = append(chunk, make([]byte, modulusSizeBytes-len(chunk))...)
		}

		buf.Write(make([]byte, modulusSizeBytes-len(chunk)))
		buf.Write(chunk)
	}

	merkleRoot, proofElements, numLeaves, err := merkletree.BuildReaderProof(&buf, hasher, modulusSizeBytes, proofIndex)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	if numLeaves != uint64(1<<depth) {
		return nil, nil, nil, 0, fmt.Errorf("the number of leaves is not equal to the depth")
	}

	verified := merkletree.VerifyProof(hasher, merkleRoot, proofElements, proofIndex, numLeaves)
	if !verified {
		return nil, nil, nil, 0, fmt.Errorf("the created Merkle Proof is not valid")
	}

	return merkleRoot, proofElements, proofChunk, numLeaves, nil
}

func GenerateMerkleTree(payload []byte, modulus *big.Int, chunkSize int, hasher hash.Hash, proofIndex uint64) ([]byte, [][]byte, []byte, uint64, int, error) {
	modulusSizeBytes := len(modulus.Bytes())

	var proofChunk []byte
	nrLeaves := (len(payload) + chunkSize - 1) / chunkSize

	var buf bytes.Buffer
	// Print each chunk as we process it
	for i := 0; i < nrLeaves; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[start:end]
		paddedChunk := make([]byte, modulusSizeBytes-len(chunk))
		paddedChunk = append(paddedChunk, chunk...)
		if i == int(proofIndex) {
			proofChunk = make([]byte, len(paddedChunk))
			copy(proofChunk, paddedChunk)
		}
		// Fill with zeros to make sure it's a field element!
		buf.Write(paddedChunk)
	}

	merkleRoot, proofElements, numLeaves, err := merkletree.BuildReaderProof(&buf, hasher, modulusSizeBytes, proofIndex)
	if err != nil {
		return nil, nil, nil, 0, 0, err
	}

	verified := merkletree.VerifyProof(hasher, merkleRoot, proofElements, proofIndex, numLeaves)
	if !verified {
		return nil, nil, nil, 0, 0, fmt.Errorf("the created Merkle Proof is not valid")
	}
	treeDepth := int(math.Log2(float64(numLeaves)))
	return merkleRoot, proofElements, proofChunk, numLeaves, treeDepth, nil
}

type ContractArgs struct {
	Value []byte `json:"value"` // To match the serialization/deserialization of the contract
}

type InvokeContractPayload struct {
	FunctionName string         `json:"functionName"`
	Args         []ContractArgs `json:"args"`
	GasLimit     uint64         `json:"gasLimit"`
}

type RollbackContractPayload struct {
	TargetVersion  uint64 `json:"targetVersion"`
	RollbackReason string `json:"rollbackReason,omitempty"`
}

type UpgradeContractPayload struct {
	NewSourceCode string `json:"newSourceCode"`
	UpgradeReason string `json:"upgradeReason,omitempty"`
}

type CreateTokenPayload struct {
	TokenType     string `json:"tokenType"` // "ERC20", "ERC721", "ERC1155"
	Name          string `json:"name"`
	Symbol        string `json:"symbol"`
	Decimals      uint8  `json:"decimals,omitempty"`      // ERC20 only
	InitialSupply uint64 `json:"initialSupply,omitempty"` // ERC20 only
	BaseURI       string `json:"baseURI,omitempty"`       // NFT only
	Mintable      bool   `json:"mintable"`
	Burnable      bool   `json:"burnable"`
}

// Transfer payload (works for ERC20/ERC721/ERC1155)
type TransferTokenPayload struct {
	TokenAddress string   `json:"tokenAddress"`
	From         string   `json:"from,omitempty"` // Optional - defaults to tx.From
	To           string   `json:"to"`
	Amount       uint64   `json:"amount,omitempty"`   // ERC20/ERC1155
	TokenId      uint64   `json:"tokenId,omitempty"`  // ERC721/ERC1155
	TokenIds     []uint64 `json:"tokenIds,omitempty"` // ERC1155 batch
	Amounts      []uint64 `json:"amounts,omitempty"`  // ERC1155 batch
	Data         []byte   `json:"data,omitempty"`     // ERC1155 additional data
}

// Batch transfer payload for ERC1155
type BatchTransferTokenPayload struct {
	TokenAddress string   `json:"tokenAddress"`
	From         string   `json:"from,omitempty"` // Optional - defaults to tx.From
	To           string   `json:"to"`
	TokenIds     []uint64 `json:"tokenIds"`
	Amounts      []uint64 `json:"amounts"`
	Data         []byte   `json:"data,omitempty"`
}

// Approve payload
type ApproveTokenPayload struct {
	TokenAddress string `json:"tokenAddress"`
	Spender      string `json:"spender"`
	Amount       uint64 `json:"amount,omitempty"`  // ERC20/ERC1155
	TokenId      uint64 `json:"tokenId,omitempty"` // ERC721/ERC1155
}

// Mint payload
type MintTokenPayload struct {
	TokenAddress string `json:"tokenAddress"`
	To           string `json:"to"`
	Amount       uint64 `json:"amount,omitempty"`   // ERC20
	TokenId      uint64 `json:"tokenId,omitempty"`  // ERC721
	TokenURI     string `json:"tokenURI,omitempty"` // ERC721 metadata
}

// Burn payload
type BurnTokenPayload struct {
	TokenAddress string `json:"tokenAddress"`
	Amount       uint64 `json:"amount,omitempty"`  // ERC20/ERC1155
	TokenId      uint64 `json:"tokenId,omitempty"` // ERC721/ERC1155
}

// Set approval for all payload (ERC721/ERC1155)
type SetApprovalForAllPayload struct {
	TokenAddress string `json:"tokenAddress"`
	Operator     string `json:"operator"`
	Approved     bool   `json:"approved"`
}

// Token metadata structure
type TokenMetadata struct {
	TokenType    string `json:"tokenType"`
	Name         string `json:"name"`
	Symbol       string `json:"symbol"`
	Decimals     uint8  `json:"decimals,omitempty"`
	Owner        string `json:"owner"`
	BlockchainId string `json:"blockchainId"`
	Mintable     bool   `json:"mintable"`
	Burnable     bool   `json:"burnable"`
	BaseURI      string `json:"baseURI,omitempty"`
	TotalSupply  uint64 `json:"totalSupply"`
	CreatedBlock int    `json:"createdBlock"`
}

// Convert token payload (ERC1155 semi-fungible)
type ConvertTokenPayload struct {
	TokenAddress   string `json:"tokenAddress"`
	FromTokenId    uint64 `json:"fromTokenId"`
	ToTokenId      uint64 `json:"toTokenId,omitempty"`
	Amount         uint64 `json:"amount"`
	NewTokenURI    string `json:"newTokenURI,omitempty"`
	PreserveTokens bool   `json:"preserveTokens,omitempty"` // Whether to keep original tokens (default: burn them)
}

var (
	ERC20_TOKEN_TYPE   = "ERC20"
	ERC721_TOKEN_TYPE  = "ERC721"
	ERC1155_TOKEN_TYPE = "ERC1155"
)
