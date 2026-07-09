package transaction

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"golang.org/x/crypto/sha3"
)

// ===================
// TRANSACTION PARSING
// ===================

const (
	SEPARATOR           = "|"
	TIMESTAMP_SIZE      = 8 // Golang uses 64 bits for timestamps in the Unix Format
	TRANSACTION_VERSION = "2.0.0"
)

type ErrParsingTransactionStatus struct {
	Msg string
}

func (e *ErrParsingTransactionStatus) Error() string {
	return fmt.Sprintf("invalid transaction status, %s", e.Msg)
}

type EntityType string

const (
	EntityTypeOrganization EntityType = "ORGANIZATION"
	EntityTypeDepartment   EntityType = "DEPARTMENT"
	EntityTypePersonal     EntityType = "PERSONAL"
	EntityTypeService      EntityType = "SERVICE"
	EntityTypeDevice       EntityType = "DEVICE"
	EntityTypeAgent        EntityType = "AGENT"
)

// Entity name rules, mirrored from the node so an invalid name fails fast
// client-side instead of being silently dropped on-chain. The node normalizes
// the name (lowercase + trim) before validating, so "Acme Org" normalizes to
// "acme org" and is rejected for the internal space; capitals alone are fine.
const (
	MinEntityNameLength = 3
	MaxEntityNameLength = 64
)

var entityNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$`)

// NormalizeEntityName lowercases and trims the name, matching the node's
// normalization before storage and validation.
func NormalizeEntityName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ValidateEntityName reports whether name (after normalization) is a legal
// entity name: 3-64 chars of lowercase alphanumerics and hyphens, starting and
// ending with an alphanumeric. It does not check chain-wide uniqueness, which
// only the node can enforce.
func ValidateEntityName(name string) bool {
	normalized := NormalizeEntityName(name)
	if len(normalized) < MinEntityNameLength || len(normalized) > MaxEntityNameLength {
		return false
	}
	return entityNameRegex.MatchString(normalized)
}

type EntityPermission struct {
	ManageWallets     bool `json:"manageWallets"`
	ManageChildren    bool `json:"manageChildren"`
	ManageAccessList  bool `json:"manageAccessList"`
	ManageMetadata    bool `json:"manageMetadata"`
	TransferOwnership bool `json:"transferOwnership"`
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
	CREATE_ENTITY
	ALTER_ENTITY
	TRANSFER_ENTITY
	LINK_WALLET_TO_ENTITY
	UNLINK_WALLET_FROM_ENTITY
	SET_ENTITY_ACCESS_LIST
	SET_WALLET_ACCESS_LIST

	CONFIGURE_ENTITY_RECOVERY
	REQUEST_ENTITY_RECOVERY
	APPROVE_ENTITY_RECOVERY
	EXECUTE_ENTITY_RECOVERY
	CANCEL_ENTITY_RECOVERY
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
	case CREATE_ENTITY:
		return "CREATE_ENTITY"
	case ALTER_ENTITY:
		return "ALTER_ENTITY"
	case TRANSFER_ENTITY:
		return "TRANSFER_ENTITY"
	case LINK_WALLET_TO_ENTITY:
		return "LINK_WALLET_TO_ENTITY"
	case UNLINK_WALLET_FROM_ENTITY:
		return "UNLINK_WALLET_FROM_ENTITY"
	case SET_ENTITY_ACCESS_LIST:
		return "SET_ENTITY_ACCESS_LIST"
	case SET_WALLET_ACCESS_LIST:
		return "SET_WALLET_ACCESS_LIST"
	case CONFIGURE_ENTITY_RECOVERY:
		return "CONFIGURE_ENTITY_RECOVERY"
	case REQUEST_ENTITY_RECOVERY:
		return "REQUEST_ENTITY_RECOVERY"
	case APPROVE_ENTITY_RECOVERY:
		return "APPROVE_ENTITY_RECOVERY"
	case EXECUTE_ENTITY_RECOVERY:
		return "EXECUTE_ENTITY_RECOVERY"
	case CANCEL_ENTITY_RECOVERY:
		return "CANCEL_ENTITY_RECOVERY"
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
	case CREATE_ENTITY.String():
		return CREATE_ENTITY, nil
	case ALTER_ENTITY.String():
		return ALTER_ENTITY, nil
	case TRANSFER_ENTITY.String():
		return TRANSFER_ENTITY, nil
	case LINK_WALLET_TO_ENTITY.String():
		return LINK_WALLET_TO_ENTITY, nil
	case UNLINK_WALLET_FROM_ENTITY.String():
		return UNLINK_WALLET_FROM_ENTITY, nil
	case SET_ENTITY_ACCESS_LIST.String():
		return SET_ENTITY_ACCESS_LIST, nil
	case SET_WALLET_ACCESS_LIST.String():
		return SET_WALLET_ACCESS_LIST, nil
	case CONFIGURE_ENTITY_RECOVERY.String():
		return CONFIGURE_ENTITY_RECOVERY, nil
	case REQUEST_ENTITY_RECOVERY.String():
		return REQUEST_ENTITY_RECOVERY, nil
	case APPROVE_ENTITY_RECOVERY.String():
		return APPROVE_ENTITY_RECOVERY, nil
	case EXECUTE_ENTITY_RECOVERY.String():
		return EXECUTE_ENTITY_RECOVERY, nil
	case CANCEL_ENTITY_RECOVERY.String():
		return CANCEL_ENTITY_RECOVERY, nil
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

// GetSignatureDigest is the message a wallet signs: SHA3-512 over a canonical
// length-prefixed serialization of the sender-controlled fields. It must match
// the node's core.ULTransactionInput.GetSignatureDigest byte for byte.
func (t *ULTransactionInput) GetSignatureDigest() []byte {
	buf := bytes.Buffer{}

	writeField := func(s string) {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
		buf.WriteByte('|')
		buf.Write(lenBuf[:])
		buf.WriteByte('|')
		buf.WriteString(s)
	}

	writeField(t.BlockchainId)
	writeField(t.From)
	writeField(t.To)
	writeField(t.Payload)
	writeField(t.Suggestor)

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(t.SenderTimestamp.Unix()))
	buf.WriteByte('|')
	buf.Write(ts[:])

	digest := sha3.Sum512(buf.Bytes())
	return digest[:]
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

type CreateEntityPayload struct {
	Name       string            `json:"name"`
	EntityType EntityType        `json:"entityType"`
	Parent     string            `json:"parent,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type AlterEntityPayload struct {
	EntityAddress string            `json:"entityAddress"`
	Enabled       *bool             `json:"enabled,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type TransferEntityPayload struct {
	EntityAddress string `json:"entityAddress"`
	NewOwner      string `json:"newOwner"`
}

type LinkWalletPayload struct {
	EntityAddress string            `json:"entityAddress"`
	WalletAddress string            `json:"walletAddress"`
	Role          string            `json:"role"`
	Permissions   *EntityPermission `json:"permissions,omitempty"`
}

type UnlinkWalletPayload struct {
	EntityAddress string `json:"entityAddress"`
	WalletAddress string `json:"walletAddress"`
}

type AccessListOperation int

const (
	AccessListOpInvalid AccessListOperation = iota
	AccessListOpAddBlacklist
	AccessListOpRemoveBlacklist
	AccessListOpAddTrusted
	AccessListOpRemoveTrusted
)

func (op AccessListOperation) String() string {
	switch op {
	case AccessListOpAddBlacklist:
		return "ADD_BLACKLIST"
	case AccessListOpRemoveBlacklist:
		return "REMOVE_BLACKLIST"
	case AccessListOpAddTrusted:
		return "ADD_TRUSTED"
	case AccessListOpRemoveTrusted:
		return "REMOVE_TRUSTED"
	default:
		return ""
	}
}

func ParseAccessListOperation(s string) (AccessListOperation, bool) {
	switch strings.ToUpper(s) {
	case "ADD_BLACKLIST":
		return AccessListOpAddBlacklist, true
	case "REMOVE_BLACKLIST":
		return AccessListOpRemoveBlacklist, true
	case "ADD_TRUSTED":
		return AccessListOpAddTrusted, true
	case "REMOVE_TRUSTED":
		return AccessListOpRemoveTrusted, true
	default:
		return AccessListOpInvalid, false
	}
}

type SetEntityAccessListPayload struct {
	EntityAddress string `json:"entityAddress"`
	Operation     string `json:"operation"`
	TargetAddress string `json:"targetAddress"`
}

type SetWalletAccessListPayload struct {
	Operation     string `json:"operation"`
	TargetAddress string `json:"targetAddress"`
}

const (
	EntityRoleAdmin  = "admin"
	EntityRoleMember = "member"
)

type ConfigureEntityRecoveryPayload struct {
	EntityAddress   string   `json:"entityAddress"`
	RecoveryWallets []string `json:"recoveryWallets"`
	Threshold       int      `json:"threshold"`
}

type RequestEntityRecoveryPayload struct {
	EntityAddress string `json:"entityAddress"`
	NewOwner      string `json:"newOwner"`
}

type ApproveEntityRecoveryPayload struct {
	RequestId string `json:"requestId"`
}

type ExecuteEntityRecoveryPayload struct {
	RequestId string `json:"requestId"`
}

type CancelEntityRecoveryPayload struct {
	RequestId string `json:"requestId"`
}
