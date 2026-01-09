package transaction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ULedgerInc/golang-sdk/pkg/crypto"
	"github.com/ULedgerInc/golang-sdk/pkg/wallet"
)

type UL_TransactionSession struct {
	nodeEndpoint string
	suggestor    string
	wallet       wallet.UL_Wallet
}

type chainInfo struct {
	Height           int               `json:"blockHeight"`
	Pending          []string          `json:"pendingTransactions"`
	Clock            map[string]uint64 `json:"messageClock"`
	LastMessage      time.Time         `json:"lastMessageTime"`
	CommitteeMembers []string          `json:"committeeMembers"`
	IsInCommittee    bool              `json:"isInCommittee"`
	IsVoting         bool              `json:"isVoting"`
	PeerCount        int               `json:"peerCount"`
	NetworkPeers     []string          `json:"networkPeers"`
}

type healthInfo struct {
	Version string               `json:"nodeVersion"`
	Chains  map[string]chainInfo `json:"chainsInfo"`
	NodeId  string               `json:"nodeId"`
	PeerId  string               `json:"peerId"`
}

func NewUL_TransactionSession(nodeEndpoint string, wallet wallet.UL_Wallet) (UL_TransactionSession, error) {
	// Fetch the Node Metadata
	httpClient := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/health", nodeEndpoint), nil)
	// Read the response
	resp, err := httpClient.Do(req)
	if err != nil {
		return UL_TransactionSession{}, err
	}
	// Parse the response
	body, err := io.ReadAll(resp.Body)
	info := healthInfo{}
	err = json.Unmarshal(body, &info)
	if err != nil {
		return UL_TransactionSession{}, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return UL_TransactionSession{}, fmt.Errorf("server returned unexpected status code: %d", resp.StatusCode)
	}

	nodeId := info.NodeId
	resp.Body.Close()

	req, err = http.NewRequest("GET", fmt.Sprintf("%s/blockchains", nodeEndpoint), nil)
	if err != nil {
		return UL_TransactionSession{}, err
	}

	// Read the response
	resp, err = httpClient.Do(req)
	if err != nil {
		return UL_TransactionSession{}, err
	}

	// Parse the response
	defer resp.Body.Close()

	// Parse the response
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return UL_TransactionSession{}, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return UL_TransactionSession{}, fmt.Errorf("server returned unexpected status code: %d", resp.StatusCode)
	}

	chains := make([]string, 0)
	err = json.Unmarshal(body, &chains)
	if err != nil {
		return UL_TransactionSession{}, err
	}

	if len(chains) == 0 {
		return UL_TransactionSession{}, fmt.Errorf("no chains found for the node")
	}

	return UL_TransactionSession{
		nodeEndpoint: nodeEndpoint,
		suggestor:    nodeId,
		wallet:       wallet,
	}, nil
}

func (session *UL_TransactionSession) GenerateTransaction(input ULTransactionInput) (ULTransaction, error) {
	// Generate a new transaction
	// Attach the suggestor
	input.Suggestor = session.suggestor
	curTime := time.Now().UTC()
	formattedTime, _ := time.Parse(time.RFC3339, curTime.Format(time.RFC3339))
	input.SenderTimestamp = formattedTime
	// Create transactions can come from no yet known source
	if input.PayloadType != TX_CREATE_WALLET.String() {
		input.From = session.wallet.Address
	}
	input.KeyType = session.wallet.GetKey().GetType()

	hasher := crypto.GetHasherByType(input.KeyType)

	var commitment []byte
	var err error
	// If the transaction is a deploy, we just need to hash the payload with SHA3-512 and sign it
	if input.PayloadType == DEPLOY_SMART_CONTRACT.String() || input.PayloadType == UPGRADE_SMART_CONTRACT.String() ||
		input.PayloadType == TX_CREATE_WALLET.String() || input.PayloadType == TX_ALTER_WALLET.String() {
		fmt.Println("Generating commitment for deploy or create wallet transaction")
		commitment, err = input.GetUnboundCommitment(hasher)
		if err != nil {
			return ULTransaction{}, err
		}
		input.PayloadRoot = crypto.BytesToHex(commitment)
	} else {
		signatureCommitment, err := input.GetSignatureCommitment(hasher, true)
		if err != nil {
			return ULTransaction{}, err
		}
		commitment, err = input.HashSignatureCommitment(hasher, signatureCommitment)
		if err != nil {
			return ULTransaction{}, err
		}

		// Set the payload root
		input.PayloadRoot = crypto.BytesToHex(signatureCommitment.PayloadRoot)
	}

	// Sign the commitment
	signature, err := session.wallet.GetKey().SignData(commitment)
	if err != nil {
		return ULTransaction{}, err
	}

	input.SenderSignature = crypto.BytesToHex(signature)

	// HTTP Request to the Node
	httpClient := &http.Client{}

	// Parse the input to JSON
	jsonInput, err := json.Marshal(input)
	if err != nil {
		return ULTransaction{}, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/blockchains/%s/transactions", session.nodeEndpoint, input.BlockchainId), bytes.NewBuffer(jsonInput))
	if err != nil {
		return ULTransaction{}, err
	}

	// Perform the request
	resp, err := httpClient.Do(req)
	if err != nil {
		return ULTransaction{}, err
	}
	defer resp.Body.Close()

	// Parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ULTransaction{}, err
	}

	// Check status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return ULTransaction{}, fmt.Errorf("server returned unexpected status code: %d, message:%s", resp.StatusCode, body)
	}

	transaction := ULTransaction{}
	err = json.Unmarshal(body, &transaction)
	if err != nil {
		return ULTransaction{}, err
	}

	return transaction, nil
}
