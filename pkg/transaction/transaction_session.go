package transaction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

type UL_TransactionSession struct {
	nodeEndpoint string
	suggestor    string
	wallet       wallet.UL_Wallet
	httpClient   *http.Client
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
		httpClient:   httpClient,
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

	commitment := input.GetSignatureDigest()

	// Sign the commitment
	signature, err := session.wallet.GetKey().SignData(commitment)
	if err != nil {
		return ULTransaction{}, err
	}

	input.SenderSignature = crypto.BytesToHex(signature)

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
	resp, err := session.httpClient.Do(req)
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
		if resp.StatusCode == http.StatusTooManyRequests {
			// Try again with exponential backoff
			retries := 5
			backoff := time.Second
			for i := 0; i < retries; i++ {
				time.Sleep(backoff)
				resp, err = session.httpClient.Do(req)
				if err != nil {
					return ULTransaction{}, err
				}
				defer resp.Body.Close()

				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
					body, err = io.ReadAll(resp.Body)
					if err != nil {
						return ULTransaction{}, err
					}
					break
				}

				backoff *= 2
			}

			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
				return ULTransaction{}, fmt.Errorf("server returned status code: %d after %d retries, message:%s", resp.StatusCode, retries, body)
			}
		}
		return ULTransaction{}, fmt.Errorf("server returned unexpected status code: %d, message:%s", resp.StatusCode, body)
	}

	transaction := ULTransaction{}
	err = json.Unmarshal(body, &transaction)
	if err != nil {
		return ULTransaction{}, err
	}

	return transaction, nil
}
