package transaction

import (
	"bytes"
	"crypto/tls"
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
	return NewUL_TransactionSessionWithTLS(nodeEndpoint, wallet, false)
}

func NewUL_TransactionSessionWithTLS(nodeEndpoint string, wallet wallet.UL_Wallet, insecureSkipVerify bool) (UL_TransactionSession, error) {
	// Fetch the Node Metadata
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
		},
	}
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

func (session *UL_TransactionSession) ResolveDID(did string) (DIDResolutionResult, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/did/%s", session.nodeEndpoint, did), nil)
	if err != nil {
		return DIDResolutionResult{}, err
	}

	resp, err := session.httpClient.Do(req)
	if err != nil {
		return DIDResolutionResult{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return DIDResolutionResult{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return DIDResolutionResult{}, fmt.Errorf("server returned unexpected status code: %d, message:%s", resp.StatusCode, body)
	}

	result := DIDResolutionResult{}
	if err := json.Unmarshal(body, &result); err != nil {
		return DIDResolutionResult{}, err
	}

	return result, nil
}

func (session *UL_TransactionSession) ResolveDIDSigned(did string) (SignedResolutionEnvelope, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/did/%s?signed=1", session.nodeEndpoint, did), nil)
	if err != nil {
		return SignedResolutionEnvelope{}, err
	}

	resp, err := session.httpClient.Do(req)
	if err != nil {
		return SignedResolutionEnvelope{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SignedResolutionEnvelope{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return SignedResolutionEnvelope{}, fmt.Errorf("server returned unexpected status code: %d, message:%s", resp.StatusCode, body)
	}

	result := SignedResolutionEnvelope{}
	if err := json.Unmarshal(body, &result); err != nil {
		return SignedResolutionEnvelope{}, err
	}

	return result, nil
}

func (session *UL_TransactionSession) ResolveDIDChain(did string) ([]DIDResolutionResult, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/did/%s/chain", session.nodeEndpoint, did), nil)
	if err != nil {
		return nil, err
	}

	resp, err := session.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned unexpected status code: %d, message:%s", resp.StatusCode, body)
	}

	results := make([]DIDResolutionResult, 0)
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}

	return results, nil
}

func (session *UL_TransactionSession) VerifyIdentityClaim(claim IdentityClaim) (VerifyResult, error) {
	jsonInput, err := json.Marshal(claim)
	if err != nil {
		return VerifyResult{}, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/identity/verify", session.nodeEndpoint), bytes.NewBuffer(jsonInput))
	if err != nil {
		return VerifyResult{}, err
	}

	resp, err := session.httpClient.Do(req)
	if err != nil {
		return VerifyResult{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return VerifyResult{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return VerifyResult{}, fmt.Errorf("server returned unexpected status code: %d, message:%s", resp.StatusCode, body)
	}

	result := VerifyResult{}
	if err := json.Unmarshal(body, &result); err != nil {
		return VerifyResult{}, err
	}

	return result, nil
}

func (session *UL_TransactionSession) GetTransactionProof(blockchainId, txId string) (TxInclusionProofPackage, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/blockchains/%s/transactions/%s/proof", session.nodeEndpoint, blockchainId, txId), nil)
	if err != nil {
		return TxInclusionProofPackage{}, err
	}

	resp, err := session.httpClient.Do(req)
	if err != nil {
		return TxInclusionProofPackage{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TxInclusionProofPackage{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return TxInclusionProofPackage{}, fmt.Errorf("server returned unexpected status code: %d, message:%s", resp.StatusCode, body)
	}

	pkg := TxInclusionProofPackage{}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return TxInclusionProofPackage{}, err
	}

	return pkg, nil
}
