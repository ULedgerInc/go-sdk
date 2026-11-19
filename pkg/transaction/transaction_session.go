package transaction

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

// ErrRateLimited reports that the node answered 429 and the retry budget, or
// the caller's deadline, ran out before it accepted the transaction.
var ErrRateLimited = errors.New("node rate limited the request")

const (
	// Shared transport tuning: bound every phase of a request so a stuck
	// connection fails the call instead of blocking the caller.
	clientTimeout         = 10 * time.Second
	dialTimeout           = 5 * time.Second
	tlsHandshakeTimeout   = 5 * time.Second
	responseHeaderTimeout = 10 * time.Second
	idleConnTimeout       = 90 * time.Second
	maxIdleConnsPerHost   = 64

	// nodeId rarely changes; re-read it at most this often per endpoint.
	metadataTTL = 5 * time.Minute

	// 429 handling: exponential backoff from firstBackoff, or the node's
	// Retry-After, until maxRetries or retryBudget of total waiting.
	maxRetries   = 5
	firstBackoff = time.Second
	retryBudget  = 10 * time.Second
)

// SessionOptions configures how a session reaches its node.
type SessionOptions struct {
	// Client carries every request. Nil uses a shared pooled client;
	// InsecureSkipVerify applies only to that shared client.
	Client             *http.Client
	InsecureSkipVerify bool
}

type UL_TransactionSession struct {
	nodeEndpoint string
	suggestor    string
	wallet       wallet.UL_Wallet
	httpClient   *http.Client

	sleep func(time.Duration)
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

type nodeMetadata struct {
	nodeId    string
	fetchedAt time.Time
}

// One pooled client per TLS mode, shared by every session in the process,
// so a session per transaction reuses connections instead of dialing anew.
var (
	verifyingClient = sync.OnceValue(func() *http.Client { return newPooledClient(false) })
	insecureClient  = sync.OnceValue(func() *http.Client { return newPooledClient(true) })
)

var (
	metadataMu    sync.Mutex
	metadataCache = make(map[string]nodeMetadata)
)

func newPooledClient(insecureSkipVerify bool) *http.Client {
	dialer := &net.Dialer{Timeout: dialTimeout}
	return &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecureSkipVerify},
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
			IdleConnTimeout:       idleConnTimeout,
			MaxIdleConnsPerHost:   maxIdleConnsPerHost,
			ForceAttemptHTTP2:     true,
		},
	}
}

func sharedClient(insecureSkipVerify bool) *http.Client {
	if insecureSkipVerify {
		return insecureClient()
	}
	return verifyingClient()
}

func NewUL_TransactionSession(ctx context.Context, nodeEndpoint string, wallet wallet.UL_Wallet, opts SessionOptions) (UL_TransactionSession, error) {
	client := opts.Client
	if client == nil {
		client = sharedClient(opts.InsecureSkipVerify)
	}

	nodeId, err := cachedNodeId(ctx, client, nodeEndpoint)
	if err != nil {
		return UL_TransactionSession{}, err
	}

	return UL_TransactionSession{
		nodeEndpoint: nodeEndpoint,
		suggestor:    nodeId,
		wallet:       wallet,
		httpClient:   client,
	}, nil
}

// cachedNodeId returns the node's id, reading /health and /blockchains only
// when the endpoint has no entry younger than metadataTTL.
func cachedNodeId(ctx context.Context, client *http.Client, nodeEndpoint string) (string, error) {
	metadataMu.Lock()
	cached, ok := metadataCache[nodeEndpoint]
	metadataMu.Unlock()
	if ok && time.Since(cached.fetchedAt) < metadataTTL {
		return cached.nodeId, nil
	}

	info := healthInfo{}
	if err := getJSON(ctx, client, fmt.Sprintf("%s/health", nodeEndpoint), &info); err != nil {
		return "", err
	}

	chains := make([]string, 0)
	if err := getJSON(ctx, client, fmt.Sprintf("%s/blockchains", nodeEndpoint), &chains); err != nil {
		return "", err
	}
	if len(chains) == 0 {
		return "", fmt.Errorf("no chains found for the node")
	}

	metadataMu.Lock()
	metadataCache[nodeEndpoint] = nodeMetadata{nodeId: info.NodeId, fetchedAt: time.Now()}
	metadataMu.Unlock()

	return info.NodeId, nil
}

func getJSON(ctx context.Context, client *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("server returned unexpected status code: %d", resp.StatusCode)
	}

	return json.Unmarshal(body, out)
}

type submitResponse struct {
	status     int
	body       []byte
	retryAfter time.Duration
}

func (session *UL_TransactionSession) GenerateTransaction(ctx context.Context, input ULTransactionInput) (ULTransaction, error) {
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

	url := fmt.Sprintf("%s/blockchains/%s/transactions", session.nodeEndpoint, input.BlockchainId)
	resp, err := session.post(ctx, url, jsonInput)
	if err != nil {
		return ULTransaction{}, err
	}

	// Retry 429s with the same signed bytes, so every attempt carries the same
	// transaction id. Stop once the next wait would pass the budget or deadline.
	backoff := firstBackoff
	waited := time.Duration(0)
	for retry := 0; resp.status == http.StatusTooManyRequests; retry++ {
		wait := backoff
		if resp.retryAfter > 0 {
			wait = resp.retryAfter
		}

		if retry == maxRetries || !fitsRetryBudget(ctx, waited+wait, wait) {
			return ULTransaction{}, fmt.Errorf("%w: server returned status code: %d after %d retries, message:%s", ErrRateLimited, resp.status, retry, resp.body)
		}

		if err := session.wait(ctx, wait); err != nil {
			return ULTransaction{}, err
		}
		waited += wait
		backoff *= 2

		resp, err = session.post(ctx, url, jsonInput)
		if err != nil {
			return ULTransaction{}, err
		}
	}

	if resp.status != http.StatusOK && resp.status != http.StatusCreated {
		return ULTransaction{}, fmt.Errorf("server returned unexpected status code: %d, message:%s", resp.status, resp.body)
	}

	transaction := ULTransaction{}
	if err := json.Unmarshal(resp.body, &transaction); err != nil {
		return ULTransaction{}, err
	}

	return transaction, nil
}

// post sends one attempt with a fresh request, and always drains and closes
// the response body so the connection returns to the pool.
func (session *UL_TransactionSession) post(ctx context.Context, url string, body []byte) (submitResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return submitResponse{}, err
	}

	resp, err := session.httpClient.Do(req)
	if err != nil {
		return submitResponse{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return submitResponse{}, err
	}

	return submitResponse{
		status:     resp.StatusCode,
		body:       respBody,
		retryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
	}, nil
}

// parseRetryAfter reads either form RFC 9110 allows: delay seconds ("3") or an
// HTTP date. Missing or unparseable values yield 0, meaning no hint.
func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}

	if seconds, err := strconv.Atoi(value); err == nil {
		return max(time.Duration(seconds)*time.Second, 0)
	}

	if at, err := http.ParseTime(value); err == nil {
		return max(time.Until(at), 0)
	}

	return 0
}

// fitsRetryBudget reports whether waiting `wait` more keeps the total within
// retryBudget and ends before the caller's deadline.
func fitsRetryBudget(ctx context.Context, total, wait time.Duration) bool {
	if total > retryBudget {
		return false
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}

	return time.Now().Add(wait).Before(deadline)
}

// wait pauses between retries and returns early if the caller cancels.
func (session *UL_TransactionSession) wait(ctx context.Context, d time.Duration) error {
	if session.sleep != nil {
		session.sleep(d)
		return ctx.Err()
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
