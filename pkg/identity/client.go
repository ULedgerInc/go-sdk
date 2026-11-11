package identity

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ULedgerInc/go-sdk/pkg/credential"
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

// ChainHead is a blockchain's current height and hash, the reference point for
// AUTHENTICATE_INTERNAL's proof-of-control payload.
type ChainHead struct {
	Height uint64
	Hash   string
}

// chainClient is the seam between the Runner and the node, so it can be faked in tests.
type chainClient interface {
	Submit(signer *wallet.UL_Wallet, input transaction.ULTransactionInput) (transaction.ULTransaction, error)
	GetTransaction(blockchainId, txid string) (transaction.ULTransaction, error)
	GetChainHead(blockchainId string) (ChainHead, error)
	ResolveDID(signer *wallet.UL_Wallet, did string) (transaction.DIDResolutionResult, error)
	ResolveDIDChain(signer *wallet.UL_Wallet, did string) ([]transaction.DIDResolutionResult, error)
	ResolveDIDSigned(signer *wallet.UL_Wallet, did string) (transaction.SignedResolutionEnvelope, error)
	VerifyIdentityClaim(signer *wallet.UL_Wallet, claim transaction.IdentityClaim) (transaction.VerifyResult, error)
	GetTransactionProof(signer *wallet.UL_Wallet, blockchainId, txId string) (transaction.TxInclusionProofPackage, error)
	IssueIdentityCredential(claim transaction.IdentityClaim, evidenceTxId string) (string, string, error)
	IssueAuthenticationCredential(blockchainId, txId string) (string, string, error)
	FetchStatusList(blockchainId, listId string) (string, error)
}

// httpChainClient submits via a per-signer transaction session (created lazily,
// cached by wallet address) and reads tx status with a plain HTTP GET.
type httpChainClient struct {
	endpoint           string
	insecureSkipVerify bool
	httpClient         *http.Client
	sessions           map[string]*transaction.UL_TransactionSession
	credClient         *credential.Client
}

func newHTTPChainClient(endpoint string, insecureSkipVerify bool) *httpChainClient {
	return &httpChainClient{
		endpoint:           endpoint,
		insecureSkipVerify: insecureSkipVerify,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
			},
		},
		sessions: make(map[string]*transaction.UL_TransactionSession),
	}
}

func (c *httpChainClient) sessionFor(signer *wallet.UL_Wallet) (*transaction.UL_TransactionSession, error) {
	sess, ok := c.sessions[signer.Address]
	if !ok {
		s, err := transaction.NewUL_TransactionSession(context.Background(), c.endpoint, *signer, transaction.SessionOptions{InsecureSkipVerify: c.insecureSkipVerify})
		if err != nil {
			return nil, fmt.Errorf("creating session for %s: %w", signer.Address, err)
		}
		sess = &s
		c.sessions[signer.Address] = sess
	}
	return sess, nil
}

func (c *httpChainClient) Submit(signer *wallet.UL_Wallet, input transaction.ULTransactionInput) (transaction.ULTransaction, error) {
	sess, err := c.sessionFor(signer)
	if err != nil {
		return transaction.ULTransaction{}, err
	}
	return sess.GenerateTransaction(context.Background(), input)
}

func (c *httpChainClient) ResolveDID(signer *wallet.UL_Wallet, did string) (transaction.DIDResolutionResult, error) {
	sess, err := c.sessionFor(signer)
	if err != nil {
		return transaction.DIDResolutionResult{}, err
	}
	return sess.ResolveDID(did)
}

func (c *httpChainClient) ResolveDIDChain(signer *wallet.UL_Wallet, did string) ([]transaction.DIDResolutionResult, error) {
	sess, err := c.sessionFor(signer)
	if err != nil {
		return nil, err
	}
	return sess.ResolveDIDChain(did)
}

func (c *httpChainClient) ResolveDIDSigned(signer *wallet.UL_Wallet, did string) (transaction.SignedResolutionEnvelope, error) {
	sess, err := c.sessionFor(signer)
	if err != nil {
		return transaction.SignedResolutionEnvelope{}, err
	}
	return sess.ResolveDIDSigned(did)
}

func (c *httpChainClient) credentialClient() *credential.Client {
	if c.credClient == nil {
		c.credClient = credential.NewClient(c.endpoint, c.insecureSkipVerify)
	}
	return c.credClient
}

func (c *httpChainClient) IssueIdentityCredential(claim transaction.IdentityClaim, evidenceTxId string) (string, string, error) {
	return c.credentialClient().IssueIdentityCredential(claim, evidenceTxId)
}

func (c *httpChainClient) IssueAuthenticationCredential(blockchainId, txId string) (string, string, error) {
	return c.credentialClient().IssueAuthenticationCredential(blockchainId, txId)
}

func (c *httpChainClient) FetchStatusList(blockchainId, listId string) (string, error) {
	return c.credentialClient().FetchStatusList(blockchainId, listId)
}

func (c *httpChainClient) VerifyIdentityClaim(signer *wallet.UL_Wallet, claim transaction.IdentityClaim) (transaction.VerifyResult, error) {
	sess, err := c.sessionFor(signer)
	if err != nil {
		return transaction.VerifyResult{}, err
	}
	return sess.VerifyIdentityClaim(claim)
}

func (c *httpChainClient) GetTransactionProof(signer *wallet.UL_Wallet, blockchainId, txId string) (transaction.TxInclusionProofPackage, error) {
	sess, err := c.sessionFor(signer)
	if err != nil {
		return transaction.TxInclusionProofPackage{}, err
	}
	return sess.GetTransactionProof(blockchainId, txId)
}

func (c *httpChainClient) GetTransaction(blockchainId, txid string) (transaction.ULTransaction, error) {
	url := fmt.Sprintf("%s/blockchains/%s/transactions/%s", c.endpoint, blockchainId, txid)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return transaction.ULTransaction{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return transaction.ULTransaction{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return transaction.ULTransaction{}, fmt.Errorf("status %d fetching tx %s: %s", resp.StatusCode, txid, body)
	}
	var tx transaction.ULTransaction
	if err := json.Unmarshal(body, &tx); err != nil {
		return transaction.ULTransaction{}, err
	}
	return tx, nil
}

func (c *httpChainClient) GetChainHead(blockchainId string) (ChainHead, error) {
	url := fmt.Sprintf("%s/blockchains/%s", c.endpoint, blockchainId)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return ChainHead{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ChainHead{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return ChainHead{}, fmt.Errorf("status %d fetching blockchain %s: %s", resp.StatusCode, blockchainId, body)
	}
	var info struct {
		Height uint64 `json:"blockHeight"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return ChainHead{}, err
	}

	blockURL := fmt.Sprintf("%s/blockchains/%s/blocks?height=%d", c.endpoint, blockchainId, info.Height)
	blockResp, err := c.httpClient.Get(blockURL)
	if err != nil {
		return ChainHead{}, err
	}
	defer blockResp.Body.Close()
	blockBody, err := io.ReadAll(blockResp.Body)
	if err != nil {
		return ChainHead{}, err
	}
	if blockResp.StatusCode != http.StatusOK {
		return ChainHead{}, fmt.Errorf("status %d fetching block %d for %s: %s", blockResp.StatusCode, info.Height, blockchainId, blockBody)
	}
	var block struct {
		Hash string `json:"blockHash"`
	}
	if err := json.Unmarshal(blockBody, &block); err != nil {
		return ChainHead{}, err
	}
	return ChainHead{Height: info.Height, Hash: block.Hash}, nil
}
