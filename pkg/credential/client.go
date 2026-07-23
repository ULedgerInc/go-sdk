package credential

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Client talks to a node's /identity/credentials/* HTTP surface.
type Client struct {
	nodeEndpoint string
	httpClient   *http.Client
}

func NewClient(nodeEndpoint string, insecureSkipVerify bool) *Client {
	return &Client{
		nodeEndpoint: nodeEndpoint,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
			},
		},
	}
}

type issueCredentialRequest struct {
	Type         string         `json:"type"`
	Claim        *IdentityClaim `json:"claim,omitempty"`
	TxId         string         `json:"txId,omitempty"`
	BlockchainId string         `json:"blockchainId,omitempty"`
	EvidenceTxId string         `json:"evidenceTxId,omitempty"`
}

type issueCredentialResponse struct {
	Credential string `json:"credential"`
	Jti        string `json:"jti"`
}

func (c *Client) issueCredential(req issueCredentialRequest) (string, string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", "", err
	}
	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/identity/credentials/issue", c.nodeEndpoint), bytes.NewBuffer(body))
	if err != nil {
		return "", "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("server returned unexpected status code: %d, message:%s", resp.StatusCode, respBody)
	}

	var out issueCredentialResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", "", err
	}
	return out.Credential, out.Jti, nil
}

func (c *Client) IssueIdentityCredential(claim IdentityClaim, evidenceTxId string) (string, string, error) {
	return c.issueCredential(issueCredentialRequest{Type: "identity", Claim: &claim, EvidenceTxId: evidenceTxId})
}

func (c *Client) IssueAuthenticationCredential(blockchainId, txId string) (string, string, error) {
	return c.issueCredential(issueCredentialRequest{Type: "authentication", BlockchainId: blockchainId, TxId: txId})
}

func (c *Client) FetchStatusList(blockchainId, listId string) (string, error) {
	url := fmt.Sprintf("%s/identity/credentials/status/%s/%s", c.nodeEndpoint, blockchainId, listId)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned unexpected status code: %d, message:%s", resp.StatusCode, body)
	}
	return strings.TrimSpace(string(body)), nil
}
