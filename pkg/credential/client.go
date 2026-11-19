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

// Client talks to a node's /identity/credentials/* HTTP surface for
// credential issuance and status list retrieval.
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

type revokeCredentialRequest struct {
	BlockchainId string `json:"blockchainId"`
	Jti          string `json:"jti"`
}

type revokeCredentialResponse struct {
	Revoked []string `json:"revoked"`
}

// RevokeCredential calls the operator-JWT-gated revoke endpoint. bearerToken
// is the JWT from an authenticated operator challenge (pkg/auth).
func (c *Client) RevokeCredential(bearerToken, blockchainId, jti string) ([]string, error) {
	body, err := json.Marshal(revokeCredentialRequest{BlockchainId: blockchainId, Jti: jti})
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/identity/credentials/revoke", c.nodeEndpoint), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned unexpected status code: %d, message:%s", resp.StatusCode, respBody)
	}

	var out revokeCredentialResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	return out.Revoked, nil
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
