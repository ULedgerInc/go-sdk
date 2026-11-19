package txconfirm

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type State string

const (
	StateCommitted State = "committed"
	StatePending   State = "pending"
	StateRejected  State = "rejected"
	StateUnknown   State = "unknown"
)

func ParseState(s string) (State, error) {
	switch State(s) {
	case StateCommitted, StatePending, StateRejected, StateUnknown:
		return State(s), nil
	}
	return "", fmt.Errorf("unrecognized transaction state %q", s)
}

type Status struct {
	TransactionId string
	State         State
	Reason        string
	BlockHeight   uint64
}

type HTTPGetter interface {
	Get(url string) (*http.Response, error)
}

const maxStatusBodyBytes = 256 << 10

// Fetch reads the status from a single node. A rejection reason is recorded
// only on the node that rejected, so callers must query the node they
// submitted to; any other node answers unknown.
func Fetch(getter HTTPGetter, endpoint, blockchainId, txId string) (Status, error) {
	url := fmt.Sprintf("%s/blockchains/%s/transactions/%s/status", endpoint, blockchainId, txId)
	resp, err := getter.Get(url)
	if err != nil {
		return Status{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStatusBodyBytes+1))
	if err != nil {
		return Status{}, err
	}
	if len(body) > maxStatusBodyBytes {
		return Status{}, fmt.Errorf("GET %s: status %d: response body exceeds %d bytes", url, resp.StatusCode, maxStatusBodyBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return Status{}, fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, body)
	}
	var wire struct {
		TransactionId string `json:"transactionId"`
		State         string `json:"state"`
		Reason        string `json:"reason"`
		BlockHeight   uint64 `json:"blockHeight"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return Status{}, fmt.Errorf("GET %s: decoding status: %w", url, err)
	}
	state, err := ParseState(wire.State)
	if err != nil {
		return Status{}, fmt.Errorf("GET %s: %w", url, err)
	}
	return Status{TransactionId: wire.TransactionId, State: state, Reason: wire.Reason, BlockHeight: wire.BlockHeight}, nil
}
