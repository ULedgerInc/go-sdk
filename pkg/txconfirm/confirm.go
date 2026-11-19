package txconfirm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultAttempts       = 3
	defaultPollInterval   = time.Second
	defaultUnknownGrace   = 10 * time.Second
	defaultAttemptTimeout = 90 * time.Second
)

type HTTPPoster interface {
	Post(url, contentType string, body io.Reader) (*http.Response, error)
}

type Attempt struct {
	Endpoint string
	State    State
	Reason   string
}

type Result struct {
	TxId        string
	State       State
	BlockHeight uint64
	Attempts    []Attempt
}

type Confirmer struct {
	Getter       HTTPGetter
	Poster       HTTPPoster
	Endpoints    []string
	BlockchainId string
	// SignedBody is replayed identically to every endpoint. Never rebuild or
	// re-sign between attempts: a fresh signature means a fresh id.
	SignedBody     []byte
	Attempts       int
	PollInterval   time.Duration
	UnknownGrace   time.Duration
	AttemptTimeout time.Duration

	sleep func(time.Duration)
}

// Confirm replays SignedBody to distinct endpoints in order, polling each for
// the outcome of the single resulting transaction id. A failing endpoint is
// recorded and skipped; only an exhausted endpoint set errors. A unanimous
// rejection returns a nil error. Cancellation is honored between polls.
func (c *Confirmer) Confirm(ctx context.Context) (Result, error) {
	if c.Getter == nil || c.Poster == nil || c.BlockchainId == "" || len(c.SignedBody) == 0 || len(c.Endpoints) == 0 {
		return Result{}, fmt.Errorf("txconfirm: Confirmer requires Getter, Poster, BlockchainId, SignedBody and at least one endpoint")
	}
	attempts := c.Attempts
	if attempts <= 0 {
		attempts = defaultAttempts
	}
	if attempts > len(c.Endpoints) {
		attempts = len(c.Endpoints)
	}
	pollInterval := c.PollInterval
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}
	unknownGrace := c.UnknownGrace
	if unknownGrace <= 0 {
		unknownGrace = defaultUnknownGrace
	}
	attemptTimeout := c.AttemptTimeout
	if attemptTimeout <= 0 {
		attemptTimeout = defaultAttemptTimeout
	}
	sleep := c.sleep
	if sleep == nil {
		sleep = time.Sleep
	}

	var result Result
	unreachable := 0
	var lastUnreachableErr error
	for i := 0; i < attempts; i++ {
		endpoint := c.Endpoints[i]
		if err := ctx.Err(); err != nil {
			return result, err
		}
		txId, err := c.submit(endpoint)
		if err != nil {
			unreachable++
			lastUnreachableErr = fmt.Errorf("submitting to %s: %w", endpoint, err)
			result.Attempts = append(result.Attempts, Attempt{Endpoint: endpoint, State: StateUnknown, Reason: err.Error()})
			continue
		}
		if result.TxId == "" {
			result.TxId = txId
		} else if txId != result.TxId {
			return result, fmt.Errorf("endpoint %s returned transaction id %s for bytes already submitted as %s", endpoint, txId, result.TxId)
		}
		attempt := Attempt{Endpoint: endpoint, State: StateUnknown}
		attemptDeadline := time.Now().Add(attemptTimeout)
		graceDeadline := time.Now().Add(unknownGrace)
		sawStatus := false
		var lastErr error
	poll:
		for {
			if err := ctx.Err(); err != nil {
				result.Attempts = append(result.Attempts, attempt)
				return result, err
			}
			st, err := Fetch(c.Getter, endpoint, c.BlockchainId, result.TxId)
			switch {
			case err != nil:
				lastErr = err
			case st.State == StateCommitted:
				attempt.State = StateCommitted
				result.Attempts = append(result.Attempts, attempt)
				result.State = StateCommitted
				result.BlockHeight = st.BlockHeight
				return result, nil
			case st.State == StateRejected:
				attempt.State = StateRejected
				attempt.Reason = st.Reason
				result.Attempts = append(result.Attempts, attempt)
				break poll
			case st.State == StatePending:
				sawStatus = true
				attempt.State = StatePending
			default:
				sawStatus = true
				if attempt.State != StatePending && time.Now().After(graceDeadline) {
					result.Attempts = append(result.Attempts, attempt)
					break poll
				}
			}
			if time.Now().After(attemptDeadline) {
				if !sawStatus {
					unreachable++
					lastUnreachableErr = fmt.Errorf("reading status of %s on %s: %w", result.TxId, endpoint, lastErr)
					attempt.Reason = lastErr.Error()
				}
				result.Attempts = append(result.Attempts, attempt)
				break poll
			}
			sleep(pollInterval)
		}
	}

	allRejected := len(result.Attempts) > 0
	for _, a := range result.Attempts {
		if a.State != StateRejected {
			allRejected = false
		}
	}
	if allRejected {
		result.State = StateRejected
		return result, nil
	}
	if unreachable > 0 && unreachable == len(result.Attempts) {
		return result, fmt.Errorf("all %d of %d endpoints unreachable: %w", unreachable, len(c.Endpoints), lastUnreachableErr)
	}
	return result, fmt.Errorf("no terminal outcome for %s after %d attempts across %d endpoints", result.TxId, len(result.Attempts), len(c.Endpoints))
}

func (c *Confirmer) submit(endpoint string) (string, error) {
	url := fmt.Sprintf("%s/blockchains/%s/transactions", endpoint, c.BlockchainId)
	resp, err := c.Poster.Post(url, "application/json", bytes.NewReader(c.SignedBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("POST %s: status %d: %s", url, resp.StatusCode, body)
	}
	var wire struct {
		TransactionId string `json:"transactionId"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return "", fmt.Errorf("POST %s: decoding response: %w", url, err)
	}
	if wire.TransactionId == "" {
		return "", fmt.Errorf("POST %s: node returned an empty transaction id", url)
	}
	return wire.TransactionId, nil
}
