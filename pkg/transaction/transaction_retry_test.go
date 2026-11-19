package transaction

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type retryRecorder struct {
	bodies      []string
	remoteAddrs []string
}

func retryTestSession(t *testing.T, endpoint string, client *http.Client) UL_TransactionSession {
	t.Helper()
	session := testSession(t, endpoint, client)
	session.sleep = func(time.Duration) {}
	return session
}

func retryTestInput() ULTransactionInput {
	return ULTransactionInput{
		BlockchainId: "chain-1",
		Payload:      `{"note":"retry"}`,
		PayloadType:  TX_DATA.String(),
	}
}

func newRetryServer(rec *retryRecorder, tooManyFor int, successBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec.bodies = append(rec.bodies, string(b))
		rec.remoteAddrs = append(rec.remoteAddrs, r.RemoteAddr)
		if len(rec.bodies) <= tooManyFor {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(successBody))
	}))
}

func TestGenerateTransactionSucceedsOnRetryAfter429(t *testing.T) {
	rec := &retryRecorder{}
	srv := newRetryServer(rec, 1, `{"transactionId":"tx-retry-ok","blockHeight":42}`)
	defer srv.Close()

	session := retryTestSession(t, srv.URL, srv.Client())
	tx, err := session.GenerateTransaction(t.Context(), retryTestInput())
	if err != nil {
		t.Fatalf("expected nil error on successful retry, got: %v", err)
	}
	if tx.TransactionId != "tx-retry-ok" {
		t.Fatalf("expected parsed transaction id tx-retry-ok, got %q", tx.TransactionId)
	}
	if tx.BlockHeight != 42 {
		t.Fatalf("expected block height 42, got %d", tx.BlockHeight)
	}
	if len(rec.bodies) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(rec.bodies))
	}
}

func TestGenerateTransactionReplaysIdenticalBodyOnEveryAttempt(t *testing.T) {
	rec := &retryRecorder{}
	srv := newRetryServer(rec, 2, `{"transactionId":"tx-body-ok"}`)
	defer srv.Close()

	session := retryTestSession(t, srv.URL, srv.Client())
	tx, err := session.GenerateTransaction(t.Context(), retryTestInput())

	if len(rec.bodies) != 3 {
		t.Fatalf("expected 3 attempts, got %d", len(rec.bodies))
	}
	for i, body := range rec.bodies {
		if body == "" {
			t.Errorf("attempt %d sent an empty body", i+1)
		}
		if body != rec.bodies[0] {
			t.Errorf("attempt %d body differs from attempt 1:\n attempt1=%q\n attempt%d=%q", i+1, rec.bodies[0], i+1, body)
		}
	}
	if err != nil {
		t.Fatalf("expected nil error after successful retry, got: %v", err)
	}
	if tx.TransactionId != "tx-body-ok" {
		t.Fatalf("expected parsed transaction id tx-body-ok, got %q", tx.TransactionId)
	}
}

func TestGenerateTransactionNon429StatusIsNotRetried(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"bad payload"}`))
	}))
	defer srv.Close()

	session := retryTestSession(t, srv.URL, srv.Client())
	_, err := session.GenerateTransaction(t.Context(), retryTestInput())
	if err == nil {
		t.Fatal("expected an error on a 400 response")
	}
	want := `server returned unexpected status code: 400, message:{"error":"bad payload"}`
	if err.Error() != want {
		t.Fatalf("non-429 error text changed:\n want: %s\n got:  %s", want, err.Error())
	}
	if attempts != 1 {
		t.Fatalf("expected exactly 1 attempt for a non-429 status, got %d", attempts)
	}
}

func TestGenerateTransactionReportsRetryExhaustion(t *testing.T) {
	rec := &retryRecorder{}
	srv := newRetryServer(rec, 99, "")
	defer srv.Close()

	session := retryTestSession(t, srv.URL, srv.Client())
	_, err := session.GenerateTransaction(t.Context(), retryTestInput())
	if err == nil {
		t.Fatal("expected an error when every attempt returns 429")
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got: %v", err)
	}
	if !strings.Contains(err.Error(), "429") {
		t.Fatalf("expected exhaustion error mentioning status 429, got: %v", err)
	}
	// Backoffs of 1+2+4 s fit the 10 s retry budget; the next 8 s would not.
	if len(rec.bodies) != 4 {
		t.Fatalf("expected 4 attempts (1 initial + 3 retries within the 10 s budget), got %d", len(rec.bodies))
	}
	for i, addr := range rec.remoteAddrs {
		if addr != rec.remoteAddrs[0] {
			t.Fatalf("attempt %d used a new connection (%s) instead of reusing %s, so a prior response body was left unread or unclosed", i+1, addr, rec.remoteAddrs[0])
		}
	}
}
