package transaction

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const (
	callerDeadline = 200 * time.Millisecond
	returnWithin   = 2 * time.Second
)

// hangingServer accepts requests and never answers until the test ends.
// The handler is released explicitly: a server that has not read a POST
// body does not notice the client hanging up, so srv.Close would block.
func hangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))

	// Cleanups run last-in first-out: release the handlers, then close.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	return srv
}

// rateLimitedServer answers every request with 429 and the given Retry-After.
func rateLimitedServer(t *testing.T, retryAfter string, attempts *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Retry-After", retryAfter)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A caller's deadline must bound the submit, whatever the node does.
func TestGenerateHonoursDeadline(t *testing.T) {
	srv := hangingServer(t)
	session := testSession(t, srv.URL, srv.Client())

	ctx, cancel := context.WithTimeout(t.Context(), callerDeadline)
	defer cancel()

	start := time.Now()
	_, err := session.GenerateTransaction(ctx, retryTestInput())

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > returnWithin {
		t.Fatalf("returned after %s, expected within %s of a %s deadline", elapsed, returnWithin, callerDeadline)
	}
}

// Session creation reads node metadata; that read must honour the deadline too.
func TestSessionHonoursDeadline(t *testing.T) {
	srv := hangingServer(t)

	ctx, cancel := context.WithTimeout(t.Context(), callerDeadline)
	defer cancel()

	start := time.Now()
	_, err := NewUL_TransactionSession(ctx, srv.URL, poolWallet(t), SessionOptions{Client: srv.Client()})

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > returnWithin {
		t.Fatalf("returned after %s, expected within %s of a %s deadline", elapsed, returnWithin, callerDeadline)
	}
}

// When Retry-After lands past the caller's deadline, waiting is pointless:
// return ErrRateLimited at once so the caller can answer 429/503 upstream.
func TestRetryStopsAtDeadline(t *testing.T) {
	var attempts atomic.Int64
	srv := rateLimitedServer(t, "5", &attempts)

	var slept []time.Duration
	session := testSession(t, srv.URL, srv.Client())
	session.sleep = func(d time.Duration) { slept = append(slept, d) }

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	_, err := session.GenerateTransaction(ctx, retryTestInput())

	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	if len(slept) != 0 {
		t.Fatalf("expected no backoff past the deadline, slept %v", slept)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("expected 1 attempt, got %d", got)
	}
}

// Without a caller deadline, retries stay within the default 10 s budget.
func TestRetryAfterBeyondBudget(t *testing.T) {
	var attempts atomic.Int64
	srv := rateLimitedServer(t, "30", &attempts)

	var slept []time.Duration
	session := testSession(t, srv.URL, srv.Client())
	session.sleep = func(d time.Duration) { slept = append(slept, d) }

	_, err := session.GenerateTransaction(context.Background(), retryTestInput())

	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	if len(slept) != 0 {
		t.Fatalf("expected no 30 s backoff against a 10 s budget, slept %v", slept)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("expected 1 attempt, got %d", got)
	}
}

// countingTransport records every round trip made through a caller's client.
type countingTransport struct {
	next  http.RoundTripper
	trips atomic.Int64
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.trips.Add(1)
	return c.next.RoundTrip(r)
}

// A caller-supplied client carries every request: metadata reads and the submit.
func TestSessionUsesCallerClient(t *testing.T) {
	node := newPoolNode(t)
	transport := &countingTransport{next: node.srv.Client().Transport}
	client := &http.Client{Transport: transport}

	session, err := NewUL_TransactionSession(t.Context(), node.srv.URL, poolWallet(t), SessionOptions{Client: client})
	if err != nil {
		t.Fatalf("NewUL_TransactionSession: %v", err)
	}
	if _, err := session.GenerateTransaction(t.Context(), retryTestInput()); err != nil {
		t.Fatalf("GenerateTransaction: %v", err)
	}

	// /health, /blockchains and the POST; the node is new, so nothing is cached.
	if got := transport.trips.Load(); got != 3 {
		t.Fatalf("expected 3 round trips through the caller's client, got %d", got)
	}
	if session.httpClient != client {
		t.Fatal("session does not hold the caller's client")
	}
}
