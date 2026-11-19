package txconfirm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeNode struct {
	srv       *httptest.Server
	postCalls atomic.Int64
	getCalls  atomic.Int64

	mu         sync.Mutex
	postBodies [][]byte
}

func newFakeNode(t *testing.T, txId string, status func(call int) string) *fakeNode {
	t.Helper()
	f := &fakeNode{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.postBodies = append(f.postBodies, body)
			f.mu.Unlock()
			f.postCalls.Add(1)
			fmt.Fprintf(w, `{"transactionId":%q}`, txId)
			return
		}
		f.getCalls.Add(1)
		w.Write([]byte(status(int(f.getCalls.Load()))))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNode) firstPostBody() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.postBodies) == 0 {
		return nil
	}
	return f.postBodies[0]
}

func fixedState(body string) func(int) string {
	return func(int) string { return body }
}

var signedBody = []byte(`{"blockchainId":"chain-1","payload":"x","senderSignature":"aa"}`)

func testConfirmer(signed []byte, endpoints ...string) *Confirmer {
	return &Confirmer{
		Getter:       http.DefaultClient,
		Poster:       http.DefaultClient,
		Endpoints:    endpoints,
		BlockchainId: "chain-1",
		SignedBody:   signed,
		sleep:        func(time.Duration) {},
	}
}

func TestConfirmCommittedOnFirstAttemptPostsExactlyOnce(t *testing.T) {
	n := newFakeNode(t, "tx-stable", fixedState(`{"transactionId":"tx-stable","state":"committed","blockHeight":7}`))
	c := testConfirmer(signedBody, n.srv.URL)

	res, err := c.Confirm(context.Background())
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if res.State != StateCommitted || res.TxId != "tx-stable" || res.BlockHeight != 7 {
		t.Errorf("Result = %+v, want committed tx-stable at height 7", res)
	}
	if got := n.postCalls.Load(); got != 1 {
		t.Errorf("posts = %d, want exactly 1", got)
	}
	if len(res.Attempts) != 1 || res.Attempts[0].State != StateCommitted {
		t.Errorf("Attempts = %+v, want one committed attempt", res.Attempts)
	}
}

func TestConfirmReplaysTheIdenticalBytesToEveryEndpoint(t *testing.T) {
	a := newFakeNode(t, "tx-stable", fixedState(`{"transactionId":"tx-stable","state":"rejected","reason":"insufficient balance for transfer"}`))
	b := newFakeNode(t, "tx-stable", fixedState(`{"transactionId":"tx-stable","state":"committed","blockHeight":9}`))
	c := testConfirmer(signedBody, a.srv.URL, b.srv.URL)

	res, err := c.Confirm(context.Background())
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if res.State != StateCommitted || res.TxId != "tx-stable" {
		t.Errorf("Result = %+v, want committed under the single stable id", res)
	}
	if !bytes.Equal(a.firstPostBody(), signedBody) || !bytes.Equal(b.firstPostBody(), signedBody) {
		t.Error("posted bytes differ from SignedBody: Confirm must replay the identical signed bytes, never rebuild them")
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("Attempts = %+v, want 2 entries", res.Attempts)
	}
	first := res.Attempts[0]
	if first.Endpoint != a.srv.URL || first.State != StateRejected || !strings.Contains(first.Reason, "insufficient balance") {
		t.Errorf("first attempt = %+v, want the rejection on %s recorded with its reason", first, a.srv.URL)
	}
}

func TestConfirmUnanimousRejectionIsANilErrorResult(t *testing.T) {
	a := newFakeNode(t, "tx-stable", fixedState(`{"transactionId":"tx-stable","state":"rejected","reason":"insufficient balance for transfer"}`))
	b := newFakeNode(t, "tx-stable", fixedState(`{"transactionId":"tx-stable","state":"rejected","reason":"insufficient balance for transfer"}`))
	c := testConfirmer(signedBody, a.srv.URL, b.srv.URL)
	c.Attempts = 2

	res, err := c.Confirm(context.Background())
	if err != nil {
		t.Fatalf("Confirm on unanimous rejection = %v, want nil: a unanimous denial is a valid answer, not a failure", err)
	}
	if res.State != StateRejected || res.TxId != "tx-stable" {
		t.Errorf("Result = %+v, want rejected under the single stable id", res)
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("Attempts = %+v, want both rejections recorded", res.Attempts)
	}
	for _, at := range res.Attempts {
		if at.State != StateRejected || at.Reason == "" {
			t.Errorf("attempt %+v: every attempt must carry its rejection reason", at)
		}
	}
}

func TestConfirmUnknownThenRejectedWithinGrace(t *testing.T) {
	n := newFakeNode(t, "tx-stable", func(call int) string {
		if call == 1 {
			return `{"transactionId":"tx-stable","state":"unknown"}`
		}
		return `{"transactionId":"tx-stable","state":"rejected","reason":"insufficient balance for transfer"}`
	})
	c := testConfirmer(signedBody, n.srv.URL)
	c.Attempts = 1

	res, err := c.Confirm(context.Background())
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if res.State != StateRejected {
		t.Errorf("Result.State = %s, want rejected: the first unknown is the record gap, not a terminal state", res.State)
	}
	if got := n.postCalls.Load(); got != 1 {
		t.Errorf("posts = %d, want 1: an unknown inside the grace window must not trigger a replay yet", got)
	}
}

func TestConfirmAllAttemptsLostIsAnError(t *testing.T) {
	a := newFakeNode(t, "tx-stable", fixedState(`{"transactionId":"tx-stable","state":"unknown"}`))
	b := newFakeNode(t, "tx-stable", fixedState(`{"transactionId":"tx-stable","state":"unknown"}`))
	c := testConfirmer(signedBody, a.srv.URL, b.srv.URL)
	c.UnknownGrace = time.Nanosecond

	res, err := c.Confirm(context.Background())
	if err == nil {
		t.Fatal("Confirm() = nil error, want an error: every endpoint lost sight of the transaction, the outcome is undetermined")
	}
	if !strings.Contains(err.Error(), "no terminal outcome") {
		t.Errorf("error %q should say no terminal outcome was reached", err)
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("Attempts = %+v, want both lost attempts recorded for diagnosis", res.Attempts)
	}
	for _, at := range res.Attempts {
		if at.State != StateUnknown {
			t.Errorf("attempt %+v, want StateUnknown recorded", at)
		}
	}
}

func TestConfirmRecordsPendingAttemptsAsPending(t *testing.T) {
	a := newFakeNode(t, "tx-stable", fixedState(`{"transactionId":"tx-stable","state":"pending"}`))
	b := newFakeNode(t, "tx-stable", fixedState(`{"transactionId":"tx-stable","state":"pending"}`))
	c := testConfirmer(signedBody, a.srv.URL, b.srv.URL)
	c.AttemptTimeout = time.Nanosecond

	res, err := c.Confirm(context.Background())
	if err == nil {
		t.Fatal("Confirm() = nil error, want an error: pending on every endpoint is not a terminal outcome")
	}
	if got := a.postCalls.Load() + b.postCalls.Load(); got != 2 {
		t.Errorf("posts = %d, want 2: replaying past a pending attempt is safe under the stable id and must proceed", got)
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("Attempts = %+v, want 2 entries", res.Attempts)
	}
	for _, at := range res.Attempts {
		if at.State != StatePending {
			t.Errorf("attempt %+v, want StatePending recorded, not StateUnknown", at)
		}
	}
}

func TestConfirmPendingThenUnknownKeepsPollingUntilAttemptDeadline(t *testing.T) {
	n := newFakeNode(t, "tx-stable", func(call int) string {
		if call == 1 {
			return `{"transactionId":"tx-stable","state":"pending"}`
		}
		return `{"transactionId":"tx-stable","state":"unknown"}`
	})
	c := testConfirmer(signedBody, n.srv.URL)
	c.Attempts = 1
	c.UnknownGrace = time.Nanosecond
	c.AttemptTimeout = 25 * time.Millisecond

	res, err := c.Confirm(context.Background())
	if err == nil {
		t.Fatal("Confirm() = nil error, want an error: the single attempt never reached a terminal state")
	}
	if got := n.getCalls.Load(); got <= 2 {
		t.Errorf("status polls = %d, want more than 2: once pending has been observed, a later unknown past the grace window must not end the attempt early", got)
	}
	if len(res.Attempts) != 1 || res.Attempts[0].State != StatePending {
		t.Errorf("Attempts = %+v, want the attempt recorded as StatePending, its last meaningful observation", res.Attempts)
	}
}

func TestConfirmContextCancelledBetweenPollsStopsAfterTheCurrentPoll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	n := newFakeNode(t, "tx-stable", func(call int) string {
		cancel()
		return `{"transactionId":"tx-stable","state":"unknown"}`
	})
	c := testConfirmer(signedBody, n.srv.URL)

	_, err := c.Confirm(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Confirm() error = %v, want context.Canceled: cancellation is honored between polls", err)
	}
	if got := n.postCalls.Load(); got != 1 {
		t.Errorf("posts = %d, want 1", got)
	}
}

func TestConfirmContextCancelledBeforeStartSubmitsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n := newFakeNode(t, "tx-stable", fixedState(`{"transactionId":"tx-stable","state":"committed"}`))
	c := testConfirmer(signedBody, n.srv.URL)

	_, err := c.Confirm(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Confirm() error = %v, want context.Canceled", err)
	}
	if got := n.postCalls.Load(); got != 0 {
		t.Errorf("posts = %d, want 0 after cancellation", got)
	}
}

func TestConfirmPostFailureIsAnErrorNeverARejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unable to create transaction", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := testConfirmer(signedBody, srv.URL)

	res, err := c.Confirm(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unable to create transaction") {
		t.Fatalf("Confirm() error = %v, want the POST failure surfaced", err)
	}
	if res.State == StateRejected {
		t.Errorf("Result = %+v: a POST failure is indistinguishable from a node fault and must never be recorded as a rejection", res)
	}
	for _, at := range res.Attempts {
		if at.State == StateRejected {
			t.Errorf("attempt %+v: a POST failure is indistinguishable from a node fault and must never be recorded as a rejection", at)
		}
	}
}

func TestConfirmPostTransportErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead := srv.URL
	srv.Close()
	c := testConfirmer(signedBody, dead)

	if _, err := c.Confirm(context.Background()); err == nil {
		t.Fatal("Confirm() against a closed server = nil error, want a transport error")
	}
}

func TestConfirmPersistentStatusReadFailureSurfacesAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Write([]byte(`{"transactionId":"tx-stable"}`))
			return
		}
		http.Error(w, "database not initialized", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := testConfirmer(signedBody, srv.URL)
	c.AttemptTimeout = time.Nanosecond

	_, err := c.Confirm(context.Background())
	if err == nil {
		t.Fatal("Confirm() = nil error, want the status-read failure surfaced")
	}
	if strings.Contains(err.Error(), "no terminal outcome") {
		t.Errorf("error %q must be the read failure, not a lost-attempt summary: a node that answers nothing is a fault, not a denial", err)
	}
}

func deadEndpoint(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	return url
}

func TestConfirmDeadEndpointFailsOverToTheNextEndpoint(t *testing.T) {
	dead := deadEndpoint(t)
	live := newFakeNode(t, "tx-stable", fixedState(`{"transactionId":"tx-stable","state":"committed","blockHeight":4}`))
	c := testConfirmer(signedBody, dead, live.srv.URL)

	res, err := c.Confirm(context.Background())
	if err != nil {
		t.Fatalf("Confirm() = %v, want nil: an unreachable endpoint must be skipped, not abort the run", err)
	}
	if res.State != StateCommitted || res.TxId != "tx-stable" || res.BlockHeight != 4 {
		t.Errorf("Result = %+v, want committed tx-stable at height 4", res)
	}
	if got := live.postCalls.Load(); got != 1 {
		t.Errorf("posts to the live endpoint = %d, want 1", got)
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("Attempts = %+v, want the dead endpoint recorded alongside the live one", res.Attempts)
	}
	if res.Attempts[0].Endpoint != dead || res.Attempts[0].State != StateUnknown || res.Attempts[0].Reason == "" {
		t.Errorf("first attempt = %+v, want the dead endpoint recorded as StateUnknown with a reason", res.Attempts[0])
	}
	if res.Attempts[1].State != StateCommitted {
		t.Errorf("second attempt = %+v, want the live endpoint recorded as committed", res.Attempts[1])
	}
}

func TestConfirmEveryEndpointDeadIsAnUnreachableError(t *testing.T) {
	c := testConfirmer(signedBody, deadEndpoint(t), deadEndpoint(t))

	res, err := c.Confirm(context.Background())
	if err == nil {
		t.Fatal("Confirm() = nil error, want an error: every endpoint was unreachable")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("error %q should report that no endpoint was reachable, distinctly from a denial", err)
	}
	if strings.Contains(err.Error(), "no terminal outcome") {
		t.Errorf("error %q must report unreachable endpoints, not a lost-outcome summary", err)
	}
	if res.State == StateRejected {
		t.Errorf("Result = %+v: unreachable endpoints must never read as a rejection", res)
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("Attempts = %+v, want both unreachable endpoints recorded for diagnosis", res.Attempts)
	}
	for _, at := range res.Attempts {
		if at.State != StateUnknown {
			t.Errorf("attempt %+v, want StateUnknown recorded", at)
		}
	}
}

func TestConfirmRejectionPlusDeadEndpointIsNotAUnanimousRejection(t *testing.T) {
	a := newFakeNode(t, "tx-stable", fixedState(`{"transactionId":"tx-stable","state":"rejected","reason":"insufficient balance for transfer"}`))
	c := testConfirmer(signedBody, a.srv.URL, deadEndpoint(t))

	res, err := c.Confirm(context.Background())
	if err == nil {
		t.Fatal("Confirm() = nil error, want an error: one endpoint rejected and the other never answered, so the denial is not unanimous")
	}
	if res.State == StateRejected {
		t.Errorf("Result = %+v: a fault on one endpoint must never complete a unanimous denial", res)
	}
}

func TestConfirmDivergentTransactionIdIsAnError(t *testing.T) {
	a := newFakeNode(t, "tx-one", fixedState(`{"transactionId":"tx-one","state":"pending"}`))
	b := newFakeNode(t, "tx-two", fixedState(`{"transactionId":"tx-two","state":"committed"}`))
	c := testConfirmer(signedBody, a.srv.URL, b.srv.URL)
	c.AttemptTimeout = time.Nanosecond

	res, err := c.Confirm(context.Background())
	if err == nil {
		t.Fatal("Confirm() = nil error, want an error: a second id for the same bytes means an untracked transaction exists")
	}
	if !strings.Contains(err.Error(), "tx-one") || !strings.Contains(err.Error(), "tx-two") {
		t.Errorf("error %q must name both the tracked id and the divergent one", err)
	}
	if res.State == StateCommitted {
		t.Errorf("Result = %+v: a commitment under a divergent id must not be reported as success", res)
	}
}

func TestConfirmRequiresConfiguration(t *testing.T) {
	c := &Confirmer{}
	if _, err := c.Confirm(context.Background()); err == nil {
		t.Fatal("Confirm() with no Getter, Poster, BlockchainId, SignedBody or Endpoints = nil error, want a configuration error")
	}
}
