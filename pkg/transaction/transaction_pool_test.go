package transaction

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

const poolSessions = 10

// poolNode is a TLS node stub that counts connections and metadata reads,
// so tests can observe what a burst of sessions costs the node.
type poolNode struct {
	srv         *httptest.Server
	connsOpened atomic.Int64
	healthHits  atomic.Int64
	chainsHits  atomic.Int64
}

func newPoolNode(t *testing.T) *poolNode {
	t.Helper()
	node := &poolNode{}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		node.healthHits.Add(1)
		w.Write([]byte(`{"nodeId":"node-1"}`))
	})
	mux.HandleFunc("/blockchains", func(w http.ResponseWriter, r *http.Request) {
		node.chainsHits.Add(1)
		w.Write([]byte(`["chain-1"]`))
	})
	mux.HandleFunc("/blockchains/chain-1/transactions", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"transactionId":"tx-1"}`))
	})

	node.srv = httptest.NewUnstartedServer(mux)
	node.srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			node.connsOpened.Add(1)
		}
	}
	node.srv.StartTLS()
	t.Cleanup(node.srv.Close)

	return node
}

func poolWallet(t *testing.T) wallet.UL_Wallet {
	t.Helper()
	w, err := wallet.GetWalletFromHex(testSignPublicKeyHex, testSignPrivateKeyHex, crypto.KeyTypeSecp256k1)
	if err != nil {
		t.Fatalf("GetWalletFromHex: %v", err)
	}
	return w
}

// One session per transaction is how callers use the SDK under load
// (core-tms). Every session must reuse pooled connections, not dial anew.
func TestSessionsShareConnections(t *testing.T) {
	node := newPoolNode(t)
	w := poolWallet(t)

	for i := range poolSessions {
		session, err := NewUL_TransactionSession(t.Context(), node.srv.URL, w, SessionOptions{InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		if _, err := session.GenerateTransaction(t.Context(), retryTestInput()); err != nil {
			t.Fatalf("session %d: GenerateTransaction: %v", i, err)
		}
	}

	if got := node.connsOpened.Load(); got != 1 {
		t.Fatalf("expected %d sequential sessions to share 1 connection, opened %d", poolSessions, got)
	}
}

// nodeId and the chain list rarely change: creating a session must not
// cost two extra round trips each time.
func TestSessionsCacheNodeMetadata(t *testing.T) {
	node := newPoolNode(t)
	w := poolWallet(t)

	for i := range poolSessions {
		if _, err := NewUL_TransactionSession(t.Context(), node.srv.URL, w, SessionOptions{InsecureSkipVerify: true}); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}

	if got := node.healthHits.Load(); got != 1 {
		t.Errorf("expected /health once for %d sessions, got %d", poolSessions, got)
	}
	if got := node.chainsHits.Load(); got != 1 {
		t.Errorf("expected /blockchains once for %d sessions, got %d", poolSessions, got)
	}
}

// A stuck connection must fail the call, not block the caller forever.
func TestSessionClientHasTimeouts(t *testing.T) {
	node := newPoolNode(t)

	session, err := NewUL_TransactionSession(t.Context(), node.srv.URL, poolWallet(t), SessionOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("NewUL_TransactionSession: %v", err)
	}

	if session.httpClient.Timeout <= 0 {
		t.Error("http.Client.Timeout is not set")
	}

	transport, ok := session.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", session.httpClient.Transport)
	}
	if transport.TLSHandshakeTimeout <= 0 {
		t.Error("Transport.TLSHandshakeTimeout is not set")
	}
	if transport.ResponseHeaderTimeout <= 0 {
		t.Error("Transport.ResponseHeaderTimeout is not set")
	}
	if transport.IdleConnTimeout <= 0 {
		t.Error("Transport.IdleConnTimeout is not set")
	}
	if transport.MaxIdleConnsPerHost <= http.DefaultMaxIdleConnsPerHost {
		t.Errorf("Transport.MaxIdleConnsPerHost is %d, not raised above the default %d", transport.MaxIdleConnsPerHost, http.DefaultMaxIdleConnsPerHost)
	}
}

// An unparseable endpoint makes http.NewRequest fail; the constructor
// must return that error instead of sending a nil request.
func TestSessionRejectsBadEndpoint(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewUL_TransactionSession panicked on a bad endpoint: %v", r)
		}
	}()

	_, err := NewUL_TransactionSession(t.Context(), "://missing-scheme", poolWallet(t), SessionOptions{})
	if err == nil {
		t.Fatal("expected an error for an unparseable endpoint")
	}
}

// The node says how long to back off; the SDK's fixed 1 s first step
// retries too early and adds load to a node that is already shedding it.
func TestRetryHonoursRetryAfter(t *testing.T) {
	const retryAfter = 3 * time.Second

	var attempts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"transactionId":"tx-1"}`))
	}))
	defer srv.Close()

	var slept []time.Duration
	session := testSession(t, srv.URL, srv.Client())
	session.sleep = func(d time.Duration) { slept = append(slept, d) }

	if _, err := session.GenerateTransaction(t.Context(), retryTestInput()); err != nil {
		t.Fatalf("GenerateTransaction: %v", err)
	}

	if len(slept) != 1 || slept[0] != retryAfter {
		t.Fatalf("expected one backoff of %s from Retry-After, got %v", retryAfter, slept)
	}
}
