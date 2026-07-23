package identity

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

func TestHTTPClientGetTransaction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/blockchains/chain-1/transactions/tx-1" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"transactionId":"tx-1","status":"ACCEPTED","output":"SUCCESS"}`))
	}))
	defer srv.Close()

	c := newHTTPChainClient(srv.URL, false)
	tx, err := c.GetTransaction("chain-1", "tx-1")
	if err != nil {
		t.Fatal(err)
	}
	if tx.TransactionId != "tx-1" || tx.Output != "SUCCESS" {
		t.Fatalf("unexpected tx: %+v", tx)
	}
}

func TestHTTPClientGetChainHead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/blockchains/chain-1":
			w.Write([]byte(`{"blockHeight":5}`))
		case "/blockchains/chain-1/blocks":
			if r.URL.Query().Get("height") != "5" {
				http.Error(w, "unexpected height", http.StatusBadRequest)
				return
			}
			w.Write([]byte(`{"blockHash":"deadbeef"}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newHTTPChainClient(srv.URL, false)
	head, err := c.GetChainHead("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if head.Height != 5 || head.Hash != "deadbeef" {
		t.Fatalf("unexpected chain head: %+v", head)
	}
}

func TestHTTPClientResolveDID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			w.Write([]byte(`{"nodeVersion":"v1","chainsInfo":{},"nodeId":"node-1","peerId":"peer-1"}`))
		case "/blockchains":
			w.Write([]byte(`["chain-1"]`))
		case "/did/did:ulnet:chain-1:deadbeef":
			w.Write([]byte(`{"didDocument":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:ulnet:chain-1:deadbeef"},"didDocumentMetadata":{"deactivated":false,"entityType":"AGENT"}}`))
		default:
			http.Error(w, fmt.Sprintf("unexpected path %s", r.URL.Path), http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newHTTPChainClient(srv.URL, false)
	reader := &wallet.UL_Wallet{Address: "reader-addr"}
	res, err := c.ResolveDID(reader, "did:ulnet:chain-1:deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if res.DIDDocument.Id != "did:ulnet:chain-1:deadbeef" {
		t.Fatalf("unexpected did document: %+v", res.DIDDocument)
	}
	if res.DIDDocumentMetadata.Deactivated || res.DIDDocumentMetadata.EntityType != "AGENT" {
		t.Fatalf("unexpected did document metadata: %+v", res.DIDDocumentMetadata)
	}
}
