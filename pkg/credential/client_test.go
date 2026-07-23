package credential

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIssueIdentityCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/identity/credentials/issue" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `"type":"identity"`) {
			t.Errorf("expected body to contain \"type\":\"identity\", got %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"credential":"a.b.c","jti":"urn:x"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, false)
	jws, jti, err := c.IssueIdentityCredential(IdentityClaim{SubjectDID: "did:ulnet:chain-1:aa11"}, "tx-1")
	if err != nil {
		t.Fatal(err)
	}
	if jws != "a.b.c" || jti != "urn:x" {
		t.Fatalf("got jws=%q jti=%q", jws, jti)
	}
}

func TestIssueIdentityCredentialNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "claim is required", http.StatusBadRequest)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, false)
	_, _, err := c.IssueIdentityCredential(IdentityClaim{}, "")
	if err == nil || !strings.Contains(err.Error(), "claim is required") {
		t.Fatalf("expected error surfacing response body, got %v", err)
	}
}

func TestIssueAuthenticationCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/identity/credentials/issue" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `"type":"authentication"`) {
			t.Errorf("expected body to contain \"type\":\"authentication\", got %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"credential":"d.e.f","jti":"urn:y"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, false)
	jws, jti, err := c.IssueAuthenticationCredential("chain-1", "tx-1")
	if err != nil {
		t.Fatal(err)
	}
	if jws != "d.e.f" || jti != "urn:y" {
		t.Fatalf("got jws=%q jti=%q", jws, jti)
	}
}

func TestFetchStatusList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/identity/credentials/status/chain-1/1" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/vc+jwt")
		w.Write([]byte("a.b.c\n"))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, false)
	jws, err := c.FetchStatusList("chain-1", "1")
	if err != nil {
		t.Fatal(err)
	}
	if jws != "a.b.c" {
		t.Fatalf("got jws=%q", jws)
	}
}
