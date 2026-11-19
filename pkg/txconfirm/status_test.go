package txconfirm

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseStateAcceptsTheFourKnownStates(t *testing.T) {
	for _, s := range []string{"committed", "pending", "rejected", "unknown"} {
		got, err := ParseState(s)
		if err != nil {
			t.Errorf("ParseState(%q) error = %v, want nil", s, err)
		}
		if string(got) != s {
			t.Errorf("ParseState(%q) = %q", s, got)
		}
	}
}

func TestParseStateRejectsUnrecognisedValues(t *testing.T) {
	for _, s := range []string{"", "Committed", "dropped", "REJECTED"} {
		if _, err := ParseState(s); err == nil {
			t.Errorf("ParseState(%q) = nil error, want an error: an unrecognised state must be a parse error, not a fallthrough to unknown", s)
		}
	}
}

func statusServer(t *testing.T, status int, body string) (*httptest.Server, *string) {
	t.Helper()
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &gotPath
}

func TestFetchParsesEachState(t *testing.T) {
	cases := []struct {
		name string
		body string
		want Status
	}{
		{"committed", `{"transactionId":"tx-1","state":"committed","blockHeight":41}`, Status{TransactionId: "tx-1", State: StateCommitted, BlockHeight: 41}},
		{"pending", `{"transactionId":"tx-2","state":"pending"}`, Status{TransactionId: "tx-2", State: StatePending}},
		{"rejected", `{"transactionId":"tx-3","state":"rejected","reason":"insufficient balance for transfer"}`, Status{TransactionId: "tx-3", State: StateRejected, Reason: "insufficient balance for transfer"}},
		{"unknown", `{"transactionId":"tx-4","state":"unknown"}`, Status{TransactionId: "tx-4", State: StateUnknown}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, gotPath := statusServer(t, http.StatusOK, tc.body)
			got, err := Fetch(srv.Client(), srv.URL, "chain-1", tc.want.TransactionId)
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if got != tc.want {
				t.Errorf("Fetch = %+v, want %+v", got, tc.want)
			}
			wantPath := "/blockchains/chain-1/transactions/" + tc.want.TransactionId + "/status"
			if *gotPath != wantPath {
				t.Errorf("Fetch hit %s, want %s", *gotPath, wantPath)
			}
		})
	}
}

func TestFetchErrorsOnUnrecognisedState(t *testing.T) {
	srv, _ := statusServer(t, http.StatusOK, `{"transactionId":"tx-5","state":"dropped"}`)
	_, err := Fetch(srv.Client(), srv.URL, "chain-1", "tx-5")
	if err == nil {
		t.Fatal("Fetch() = nil error, want a parse error for an unrecognised state")
	}
	if !strings.Contains(err.Error(), "dropped") {
		t.Errorf("error %q should name the unrecognised state", err)
	}
}

func TestFetchErrorsOnNon200(t *testing.T) {
	srv, _ := statusServer(t, http.StatusInternalServerError, "database not initialized")
	_, err := Fetch(srv.Client(), srv.URL, "chain-1", "tx-6")
	if err == nil {
		t.Fatal("Fetch() = nil error, want an error for a 500")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "database not initialized") {
		t.Errorf("error %q should carry the status code and body", err)
	}
}

func TestFetchErrorsOnTransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	if _, err := Fetch(http.DefaultClient, url, "chain-1", "tx-7"); err == nil {
		t.Fatal("Fetch() against a closed server = nil error, want a transport error")
	}
}

func TestFetchErrorsOnOversizedBody(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"parseable json padded past the cap", `{"transactionId":"tx-9","state":"committed","blockHeight":41}` + strings.Repeat(" ", 300<<10)},
		{"reason field past the cap", `{"transactionId":"tx-9","state":"rejected","reason":"` + strings.Repeat("a", 300<<10) + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := statusServer(t, http.StatusOK, tc.body)
			got, err := Fetch(srv.Client(), srv.URL, "chain-1", "tx-9")
			if err == nil {
				t.Fatalf("Fetch = %+v with nil error, want an error: an oversized body must not parse", got)
			}
			if !strings.Contains(err.Error(), "exceeds") {
				t.Errorf("error %q should report the body size cap rather than a decode failure", err)
			}
		})
	}
}

func TestFetchAcceptsALongRejectionReasonUnderTheCap(t *testing.T) {
	reason := strings.Repeat("a", 64<<10)
	srv, _ := statusServer(t, http.StatusOK, `{"transactionId":"tx-10","state":"rejected","reason":"`+reason+`"}`)
	got, err := Fetch(srv.Client(), srv.URL, "chain-1", "tx-10")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.State != StateRejected || got.Reason != reason {
		t.Errorf("Fetch state = %q, reason length = %d, want %q and %d", got.State, len(got.Reason), StateRejected, len(reason))
	}
}

func TestFetchErrorsOnMalformedJSON(t *testing.T) {
	srv, _ := statusServer(t, http.StatusOK, `{"state":`)
	if _, err := Fetch(srv.Client(), srv.URL, "chain-1", "tx-8"); err == nil {
		t.Fatal("Fetch() = nil error, want a decode error")
	}
}
