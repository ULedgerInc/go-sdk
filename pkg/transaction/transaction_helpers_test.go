package transaction

import (
	"net/http"
	"testing"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

const (
	testSignPrivateKeyHex = "63f6062f2034bcbcc08bae2eaabee8dd780d352cd76c595dce3a631ce8877934"
	testSignPublicKeyHex  = "04f2f0fd15ba3a7f4ba62cd705c4df8094917e7e85cab345beaf0b378f84a3422ced9a9cf925c05ded76c63ab677207287a5b64b2fb683803abef934259fa37c5d"
)

// testSession builds a session around a caller-supplied client without
// touching the network, so tests control exactly what the node returns.
func testSession(t *testing.T, endpoint string, client *http.Client) UL_TransactionSession {
	t.Helper()
	w, err := wallet.GetWalletFromHex(testSignPublicKeyHex, testSignPrivateKeyHex, crypto.KeyTypeSecp256k1)
	if err != nil {
		t.Fatalf("GetWalletFromHex: %v", err)
	}
	return UL_TransactionSession{nodeEndpoint: endpoint, suggestor: "node-1", wallet: w, httpClient: client}
}
