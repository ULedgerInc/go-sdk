package credential

import (
	"github.com/ULedgerInc/go-sdk/pkg/transaction"
)

const (
	ContextCredentialsV2 = "https://www.w3.org/ns/credentials/v2"
	ContextULedgerV1     = "https://uledger.io/ns/credentials/v1"

	TypeVerifiableCredential            = "VerifiableCredential"
	TypeULedgerIdentityCredential       = "ULedgerIdentityCredential"
	TypeULedgerAuthenticationCredential = "ULedgerAuthenticationCredential"
	TypeBitstringStatusListCredential   = "BitstringStatusListCredential"
	TypeBitstringStatusListEntry        = "BitstringStatusListEntry"
	TypeULedgerTransactionEvidence      = "ULedgerTransactionEvidence"

	StatusPurposeRevocation = "revocation"
)

func ChainIssuer(chainId string) string {
	return "did:ulnet:" + chainId
}

// IdentityClaim aliases transaction.IdentityClaim, reused here rather than redefined.
type IdentityClaim = transaction.IdentityClaim

type Evidence struct {
	Type          string `json:"type"`
	TxId          string `json:"txId,omitempty"`
	BlockchainId  string `json:"blockchainId,omitempty"`
	BlockHeight   uint64 `json:"blockHeight,omitempty"`
	ProofEndpoint string `json:"proofEndpoint,omitempty"`
}

type CredentialStatus struct {
	Type                 string `json:"type"`
	StatusPurpose        string `json:"statusPurpose"`
	StatusListIndex      string `json:"statusListIndex"`
	StatusListCredential string `json:"statusListCredential"`
}

type CredentialSubject struct {
	Id                    string                   `json:"id"`
	Entity                string                   `json:"entity,omitempty"`
	Role                  string                   `json:"role,omitempty"`
	EntityType            string                   `json:"entityType,omitempty"`
	Capabilities          []transaction.Capability `json:"capabilities,omitempty"`
	ValidUntilHeight      uint64                   `json:"validUntilHeight,omitempty"`
	AuthenticatedAtHeight uint64                   `json:"authenticatedAtHeight,omitempty"`
	TxId                  string                   `json:"txId,omitempty"`
	Audience              string                   `json:"audience,omitempty"`
	ReferenceBlockHash    string                   `json:"referenceBlockHash,omitempty"`
	StatusPurpose         string                   `json:"statusPurpose,omitempty"`
	EncodedList           string                   `json:"encodedList,omitempty"`
}

type VerifiableCredential struct {
	Context           []string          `json:"@context"`
	Id                string            `json:"id,omitempty"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"`
	ValidFrom         string            `json:"validFrom"`
	ValidUntil        string            `json:"validUntil,omitempty"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	CredentialStatus  *CredentialStatus `json:"credentialStatus,omitempty"`
	Evidence          []Evidence        `json:"evidence,omitempty"`
}

type CredentialPayload struct {
	VerifiableCredential
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}
