package transaction

import (
	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/wallet"
)

type CapabilityLimits struct {
	MaxAmount      string `json:"maxAmount,omitempty"`
	MaxInvocations uint64 `json:"maxInvocations,omitempty"`
}

type Capability struct {
	Action   string            `json:"action"`
	Resource string            `json:"resource"`
	Limits   *CapabilityLimits `json:"limits,omitempty"`
	NotAfter uint64            `json:"notAfter,omitempty"`
}

// DID document and resolution types, matching the JSON returned by the node's DID resolver.
type PublicKeyJwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
}

type VerificationMethod struct {
	Id                 string        `json:"id"`
	Type               string        `json:"type"`
	Controller         string        `json:"controller"`
	PublicKeyJwk       *PublicKeyJwk `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase string        `json:"publicKeyMultibase,omitempty"`
}

type CapabilityView struct {
	Action   string            `json:"action"`
	Resource string            `json:"resource,omitempty"`
	NotAfter uint64            `json:"notAfter,omitempty"`
	Limits   *CapabilityLimits `json:"limits,omitempty"`
}

type ServiceEntry struct {
	Id              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

type DIDDocument struct {
	Context              []string             `json:"@context"`
	Id                   string               `json:"id"`
	Controller           string               `json:"controller,omitempty"`
	VerificationMethod   []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication       []string             `json:"authentication,omitempty"`
	AssertionMethod      []string             `json:"assertionMethod,omitempty"`
	CapabilityDelegation []string             `json:"capabilityDelegation,omitempty"`
	CapabilityInvocation []string             `json:"capabilityInvocation,omitempty"`
	Service              []ServiceEntry       `json:"service,omitempty"`
}

type DIDDocumentMetadata struct {
	Deactivated      bool             `json:"deactivated"`
	ResolvedAtHeight uint64           `json:"resolvedAtHeight,omitempty"`
	CreatedBlock     uint64           `json:"createdBlock,omitempty"`
	EntityType       string           `json:"entityType,omitempty"`
	Name             string           `json:"name,omitempty"`
	Capabilities     []CapabilityView `json:"capabilities,omitempty"`
}

type DIDResolutionMetadata struct {
	ContentType string `json:"contentType,omitempty"`
	Retrieved   string `json:"retrieved,omitempty"`
	Error       string `json:"error,omitempty"`
}

type DIDResolutionResult struct {
	DIDResolutionMetadata DIDResolutionMetadata `json:"didResolutionMetadata"`
	DIDDocument           DIDDocument           `json:"didDocument"`
	DIDDocumentMetadata   DIDDocumentMetadata   `json:"didDocumentMetadata"`
}

// Signed DID-resolution envelope, returned by the resolver when signed=1 is requested.
type ResolutionFreshness struct {
	ChainId       string `json:"chainId"`
	HeadHeight    uint64 `json:"headHeight"`
	HeadBlockHash string `json:"headBlockHash"`
	SignedAt      string `json:"signedAt"`
}

type ResolutionSigner struct {
	PublicKey string         `json:"publicKey"`
	KeyType   crypto.KeyType `json:"keyType"`
}

type SignedResolutionEnvelope struct {
	Payload   string              `json:"payload"`
	Freshness ResolutionFreshness `json:"freshness"`
	Signer    ResolutionSigner    `json:"signer"`
	Signature string              `json:"signature"`
}

// IdentityClaim and VerifyResult are the request and response for the node's
// identity-verify endpoint.
type IdentityClaim struct {
	SubjectDID       string       `json:"subjectDid"`
	EntityAddress    string       `json:"entityAddress,omitempty"`
	Role             string       `json:"role,omitempty"`
	EntityType       string       `json:"entityType,omitempty"`
	Capabilities     []Capability `json:"capabilities,omitempty"`
	ValidUntilHeight uint64       `json:"validUntilHeight,omitempty"`
}

type VerifyResult struct {
	Valid   bool     `json:"valid"`
	Reasons []string `json:"reasons,omitempty"`
}

type WalletRecord struct {
	PublicKey        string                              `json:"publicKey"`
	Address          string                              `json:"address"`
	Parent           string                              `json:"parent"`
	Entity           string                              `json:"entity"`
	Enabled          bool                                `json:"enabled"`
	SatelliteWallets []string                            `json:"satelliteWallets"`
	AuthGroups       map[string]wallet.UL_AuthPermission `json:"authGroups"`
	Capabilities     []Capability                        `json:"capabilities,omitempty"`
	KeyType          crypto.KeyType                      `json:"keyType"`
}
