package transaction

type AuthenticateInternalPayload struct {
	Type               string `json:"type"`
	Subject            string `json:"subject,omitempty"`
	ReferenceHeight    uint64 `json:"referenceHeight"`
	ReferenceBlockHash string `json:"referenceBlockHash"`
}

type AuthenticateExternalPayload struct {
	Type     string            `json:"type"`
	Subject  string            `json:"subject,omitempty"`
	Audience string            `json:"audience"`
	Nonce    string            `json:"nonce"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func NewAuthenticateInternalPayload(subject string, referenceHeight uint64, referenceBlockHash string) AuthenticateInternalPayload {
	return AuthenticateInternalPayload{
		Type:               AUTHENTICATE_INTERNAL.String(),
		Subject:            subject,
		ReferenceHeight:    referenceHeight,
		ReferenceBlockHash: referenceBlockHash,
	}
}

func NewAuthenticateExternalPayload(subject, audience, nonce string, metadata map[string]string) AuthenticateExternalPayload {
	return AuthenticateExternalPayload{
		Type:     AUTHENTICATE_EXTERNAL.String(),
		Subject:  subject,
		Audience: audience,
		Nonce:    nonce,
		Metadata: metadata,
	}
}
