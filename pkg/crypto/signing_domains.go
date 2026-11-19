package crypto

import (
	"bytes"
	"errors"
	"fmt"
)

type SigningDomain string

const (
	DomainTransaction          SigningDomain = "ul/tx/v1"
	DomainWalletPossession     SigningDomain = "ul/wallet-pop/v1"
	DomainBlock                SigningDomain = "ul/block/v1"
	DomainVote                 SigningDomain = "ul/vote/v1"
	DomainCouncilJoin          SigningDomain = "ul/council-join/v1"
	DomainCouncilLeave         SigningDomain = "ul/council-leave/v1"
	DomainCouncilRoundChange   SigningDomain = "ul/council-round-change/v1"
	DomainXmGenesisAnnounce    SigningDomain = "ul/xm-genesis-announce/v1"
	DomainXmGenesisAttestation SigningDomain = "ul/xm-genesis-attestation/v1"
	DomainCheckpointReceipt    SigningDomain = "ul/checkpoint-receipt/v1"
	DomainEventRecord          SigningDomain = "ul/event-record/v1"
	DomainDIDResolution        SigningDomain = "ul/did-resolution/v1"
	DomainOperatorLogin        SigningDomain = "ul/operator-login/v1"
)

const domainSeparationTag = "ULDOMAIN"

var (
	errSignatureSelfCheck     = errors.New("signature self-check failed")
	errDomainTaggedRawMessage = errors.New("raw message must not begin with the " + domainSeparationTag + " tag")
)

// The secp256k1 and bls12377 backends separate domains only by this prefix, so
// their raw paths must never sign or accept tagged input: otherwise a raw
// signature over attacker-chosen bytes would verify as a domain signature.
func rejectDomainTagged(data []byte) error {
	if bytes.HasPrefix(data, []byte(domainSeparationTag)) {
		return errDomainTaggedRawMessage
	}
	return nil
}

func validateDomain(domain SigningDomain) error {
	if len(domain) == 0 || len(domain) > 255 {
		return fmt.Errorf("invalid signing domain length %d", len(domain))
	}
	return nil
}

func DomainSeparatedMessage(domain SigningDomain, data []byte) ([]byte, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	msg := make([]byte, 0, len(domainSeparationTag)+1+len(domain)+len(data))
	msg = append(msg, domainSeparationTag...)
	msg = append(msg, byte(len(domain)))
	msg = append(msg, domain...)
	return append(msg, data...), nil
}
