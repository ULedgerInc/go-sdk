package crypto

// IsSignatureValid mirrors the node's internal/util.IsSignatureValid: it
// reconstructs a verifying key of the given type from a hex-encoded public
// key and checks the signature over content under domain. publicKey is
// always treated as compressed=true, matching the node's own call site.
func IsSignatureValid(domain SigningDomain, publicKey string, content []byte, signature []byte, keyType KeyType) (bool, error) {
	key, err := GetKeyByType(keyType, GetHasherByType(keyType))
	if err != nil {
		return false, err
	}
	if err := key.GeneratePublicKeyFromHex(true, publicKey); err != nil {
		return false, err
	}
	return key.VerifyWithContext(domain, content, signature)
}
