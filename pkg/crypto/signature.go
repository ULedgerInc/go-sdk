package crypto

// IsSignatureValid checks a signature over content using a hex public key,
// always treated as compressed.
func IsSignatureValid(publicKey string, content []byte, signature []byte, keyType KeyType) (bool, error) {
	key, err := GetKeyByType(keyType, GetHasherByType(keyType))
	if err != nil {
		return false, err
	}
	if err := key.GeneratePublicKeyFromHex(true, publicKey); err != nil {
		return false, err
	}
	return key.VerifySignature(content, signature)
}
