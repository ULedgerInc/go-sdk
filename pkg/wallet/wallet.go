package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ULedgerInc/go-sdk/pkg/crypto"
	"github.com/ULedgerInc/go-sdk/pkg/utils"
)

type UL_Wallet struct {
	Address    string                       `json:"address"`
	Enabled    bool                         `json:"enabled"`
	Parent     string                       `json:"parent"`
	Entity     string                       `json:"entity"`
	AuthGroups map[string]UL_AuthPermission `json:"authGroups"`
	key        crypto.ULKey                 `json:"-"`
}

type UL_AuthPermission struct {
	Create bool `json:"create"` // Create new entries of this type
	Read   bool `json:"read"`   // Read existing entries of this type
	Update bool `json:"update"` // Update existing entries of this type
	Delete bool `json:"delete"` // Delete existing entries of this type
}

// WalletData represents the JSON structure for wallet persistence
type WalletData struct {
	Address       string                       `json:"address"`
	Enabled       bool                         `json:"enabled"`
	Parent        string                       `json:"parent"`
	AuthGroups    map[string]UL_AuthPermission `json:"authGroups"`
	Mnemonic      string                       `json:"mnemonic"`
	KeyType       crypto.KeyType               `json:"keyType"`
	PublicKeyHex  string                       `json:"publicKeyHex"`
	PrivateKeyHex string                       `json:"privateKeyHex"`
}

// These are default known auth group names for common operations
const (
	WALLET_GROUP_NAME = "wallet"
)

// Signed and verified on load to prove the stored key halves belong together
const keyPairCheckMessage = "ul-wallet-key-pair-check"

var (
	errNoKeyMaterial    = errors.New("wallet file has neither a public key nor a mnemonic")
	errMissingPublicKey = errors.New("wallet file has a private key but no public key")
	errKeyPairMismatch  = errors.New("public key does not belong to the private key")
	errMnemonicMismatch = errors.New("mnemonic and passphrase do not derive the stored key (wrong passphrase or mismatched file)")
	errAddressMismatch  = errors.New("address does not match the public key")
)

func (w *UL_Wallet) GetKey() crypto.ULKey {
	return w.key
}

// Loads a wallet from a JSON string. The passphrase is used to derive the key from the mnemonic, if present.
func FromJson(data string, passphrase string) (*UL_Wallet, error) {
	wd := &WalletData{}
	err := json.Unmarshal([]byte(data), wd)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal wallet JSON: %s", utils.HandleJsonError(err))
	}

	wallet, err := fromWalletData(*wd, passphrase)
	if err != nil {
		return nil, err
	}

	return &wallet, nil
}

// Primary loader for derived wallet data. It checks the address against the derived public key
//
// Returns:
// - error if the address does not match the derived public key.
func fromWalletData(wd WalletData, passphrase string) (UL_Wallet, error) {
	key, err := keyFromWalletData(wd, passphrase)
	if err != nil {
		return UL_Wallet{}, err
	}

	// Parse the address from the uncompressed public key hex.
	address := ParseAddress(key.GetPublicKeyHex(false))
	if wd.Address != "" && !strings.EqualFold(wd.Address, address) {
		return UL_Wallet{}, fmt.Errorf("%w: file has %s, key gives %s", errAddressMismatch, wd.Address, address)
	}

	wallet := UL_Wallet{
		Address:    address,
		Parent:     wd.Parent,
		Enabled:    wd.Enabled,
		AuthGroups: wd.AuthGroups,
		key:        key,
	}

	return wallet, nil
}

// Resolves the key from the hex fields and the mnemonic in the wallet data.
//
//	hex keys | mnemonic | result
//	---------+----------+-------------------------------------------
//	yes      | no       | hex key (can not sign if private key is missing)
//	no       | yes      | mnemonic-derived key
//	yes      | yes      | mnemonic-derived key, must match hex key
//	no       | no       | error
func keyFromWalletData(wd WalletData, passphrase string) (crypto.ULKey, error) {
	stored, err := keyFromHex(wd)
	if err != nil {
		return nil, err
	}

	if wd.Mnemonic == "" {
		if stored == nil {
			return nil, errNoKeyMaterial
		}
		return stored, nil
	}

	derived, err := GenerateFromMnemonic(wd.Mnemonic, passphrase, wd.KeyType)
	if err != nil {
		return nil, err
	}

	if stored != nil && !strings.EqualFold(stored.GetPublicKeyHex(false), derived.key.GetPublicKeyHex(false)) {
		return nil, errMnemonicMismatch
	}

	return derived.key, nil
}

// Generates a key based on the hex fields in the wallet data.
//
// Returns:
// - nil if no public key is present.
// - error if a private key is present but no public key.
// - error if the hex values are invalid/keypair does not match.
func keyFromHex(wd WalletData) (crypto.ULKey, error) {
	if wd.PublicKeyHex == "" {
		if wd.PrivateKeyHex != "" {
			return nil, errMissingPublicKey
		}
		return nil, nil
	}

	key, err := crypto.GetKeyByType(wd.KeyType, crypto.GetHasherByType(wd.KeyType))
	if err != nil {
		return nil, fmt.Errorf("failed to get key by type: %w", err)
	}

	if err := key.GeneratePublicKeyFromHex(false, wd.PublicKeyHex); err != nil {
		return nil, fmt.Errorf("failed to generate public key from hex: %w", err)
	}

	if wd.PrivateKeyHex == "" {
		return key, nil
	}

	if err := key.GeneratePrivateKeyFromHex(wd.PrivateKeyHex); err != nil {
		return nil, fmt.Errorf("failed to generate private key from hex: %w", err)
	}

	if err := checkKeyPair(key); err != nil {
		return nil, err
	}

	return key, nil
}

// Checks that a key pair is valid by signing and verifying a known message.
//
// Returns:
// - error if the key can not sign or verify the message, indicating a mismatch between the public and private keys.
func checkKeyPair(key crypto.ULKey) error {
	sig, err := key.SignData([]byte(keyPairCheckMessage))
	if err != nil {
		return fmt.Errorf("%w: %v", errKeyPairMismatch, err)
	}

	ok, err := key.VerifySignature([]byte(keyPairCheckMessage), sig)
	if err != nil || !ok {
		return errKeyPairMismatch
	}

	return nil
}

// Creates a wallet from the provided public and private key hex strings. The keyType specifies the type of key (e.g., secp256k1, ed25519, ...).
func GetWalletFromHex(publicKeyHex, privateKeyHex string, keyType crypto.KeyType) (UL_Wallet, error) {
	hasher := crypto.GetHasherByType(keyType)
	key, err := crypto.GetKeyByType(keyType, hasher)
	if err != nil {
		return UL_Wallet{}, err
	}
	err = key.GeneratePublicKeyFromHex(false, publicKeyHex)
	if err != nil {
		return UL_Wallet{}, err
	}
	err = key.GeneratePrivateKeyFromHex(privateKeyHex)
	if err != nil {
		return UL_Wallet{}, err
	}

	address := ParseAddress(key.GetPublicKeyHex(false))

	wallet := UL_Wallet{
		Address: address,
		key:     key,
	}

	return wallet, nil
}

// Gets the SHA-256 hash of the lowercase public key hex string.
func ParseAddress(publicKeyHex string) string {
	lower := strings.ToLower(publicKeyHex)
	d := sha256.Sum256([]byte(lower))
	return hex.EncodeToString(d[:])
}

// Creates a new wallet from a BIP-39 mnemonic phrase.
//
// Returns:
// - error if the mnemonic is invalid or the key generation fails.
func GenerateFromMnemonic(mnemonic string, passphrase string, keyType crypto.KeyType) (UL_Wallet, error) {
	// Convert mnemonic to seed
	seed, err := MnemonicToSeed(mnemonic, passphrase)
	if err != nil {
		return UL_Wallet{}, fmt.Errorf("failed to convert mnemonic to seed: %w", err)
	}

	// Generate key from seed
	hasher := crypto.GetHasherByType(keyType)
	key, err := crypto.GetKeyByType(keyType, hasher)
	if err != nil {
		return UL_Wallet{}, err
	}

	// Generate key pair
	err = key.GenerateKeyFromSeed(seed)
	if err != nil {
		return UL_Wallet{}, err
	}

	// Create wallet, this is incomplete as the parent, enabled, and auth fields are populated later
	address := ParseAddress(key.GetPublicKeyHex(false))
	wallet := UL_Wallet{
		Address: address,
		key:     key,
	}

	return wallet, nil
}

// Generates a new wallet with a random mnemonic and derives the key from it.
// The passphrase is used to derive the key from the mnemonic, and the keyType specifies the type of key (e.g., secp256k1, ed25519, ...).
// The parent and authGroups are optional fields that can be set for the wallet.
// The entropy parameter allows for custom entropy to be provided for mnemonic generation; if nil, default entropy is used. This follows BIP-39 standards for mnemonic generation.
//
// Returns:
// - error if the mnemonic generation or key derivation fails.
func GenerateNewWallet(passphrase string, keyType crypto.KeyType, parent string, authGroups map[string]UL_AuthPermission, entropy Entropy) (UL_Wallet, string, error) {
	// Generate new mnemonic
	mnemonic, err := GenerateMnemonic(entropy)
	if err != nil {
		return UL_Wallet{}, "", fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	// Create wallet from mnemonic
	wallet, err := GenerateFromMnemonic(mnemonic, passphrase, keyType)
	if err != nil {
		return UL_Wallet{}, "", err
	}
	wallet.Parent = parent
	wallet.Enabled = true
	wallet.AuthGroups = authGroups

	return wallet, mnemonic, nil
}

// Saves the wallet data to a file with .ukey extension
func (w *UL_Wallet) SaveToFile(filePath string, mnemonic string, includePrivateKey bool) error {
	// Ensure file has .ukey extension
	if !strings.HasSuffix(filePath, ".ukey") {
		filePath += ".ukey"
	}

	// Create wallet data
	data := WalletData{
		Address:      w.Address,
		Parent:       w.Parent,
		Enabled:      w.Enabled,
		KeyType:      w.key.GetType(),
		Mnemonic:     mnemonic,
		PublicKeyHex: w.key.GetPublicKeyHex(false),
		AuthGroups:   w.AuthGroups,
	}

	// Only include private key if explicitly requested
	if includePrivateKey {
		data.PrivateKeyHex = w.key.GetPrivateKeyHex()
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal wallet data: %w", err)
	}

	// Write to file with strict permissions
	if err := os.WriteFile(filePath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write wallet file: %w", err)
	}

	return nil
}

// Loads a wallet from a .ukey file
func LoadFromFile(filePath string, passphrase string) (UL_Wallet, error) {
	// Read file
	jsonData, err := os.ReadFile(filePath)
	if err != nil {
		return UL_Wallet{}, fmt.Errorf("failed to read wallet file: %w", err)
	}

	// Parse JSON
	var data WalletData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return UL_Wallet{}, fmt.Errorf("failed to parse wallet data: %w", err)
	}

	return fromWalletData(data, passphrase)
}
