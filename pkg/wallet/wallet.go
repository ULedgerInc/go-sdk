package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ULedgerInc/golang-sdk/pkg/crypto"
	"github.com/ULedgerInc/golang-sdk/pkg/utils"
)

type UL_Wallet struct {
	Address    string                       `json:"address"`
	Enabled    bool                         `json:"enabled"`
	Parent     string                       `json:"parent"`
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

func (w *UL_Wallet) GetKey() crypto.ULKey {
	return w.key
}

func FromJson(data string, passphrase string) (*UL_Wallet, error) {
	wd := &WalletData{}
	err := json.Unmarshal([]byte(data), wd)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal wallet JSON: %s", utils.HandleJsonError(err))
	}

	wallet := UL_Wallet{
		Address:    wd.Address,
		Parent:     wd.Parent,
		Enabled:    wd.Enabled,
		AuthGroups: wd.AuthGroups,
	}

	wallet.key, err = crypto.GetKeyByType(wd.KeyType, crypto.GetHasherByType(wd.KeyType))
	if err != nil {
		return nil, fmt.Errorf("failed to get key by type: %w", err)
	}

	if wallet.key == nil {
		return nil, fmt.Errorf("unsupported key type: %d", wd.KeyType)
	}

	// SECP256K1 requires public key bytes to be valid
	err = wallet.key.GeneratePublicKeyFromHex(false, wd.PublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key from hex: %w", err)
	}

	err = wallet.key.GeneratePrivateKeyFromHex(wd.PrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key from hex: %w", err)
	}

	return &wallet, nil
}

func GetWalletFromHex(publicKeyHex, privateKeyHex string, keyType crypto.KeyType) (UL_Wallet, error) {
	// By default, the hasher is MimcHash on the BN254 curve
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

func ParseAddress(publicKeyHex string) string {
	lower := strings.ToLower(publicKeyHex)
	d := sha256.Sum256([]byte(lower))
	return hex.EncodeToString(d[:])
}

// GenerateFromMnemonic creates a new wallet from a BIP-39 mnemonic phrase
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

// GenerateNewWallet creates a new wallet with a random mnemonic phrase
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

// SaveToFile saves the wallet data to a file with .ukey extension
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

// LoadFromFile loads a wallet from a .ukey file
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

	// If mnemonic is present, use it to generate the wallet
	if data.Mnemonic != "" {
		return GenerateFromMnemonic(data.Mnemonic, passphrase, data.KeyType)
	}

	// If private key is present, use it to generate the wallet
	if data.PrivateKeyHex != "" {
		hasher := crypto.GetHasherByType(data.KeyType)
		key, err := crypto.GetKeyByType(data.KeyType, hasher)
		if err != nil {
			return UL_Wallet{}, err
		}

		// Generate public key from hex
		if err := key.GeneratePublicKeyFromHex(false, data.PublicKeyHex); err != nil {
			return UL_Wallet{}, err
		}

		// Generate private key from hex
		if err := key.GeneratePrivateKeyFromHex(data.PrivateKeyHex); err != nil {
			return UL_Wallet{}, err
		}

		// Create wallet
		wallet := UL_Wallet{
			Address: data.Address,
			key:     key,
		}

		return wallet, nil
	}

	// Otherwise, try to load from public key only
	hasher := crypto.GetHasherByType(data.KeyType)
	key, err := crypto.GetKeyByType(data.KeyType, hasher)
	if err != nil {
		return UL_Wallet{}, err
	}

	// Generate public key from hex
	if err := key.GeneratePublicKeyFromHex(false, data.PublicKeyHex); err != nil {
		return UL_Wallet{}, err
	}

	// Create wallet
	wallet := UL_Wallet{
		Address: data.Address,
		key:     key,
	}

	return wallet, nil
}
