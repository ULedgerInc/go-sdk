package wallet

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

type Entropy int

const (
	// Entropy sizes in bits
	Entropy128 Entropy = 128
	Entropy160 Entropy = 160
	Entropy192 Entropy = 192
	Entropy224 Entropy = 224
	Entropy256 Entropy = 256

	// Default entropy size (128 bits = 12 words)
	DefaultEntropy = Entropy256
)

func MakeEntropy(i int) Entropy {
	switch i {
	case 128:
		return Entropy128
	case 160:
		return Entropy160
	case 192:
		return Entropy192
	case 224:
		return Entropy224
	case 256:
		return Entropy256
	default:
		return DefaultEntropy
	}
}

// GenerateMnemonic generates a BIP-39 mnemonic phrase with the specified entropy size
// The entropy size must be a multiple of 32 bits between 128 and 256 bits
func GenerateMnemonic(entropySize Entropy) (string, error) {
	if entropySize%32 != 0 || entropySize < 128 || entropySize > 256 {
		return "", fmt.Errorf("entropy size must be a multiple of 32 between 128 and 256 bits")
	}

	// Generate random entropy
	entropy := make([]byte, entropySize/8)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("failed to generate entropy: %w", err)
	}

	// Generate mnemonic using the entropy
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	return mnemonic, nil
}

// MnemonicToSeed converts a BIP-39 mnemonic phrase to a seed
// The passphrase is optional and can be an empty string
func MnemonicToSeed(mnemonic string, passphrase string) ([]byte, error) {
	// Validate mnemonic
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic phrase")
	}

	// Convert mnemonic to seed using PBKDF2
	seed := bip39.NewSeed(mnemonic, passphrase)
	return seed, nil
}

// ValidateMnemonic checks if a mnemonic phrase is valid according to BIP-39
func ValidateMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(mnemonic)
}

// GetWordList returns the BIP-39 word list
func GetWordList() []string {
	return bip39.GetWordList()
}

// GetWordIndex returns the index of a word in the BIP-39 word list
func GetWordIndex(word string) (int, error) {
	wordList := bip39.GetWordList()
	for i, w := range wordList {
		if w == word {
			return i, nil
		}
	}
	return -1, fmt.Errorf("word not found in BIP-39 word list")
}

// GetWordCount returns the number of words in a mnemonic phrase
func GetWordCount(mnemonic string) int {
	return len(strings.Fields(mnemonic))
}

// GetEntropySize returns the entropy size in bits for a given mnemonic phrase
func GetEntropySize(mnemonic string) (Entropy, error) {
	wordCount := GetWordCount(mnemonic)
	switch wordCount {
	case 12:
		return Entropy128, nil
	case 15:
		return Entropy160, nil
	case 18:
		return Entropy192, nil
	case 21:
		return Entropy224, nil
	case 24:
		return Entropy256, nil
	default:
		return 0, fmt.Errorf("invalid word count: %d", wordCount)
	}
}
