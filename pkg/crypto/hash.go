package crypto

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/sha3"
)

type UL_HashingStrategy int

const (
	INVALID_HASH_STRATEGY                    = 0
	HASH_SHA256           UL_HashingStrategy = 20
	HASH_SHA3_256         UL_HashingStrategy = 30
	HASH_SHA3_512         UL_HashingStrategy = 31
)

func GetHasher(strategy UL_HashingStrategy) (hash.Hash, error) {
	switch strategy {
	case HASH_SHA256:
		return sha256.New(), nil
	case HASH_SHA3_256:
		return sha3.New256(), nil
	case HASH_SHA3_512:
		return sha3.New512(), nil
	default:
		return nil, fmt.Errorf("unknown hasher: %d", strategy)
	}
}

func (strat UL_HashingStrategy) String() string {
	switch strat {
	case HASH_SHA256:
		return "HASH_SHA256"
	case HASH_SHA3_512:
		return "HASH_SHA3_512"
	case HASH_SHA3_256:
		return "HASH_SHA3_256"
	default:
		return ""
	}
}

func Hash(data []byte, strategy UL_HashingStrategy) []byte {
	hasher, err := GetHasher(strategy)
	if err != nil {
		return nil
	}
	hasher.Write(data)
	return hasher.Sum(nil)
}

type ErrInvalidHashingStrategy struct {
	Msg string
}

func (e *ErrInvalidHashingStrategy) Error() string {
	return fmt.Sprintf("invalid hashing strategy, %s", e.Msg)
}

// ParseHashingStrategy accepts only the non-MiMC strategies: MiMC hashers are
// consensus-relevant field-arithmetic hashers with no offline client equivalent.
func ParseHashingStrategy(str string) (UL_HashingStrategy, error) {
	switch strings.ToUpper(str) {
	case HASH_SHA256.String():
		return HASH_SHA256, nil
	case HASH_SHA3_256.String():
		return HASH_SHA3_256, nil
	case HASH_SHA3_512.String():
		return HASH_SHA3_512, nil
	default:
		return 0, &ErrInvalidHashingStrategy{Msg: str}
	}
}
