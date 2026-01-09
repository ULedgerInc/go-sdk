package crypto

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	DEFAULT_SALT = "uledger-deterministic-reader"
)

type deterministicReader struct {
	data   []byte
	offset int
}

// Will use PBKDF2 to expand the seed into a longer sequence
func NewDeterministicReader(seed []byte, salt []byte) *deterministicReader {
	dk := pbkdf2.Key(seed, salt, 4096, 64, sha1.New)
	return &deterministicReader{
		data:   dk,
		offset: 0,
	}
}

func NewDeterministicReaderHexSeed(seedHex string) (*deterministicReader, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, err
	}
	return &deterministicReader{
		data:   seed,
		offset: 0,
	}, nil
}

func (r *deterministicReader) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func HexToBytes(h string) ([]byte, error) {
	data, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("unable to decode input string, %w", err)
	}

	return data, nil
}

func BytesToHex(b []byte) string {
	data := hex.EncodeToString(b)
	return strings.ToUpper(data)
}
