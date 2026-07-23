package credential

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const StatusListBits = 131072

func checkIndex(bits []byte, index uint64) error {
	if index >= uint64(len(bits))*8 {
		return fmt.Errorf("status list index %d out of range", index)
	}
	return nil
}

func GetBit(bits []byte, index uint64) (bool, error) {
	if err := checkIndex(bits, index); err != nil {
		return false, err
	}
	return bits[index/8]&(0x80>>(index%8)) != 0, nil
}

func DecodeList(encoded string) ([]byte, error) {
	if !strings.HasPrefix(encoded, "u") {
		return nil, fmt.Errorf("encoded list is not multibase base64url")
	}
	compressed, err := base64.RawURLEncoding.DecodeString(encoded[1:])
	if err != nil {
		return nil, fmt.Errorf("invalid encoded list: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("invalid gzip: %w", err)
	}
	defer zr.Close()
	bits, err := io.ReadAll(io.LimitReader(zr, StatusListBits/8+1))
	if err != nil {
		return nil, err
	}
	if len(bits) > StatusListBits/8 {
		return nil, fmt.Errorf("status list larger than %d bits", StatusListBits)
	}
	return bits, nil
}
