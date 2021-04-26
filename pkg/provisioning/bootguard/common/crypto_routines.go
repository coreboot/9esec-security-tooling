package common

import (
	"crypto"
	"fmt"
	"hash"
	"strings"

	_ "crypto/sha1"
	_ "crypto/sha256"
)

type Algorithm uint16

const (
	AlgUnknown Algorithm = 0x0000
	AlgRSA     Algorithm = 0x0001
	AlgSHA1    Algorithm = 0x0004
	AlgSHA256  Algorithm = 0x000B
	AlgRSASSA  Algorithm = 0x0014
)

var hashInfo = []struct {
	alg  Algorithm
	hash hash.Hash
}{
	{AlgSHA1, crypto.SHA1.New()},
	{AlgSHA256, crypto.SHA256.New()},
}

func (a Algorithm) IsNull() bool {
	return a == AlgUnknown
}

func (a Algorithm) Hash() (hash.Hash, error) {
	for _, info := range hashInfo {
		if info.alg == a {
			if info.hash == nil {
				return nil, fmt.Errorf("go hash algorithm #%snot available", info.alg.String())
			}
			return info.hash, nil
		}
	}
	return nil, fmt.Errorf("hash algorithm not supported: %s", a.String())
}

func (a Algorithm) String() string {
	var s strings.Builder
	var err error
	switch a {
	case AlgUnknown:
		_, err = s.WriteString("AlgUnknown")
	case AlgRSA:
		_, err = s.WriteString("RSA")
	case AlgSHA1:
		_, err = s.WriteString("SHA1")
	case AlgSHA256:
		_, err = s.WriteString("SHA256")
	case AlgRSASSA:
		_, err = s.WriteString("RSASSA")
	default:
		return fmt.Sprintf("Alg?<%d>", int(a))
	}
	if err != nil {
		return fmt.Sprintf("Writing to string builder failed: %v", err)
	}
	return s.String()
}
