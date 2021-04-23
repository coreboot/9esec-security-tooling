package bootguard

import (
	"errors"
	"io"

	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/key"
)

func ParseKM(reader io.Reader) (*key.Manifest, error) {
	km := &key.Manifest{}
	_, err := km.ReadFrom(reader)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return km, nil
}
