//go:build !manifestcodegen
// +build !manifestcodegen

// Code generated by "menifestcodegen". DO NOT EDIT.
// To reproduce: go run github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/manifestcodegen/cmd/manifestcodegen github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest

package manifest

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/pretty"
)

var (
	// Just to avoid errors in "import" above in case if it wasn't used below
	_ = binary.LittleEndian
	_ = (fmt.Stringer)(nil)
	_ = (io.Reader)(nil)
	_ = pretty.Header
	_ = strings.Join
)

// NewKey returns a new instance of Key with
// all default values set.
func NewKey() *Key {
	s := &Key{}
	// Set through tag "required":
	s.Version = 0x10
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *Key) Validate() error {
	// See tag "require"
	if s.Version != 0x10 {
		return fmt.Errorf("field 'Version' expects value '0x10', but has %v", s.Version)
	}

	return nil
}

// ReadFrom reads the Key from 'r' in format defined in the document #575623.
func (s *Key) ReadFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// KeyAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Read(r, binary.LittleEndian, &s.KeyAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KeyAlg': %w", err)
		}
		totalN += int64(n)
	}

	// Version (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.Version)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Version': %w", err)
		}
		totalN += int64(n)
	}

	// KeySize (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Read(r, binary.LittleEndian, &s.KeySize)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KeySize': %w", err)
		}
		totalN += int64(n)
	}

	// Data (ManifestFieldType: arrayDynamic)
	{
		size := uint16(s.keyDataSize())
		s.Data = make([]byte, size)
		n, err := len(s.Data), binary.Read(r, binary.LittleEndian, s.Data)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Data': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *Key) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *Key) Rehash() {
}

// WriteTo writes the Key into 'w' in format defined in
// the document #575623.
func (s *Key) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// KeyAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.KeyAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KeyAlg': %w", err)
		}
		totalN += int64(n)
	}

	// Version (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.Version)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Version': %w", err)
		}
		totalN += int64(n)
	}

	// KeySize (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.KeySize)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KeySize': %w", err)
		}
		totalN += int64(n)
	}

	// Data (ManifestFieldType: arrayDynamic)
	{
		n, err := len(s.Data), binary.Write(w, binary.LittleEndian, s.Data)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Data': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// KeyAlgSize returns the size in bytes of the value of field KeyAlg
func (s *Key) KeyAlgTotalSize() uint64 {
	return 2
}

// VersionSize returns the size in bytes of the value of field Version
func (s *Key) VersionTotalSize() uint64 {
	return 1
}

// KeySizeSize returns the size in bytes of the value of field KeySize
func (s *Key) KeySizeTotalSize() uint64 {
	return 2
}

// DataSize returns the size in bytes of the value of field Data
func (s *Key) DataTotalSize() uint64 {
	return uint64(len(s.Data))
}

// KeyAlgOffset returns the offset in bytes of field KeyAlg
func (s *Key) KeyAlgOffset() uint64 {
	return 0
}

// VersionOffset returns the offset in bytes of field Version
func (s *Key) VersionOffset() uint64 {
	return s.KeyAlgOffset() + s.KeyAlgTotalSize()
}

// KeySizeOffset returns the offset in bytes of field KeySize
func (s *Key) KeySizeOffset() uint64 {
	return s.VersionOffset() + s.VersionTotalSize()
}

// DataOffset returns the offset in bytes of field Data
func (s *Key) DataOffset() uint64 {
	return s.KeySizeOffset() + s.KeySizeTotalSize()
}

// Size returns the total size of the Key.
func (s *Key) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	var size uint64
	size += s.KeyAlgTotalSize()
	size += s.VersionTotalSize()
	size += s.KeySizeTotalSize()
	size += s.DataTotalSize()
	return size
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *Key) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Key", s))
	}
	if s == nil {
		return strings.Join(lines, "\n")
	}
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Key Alg", "", &s.KeyAlg, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Version", "", &s.Version, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Key Size", "", &s.KeySize, opts...)...)
	// ManifestFieldType is arrayDynamic
	lines = append(lines, pretty.SubValue(depth+1, "Data", "", &s.Data, opts...)...)
	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v BitSize) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Bit Size", v))
	}
	lines = append(lines, pretty.SubValue(depth+1, "In Bits", "", v.InBits(), opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "In Bytes", "", v.InBytes(), opts...)...)
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (v BitSize) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the BitSize into 'w' in binary format.
func (v BitSize) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the BitSize from 'r' in binary format.
func (v BitSize) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}
