package key

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/pretty"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/common"
)

const StructureIDManifest = "__KEYM__"

type Manifest struct {
	common.StructInfo
	KMVersion       uint8
	KMSVN           manifest.SVN
	KMID            uint8
	BPKey           manifest.HashStructure
	KeyAndSignature manifest.KeySignature
}

func NewManifest() *Manifest {
	m := &Manifest{}
	copy(m.StructInfo.ID[:], []byte(StructureIDManifest))
	m.StructInfo.Version = 0x10
	m.KeyAndSignature = *manifest.NewKeySignature()
	return m
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Manifest) GetStructInfo() common.StructInfo {
	return s.StructInfo
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Manifest) SetStructInfo(newStructInfo common.StructInfo) {
	s.StructInfo = newStructInfo
}

// ReadFrom reads the Manifest from 'r' in format defined in the document #575623.
func (s *Manifest) ReadFrom(r io.Reader) (int64, error) {
	var totalN int64

	err := binary.Read(r, binary.LittleEndian, &s.StructInfo)
	if err != nil {
		return totalN, fmt.Errorf("unable to read structure info at %d: %w", totalN, err)
	}
	totalN += int64(binary.Size(s.StructInfo))

	n, err := s.ReadDataFrom(r)
	if err != nil {
		return totalN, fmt.Errorf("unable to read data: %w", err)
	}
	totalN += n

	return totalN, nil
}

// ReadDataFrom reads the Manifest from 'r' excluding StructInfo,
// in format defined in the document #575623.
func (s *Manifest) ReadDataFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// StructInfo (ManifestFieldType: structInfo)
	{
		// ReadDataFrom does not read Struct, use ReadFrom for that.
	}

	// KMVersion (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.KMVersion)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Revision': %w", err)
		}
		totalN += int64(n)
	}

	// KMSVN (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.KMSVN)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KMSVN': %w", err)
		}
		totalN += int64(n)
	}

	// KMID (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.KMID)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KMID': %w", err)
		}
		totalN += int64(n)
	}

	// Hash (ManifestFieldType: list)
	{
		n, err := s.BPKey.ReadFrom(r)
		if err != nil {
			return totalN, fmt.Errorf("unable to read the count for field 'Hash': %w", err)
		}
		totalN += int64(n)
	}

	// KeyAndSignature (ManifestFieldType: subStruct)
	{
		n, err := s.KeyAndSignature.ReadFrom(r)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KeyAndSignature': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// Print prints the Key Manifest.
func (m *Manifest) Print() {
	if m.KeyAndSignature.Signature.DataTotalSize() < 1 {
		fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(true)))
		fmt.Printf("  --KeyAndSignature--\n\tKey Manifest not signed!\n\n")
	} else {
		fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
	}
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *Manifest) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Key Manifest", s))
	}
	if s == nil {
		return strings.Join(lines, "\n")
	}
	// ManifestFieldType is structInfo
	lines = append(lines, pretty.SubValue(depth+1, "Struct Info", "", &s.StructInfo, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Version", "", &s.KMVersion, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "KMSVN", "", &s.KMSVN, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "KMID", "", &s.KMID, opts...)...)
	// ManifestFieldType is subStruct
	lines = append(lines, pretty.SubValue(depth+1, "BPKEY:", "", &s.BPKey, opts...)...)
	// ManifestFieldType is subStruct
	lines = append(lines, pretty.SubValue(depth+1, "Key And Signature", "", &s.KeyAndSignature, opts...)...)
	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}
