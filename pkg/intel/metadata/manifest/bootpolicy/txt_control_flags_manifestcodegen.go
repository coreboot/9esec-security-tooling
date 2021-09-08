//go:build !manifestcodegen
// +build !manifestcodegen

// Code generated by "menifestcodegen". DO NOT EDIT.
// To reproduce: go run github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/manifestcodegen/cmd/manifestcodegen github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/bootpolicy

package bootpolicy

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/pretty"
)

var (
	// Just to avoid errors in "import" above in case if it wasn't used below
	_ = binary.LittleEndian
	_ = (fmt.Stringer)(nil)
	_ = (io.Reader)(nil)
	_ = pretty.Header
	_ = strings.Join
	_ = manifest.StructInfo{}
)

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v BackupActionPolicy) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return v.String()
}

// TotalSize returns the total size measured through binary.Size.
func (v BackupActionPolicy) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the BackupActionPolicy into 'w' in binary format.
func (v BackupActionPolicy) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the BackupActionPolicy from 'r' in binary format.
func (v BackupActionPolicy) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v ExecutionProfile) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return v.String()
}

// TotalSize returns the total size measured through binary.Size.
func (v ExecutionProfile) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the ExecutionProfile into 'w' in binary format.
func (v ExecutionProfile) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the ExecutionProfile from 'r' in binary format.
func (v ExecutionProfile) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v MemoryScrubbingPolicy) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return v.String()
}

// TotalSize returns the total size measured through binary.Size.
func (v MemoryScrubbingPolicy) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the MemoryScrubbingPolicy into 'w' in binary format.
func (v MemoryScrubbingPolicy) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the MemoryScrubbingPolicy from 'r' in binary format.
func (v MemoryScrubbingPolicy) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v ResetAUXControl) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return v.String()
}

// TotalSize returns the total size measured through binary.Size.
func (v ResetAUXControl) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the ResetAUXControl into 'w' in binary format.
func (v ResetAUXControl) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the ResetAUXControl from 'r' in binary format.
func (v ResetAUXControl) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v TXTControlFlags) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "TXT Control Flags", v))
	}
	lines = append(lines, pretty.SubValue(depth+1, "Execution Profile", "", v.ExecutionProfile(), opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "Memory Scrubbing Policy", "", v.MemoryScrubbingPolicy(), opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "Backup Action Policy", "", v.BackupActionPolicy(), opts...)...)
	if v.IsSACMRequestedToExtendStaticPCRs() {
		lines = append(lines, pretty.SubValue(depth+1, "Is SACM Requested To Extend Static PC Rs", "Default setting. S-ACM is requested to extend static PCRs", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "Is SACM Requested To Extend Static PC Rs", "S-ACM is not requested to extend static PCRs", false, opts...)...)
	}
	lines = append(lines, pretty.SubValue(depth+1, "Reset AUX Control", "", v.ResetAUXControl(), opts...)...)
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (v TXTControlFlags) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the TXTControlFlags into 'w' in binary format.
func (v TXTControlFlags) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the TXTControlFlags from 'r' in binary format.
func (v TXTControlFlags) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}
