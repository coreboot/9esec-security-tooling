package manifest

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// Refer to: AMD Platform Security Processor BIOS Architecture Design Guide for AMD Family 17h and Family 19h
// Processors (NDA), Publication # 55758 Revision: 1.11 Issue Date: August 2020 (1)

// PSPDirectoryTableEntry represents a single entry in PSP Directory Table
// Table 5 in (1)
type PSPDirectoryTableEntry struct {
	Type            PSPDirectoryTableEntryType
	Subprogram      uint8
	ROMId           uint8
	Size            uint32
	LocationOrValue uint64
}

// PSPDirectoryTable represents PSP Directory Table Header with all entries
// Table 3 in (1)
type PSPDirectoryTable struct {
	PSPCookie      cookie
	Checksum       uint32
	TotalEntries   uint32
	AdditionalInfo uint32
	Entries        []PSPDirectoryTableEntry
}

func (p PSPDirectoryTable) String() string {
	var s strings.Builder
	cookieBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(cookieBytes, p.PSPCookie.Uint32())
	fmt.Fprintf(&s, "PSP Cookie: 0x%x (%s)\n", p.PSPCookie, cookieBytes)
	fmt.Fprintf(&s, "Checksum: %d\n", p.Checksum)
	fmt.Fprintf(&s, "Total Entries: %d\n", p.TotalEntries)
	fmt.Fprintf(&s, "Additional Info: 0x%x\n\n", p.AdditionalInfo)
	fmt.Fprintf(&s, "%-5s | %-8s | %-5s | %-10s | %-10s\n",
		"Type",
		"Subprogram",
		"ROMId",
		"Size",
		"Location/Value")
	fmt.Fprintf(&s, "%s\n", "------------------------------------------------------------------------")
	for _, entry := range p.Entries {
		fmt.Fprintf(&s, "0x%-3x | 0x%-8x | 0x%-3x | %-10d | 0x%-10x\n",
			entry.Type,
			entry.Subprogram,
			entry.ROMId,
			entry.Size,
			entry.LocationOrValue)
	}
	return s.String()
}

// ParsePSPDirectoryTable converts input bytes into PSPDirectoryTable
func ParsePSPDirectoryTable(r io.Reader) (*PSPDirectoryTable, error) {
	var table PSPDirectoryTable
	if err := binary.Read(r, binary.LittleEndian, &table.PSPCookie); err != nil {
		return nil, err
	}
	if table.PSPCookie != PSPDirectoryTableCookie && table.PSPCookie != PSPDirectoryTableLevel2Cookie {
		return nil, fmt.Errorf("incorrect cookie: %d", table.PSPCookie)
	}

	if err := binary.Read(r, binary.LittleEndian, &table.Checksum); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &table.TotalEntries); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &table.AdditionalInfo); err != nil {
		return nil, err
	}

	for idx := uint32(0); idx < table.TotalEntries; idx++ {
		entry, err := ParsePSPDirectoryTableEntry(r)
		if err != nil {
			return nil, err
		}
		table.Entries = append(table.Entries, *entry)
	}
	return &table, nil
}

// ParsePSPDirectoryTableEntry converts input bytes into PSPDirectoryTableEntry
func ParsePSPDirectoryTableEntry(r io.Reader) (*PSPDirectoryTableEntry, error) {
	var entry PSPDirectoryTableEntry
	if err := binary.Read(r, binary.LittleEndian, &entry.Type); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &entry.Subprogram); err != nil {
		return nil, err
	}

	var flags uint16
	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return nil, err
	}
	entry.ROMId = uint8(flags>>14) & 0x3

	if err := binary.Read(r, binary.LittleEndian, &entry.Size); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &entry.LocationOrValue); err != nil {
		return nil, err
	}
	return &entry, nil
}
