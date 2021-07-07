package manifest

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// Refer to: AMD Platform Security Processor BIOS Architecture Design Guide for AMD Family 17h and Family 19h
// Processors (NDA), Publication # 55758 Revision: 1.11 Issue Date: August 2020 (1)

// BIOSDirectoryTableEntry represents a single entry in BIOS Directory Table
// Table 12 from (1)
type BIOSDirectoryTableEntry struct {
	Type       BIOSDirectoryTableEntryType
	RegionType uint8

	ResetImage bool
	CopyImage  bool
	ReadOnly   bool
	Compressed bool
	Instance   uint8
	Subprogram uint8
	RomID      uint8

	Size               uint32
	SourceAddress      uint64
	DestinationAddress uint64
}

// BIOSDirectoryTable represents a BIOS Directory Table Header with all entries
// Table 11 from (1)
type BIOSDirectoryTable struct {
	BIOSCookie   cookie
	Checksum     uint32
	TotalEntries uint32
	Reserved     uint32

	Entries []BIOSDirectoryTableEntry
}

func (b BIOSDirectoryTable) String() string {
	var s strings.Builder
	cookieBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(cookieBytes, b.BIOSCookie.Uint32())
	fmt.Fprintf(&s, "BIOS Cookie: 0x%x (%s)\n", b.BIOSCookie, cookieBytes)
	fmt.Fprintf(&s, "Checksum: %d\n", b.Checksum)
	fmt.Fprintf(&s, "Total Entries: %d\n", b.TotalEntries)
	fmt.Fprintf(&s, "%-5s | %-10s | %-10s | %-9s | %-8s | %-10s | %-8s | %-10s | %-5s | %-7s | %-13s | %-18s\n",
		"Type",
		"RegionType",
		"ResetImage",
		"CopyImage",
		"ReadOnly",
		"Compressed",
		"Instance",
		"Subprogram",
		"RomID",
		"Size",
		"SourceAddress",
		"DestinationAddress")
	fmt.Fprintf(&s, "%s\n", "----------------------------------------------------------------------------------------------------------------------------------------------------------------")
	for _, entry := range b.Entries {
		fmt.Fprintf(&s, "0x%-3x | 0x%-8x | %-10v | %-9v | %-8v | %-10v | 0x%-6x | 0x%-8x | 0x%-3x | %-7d | 0x%-11x | 0x%-18x\n",
			entry.Type,
			entry.RegionType,
			entry.ResetImage,
			entry.CopyImage,
			entry.ReadOnly,
			entry.Compressed,
			entry.Instance,
			entry.Subprogram,
			entry.RomID,
			entry.Size,
			entry.SourceAddress,
			entry.DestinationAddress)
	}
	return s.String()
}

// ParseBIOSDirectoryTable converts input bytes into BIOSDirectoryTable
func ParseBIOSDirectoryTable(r io.Reader) (*BIOSDirectoryTable, error) {
	var table BIOSDirectoryTable
	if err := binary.Read(r, binary.LittleEndian, &table.BIOSCookie); err != nil {
		return nil, err
	}
	if table.BIOSCookie != BIOSDirectoryTableCookie && table.BIOSCookie != BIOSDirectoryTableLevel2Cookie {
		return nil, fmt.Errorf("incorrect cookie: %d", table.BIOSCookie)
	}

	if err := binary.Read(r, binary.LittleEndian, &table.Checksum); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &table.TotalEntries); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &table.Reserved); err != nil {
		return nil, err
	}

	table.Entries = make([]BIOSDirectoryTableEntry, 0, table.TotalEntries)
	for idx := uint32(0); idx < table.TotalEntries; idx++ {
		entry, err := ParseBIOSDirectoryTableEntry(r)
		if err != nil {
			return nil, err
		}
		table.Entries = append(table.Entries, *entry)
	}
	return &table, nil
}

// ParseBIOSDirectoryTableEntry converts input bytes into BIOSDirectoryTableEntry
func ParseBIOSDirectoryTableEntry(r io.Reader) (*BIOSDirectoryTableEntry, error) {
	var entry BIOSDirectoryTableEntry
	if err := binary.Read(r, binary.LittleEndian, &entry.Type); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &entry.RegionType); err != nil {
		return nil, err
	}

	var flags uint8
	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return nil, err
	}
	entry.ResetImage = (flags>>7)&0x1 != 0
	entry.CopyImage = (flags>>6)&0x1 != 0
	entry.ReadOnly = (flags>>5)&0x1 != 0
	entry.Compressed = (flags>>4)&0x1 != 0
	entry.Instance = flags >> 3

	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return nil, err
	}
	entry.Subprogram = flags & 7
	entry.RomID = (flags >> 3) & 0x3

	if err := binary.Read(r, binary.LittleEndian, &entry.Size); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &entry.SourceAddress); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &entry.DestinationAddress); err != nil {
		return nil, err
	}
	return &entry, nil
}
