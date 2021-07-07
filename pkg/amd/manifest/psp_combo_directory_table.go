package manifest

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// PSPComboDirectoryTable represents PSP Combo Directory Table Header with all entries
type ComboDirectoryTable struct {
	ComboCookie  cookie
	Checksum     uint32
	TotalEntries uint32
	LookUpMode   uint32
	Reserved     [16]byte
	Entries      []ComboDirectoryTableEntry
}

// PSPComboDirectoryTableEntry represents a single entry in PSP Combo Directory Table
// Each entry points to a different PSP Directory Table Level 2 Header
type ComboDirectoryTableEntry struct {
	IDSelect                   uint32
	ID                         uint32
	PSPDirectoryTableL2Address uint64
}

func (p ComboDirectoryTable) String() string {
	var s strings.Builder
	cookieBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(cookieBytes, p.ComboCookie.Uint32())
	fmt.Fprintf(&s, "PSP Combo Cookie: 0x%x (%s)\n", p.ComboCookie, cookieBytes)
	fmt.Fprintf(&s, "Checksum: %d\n", p.Checksum)
	fmt.Fprintf(&s, "Total Entries: %d\n", p.TotalEntries)
	fmt.Fprintf(&s, "LookIp Mode: 0x%x\n\n", p.LookUpMode)
	fmt.Fprintf(&s, "%-8s | %-10s | %-26s\n",
		"IDSelect",
		"ID",
		"PSPDirectoryTableL2Address")
	fmt.Fprintf(&s, "%s\n", "------------------------------------------------------------------------")
	for _, entry := range p.Entries {
		fmt.Fprintf(&s, "0x%-6x | 0x%-8x | 0x%-3x\n",
			entry.IDSelect,
			entry.ID,
			entry.PSPDirectoryTableL2Address)
	}
	return s.String()
}

// ParseComboDirectoryTable converts input bytes into ComboDirectoryTable
func ParseComboDirectoryTable(r io.Reader) (*ComboDirectoryTable, error) {
	var table ComboDirectoryTable
	if err := binary.Read(r, binary.LittleEndian, &table.ComboCookie); err != nil {
		return nil, err
	}
	if table.ComboCookie != PSPComboDirectoryTableCookie && table.ComboCookie != BIOSComboDirectoryTableCookie {
		return nil, fmt.Errorf("incorrect cookie: %d", table.ComboCookie)
	}

	if err := binary.Read(r, binary.LittleEndian, &table.Checksum); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &table.TotalEntries); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &table.LookUpMode); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &table.Reserved); err != nil {
		return nil, err
	}
	for idx := uint32(0); idx < table.TotalEntries; idx++ {
		entry, err := ParseComboDirectoryTableEntry(r)
		if err != nil {
			return nil, err
		}
		table.Entries = append(table.Entries, *entry)
	}
	return &table, nil
}

func ParseComboDirectoryTableEntry(r io.Reader) (*ComboDirectoryTableEntry, error) {
	var entry ComboDirectoryTableEntry
	if err := binary.Read(r, binary.LittleEndian, &entry.IDSelect); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &entry.ID); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &entry.PSPDirectoryTableL2Address); err != nil {
		return nil, err
	}
	return &entry, nil
}
