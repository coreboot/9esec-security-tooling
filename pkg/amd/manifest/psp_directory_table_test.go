package manifest

import (
	"bytes"
	"testing"
)

var pspDirectoryTableDataChunk = []byte{
	0x24, 0x50, 0x53, 0x50,
	0xcf, 0x55, 0x73, 0x1b,
	0x01, 0x00, 0x00, 0x00,
	0x10, 0x05, 0x00, 0x20,

	0x00,
	0x00,
	0x00, 0x00,
	0x40, 0x04, 0x00, 0x00,
	0x00, 0x24, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func TestPspDirectoryTableParsing(t *testing.T) {
	table, err := ParsePSPDirectoryTable(bytes.NewBuffer(pspDirectoryTableDataChunk))
	if err != nil {
		t.Errorf("Failed to parse PSP Directory table, err: %v", err)
		t.Skip()
	}
	if table == nil {
		t.Errorf("result PSP Directory table is nil")
		t.Skip()
	}

	if table.PSPCookie != PSPDirectoryTableCookie {
		t.Errorf("BIOSCookie is incorrect: %d, expected: %d", table.PSPCookie, PSPDirectoryTableCookie)
	}
	if table.TotalEntries != 1 {
		t.Errorf("TotalEntries is incorrect: %d, expected: %d", table.TotalEntries, 1)
	}
	if len(table.Entries) != 1 {
		t.Errorf("Result number of entries is incorrect: %d, expected: %d", len(table.Entries), 1)
		t.Skip()
	}

	if table.Entries[0].Type != AMDPublicKeyEntry {
		t.Errorf("Table entry [0] type is incorrect: %d, expected: %d", table.Entries[0].Type, AMDPublicKeyEntry)
	}
	if table.Entries[0].Subprogram != 0 {
		t.Errorf("Table entry [0] subprogram is incorrect: %d, expected: %d", table.Entries[0].Subprogram, 0)
	}
	if table.Entries[0].LocationOrValue != 0x62400 {
		t.Errorf("Table entry [0] location is incorrect: %d, expected: 0x62400", table.Entries[0].LocationOrValue)
	}
}
