package manifest

import (
	"bytes"
	"testing"
)

var biosDirectoryTableDataChunk = []byte{
	0x24, 0x42, 0x48, 0x44,
	0xee, 0x7f, 0xd9, 0xab,
	0x01, 0x00, 0x00, 0x00,
	0x40, 0x04, 0x00, 0x20,

	0x68,
	0x00,
	0x10,
	0x01,
	0x00, 0x20, 0x00, 0x00,
	0x00, 0x30, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

func TestBiosDirectoryTableParsing(t *testing.T) {
	table, err := ParseBIOSDirectoryTable(bytes.NewBuffer(biosDirectoryTableDataChunk))
	if err != nil {
		t.Errorf("Failed to parse BIOS Directory table, err: %v", err)
		t.Skip()
	}
	if table == nil {
		t.Errorf("result BIOS Directory table is nil")
		t.Skip()
	}

	if table.BIOSCookie != BIOSDirectoryTableCookie {
		t.Errorf("BIOSCookie is incorrect: %d, expected: %d", table.BIOSCookie, BIOSDirectoryTableCookie)
	}
	if table.TotalEntries != 1 {
		t.Errorf("TotalEntries is incorrect: %d, expected: %d", table.TotalEntries, 1)
	}
	if len(table.Entries) != 1 {
		t.Errorf("Result number of entries is incorrect: %d, expected: %d", len(table.Entries), 1)
		t.Skip()
	}

	if table.Entries[0].Type != 0x68 {
		t.Errorf("Table entry [0] type is incorrect: %d, expected: %d", table.Entries[0].Type, 0x68)
	}
	if table.Entries[0].ResetImage {
		t.Errorf("Table entry [0] reset image is incorrect, expected false")
	}
	if table.Entries[0].CopyImage {
		t.Errorf("Table entry [0] copy image is incorrect, expected false")
	}
	if table.Entries[0].ReadOnly {
		t.Errorf("Table entry [0] read only is incorrect, expected false")
	}
	if !table.Entries[0].Compressed {
		t.Errorf("Table entry [0] compress is incorrect, expected true")
	}
	if table.Entries[0].SourceAddress != 0x173000 {
		t.Errorf("Table entry [0] source address is incorrect: %x, expected: 0x173000",
			table.Entries[0].SourceAddress)
	}
	if table.Entries[0].DestinationAddress != 0xffffffffffffffff {
		t.Errorf("Table entry [0] destination address is incorrect: %x, expected: 0xffffffffffffffff",
			table.Entries[0].DestinationAddress)
	}
}
