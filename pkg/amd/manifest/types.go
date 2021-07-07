package manifest

import "encoding/binary"

type cookie uint32

const (
	// PSPDirectoryTableCookie is a special identifier of PSP Directory table level 1
	PSPDirectoryTableCookie cookie = 0x50535024 // "$PSP"
	// PSPDirectoryTableLevel2Cookie is a special identifier of PSP Directory table level 2
	PSPDirectoryTableLevel2Cookie cookie = 0x324C5024 // "$PL2"
	// BIOSDirectoryTableCookie is a special identifier of BIOS Directory table level 1
	BIOSDirectoryTableCookie cookie = 0x44484224 // $BHD
	// BIOSDirectoryTableLevel2Cookie is a special identifier of BIOS Directory table level 2
	BIOSDirectoryTableLevel2Cookie cookie = 0x324C4224 // $BL2
	// PSPComboDirectoryTableCookie is a special identifier of PSP Combo Directory table
	PSPComboDirectoryTableCookie cookie = 0x50535032 // "$2PSP"
	// BIOSComboDirectoryTableCookie is a special identifier of BIOS Combo Directory table
	BIOSComboDirectoryTableCookie cookie = 0x44484232 // “2BHD”
)

func (c cookie) Uint32() uint32 {
	return uint32(c)
}

func (c cookie) String() string {
	s := make([]byte, 4)
	binary.LittleEndian.PutUint32(s, c.Uint32())
	return string(s)
}

// PSPDirectoryTableEntryType is an entry type of PSP Directory table
type PSPDirectoryTableEntryType uint8

const (
	// AMDPublicKeyEntry denotes AMD public key entry in PSP Directory table
	AMDPublicKeyEntry PSPDirectoryTableEntryType = 0x00
	// PSPBootloaderFirmwareEntry denotes a PSP bootloader firmware entry in PSP Directory table
	PSPBootloaderFirmwareEntry PSPDirectoryTableEntryType = 0x01
	// PSPDirectoryTableLevel2Entry denotes an entry that points to PSP Directory table level 2
	PSPDirectoryTableLevel2Entry PSPDirectoryTableEntryType = 0x40
)

// BIOSDirectoryTableEntryType is an entry type of BIOS Directory table
type BIOSDirectoryTableEntryType uint8

const (
	// APCBBinaryEntry denotes APCB binary entry in BIOS Directory table
	APCBBinaryEntry BIOSDirectoryTableEntryType = 0x60
	// BIOSRTMVolumeEntry denotes BIOS RTM Volume entry in BIOS Directory table
	BIOSRTMVolumeEntry BIOSDirectoryTableEntryType = 0x62
	// BIOSDirectoryTableLevel2Entry denotes an entry that points to BIOS Directory table level 2
	BIOSDirectoryTableLevel2Entry BIOSDirectoryTableEntryType = 0x70
)
