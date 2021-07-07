package manifest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Refer to: AMD Platform Security Processor BIOS Architecture Design Guide for AMD Family 17h and Family 19h
// Processors (NDA), Publication # 55758 Revision: 1.11 Issue Date: August 2020 (1)

// EmbeddedFirmwareStructureSignature is a special identifier of Firmware Embedded Structure
const EmbeddedFirmwareStructureSignature = 0x55aa55aa

// EmbeddedFirmwareStructure represents Embedded Firmware Structure defined in Table 2 in (1)
type EmbeddedFirmwareStructure struct {
	Signature                uint32
	Required1                [16]byte
	PSPDirectoryTablePointer uint32

	BIOSDirectoryTableFamily17hModels00h0FhPointer uint32
	BIOSDirectoryTableFamily17hModels10h1FhPointer uint32
	BIOSDirectoryTableFamily17hModels30h3FhPointer uint32
}

// FindEmbeddedFirmwareStructure locates and parses Embedded Firmware Structure
func FindEmbeddedFirmwareStructure(firmware Firmware) (*EmbeddedFirmwareStructure, uint32, error) {
	var addresses = []uint32{
		0xfa0000,
		0xf20000,
		0xe20000,
		0xc20000,
		0x820000,
		0x020000,
	}

	image := firmware.ImageBytes()

	for _, addr := range addresses {
		offset := addr + firmware.FlashBase()
		if offset+4 > uint32(len(image)) {
			continue
		}
		actualSignature := binary.LittleEndian.Uint32(image[offset:])
		if actualSignature == EmbeddedFirmwareStructureSignature {
			result, err := ParseEmbeddedFirmwareStructure(bytes.NewBuffer(image[offset:]))
			return result, offset, err
		}
	}
	return nil, 0, fmt.Errorf("EmbeddedFirmwareStructure is not found")
}

// ParseEmbeddedFirmwareStructure converts input bytes into EmbeddedFirmwareStructure
func ParseEmbeddedFirmwareStructure(r io.Reader) (*EmbeddedFirmwareStructure, error) {
	var result EmbeddedFirmwareStructure
	if err := binary.Read(r, binary.LittleEndian, &result); err != nil {
		return nil, err
	}

	if result.Signature != EmbeddedFirmwareStructureSignature {
		return nil, fmt.Errorf("incorrect signature: %d", result.Signature)
	}

	return &result, nil
}

// ExtractEFSInformation jumps to PSP/BIOS/Combo Directory table address at EFS offset 0x14 and returns
// the found structure, depending on the found cookie
func ExtractEFSInformation(firmware Firmware) ([]interface{}, error) {
	var ret []interface{}
	// PSPDirectory or PSP/BIOSCombo Directory address is set in EFS, so we get the EFS first
	efs, _, err := FindEmbeddedFirmwareStructure(firmware)
	if err != nil {
		return nil, err
	}
	image := firmware.ImageBytes()
	var surpriseCookie cookie
	// We only check the cookie on PSP/Combo Directory Table, BIOS cookies, well, BIOS cookies.
	if efs.PSPDirectoryTablePointer != 0 {
		pspaddr := efs.PSPDirectoryTablePointer + firmware.FlashBase()
		if err := binary.Read(bytes.NewReader(image[pspaddr:]), binary.LittleEndian, &surpriseCookie); err != nil {
			return nil, err
		}
		switch surpriseCookie {
		case PSPDirectoryTableCookie:
			psp, err := ParsePSPDirectoryTable(bytes.NewReader(image[pspaddr:]))
			if err != nil {
				return nil, err
			}
			ret = append(ret, psp)
		case PSPComboDirectoryTableCookie, BIOSComboDirectoryTableCookie:
			combo, err := ParseComboDirectoryTable(bytes.NewReader(image[pspaddr:]))
			if err != nil {
				return nil, err
			}
			ret = append(ret, combo)
		}
	}
	// We dont need to check on cookies, only if the addresses are set or not
	if efs.BIOSDirectoryTableFamily17hModels00h0FhPointer != 0 {
		bios00h0faddr := efs.BIOSDirectoryTableFamily17hModels00h0FhPointer + firmware.FlashBase()
		bios, err := ParseBIOSDirectoryTable(bytes.NewReader(image[bios00h0faddr:]))
		if err != nil {
			return nil, err
		}
		ret = append(ret, bios)
	}
	if efs.BIOSDirectoryTableFamily17hModels10h1FhPointer != 0 {
		bios10h1faddr := efs.BIOSDirectoryTableFamily17hModels10h1FhPointer + firmware.FlashBase()
		bios, err := ParseBIOSDirectoryTable(bytes.NewReader(image[bios10h1faddr:]))
		if err != nil {
			return nil, err
		}
		ret = append(ret, bios)
	}
	if efs.BIOSDirectoryTableFamily17hModels30h3FhPointer != 0 {
		bios30h3faddr := efs.BIOSDirectoryTableFamily17hModels30h3FhPointer + firmware.FlashBase()
		bios, err := ParseBIOSDirectoryTable(bytes.NewReader(image[bios30h3faddr:]))
		if err != nil {
			return nil, err
		}
		ret = append(ret, bios)
	}

	return ret, nil
}
