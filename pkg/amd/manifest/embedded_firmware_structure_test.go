package manifest

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"
)

const image = string("/home/riot/NDA/AMD/BIOS/H11SSL0.221_D32")

const PhysBase = 1 << 32 // "4GB"

type DummyFirmware struct {
	Data []byte
}

func (f *DummyFirmware) ImageBytes() []byte {
	return f.Data
}

func SetupFirmware(img []byte) ([]DummyFirmware, error) {
	firmware := make([]DummyFirmware, 0)
	// If image size > 16M, the image is divided into 16M chunks (mostly server firmware)
	// 32M images = 2x16, 64M images = 4*16 ==> We need to split the image accordingly
	if len(image) <= (1 << 24) {
		// 16M image
		fw := DummyFirmware{
			Data: img,
		}
		firmware := append(firmware, fw)
		return firmware, nil
	}
	if len(image) > (1<<24) && len(image) <= (1<<25) {
		fmt.Printf("Image length: %d\n", len(image))
		// 32M image
	}
	if len(image) > (1<<25) && len(image) <= (1<<26) {
		fmt.Printf("Image length: %d\n", len(image))
		// 64M image
	}
}

func (f *DummyFirmware) FlashBase() uint32 {
	// FlashBase depends on the size of SPI Flash Memory available or image size.
	// Images with 16M have a FlashBase of 0x1000000. All addresses found need to add
	// the FlashBase to get the correct offset. We're not handling intel with their
	// 4GiB back and forth, end is beginning bs.
	var counter int
	a := uint32(len(f.ImageBytes()))
	for {
		if (a & (0x1 << counter)) != 0 {
			if counter <= 24 {
				return 0x1 << counter
			}
			if counter > 24 {
				return 0x1 << 24
			}
		}
		counter++
	}
}

func TestFindEFS(t *testing.T) {
	img, err := ioutil.ReadFile(image)
	if err != nil {
		t.Error(err)
	}
	fw := &DummyFirmware{
		Data: img,
	}
	_, _, err = FindEmbeddedFirmwareStructure(fw)
	if err != nil {
		t.Error(err)
	}
}

func TestPSPCombo(t *testing.T) {
	img, err := ioutil.ReadFile(image)
	if err != nil {
		t.Error(err)
	}
	fw := &DummyFirmware{
		Data: img,
	}
	finding, err := ExtractEFSInformation(fw)
	if err != nil {
		t.Error(err)
	}
	for _, table := range finding {
		switch suprise := table.(type) {
		case *PSPDirectoryTable:
			fmt.Printf("PSP Directory Cookie%s\n", suprise.String())
		case *BIOSDirectoryTable:
			fmt.Printf("BIOS Directory Cookie%s\n", suprise.String())
		case *ComboDirectoryTable:
			fmt.Printf("Combo Directory Cookie%s\n", suprise.String())
		default:
			t.Errorf("No valid information found: %v", reflect.TypeOf(finding))
		}
	}
}
