package manifest

// Firmware is an abstraction of a firmware image, obtained for example via flashrom
type Firmware interface {
	ImageBytes() []byte
	// All addresses read from the image needs to add the FlashBase value to get the correct absolut address in terms
	// of image address (offset from 0x0)
	FlashBase() uint32
}
