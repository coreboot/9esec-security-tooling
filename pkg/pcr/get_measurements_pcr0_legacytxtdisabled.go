package pcr

import (
	"fmt"
	"math"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	"github.com/9elements/converged-security-suite/v2/pkg/pcd"
	ffsConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/ffs/consts"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
	"github.com/xaionaro-go/bytesextra"
)

// MeasurePCDFirmwareVendorVersionData returns PCD firmware vendor version measurement.
func MeasurePCDFirmwareVendorVersionData(pcdData pcd.ParsedFirmware) (*Measurement, error) {
	if pcdData == nil {
		return nil, fmt.Errorf("pcdData is nil")
	}

	dataRanges := pcdData.GetFirmwareVendorVersionRanges()
	if dataRanges == nil {
		// See parseFirmwareOCPGeneric.
		//
		// `dataRanges == nil` means we were unable find where the bytes
		// of firmware vendor version are stored. But sometimes we have
		// a fallback hardcoded value, so let's try to use it here:
		return NewStaticDataMeasurement(MeasurementIDPCDFirmwareVendorVersionData, pcdData.GetFirmwareVendorVersion()), ErrPCDVendorVersion{}
	}

	return NewRangesMeasurement(MeasurementIDPCDFirmwareVendorVersionData, dataRanges), nil
}

// MeasurePCDFirmwareVendorVersionCode returns a fake measurement which includes
// the executable containing the PCD firmware vendor version value.
func MeasurePCDFirmwareVendorVersionCode(pcdData pcd.ParsedFirmware) (*Measurement, error) {
	if pcdData == nil {
		return nil, fmt.Errorf("pcdData is nil")
	}

	codeRanges := pcdData.GetFirmwareVendorVersionCodeRanges()
	if len(codeRanges) == 0 {
		return nil, fmt.Errorf("no code-ranges found")
	}

	return NewRangesMeasurement(
		MeasurementIDPCDFirmwareVendorVersionCode,
		codeRanges,
	), nil
}

// MeasureDXE returns the DXE measurement.
func MeasureDXE(firmware Firmware) (*Measurement, error) {
	mErr := &errors.MultiError{}

	// DXE could be compressed and in this case it is placed into a special
	// container. If there's no such container then DXE is not compressed
	// and could be accessed directly.
	dxeVolumes, err := firmware.GetByGUID(ffsConsts.GUIDDXEContainer)
	if len(dxeVolumes) == 0 {
		dxeVolumes, err = firmware.GetByGUID(ffsConsts.GUIDDXE)
	}
	_ = mErr.Add(err)

	if len(dxeVolumes) == 0 {
		return nil, mErr.ReturnValue()
	}

	var dxeRanges pkgbytes.Ranges
	for _, dxeVolume := range dxeVolumes {
		if dxeVolume.Offset == math.MaxUint64 {
			// Was unable to detect the offset; it is expected
			// if the volume is in a compressed area.
			_ = mErr.Add(fmt.Errorf("unable to detect the offset of a DXE volume"))
			continue
		}
		dxeRanges = append(dxeRanges, dxeVolume.Range)
	}
	if len(dxeRanges) == 0 {
		return nil, mErr.ReturnValue()
	}

	return NewRangesMeasurement(MeasurementIDDXE, dxeRanges), mErr.ReturnValue()
}

// MeasureFITPointer returns a fake measurement for FIT pointer.
func MeasureFITPointer(firmware Firmware) *Measurement {
	fitHeadersPtrStartIdx, fitHeadersPtrEndIdx := fit.GetPointerCoordinates(uint64(len(firmware.Buf())))
	if fitHeadersPtrStartIdx < 0 || fitHeadersPtrEndIdx < 0 || fitHeadersPtrEndIdx < fitHeadersPtrStartIdx {
		return nil
	}
	return NewRangeMeasurement(
		MeasurementIDFITPointer,
		uint64(fitHeadersPtrStartIdx),
		uint64(fitHeadersPtrEndIdx-fitHeadersPtrStartIdx),
	)
}

// MeasureFITHeaders returns a fake measurement for FIT headers.
func MeasureFITHeaders(firmware Firmware) (*Measurement, error) {
	fitHeadersStartIdx, fitHeadersEndIdx, err := fit.GetHeadersTableRangeFrom(bytesextra.NewReadWriteSeeker(firmware.Buf()))
	if err != nil {
		return nil, err
	}

	return NewRangeMeasurement(
		MeasurementIDFITHeaders,
		fitHeadersStartIdx,
		fitHeadersEndIdx-fitHeadersStartIdx,
	), nil
}

// MeasureSeparator returns the separator measurement.
func MeasureSeparator() *Measurement {
	return NewStaticDataMeasurement(MeasurementIDSeparator, Separator)
}
