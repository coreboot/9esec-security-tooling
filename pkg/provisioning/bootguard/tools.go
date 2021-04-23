package bootguard

import (
	"os"

	cbnt "github.com/9elements/converged-security-suite/v2/pkg/provisioning/cbnt"
)

func WriteBGStructures(image []byte, bpmFile, kmFile, acmFile *os.File) error {
	bpm, km, acm, err := cbnt.ParseFITEntries(image)
	if err != nil {
		return err
	}
	if bpmFile != nil && len(bpm.DataBytes) > 0 {
		if _, err = bpmFile.Write(bpm.DataBytes); err != nil {
			return err
		}
	}
	if kmFile != nil && len(km.DataBytes) > 0 {
		if _, err = kmFile.Write(km.DataBytes); err != nil {
			return err
		}
	}
	if acmFile != nil && len(acm.DataBytes) > 0 {
		if _, err = acmFile.Write(acm.DataBytes); err != nil {
			return err
		}
	}
	return nil
}
