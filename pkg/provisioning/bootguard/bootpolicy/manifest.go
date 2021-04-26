package bootpolicy

import (
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/common"
)

// StructInfo is the common header of any element.
type StructInfo = common.StructInfo

// PrettyString: Boot Policy Manifest
type Manifest struct {
	// PrettyString: BPMH: Header
	BPMH `rehashValue:"rehashedBPMH()" json:"bpmHeader"`

	SE []SE `json:"bpmSE"`
	// PrettyString: PME: Platform Manufacturer
	PME *PM `json:"bpmPME,omitempty"`
	// PrettyString: PMSE: Signature
	PMSE Signature `json:"bpmSignature"`
}

func (bpm Manifest) StructInfo() StructInfo {
	return bpm.BPMH.StructInfo
}
