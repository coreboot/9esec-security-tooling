package key

import (
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/common"
)

const StructureIDManifest = "__KEYM__"

type Manifest struct {
	common.StructInfo `id:"__KEYM__" version:"0x10"`

	KMVersion uint8 `json:"kmVersion"`

	KMSVN manifest.SVN `json:"kmSVN"`

	KMID uint8 `json:"kmID"`

	BPKey manifest.HashStructure `json:"kmBPKey"`

	KeyAndSignature manifest.KeySignature `json:"kmKeySignature"`
}
