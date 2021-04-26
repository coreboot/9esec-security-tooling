package bootpolicy

import (
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
)

type Signature struct {
	StructInfo `id:"__PMSG__" version:"0x20"`

	manifest.KeySignature `json:"sigKeySignature"`
}
