package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/amdconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/intelconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
)

var Root = types.Flow{
	commonsteps.If(intelconds.FITPresent{}, commonsteps.SetFlow(Intel)),
	commonsteps.If(amdconds.ManifestPresent{}, commonsteps.SetFlow(AMD)),
	commonsteps.Panic("unknown flow: neither AMD not Intel"),
}