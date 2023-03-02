package amdsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/amddata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
)

type MeasureEmbeddedFirmwareStructure struct{}

var _ types.Step = (*MeasureEmbeddedFirmwareStructure)(nil)

func (MeasureEmbeddedFirmwareStructure) Actions(ctx context.Context, s *types.State) types.Actions {
	return types.Actions{
		tpmactions.NewTPMEvent(pcrtypes.ID(0), amddata.EmbeddedFirmware{}, []byte("EmbeddedFirmware")),
	}
}