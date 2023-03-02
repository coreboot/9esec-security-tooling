package amdsteps

import (
	"context"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources/amddata"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
)

type MeasureBIOSDirectory struct{}

var _ types.Step = (*MeasureBIOSDirectory)(nil)

func (MeasureBIOSDirectory) Actions(ctx context.Context, s *types.State) types.Actions {
	return measureToTPMEachRangeSeparately(ctx, s, pcrtypes.ID(0), amddata.BIOSDirectory{}, "BIOSDirectory")
}