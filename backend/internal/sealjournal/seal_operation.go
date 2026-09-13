package sealjournal

import (
	"context"
	"fmt"
)

const (
	KindSealReceived           = "seal_received"
	KindSealOutcome            = "seal_outcome"
	slotKindSealReceived uint8 = 4
	slotKindSealOutcome  uint8 = 5
)

func (j *Journal) WriteSealReceived(ctx context.Context, gen uint64, metadata string) (uint64, error) {
	if len(metadata) == 0 || len(metadata) > criticalPayloadCap {
		return 0, fmt.Errorf("seal metadata length invalid")
	}
	wctx, cancel := j.writeCtx(ctx)
	defer cancel()
	return submit(j, wctx, func() (uint64, error) { return j.writeCritical(slotKindSealReceived, gen, 0, metadata, "") })
}
func (j *Journal) WriteSealOutcome(ctx context.Context, gen, seq uint64, outcome string) error {
	if outcome != "seal_completed" && outcome != "seal_failed" {
		return ErrInvalidOutcome
	}
	wctx, cancel := j.writeCtx(ctx)
	defer cancel()
	_, err := submit(j, wctx, func() (uint64, error) {
		if seq == 0 || seq >= j.hdr.SeqNext {
			return 0, ErrUnknownSeq
		}
		return j.writeCritical(slotKindSealOutcome, gen, seq, "", outcome)
	})
	return err
}
