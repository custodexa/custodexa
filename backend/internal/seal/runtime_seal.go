package seal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// SealJournal records runtime sealing separately from unseal publication.
type SealJournal interface {
	WriteSealReceived(context.Context, uint64, string) (uint64, error)
	WriteSealOutcome(context.Context, uint64, uint64, string) error
}
type SealRequest struct {
	Actor        uint   `json:"actor"`
	Mode         string `json:"mode"`
	SourceDigest string `json:"source"`
}
type materialGraph interface{ MaterialGate() *MaterialGate }

// Seal persists acceptance before closing the generation and withdrawing services.
func (m *Machine) Seal(ctx context.Context, req SealRequest) (Result, error) {
	if !m.sealBusy.CompareAndSwap(false, true) {
		return Result{}, newError(CodeCleanupPending, cellRejected, m.Snapshot().Generation, nil)
	}
	defer m.sealBusy.Store(false)
	cur := m.node.Load()
	if cur.state != StateUnsealed || cur.cleanup != nil || req.Actor == 0 {
		return Result{}, newError(CodeCleanupPending, cellRejected, cur.generation, nil)
	}
	journal, ok := m.journal.(SealJournal)
	if !ok {
		return Result{}, newError(CodeJournalIOFailure, cellRejected, cur.generation, errors.New("seal journal unavailable"))
	}
	graph, ok := cur.services.(materialGraph)
	if !ok || graph.MaterialGate() == nil {
		return Result{}, newError(CodeInitFailed, cellRejected, cur.generation, errors.New("material gate unavailable"))
	}
	metadata, err := json.Marshal(req)
	if err != nil {
		return Result{}, err
	}
	pctx, pcancel := context.WithTimeout(ctx, m.prepareTimeout)
	seq, err := journal.WriteSealReceived(pctx, cur.generation+1, string(metadata))
	pcancel()
	if err != nil {
		return Result{}, newError(CodeJournalIOFailure, cellRejected, cur.generation, err)
	}
	cell, ok := Resolve(Situation{From: cur.state, Event: EventSealRequest, HolderAcquired: true})
	if !ok {
		return Result{}, newError(CodeCleanupPending, cellRejected, cur.generation, nil)
	}
	next := applyCell(cur, cell, m.now(), nil)
	if !graph.MaterialGate().CloseWith(func() bool { return m.node.CompareAndSwap(cur, next) }) {
		return Result{}, newError(CodeCleanupPending, cellRejected, cur.generation, nil)
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.cleanupTimeout)
	defer cancel()
	err = graph.MaterialGate().Drain(rctx)
	if err == nil {
		err = releaseBounded(rctx, cur.services)
	}
	outcome := "seal_completed"
	if err != nil {
		outcome = "seal_failed"
	}
	wctx, wcancel := context.WithTimeout(context.WithoutCancel(ctx), m.journalTimeout)
	werr := journal.WriteSealOutcome(wctx, next.generation, seq, outcome)
	wcancel()
	if err != nil || werr != nil {
		m.sealCleanupFailed(next)
		return Result{}, newError(CodeSealCleanupFailed, cellSealFailed, next.generation, errors.Join(err, werr))
	}
	if !m.CompleteCleanup(next.generation) {
		return Result{}, newError(CodeCleanupPending, cellSealFailed, next.generation, nil)
	}
	return Result{Generation: next.generation, State: StateSealed}, nil
}
func (m *Machine) sealCleanupFailed(observed *sealNode) {
	cell, ok := Resolve(Situation{From: observed.state, Event: EventSealCleanupFailed, HasCleanup: observed.cleanup != nil})
	if !ok {
		return
	}
	next := applyCell(observed, cell, m.now(), func(n *sealNode) { n.faultCode = CodeSealCleanupFailed })
	m.node.CompareAndSwap(observed, next)
}
func releaseBounded(ctx context.Context, graph ServiceGraph) error {
	if graph == nil {
		return nil
	}
	done := make(chan error, 1)
	go func() {
		var err error
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("seal: release panic: %v", p)
			}
			done <- err
		}()
		err = graph.Release(ctx)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
