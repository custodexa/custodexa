package seal

import (
	"context"
	"errors"
	"sync"
)

var ErrMaterialSealed = errors.New("seal: material generation is closed")

// MaterialGate belongs to one service generation and is never reopened.
// Closing and publishing a state transition share the same critical section.
type MaterialGate struct {
	mu      sync.Mutex
	closed  bool
	active  int
	drained chan struct{}
}
type MaterialLease struct{ gate *MaterialGate }

func (g *MaterialGate) Borrow() (*MaterialLease, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, ErrMaterialSealed
	}
	g.active++
	return &MaterialLease{gate: g}, nil
}

// Finish linearizes result delivery against closure and releases the borrow.
func (l *MaterialLease) Finish(publish func(bool)) {
	g := l.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	defer func() {
		g.active--
		if g.closed && g.active == 0 {
			close(g.drained)
		}
	}()
	publish(!g.closed)
}
func (g *MaterialGate) CloseWith(transition func() bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	if transition != nil && !transition() {
		return false
	}
	g.closed = true
	g.drained = make(chan struct{})
	if g.active == 0 {
		close(g.drained)
	}
	return true
}
func (g *MaterialGate) Drain(ctx context.Context) error {
	g.mu.Lock()
	ch := g.drained
	closed := g.closed
	g.mu.Unlock()
	if !closed {
		return errors.New("seal: drain requires closed generation")
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Closed reports whether the generation has been closed.
//
// Read-only observation for callers that must re-check the gate before
// publishing material they obtained outside a lease-held critical section
// (a DEK re-unwrap that returned while sealing was under way). It changes no
// seal semantics: closing, draining and state publication stay exactly as they
// were, and a caller that observes false may still race a concurrent close —
// the authoritative linearization remains Finish's publish callback.
func (g *MaterialGate) Closed() bool { g.mu.Lock(); defer g.mu.Unlock(); return g.closed }

// InFlight reports outstanding borrowers for drain diagnostics.
func (g *MaterialGate) InFlight() int { g.mu.Lock(); defer g.mu.Unlock(); return g.active }
