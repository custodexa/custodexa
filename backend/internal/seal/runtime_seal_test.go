package seal

import (
	"context"
	"errors"
	"testing"
)

type runtimeJournal struct{ *fakeJournal }

func (j runtimeJournal) WriteSealReceived(ctx context.Context, g uint64, s string) (uint64, error) {
	return j.WriteReceived(ctx, g, s)
}
func (j runtimeJournal) WriteSealOutcome(ctx context.Context, g, q uint64, s string) error {
	return j.WriteOutcome(ctx, g, q, s)
}

type runtimeGraph struct {
	gate       MaterialGate
	releaseErr error
	released   bool
}

func (g *runtimeGraph) MaterialGate() *MaterialGate   { return &g.gate }
func (g *runtimeGraph) Release(context.Context) error { g.released = true; return g.releaseErr }
func TestSealOperationJournal(t *testing.T) {
	for _, which := range []string{"success", "acceptance-failed", "outcome-failed", "release-failed"} {
		t.Run(which, func(t *testing.T) {
			j := runtimeJournal{newFakeJournal()}
			g := &runtimeGraph{}
			m, err := New(Config{Journal: j, Verify: func(context.Context, []byte) (VerifiedMaterial, error) { return VerifiedMaterial{}, nil }, Stage2: func(context.Context, VerifiedMaterial) (ServiceGraph, error) { return g, nil }})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = m.Unseal(context.Background(), UnsealRequest{Material: []byte("fixture")}); err != nil {
				t.Fatal(err)
			}
			before := m.Snapshot()
			if which == "acceptance-failed" {
				j.failReceived = errors.New("acceptance unavailable")
			}
			if which == "outcome-failed" {
				j.failOutcome["seal_completed"] = errors.New("outcome unavailable")
			}
			if which == "release-failed" {
				g.releaseErr = errors.New("release unavailable")
			}
			_, err = m.Seal(context.Background(), SealRequest{Actor: 1, Mode: "ui", SourceDigest: "digest"})
			after := m.Snapshot()
			switch which {
			case "success":
				if err != nil || after.State != StateSealed || after.CleanupPending || !g.released {
					t.Fatalf("result=%+v err=%v", after, err)
				}
			case "acceptance-failed":
				if err == nil || after != before || g.released {
					t.Fatalf("acceptance changed state: %+v err=%v", after, err)
				}
			default:
				if err == nil || after.State != StateSealedFaulted || !after.CleanupPending {
					t.Fatalf("cleanup failure lost: %+v err=%v", after, err)
				}
				if _, ok := j.find("outcome", "seal_completed"); ok {
					t.Fatal("false successful seal record")
				}
			}
			t.Logf("%s: state=%s cleanup=%v error=%v", which, after.State, after.CleanupPending, err)
		})
	}
}
func TestUnsealBodyAllExitZeroize(t *testing.T) {
	for _, which := range []string{"success", "acquire", "journal"} {
		t.Run(which, func(t *testing.T) {
			h := newHarness(t, nil)
			raw := []byte("owned-material")
			if which == "acquire" {
				h.m = NewUnsealed(nil)
			}
			if which == "journal" {
				h.j.failReceived = errors.New("journal unavailable")
			}
			_, err := h.m.Unseal(context.Background(), UnsealRequest{Material: raw})
			for _, b := range raw {
				if b != 0 {
					t.Fatal("material retained")
				}
			}
			t.Logf("%s: original buffer zero; rejected=%v", which, err != nil)
		})
	}
}
