package seal

import (
	"context"
	"testing"
	"time"
)

func TestSealMaterialFence(t *testing.T) {
	g := &MaterialGate{}
	lease, err := g.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	transitioned := false
	if !g.CloseWith(func() bool { transitioned = true; return true }) || !transitioned {
		t.Fatal("transition not closed")
	}
	if _, err = g.Borrow(); err == nil {
		t.Fatal("closed generation admitted new work")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if g.Drain(ctx) == nil {
		t.Fatal("drain completed before borrower")
	}
	lease.Finish(func(valid bool) {
		if valid {
			t.Fatal("stale result published")
		}
	})
	if err = g.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Log("generation closed; new borrow rejected; stale delivery rejected; drain completed")
}
