package main

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/notifycat"
)

// failCatcher turns Fatalf into a recorded panic so a test can assert that the
// wait gave up instead of returning.
type failCatcher struct {
	testing.TB
	failed bool
}

type failCatcherStop struct{}

func (f *failCatcher) Helper() {}
func (f *failCatcher) Fatalf(string, ...any) {
	f.failed = true
	panic(failCatcherStop{})
}

// runWait runs the wait and reports whether it returned or failed.
func runWait(timeout time.Duration, pending func() int64) (failed bool) {
	f := &failCatcher{}
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(failCatcherStop); !ok {
				panic(r)
			}
		}
		failed = f.failed
	}()
	awaitBackgroundWith(f, timeout, pending)
	return false
}

// Counted background work keeps the wait open even when no goroutine carries a
// marker, and the wait returns once the counter drops to zero.
func TestAwaitBackgroundWaitsForCountedWork(t *testing.T) {
	var pending atomic.Int64
	pending.Store(1)
	if !runWait(150*time.Millisecond, pending.Load) {
		t.Fatal("wait returned while counted work was still in flight")
	}
	pending.Store(0)
	if runWait(10*time.Second, pending.Load) {
		t.Fatal("wait did not return after counted work finished")
	}
}

// An audit-failure notice is written (or sent directly) in a goroutine the
// notifier counts; the wait holds until that work has finished.
func TestAwaitBackgroundWaitsForAuditNotice(t *testing.T) {
	n := audit.NewAlertNotifier(nil, nil) // no database: the write fails, no channels to send to
	n.EnqueueAuditFailureNotice(notifycat.EventAuditFailure, map[string]string{"mechanism": "audit_write"})
	if runWait(10*time.Second, n.BackgroundInFlight) {
		t.Fatal("wait did not return after the audit-failure notice finished")
	}
	if got := n.BackgroundInFlight(); got != 0 {
		t.Fatalf("pending after drain = %d, want 0", got)
	}
}
