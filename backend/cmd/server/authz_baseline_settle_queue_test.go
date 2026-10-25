package main

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
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

// An alert sits in the notifier queue and has not entered the delivery
// function: no goroutine carries a marker, so a stack scan alone sees nothing
// and would return early. The wait must hold until the worker has finished it.
func TestAwaitBackgroundWaitsForQueuedNotification(t *testing.T) {
	n := audit.NewAlertNotifier(nil, nil) // worker not started: the alert stays queued
	n.Enqueue(model.CommandAlert{})

	if hits := inflightBackground(); len(hits) != 0 {
		t.Fatalf("precondition: a stack scan must see nothing for queued work, got %d", len(hits))
	}
	if got := n.PendingNotifications(); got != 1 {
		t.Fatalf("precondition: queued alert must be counted, got %d", got)
	}
	if !runWait(150*time.Millisecond, n.PendingNotifications) {
		t.Fatal("wait returned while an alert was still queued")
	}

	n.Start() // worker takes the alert and delivers (no channels: returns at once)
	if runWait(10*time.Second, n.PendingNotifications) {
		t.Fatal("wait did not return after the worker drained the queue")
	}
	if got := n.PendingNotifications(); got != 0 {
		t.Fatalf("pending after drain = %d, want 0", got)
	}
}
