package main

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/modules/audit"
)

// Background work the product starts as a side effect of a request must be
// finished before a scenario's effects are captured; otherwise the capture
// depends on scheduling. Instead of sleeping, the harness looks for the
// goroutines that carry that work: a goroutine exists from the moment it is
// spawned, so "no such goroutine" means the work has been handed over and
// completed. The wait is bounded and a timeout fails the test with the
// offending stacks.

// baselineBackgroundMarkers function names whose presence in any goroutine
// stack (running, or still to be scheduled: "created by ...") means work the
// request started is in flight.
var baselineBackgroundMarkers = []string{
	// system-event and alert webhook deliveries (retries included)
	"(*AlertNotifier).NotifyEvent",
	"(*AlertNotifier).notify",
	"(*AlertNotifier).deliverWithRetry",
	// events of the sealed period replayed into the audit trail after unseal
	"startSealJournalReplay",
}

// baselineSettleTimeout upper bound for background work to finish.
const baselineSettleTimeout = 60 * time.Second

// inflightBackground returns the stacks of goroutines matching a marker.
func inflightBackground() []string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, len(buf)*2)
	}
	var hits []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		for _, m := range baselineBackgroundMarkers {
			if strings.Contains(g, m) {
				hits = append(hits, g)
				break
			}
		}
	}
	return hits
}

// pendingNotifications counts alerts handed to the notifier queue and not
// yet delivered. The queue is consumed by a long-lived worker, so queued work
// has no goroutine of its own and the stack scan cannot see it: the notifier
// counts it explicitly (queued, taken by the worker, running).
func pendingNotifications() int64 {
	if n := audit.GetAlertNotifier(); n != nil {
		return n.PendingNotifications()
	}
	return 0
}

// awaitBackground blocks until no background work is in flight, or fails the
// test after baselineSettleTimeout.
func awaitBackground(t testing.TB) {
	t.Helper()
	awaitBackgroundWith(t, baselineSettleTimeout, pendingNotifications)
}

// awaitBackgroundWith is awaitBackground with an injectable queue counter
// and deadline: work is in flight while the counter is positive or a marked
// goroutine exists.
func awaitBackgroundWith(t testing.TB, timeout time.Duration, pending func() int64) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		hits := inflightBackground()
		p := pending()
		if len(hits) == 0 && p == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("background work still in flight after %s (%d queued notifications, %d goroutines):\n%s",
				timeout, p, len(hits), strings.Join(hits, "\n\n"))
		}
		time.Sleep(5 * time.Millisecond)
	}
}
