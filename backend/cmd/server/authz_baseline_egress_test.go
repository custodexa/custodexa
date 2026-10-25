package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Authorization decision baseline: outbound receivers.
//
// Instead of adding injection points to every remote entry in product code,
// every outbound target in the fixture (asset hosts, guacd, Kubernetes API,
// LDAP, OIDC issuer, syslog, notification webhook, offsite endpoint) points
// at a receiver started here, and command-line clients are shadowed by
// recording stand-ins placed first on PATH. A scenario's `remote` field is
// the per-category count of connections (or process starts) observed.
//
// Receivers never complete a protocol: TCP receivers accept and close, HTTP
// receivers answer with a fixed status. Product code therefore takes its
// "remote failed" branch; what the baseline proves is that the decision
// reached the remote call.

// egressTCPCategories accept-and-close receivers.
var egressTCPCategories = []string{
	"ssh", "guacd", "db-mysql", "db-postgres", "db-redis", "db-mssql", "ldap", "syslog",
}

// egressHTTPCategories fixed-status HTTP receivers.
var egressHTTPCategories = map[string]int{
	"k8s":     http.StatusServiceUnavailable,
	"winrm":   http.StatusServiceUnavailable,
	"oidc":    http.StatusNotFound,
	"notify":  http.StatusOK,
	"offsite": http.StatusServiceUnavailable,
}

// defaultBaselineReceiverPortBase first fixed receiver port of the scenario
// runs (13 consecutive ports); the golden records addresses in this range.
const defaultBaselineReceiverPortBase = 46100

// baselineFixedPortWait how long a fixed-port receiver retries a bind that
// fails with "address already in use". The range lies inside the Linux
// ephemeral port range, so a client socket of another process can briefly
// hold one of its ports, most often in TIME_WAIT (60 s), which a listener
// cannot reuse.
const baselineFixedPortWait = 75 * time.Second

// baselineReceiverPortBase first receiver port, or 0 for kernel-assigned
// ports.
//
// Fixed ports are needed only where receiver addresses are compared with the
// golden: the scenario groups (AUTHZ_BASELINE=1, run with this package alone
// by scripts/authz_baseline.sh and the dedicated CI step). Every other run
// (the plain package, `go test ./...` with other test binaries in the same
// network namespace) uses kernel-assigned ports, so it cannot collide with a
// concurrent socket. An explicit AUTHZ_BASELINE_PORT_BASE always applies.
var baselineReceiverPortBase = func() int {
	if v := os.Getenv("AUTHZ_BASELINE_PORT_BASE"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 1024 {
			return n
		}
	}
	if os.Getenv("AUTHZ_BASELINE") == "1" {
		return defaultBaselineReceiverPortBase
	}
	return 0
}()

// listenBaselineReceiver binds one receiver: a kernel-assigned port when port
// is 0, otherwise that fixed port, retrying while it is in use.
func listenBaselineReceiver(port int) (net.Listener, error) {
	if port == 0 {
		return net.Listen("tcp", "127.0.0.1:0")
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(baselineFixedPortWait)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil || !errors.Is(err, syscall.EADDRINUSE) || time.Now().After(deadline) {
			return ln, err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// egressStubsNotRequired stand-ins kept on PATH (so the real client can
// never start) but exempt from the reached-at-least-once guard, with why.
var egressStubsNotRequired = map[string]string{
	"mysql": "the MySQL terminal entry starts the mariadb client; the mysql name is shadowed only as a safety net",
}

// egressProcessStubs command-line clients shadowed on PATH.
var egressProcessStubs = []string{"kubectl", "psql", "mariadb", "mysql", "redis-cli", "sqlcmd"}

type egressReceivers struct {
	mu      sync.Mutex
	hits    map[string]int
	tcp     map[string]net.Listener
	http    map[string]*httptest.Server
	stubDir string
	stubLog string // "" when stand-ins do not log (no scenario run)
	logPos  int64
}

func startEgressReceivers(t testing.TB) *egressReceivers {
	r := &egressReceivers{
		hits: map[string]int{},
		tcp:  map[string]net.Listener{},
		http: map[string]*httptest.Server{},
	}
	// Scenario runs use fixed ports: receiver addresses end up in stored
	// objects and responses, so they must be identical across runs for the
	// golden to be stable. Other runs take kernel-assigned ports (see
	// baselineReceiverPortBase).
	next := baselineReceiverPortBase
	listen := func(cat string) net.Listener {
		ln, err := listenBaselineReceiver(next)
		if err != nil {
			if next == 0 {
				t.Fatalf("receiver %s: %v", cat, err)
			}
			t.Fatalf("receiver %s on fixed port %d: %v (set a free range with AUTHZ_BASELINE_PORT_BASE)", cat, next, err)
		}
		if next != 0 {
			next++
		}
		return ln
	}
	for _, cat := range egressTCPCategories {
		ln, err := listen(cat), error(nil)
		if err != nil {
			t.Fatalf("receiver %s: %v", cat, err)
		}
		r.tcp[cat] = ln
		go r.acceptLoop(cat, ln)
	}
	httpCats := make([]string, 0, len(egressHTTPCategories))
	for cat := range egressHTTPCategories {
		httpCats = append(httpCats, cat)
	}
	sort.Strings(httpCats)
	for _, cat := range httpCats {
		cat, status := cat, egressHTTPCategories[cat]
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Connection", "close")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{}`))
		}))
		// Count connections, not requests: a client that speaks TLS to this
		// plain listener still reached the remote call.
		srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
			if st == http.StateNew {
				r.hit(cat)
			}
		}
		srv.Config.SetKeepAlivesEnabled(false)
		srv.Listener.Close()
		srv.Listener = listen(cat)
		srv.Start()
		r.http[cat] = srv
	}
	// Command-line stand-ins append their name to a log the receivers read.
	// The log must be writable by the de-privileged account the database
	// clients run as, which the product's file-system invariant test
	// (internal/localpty) rejects while it exists; it is therefore created
	// only when scenarios run (AUTHZ_BASELINE=1), and that mode runs this
	// package alone. Appending from the shell itself (no extra process)
	// keeps the record ahead of any shutdown of the client by the product.
	// The directory lives outside the 0700 test temp tree so that account
	// can reach it.
	dir, err := os.MkdirTemp("", "authz-baseline-stub-")
	if err != nil {
		t.Fatalf("stub dir: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("stub dir chmod: %v", err)
	}
	r.stubDir = dir
	logLine := ""
	if os.Getenv("AUTHZ_BASELINE") == "1" {
		r.stubLog = filepath.Join(dir, "calls.log")
		if err := os.WriteFile(r.stubLog, nil, 0o666); err != nil {
			t.Fatalf("stub log: %v", err)
		}
		_ = os.Chmod(r.stubLog, 0o666)
		logLine = "echo %s >> " + r.stubLog + "\n"
	}
	for _, name := range egressProcessStubs {
		script := "#!/bin/sh\n"
		if logLine != "" {
			script += fmt.Sprintf(logLine, name)
		}
		script += "exit 1\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o555); err != nil {
			t.Fatalf("stub %s: %v", name, err)
		}
	}
	t.Cleanup(func() {
		for _, ln := range r.tcp {
			_ = ln.Close()
		}
		for _, srv := range r.http {
			srv.Close()
		}
		_ = os.RemoveAll(dir)
	})
	return r
}

func (r *egressReceivers) acceptLoop(cat string, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r.hit(cat)
		if cat == "syslog" {
			// Let a sender finish its write before the close.
			go func(c net.Conn) {
				_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}(c)
			continue
		}
		_ = c.Close()
	}
}

func (r *egressReceivers) hit(cat string) {
	r.mu.Lock()
	r.hits[cat]++
	r.mu.Unlock()
}

// addr host:port of a TCP receiver.
func (r *egressReceivers) addr(cat string) string {
	ln, ok := r.tcp[cat]
	if !ok {
		panic("unknown TCP receiver " + cat)
	}
	return ln.Addr().String()
}

// port of a TCP or HTTP receiver.
func (r *egressReceivers) port(cat string) int {
	var a string
	if ln, ok := r.tcp[cat]; ok {
		a = ln.Addr().String()
	} else if srv, ok := r.http[cat]; ok {
		a = strings.TrimPrefix(srv.URL, "http://")
	} else {
		panic("unknown receiver " + cat)
	}
	_, p, _ := net.SplitHostPort(a)
	var n int
	fmt.Sscanf(p, "%d", &n)
	return n
}

// url base URL of an HTTP receiver.
func (r *egressReceivers) url(cat string) string {
	srv, ok := r.http[cat]
	if !ok {
		panic("unknown HTTP receiver " + cat)
	}
	return srv.URL
}

// take returns the counts observed since the previous take and clears them.
// Stand-in starts are folded in as "proc-<name>".
func (r *egressReceivers) take() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.hits
	r.hits = map[string]int{}
	if r.stubLog != "" {
		if f, err := os.Open(r.stubLog); err == nil {
			if _, err := f.Seek(r.logPos, 0); err == nil {
				sc := bufio.NewScanner(f)
				for sc.Scan() {
					r.logPos += int64(len(sc.Bytes())) + 1
					if name := strings.TrimSpace(sc.Text()); name != "" {
						out["proc-"+name]++
					}
				}
			}
			_ = f.Close()
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// egressCategories all categories a run is expected to reach at least once.
func egressCategories() []string {
	var out []string
	out = append(out, egressTCPCategories...)
	for cat := range egressHTTPCategories {
		out = append(out, cat)
	}
	for _, p := range egressProcessStubs {
		if _, excluded := egressStubsNotRequired[p]; excluded {
			continue
		}
		out = append(out, "proc-"+p)
	}
	sort.Strings(out)
	return out
}

// remoteList renders counts as a sorted, comparable list.
func remoteList(m map[string]int) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, fmt.Sprintf("%s x%d", k, v))
	}
	sort.Strings(out)
	return out
}
