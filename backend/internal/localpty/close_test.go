package localpty

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A: closing a terminal must terminate and reap the dedicated-UID child.
func TestCloseReapsCLIChild(t *testing.T) {
	uid, gid, _, err := LookupUser(CLIUser)
	if err != nil {
		t.Fatal(err)
	}
	// Ignore PTY hangup so the test requires the explicit termination path.
	conn, err := StartWithOptions("/bin/sh", []string{"-c", "trap '' HUP; echo ready; exec /bin/busybox sleep 30"}, nil, 80, 24, Options{User: CLIUser})
	if err != nil {
		t.Fatal(err)
	}
	pid := conn.Pid()
	done := make(chan struct{})
	t.Cleanup(func() {
		// The red run lacks CAP_KILL; the same UID can clean up its own child.
		cleanup := exec.Command("/bin/busybox", "kill", "-9", fmt.Sprint(pid))
		cleanup.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
			_ = cleanup.Run()
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("Close still blocked after fixture cleanup")
		}
	})
	if out := readUntil(t, conn, "ready", 3*time.Second); !strings.Contains(out, "ready") {
		t.Fatal("child did not become ready")
	}
	go func() { conn.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Close did not return within 2s; dedicated-UID child was not reaped")
		return
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("child still exists after Close: pid=%d, stat error=%v", pid, err)
	}
	conn.Close()
}

type closeTestProcess struct {
	killErr, waitErr error
	release, waited  chan struct{}
	kills, waits     atomic.Int32
}

func (p *closeTestProcess) Kill() error { p.kills.Add(1); return p.killErr }
func (p *closeTestProcess) Wait() (*os.ProcessState, error) {
	p.waits.Add(1)
	<-p.release
	// Only the first Wait signals completion; additional calls are asserted below.
	select {
	case p.waited <- struct{}{}:
	default:
	}
	return nil, p.waitErr
}

type closeTestLog struct {
	sync.Mutex
	bytes.Buffer
}

func (b *closeTestLog) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}
func (b *closeTestLog) text() string { b.Lock(); defer b.Unlock(); return b.Buffer.String() }

// A: a failed Kill or delayed Wait must not block stop/terminate or repeat cleanup.
func TestCloseReturnsWhenKillDenied(t *testing.T) {
	for _, tc := range []struct {
		name             string
		killErr, waitErr error
		delayed          bool
		wantLogs         []string
	}{
		{"permission_denied", syscall.EPERM, nil, true, []string{"kill", "operation not permitted", "timed out"}},
		{"wait_delayed_after_kill", nil, nil, true, []string{"timed out"}},
		{"already_exited", os.ErrProcessDone, nil, false, nil},
		{"wait_error", nil, syscall.ECHILD, false, []string{"wait", "no child processes"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &closeTestProcess{killErr: tc.killErr, waitErr: tc.waitErr, release: make(chan struct{}), waited: make(chan struct{}, 8)}
			var release sync.Once
			finish := func() { release.Do(func() { close(p.release) }) }
			if !tc.delayed {
				finish()
			}
			var logs closeTestLog
			previous := log.Writer()
			log.SetOutput(&logs)
			defer log.SetOutput(previous)
			var cleaned atomic.Int32
			c := &Conn{process: p, pid: 12345, onClose: func() { cleaned.Add(1) }}
			var wg sync.WaitGroup
			wg.Add(4)
			for i := 0; i < 4; i++ {
				go func() { defer wg.Done(); c.Close() }()
			}
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			defer func() { finish(); <-done }()
			select {
			case <-done:
			case <-time.After(1500 * time.Millisecond):
				t.Error("Close blocked on child Wait; connection cleanup cannot proceed")
				return
			}
			c.Close()
			if cleaned.Load() != 1 || p.kills.Load() != 1 || p.waits.Load() != 1 {
				t.Errorf("Close must clean/kill/wait once: cleaned=%d kills=%d waits=%d", cleaned.Load(), p.kills.Load(), p.waits.Load())
			}
			for _, want := range tc.wantLogs {
				if !strings.Contains(logs.text(), want) {
					t.Errorf("missing diagnostic %q", want)
				}
			}
			if tc.name == "already_exited" && logs.text() != "" {
				t.Error("normal exit must not log a kill failure")
			}
			finish()
			select {
			case <-p.waited:
			case <-time.After(time.Second):
				t.Error("late child exit was not reaped")
			}
		})
	}
}
