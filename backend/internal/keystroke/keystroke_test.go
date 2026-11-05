package keystroke

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCoverageTable(t *testing.T) {
	cases := []struct {
		kind    SessionKind
		covered bool
		reason  string
	}{
		{KindSSHTerminal, true, ""},
		{KindDBCLI, true, ""},
		{KindK8sExec, true, ""},
		{KindAgentTerminal, true, ""},
		{KindK8sLogs, false, ReasonK8sLogsReadonly},
		{KindDBConsole, false, ReasonDBConsole},
		{KindAgentDBConsole, false, ReasonDBConsole},
		{KindGraphics, true, ""},
		{KindFileTransfer, false, ReasonFileTransfer},
		{SessionKind("nope"), false, ""},
	}
	for _, c := range cases {
		cov, reason := Coverage(c.kind)
		if cov != c.covered || reason != c.reason {
			t.Fatalf("%s: got (%v,%q)", c.kind, cov, reason)
		}
	}
}

func TestPathRelAndRoot(t *testing.T) {
	ts := time.Date(2026, 11, 5, 23, 59, 59, 0, time.FixedZone("x", 8*3600))
	got := RelPath("abc", ts)
	if got != filepath.Join("2026-11-05", "abc.cxkr") { // 取 UTC 日期：+8 時區的 11-05 23:59 仍是 11-05 15:59
		t.Fatalf("rel=%s", got)
	}
	if RootFromAuditDir("/a/b") != "/a/b/keystrokes" {
		t.Fatal("root")
	}
}

func TestProbe(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ks")
	if err := Probe(root); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(root)
	if len(ents) != 0 {
		t.Fatal("probe left files behind")
	}
	fi, _ := os.Stat(root)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("perm=%v", fi.Mode().Perm())
	}
	blocker := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(blocker, nil, 0o600)
	if err := Probe(filepath.Join(blocker, "ks")); err == nil {
		t.Fatal("expected error")
	}
}
