//go:build linux

package prochardening

import (
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestProcessHardeningRuntime(t *testing.T) {
	if err := Harden(); err != nil {
		t.Fatal(err)
	}
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || dumpable != 0 {
		t.Fatalf("PR_GET_DUMPABLE = %d, error = %v; want 0", dumpable, err)
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &limit); err != nil {
		t.Fatal(err)
	}
	if limit.Cur != 0 || limit.Max != 0 {
		t.Fatalf("RLIMIT_CORE = %+v; want both limits 0", limit)
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmLck:" && fields[2] == "kB" {
			locked, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil || locked == 0 {
				t.Fatalf("%s; want nonzero locked memory", line)
			}
			return
		}
	}
	t.Fatal("VmLck missing from /proc/self/status")
}
