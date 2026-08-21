package sshproxy

import (
	"strings"
	"testing"
)

const sampleStatsOutput = `3600.50 7200.00
__OT_SEP__
0.15 0.25 0.35 2/345 6789
__OT_SEP__
MemTotal:        8000000 kB
MemFree:         2000000 kB
MemAvailable:    5000000 kB
__OT_SEP__
cpu  100 0 50 800 50 0 0 0 0 0
cpu0 50 0 25 400 25 0 0 0 0 0
__OT_SEP__
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 999999     100    0    0    0     0          0         0   999999     100    0    0    0     0       0          0
  eth0: 1000000    500    0    0    0     0          0         0   2000000    600    0    0    0     0       0          0
  eth1:  500000    200    0    0    0     0          0         0   300000     250    0    0    0     0       0          0
__OT_SEP__
test-host
`

func TestParseStats(t *testing.T) {
	stats, err := ParseStats(sampleStatsOutput)
	if err != nil {
		t.Fatalf("ParseStats error: %v", err)
	}

	if stats.Hostname != "test-host" {
		t.Errorf("hostname = %q", stats.Hostname)
	}
	if stats.UptimeSec != 3600.50 {
		t.Errorf("uptime = %v", stats.UptimeSec)
	}
	if stats.Load1 != 0.15 || stats.Load5 != 0.25 || stats.Load15 != 0.35 {
		t.Errorf("load = %v %v %v", stats.Load1, stats.Load5, stats.Load15)
	}
	if stats.MemTotalKB != 8000000 || stats.MemAvailKB != 5000000 {
		t.Errorf("mem = %d/%d", stats.MemAvailKB, stats.MemTotalKB)
	}
	// cpu: total=1000, idle=800+50=850, busy=150
	if stats.CPUTotal != 1000 || stats.CPUBusy != 150 {
		t.Errorf("cpu = busy %d / total %d", stats.CPUBusy, stats.CPUTotal)
	}
	// net: lo 排除，eth0+eth1
	if stats.NetRxBytes != 1500000 {
		t.Errorf("rx = %d", stats.NetRxBytes)
	}
	if stats.NetTxBytes != 2300000 {
		t.Errorf("tx = %d", stats.NetTxBytes)
	}
}

func TestParseStatsMissingSections(t *testing.T) {
	_, err := ParseStats("command not found")
	if err == nil {
		t.Fatal("expected error for non-/proc output")
	}
	if !strings.Contains(err.Error(), "缺段") {
		t.Errorf("unexpected error: %v", err)
	}
}
