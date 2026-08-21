package sshproxy

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SessionStats SSH 會話目標主機即時指標（session-stats D2）：
// counters 回原始值，CPU%/網速由前端兩次輪詢差分，後端 stateless
type SessionStats struct {
	Hostname   string  `json:"hostname"`
	UptimeSec  float64 `json:"uptime_sec"`
	Load1      float64 `json:"load1"`
	Load5      float64 `json:"load5"`
	Load15     float64 `json:"load15"`
	MemTotalKB uint64  `json:"mem_total_kb"`
	MemAvailKB uint64  `json:"mem_avail_kb"`
	CPUBusy    uint64  `json:"cpu_busy"`
	CPUTotal   uint64  `json:"cpu_total"`
	NetRxBytes uint64  `json:"net_rx_bytes"`
	NetTxBytes uint64  `json:"net_tx_bytes"`
}

const statsSectionSep = "__OT_SEP__"

// statsCommand 單 channel 串讀（design D1）：以分隔標記切段，降低輪詢 channel 開銷
const statsCommand = "cat /proc/uptime; echo " + statsSectionSep +
	"; cat /proc/loadavg; echo " + statsSectionSep +
	"; cat /proc/meminfo; echo " + statsSectionSep +
	"; cat /proc/stat; echo " + statsSectionSep +
	"; cat /proc/net/dev; echo " + statsSectionSep +
	"; hostname"

// CollectStats 在既有 SSH 連線上開新 session channel 採集指標
func CollectStats(client *ssh.Client) (*SessionStats, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("開啟採集 channel 失敗: %w", err)
	}
	defer sess.Close()

	out, err := sess.Output(statsCommand)
	if err != nil {
		return nil, fmt.Errorf("採集指令執行失敗: %w", err)
	}
	return ParseStats(string(out))
}

// ParseStats 解析串讀輸出（純函數，單元測試覆蓋）
func ParseStats(raw string) (*SessionStats, error) {
	parts := strings.Split(raw, statsSectionSep)
	if len(parts) < 6 {
		return nil, fmt.Errorf("目標主機輸出缺段（%d/6），可能不支援 /proc", len(parts))
	}
	stats := &SessionStats{}

	// /proc/uptime: "12345.67 23456.78"
	if fields := strings.Fields(parts[0]); len(fields) > 0 {
		stats.UptimeSec, _ = strconv.ParseFloat(fields[0], 64)
	}

	// /proc/loadavg: "0.10 0.20 0.30 1/234 5678"
	if fields := strings.Fields(parts[1]); len(fields) >= 3 {
		stats.Load1, _ = strconv.ParseFloat(fields[0], 64)
		stats.Load5, _ = strconv.ParseFloat(fields[1], 64)
		stats.Load15, _ = strconv.ParseFloat(fields[2], 64)
	}

	// /proc/meminfo: MemTotal/MemAvailable 行
	for _, line := range strings.Split(parts[2], "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			stats.MemTotalKB, _ = strconv.ParseUint(fields[1], 10, 64)
		case "MemAvailable:":
			stats.MemAvailKB, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}

	// /proc/stat 首行: cpu user nice system idle iowait irq softirq steal ...
	for _, line := range strings.Split(parts[3], "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 8 && fields[0] == "cpu" {
			var vals []uint64
			for _, f := range fields[1:] {
				v, parseErr := strconv.ParseUint(f, 10, 64)
				if parseErr != nil {
					break
				}
				vals = append(vals, v)
			}
			var total uint64
			for _, v := range vals {
				total += v
			}
			var idle uint64
			if len(vals) >= 5 {
				idle = vals[3] + vals[4] // idle + iowait
			}
			stats.CPUTotal = total
			stats.CPUBusy = total - idle
			break
		}
	}

	// /proc/net/dev: 跳過 lo，加總 rx(第1欄)/tx(第9欄)
	for _, line := range strings.Split(parts[4], "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		seg := strings.SplitN(line, ":", 2)
		ifname := strings.TrimSpace(seg[0])
		if ifname == "lo" {
			continue
		}
		fields := strings.Fields(seg[1])
		if len(fields) >= 9 {
			rx, _ := strconv.ParseUint(fields[0], 10, 64)
			tx, _ := strconv.ParseUint(fields[8], 10, 64)
			stats.NetRxBytes += rx
			stats.NetTxBytes += tx
		}
	}

	stats.Hostname = strings.TrimSpace(parts[5])
	return stats, nil
}
