package proxy

import (
	"testing"
	"time"
)

// TestEvalTunnelTimeout 逾時判定：max 優先於 idle、0=停用該檢查
func TestEvalTunnelTimeout(t *testing.T) {
	now := time.Now()
	start := now.Add(-2 * time.Hour)
	recentInput := now.Add(-5 * time.Minute)
	staleInput := now.Add(-30 * time.Minute)

	tests := []struct {
		name       string
		lastInput  time.Time
		idle, max  time.Duration
		wantReason string
		wantFire   bool
	}{
		{"雙檢查停用永不觸發", staleInput, 0, 0, "", false},
		{"閒置未逾窗口", recentInput, 15 * time.Minute, 0, "", false},
		{"閒置逾窗口觸發", staleInput, 15 * time.Minute, 0, tunnelEndReasonIdleTimeout, true},
		{"達最大時長觸發", recentInput, 0, time.Hour, tunnelEndReasonMaxDuration, true},
		{"同時逾時 max 優先", staleInput, 15 * time.Minute, time.Hour, tunnelEndReasonMaxDuration, true},
		{"idle 停用僅查 max", staleInput, 0, 3 * time.Hour, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, fire := evalTunnelTimeout(now, start, tt.lastInput, tt.idle, tt.max)
			if reason != tt.wantReason || fire != tt.wantFire {
				t.Errorf("evalTunnelTimeout() = (%q, %v), want (%q, %v)",
					reason, fire, tt.wantReason, tt.wantFire)
			}
		})
	}
}

// TestClientInputOpcodes 僅使用者輸入算活動，協議心跳與畫面更新不算
func TestClientInputOpcodes(t *testing.T) {
	for _, op := range []string{"mouse", "key", "touch", "clipboard", "file"} {
		if !clientInputOpcodes[op] {
			t.Errorf("%s 應計入使用者活動", op)
		}
	}
	// sync/nop 是 guacamole 協議心跳、size 是視窗控制——都不得重置閒置計時，
	// 否則前端掛著不動也永不逾時
	for _, op := range []string{"sync", "nop", "size", "img", "png"} {
		if clientInputOpcodes[op] {
			t.Errorf("%s 不應計入使用者活動", op)
		}
	}
}
