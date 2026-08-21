package sshproxy

import (
	"testing"
	"time"
)

func TestEvalTimeout(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	start := now.Add(-10 * time.Minute)       // 會話已 10 分鐘
	activeRecent := now.Add(-1 * time.Minute) // 1 分鐘前有輸入
	activeStale := now.Add(-31 * time.Minute) // 31 分鐘前最後輸入

	cases := []struct {
		name       string
		lastActive time.Time
		idle, max  time.Duration
		wantReason string
		wantFire   bool
	}{
		{"皆停用", activeStale, 0, 0, "", false},
		{"閒置觸發", activeStale, 30 * time.Minute, 0, endReasonIdleTimeout, true},
		{"閒置內不觸發", activeRecent, 30 * time.Minute, 0, "", false},
		{"時長觸發", activeRecent, 0, 5 * time.Minute, endReasonMaxDuration, true},
		{"時長內不觸發", activeRecent, 0, 30 * time.Minute, "", false},
		{"時長優先於閒置", activeStale, 30 * time.Minute, 5 * time.Minute, endReasonMaxDuration, true},
		{"恰好等於不觸發", now.Add(-30 * time.Minute), 30 * time.Minute, 0, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason, fire := evalTimeout(now, start, c.lastActive, c.idle, c.max)
			if fire != c.wantFire || reason != c.wantReason {
				t.Errorf("evalTimeout = (%q, %v), 期望 (%q, %v)", reason, fire, c.wantReason, c.wantFire)
			}
		})
	}
}

func TestBridgeTouchAndEndReason(t *testing.T) {
	b := newBridge(nil, nil, nil, nil, "", 0, 0)

	// 預設斷線原因為 normal
	if b.EndReason() != endReasonNormal {
		t.Errorf("預設 EndReason = %q, 期望 normal", b.EndReason())
	}

	// touchActive 更新時戳
	before := b.lastActiveNano.Load()
	time.Sleep(2 * time.Millisecond)
	b.touchActive()
	if b.lastActiveNano.Load() <= before {
		t.Error("touchActive 未更新時戳")
	}

	// 第一個原因勝出，後續不覆蓋
	b.setEndReason(endReasonIdleTimeout)
	b.setEndReason(endReasonMaxDuration)
	if b.EndReason() != endReasonIdleTimeout {
		t.Errorf("EndReason = %q, 期望首個 idle_timeout 勝出", b.EndReason())
	}
}

func TestSetTimeouts(t *testing.T) {
	b := newBridge(nil, nil, nil, nil, "", 0, 0)
	b.setTimeouts(30*time.Minute, 8*time.Hour)
	if b.idleTimeout != 30*time.Minute || b.maxDuration != 8*time.Hour {
		t.Errorf("setTimeouts 未生效: idle=%v max=%v", b.idleTimeout, b.maxDuration)
	}
}
