package seal

import (
	"testing"
	"time"
)

func TestBackoffGrowsExponentiallyAndCaps(t *testing.T) {
	base := time.Second
	max := 8 * time.Second
	// 逐次失敗的退避：0（未失敗）、1s、2s、4s、8s，其後封頂於 8s
	want := []time.Duration{0, time.Second, 2 * time.Second, 4 * time.Second,
		8 * time.Second, 8 * time.Second, 8 * time.Second}
	for failures, w := range want {
		if got := backoffFor(base, max, uint32(failures)); got != w {
			t.Errorf("failures=%d: 預期 %v 實得 %v", failures, w, got)
		}
	}
}

func TestAllowSourceIsPureReadAndDoesNotExtend(t *testing.T) {
	l := NewLimiter(LimiterConfig{BaseBackoff: time.Hour, MaxBackoff: time.Hour, GlobalThreshold: 1000})
	now := time.Unix(1000, 0)
	l.RecordMaterialFailure("a", now)

	allowed, until := l.AllowSource("a", now)
	if allowed {
		t.Fatal("失敗後該來源應被退避")
	}
	// 退避期的重複探詢不得推遲到期時間
	for i := 0; i < 5; i++ {
		_, again := l.AllowSource("a", now.Add(time.Duration(i)*time.Second))
		if !again.Equal(until) {
			t.Fatalf("退避期的嘗試不得刷新到期時間：%v → %v", until, again)
		}
	}
	if ok, _ := l.AllowSource("b", now); !ok {
		t.Fatal("退避應為 per-source，其他來源不得被誤擋")
	}
	if ok, _ := l.AllowSource("a", now.Add(2*time.Hour)); !ok {
		t.Fatal("退避期滿後應自動恢復可嘗試，不需重啟")
	}
}

func TestRecordSuccessResetsCounts(t *testing.T) {
	l := NewLimiter(LimiterConfig{BaseBackoff: time.Hour, MaxBackoff: time.Hour, GlobalThreshold: 5})
	now := time.Unix(1000, 0)
	l.RecordMaterialFailure("a", now)
	l.RecordMaterialFailure("a", now)
	if l.GlobalFailures() != 2 {
		t.Fatalf("預期 2 次失敗，實得 %d", l.GlobalFailures())
	}
	l.RecordSuccess("a")
	if l.GlobalFailures() != 0 {
		t.Fatal("成功後計數應歸零")
	}
	if ok, _ := l.AllowSource("a", now); !ok {
		t.Fatal("成功後該來源的退避應解除")
	}
}

func TestGlobalCooldownArmsAtThresholdAndIsCapped(t *testing.T) {
	l := NewLimiter(LimiterConfig{
		BaseBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond,
		GlobalThreshold: 3, GlobalCooldown: time.Minute, MaxGlobalCooldown: 2 * time.Minute,
	})
	now := time.Unix(1000, 0)
	for i := 0; i < 2; i++ {
		if _, armed := l.RecordMaterialFailure("a", now); armed {
			t.Fatalf("第 %d 次失敗不應武裝全域冷卻", i+1)
		}
	}
	until, armed := l.RecordMaterialFailure("a", now)
	if !armed {
		t.Fatal("達門檻應武裝全域冷卻")
	}
	if until.Sub(now) != time.Minute {
		t.Fatalf("首次冷卻應為基準時長，實得 %v", until.Sub(now))
	}
	until, _ = l.RecordMaterialFailure("a", now)
	if until.Sub(now) != 2*time.Minute {
		t.Fatalf("冷卻應指數成長，實得 %v", until.Sub(now))
	}
	until, _ = l.RecordMaterialFailure("a", now)
	if until.Sub(now) != 2*time.Minute {
		t.Fatalf("冷卻應封頂於 MaxGlobalCooldown，實得 %v", until.Sub(now))
	}
}

// 逾時 SHALL NOT 計入材料失敗計數，另計逾時次數並於達門檻時告警。
func TestRecordTimeoutIsSeparateFromMaterialFailures(t *testing.T) {
	l := NewLimiter(LimiterConfig{GlobalThreshold: 2, TimeoutAlertThreshold: 2})
	if total, alert := l.RecordTimeout(); total != 1 || alert {
		t.Fatalf("首次逾時不應告警，實得 total=%d alert=%v", total, alert)
	}
	if total, alert := l.RecordTimeout(); total != 2 || !alert {
		t.Fatalf("達門檻應告警，實得 total=%d alert=%v", total, alert)
	}
	if l.GlobalFailures() != 0 {
		t.Fatal("逾時不得計入材料失敗計數")
	}
	if ok, _ := l.AllowSource("a", time.Unix(1000, 0)); !ok {
		t.Fatal("逾時不得把來源推進退避")
	}
	if l.TimeoutTotal() != 2 {
		t.Fatalf("逾時次數應為 2，實得 %d", l.TimeoutTotal())
	}
}

func TestPruneBoundsSourceTable(t *testing.T) {
	l := NewLimiter(LimiterConfig{
		BaseBackoff: time.Second, MaxBackoff: time.Second,
		GlobalThreshold: 100000, MaxSources: 4,
	})
	now := time.Unix(1000, 0)
	for i := 0; i < 20; i++ {
		l.RecordMaterialFailure(string(rune('a'+i)), now)
	}
	// 全部仍在退避期內，不會被清除
	l.mu.Lock()
	before := len(l.sources)
	l.mu.Unlock()
	if before != 20 {
		t.Fatalf("退避期內的條目不得被清除，實得 %d", before)
	}
	// 時間推進後再有新失敗時，過期條目應被清掉
	l.RecordMaterialFailure("zz", now.Add(time.Hour))
	l.mu.Lock()
	after := len(l.sources)
	l.mu.Unlock()
	if after != 1 {
		t.Fatalf("逾量時應清除已過退避期的條目，實得 %d", after)
	}
}

func TestNewLimiterFillsDefaults(t *testing.T) {
	l := NewLimiter(LimiterConfig{})
	d := DefaultLimiterConfig()
	if l.cfg != d {
		t.Fatalf("零值應以預設補齊，實得 %+v", l.cfg)
	}
}
