package offsite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func fixedNow() time.Time { return time.Unix(1756600000, 42) }

func stepByName(steps []StepResult, name string) *StepResult {
	for i := range steps {
		if steps[i].Step == name {
			return &steps[i]
		}
	}
	return nil
}

// TestConnectionAllGreen 無故障對照（testing.md §7 第 3 條）：
// 全步驟 ok、探測物寫入後被刪除、無殘留。
func TestConnectionAllGreen(t *testing.T) {
	f := NewFakeClient("b")
	f.SetGovernance(BucketGovernance{Versioning: VersioningEnabled, Retention: RetentionNone})

	steps := RunConnectionTest(context.Background(), f, "pfx", fixedNow)
	if len(steps) != 6 {
		t.Fatalf("步驟數=%d, want 6（probe/versioning/retention/write/read/delete）: %+v", len(steps), steps)
	}
	for _, s := range steps {
		if s.Outcome != StepOK {
			t.Errorf("步驟 %s outcome=%s, want ok（detail=%s）", s.Step, s.Outcome, s.Detail)
		}
	}
	if HasFailure(steps) {
		t.Error("全綠結果不應被判為含 fail")
	}
	if n := f.ObjectCount(); n != 0 {
		t.Errorf("探測物應已刪除，殘留 %d 件", n)
	}
	if f.DeleteCalls() != 1 {
		t.Errorf("DeleteCalls=%d, want 1", f.DeleteCalls())
	}
	// versioning 揭露照實陳述
	if v := stepByName(steps, StepVersioning); v == nil || v.Detail != "enabled" {
		t.Errorf("versioning 揭露不符: %+v", v)
	}
}

// TestConnectionBucketUnreachableFails 第 0 段失敗＝fail 並停在該步。
func TestConnectionBucketUnreachableFails(t *testing.T) {
	f := NewFakeClient("b")
	f.SetProbeError(errors.New("probe boom"))

	steps := RunConnectionTest(context.Background(), f, "", fixedNow)
	if len(steps) != 1 {
		t.Fatalf("失敗後應停步，got %d 步: %+v", len(steps), steps)
	}
	s := steps[0]
	if s.Step != StepProbeBucket || s.Outcome != StepFail || s.ErrorCode != CodeTestBucketUnreachable {
		t.Fatalf("probe 失敗步不符: %+v", s)
	}
	if !HasFailure(steps) {
		t.Error("HasFailure 應為 true")
	}
}

// TestConnectionGovernanceUnknownWarns 治理揭露讀不到→warn、不影響後續實測
// （無法確認，不影響上傳）。
func TestConnectionGovernanceUnknownWarns(t *testing.T) {
	f := NewFakeClient("b")
	f.SetGovernance(BucketGovernance{Versioning: VersioningUnknown, Retention: RetentionUnknown})

	steps := RunConnectionTest(context.Background(), f, "", fixedNow)
	for _, name := range []string{StepVersioning, StepRetention} {
		s := stepByName(steps, name)
		if s == nil || s.Outcome != StepWarn || s.ErrorCode != CodeTestGovernanceUnknown {
			t.Errorf("%s 應為 warn＋%s: %+v", name, CodeTestGovernanceUnknown, s)
		}
	}
	// warn 不中斷：寫讀刪照跑到底
	for _, name := range []string{StepWrite, StepRead, StepDelete} {
		if s := stepByName(steps, name); s == nil || s.Outcome != StepOK {
			t.Errorf("%s 應照跑且 ok: %+v", name, s)
		}
	}
	if HasFailure(steps) {
		t.Error("warn 不是 fail")
	}
}

// TestConnectionWriteFailure 寫入失敗→fail（注入格 fired 斷言）。
func TestConnectionWriteFailure(t *testing.T) {
	f := NewFakeClient("b")
	sentinel := errors.New("put denied")
	slot := f.Inject(&FaultSlot{Op: "put", Err: sentinel})
	t.Cleanup(func() {
		if slot.Fired() == 0 {
			t.Error("put 注入格從未 fire：測試沒走到注入點")
		}
	})

	steps := RunConnectionTest(context.Background(), f, "", fixedNow)
	s := stepByName(steps, StepWrite)
	if s == nil || s.Outcome != StepFail || s.ErrorCode != CodeTestWriteFailed {
		t.Fatalf("write 失敗步不符: %+v", s)
	}
	if stepByName(steps, StepRead) != nil {
		t.Error("write 失敗後不應繼續 read")
	}
}

// TestConnectionReadFailure 讀回失敗→fail。
func TestConnectionReadFailure(t *testing.T) {
	f := NewFakeClient("b")
	sentinel := errors.New("get refused")
	slot := f.Inject(&FaultSlot{Op: "fetch", Err: sentinel})
	t.Cleanup(func() {
		if slot.Fired() == 0 {
			t.Error("fetch 注入格從未 fire")
		}
	})

	steps := RunConnectionTest(context.Background(), f, "", fixedNow)
	s := stepByName(steps, StepRead)
	if s == nil || s.Outcome != StepFail || s.ErrorCode != CodeTestReadFailed {
		t.Fatalf("read 失敗步不符: %+v", s)
	}
}

// TestConnectionReadMismatchFails 讀回內容被竄改→fail（內容替換格）。
func TestConnectionReadMismatchFails(t *testing.T) {
	f := NewFakeClient("b")
	slot := f.Inject(&FaultSlot{Op: "fetch", Content: []byte("tampered")})
	t.Cleanup(func() {
		if slot.Fired() == 0 {
			t.Error("內容替換格從未 fire")
		}
	})

	steps := RunConnectionTest(context.Background(), f, "", fixedNow)
	s := stepByName(steps, StepRead)
	if s == nil || s.Outcome != StepFail || s.ErrorCode != CodeTestReadMismatch {
		t.Fatalf("read 不符步不符: %+v", s)
	}
}

// TestConnectionDeleteDeniedWarns 刪除被拒→**warn** offsite.test_delete_denied、
// 不細分（正式路徑對遠端零刪除，不依賴刪除能力）。
func TestConnectionDeleteDeniedWarns(t *testing.T) {
	f := NewFakeClient("b")
	sentinel := errors.New("retention holds it")
	slot := f.Inject(&FaultSlot{Op: "delete", Err: sentinel})
	t.Cleanup(func() {
		if slot.Fired() == 0 {
			t.Error("delete 注入格從未 fire")
		}
	})

	steps := RunConnectionTest(context.Background(), f, "", fixedNow)
	s := stepByName(steps, StepDelete)
	if s == nil || s.Outcome != StepWarn || s.ErrorCode != CodeTestDeleteDenied {
		t.Fatalf("delete 被拒步不符: %+v", s)
	}
	if HasFailure(steps) {
		t.Error("刪除被拒收斂為 warn，不得判整體 fail")
	}
	// 寫讀兩步照常成功（對照斷言）
	for _, name := range []string{StepWrite, StepRead} {
		if st := stepByName(steps, name); st == nil || st.Outcome != StepOK {
			t.Errorf("%s 應 ok: %+v", name, st)
		}
	}
}

// TestConnectionResultsCarryNoSecrets 回應面不含憑證與端點成分：
// 全部 Detail／ErrorCode 不得出現金鑰樣式字串（測試連線與端點淨化的回應面紀律；
// 這裡以「注入含秘密字樣的錯誤」證明錯誤原文不被回顯）。
func TestConnectionResultsCarryNoSecrets(t *testing.T) {
	f := NewFakeClient("b")
	f.Inject(&FaultSlot{Op: "put", Err: errors.New("AKIA" + "IOSFODNN7EXAMPLE secret leaked http://minio.internal:9000/path")})

	steps := RunConnectionTest(context.Background(), f, "", fixedNow)
	for _, s := range steps {
		for _, needle := range []string{"AKIA", "secret leaked", "minio.internal"} {
			if strings.Contains(s.Detail, needle) || strings.Contains(s.ErrorCode, needle) {
				t.Errorf("步驟 %s 回顯了錯誤原文（%s）：detail=%q", s.Step, needle, s.Detail)
			}
		}
	}
}
