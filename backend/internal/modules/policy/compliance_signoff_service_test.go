package policy

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// newSignoffComplianceStack 內建組種子＋政策變更歷史表的記憶體庫上的政策服務與合規服務
func newSignoffComplianceStack(t *testing.T) (*SecurityPolicyService, *ComplianceService) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	// :memory: 連線池陷阱：多條連線各自是一個空庫
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.SecurityPolicy{}, &model.SecurityPolicyHistory{}, &model.PolicyGroup{},
		&model.PolicyClause{}, &model.PolicyClauseControl{}, &model.PolicyClauseAnnotation{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := SeedBuiltinPolicyGroups(db); err != nil {
		t.Fatalf("內建組種子: %v", err)
	}
	policies := NewSecurityPolicyService(db)
	return policies, NewComplianceService(policies, NewPolicyGroupRepository(db))
}

// fakeSignoffSource 運作紀錄來源替身：回固定紀錄或錯誤，並記被呼叫幾次
type fakeSignoffSource struct {
	rec   *SignoffRecord
	err   error
	calls int
}

func (f *fakeSignoffSource) SignoffRecord(bool) (*SignoffRecord, error) {
	f.calls++
	return f.rec, f.err
}

// TestComplianceSnapshotSignoffSourceError 擋：來源錯誤在組裝層被吞掉，最後退回只看
// 開關而判符合。經實際 ComplianceService（內建組種子、政策現值開啟）建構快照。
func TestComplianceSnapshotSignoffSourceError(t *testing.T) {
	pciVerdict := func(t *testing.T, svc *ComplianceService) Verdict {
		t.Helper()
		snap, err := svc.Snapshot(pciGroupCode, nil)
		if err != nil {
			t.Fatalf("快照: %v", err)
		}
		for _, v := range snap.VerdictsForKey(PolicyDailyReviewEnabled) {
			if v.GroupCode == pciGroupCode {
				if v.ClauseNo != "10.4.1" || v.Comparator != model.PolicyControlComparatorSignoffRecord {
					t.Fatalf("PCI 對每日審閱的要求 = %s %s, want 10.4.1 signoff_record", v.ClauseNo, v.Comparator)
				}
				return v
			}
		}
		t.Fatal("PCI 組沒有每日審閱簽核的判定")
		return Verdict{}
	}
	enable := func(t *testing.T, policies *SecurityPolicyService) {
		t.Helper()
		if _, err := policies.Update(PolicyDailyReviewEnabled, "true", "admin"); err != nil {
			t.Fatalf("開啟每日審閱: %v", err)
		}
	}

	t.Run("來源回錯誤", func(t *testing.T) {
		policies, svc := newSignoffComplianceStack(t)
		enable(t, policies)
		src := &fakeSignoffSource{err: errors.New("db down")}
		svc.SetSignoffSource(src)
		v := pciVerdict(t, svc)
		if v.Result != ComplianceResultInsufficientData || v.Reason != ComplianceReasonSignoffSourceUnavailable {
			t.Errorf("結果 %s／%s, want insufficient_data／signoff_source_unavailable", v.Result, v.Reason)
		}
		if src.calls == 0 {
			t.Error("來源未被呼叫：判定沒有走運作紀錄")
		}
	})
	t.Run("未注入", func(t *testing.T) {
		policies, svc := newSignoffComplianceStack(t)
		enable(t, policies)
		v := pciVerdict(t, svc)
		if v.Result != ComplianceResultInsufficientData || v.Reason != ComplianceReasonSignoffSourceUnavailable {
			t.Errorf("結果 %s／%s, want insufficient_data／signoff_source_unavailable", v.Result, v.Reason)
		}
	})
	t.Run("對照：來源正常且全簽為符合", func(t *testing.T) {
		policies, svc := newSignoffComplianceStack(t)
		enable(t, policies)
		svc.SetSignoffSource(&fakeSignoffSource{rec: buildSignoffRecord(t, enabledFrom(t, "2026-09-01"),
			signAll("2026-09-11", "2026-10-09"), false)})
		if v := pciVerdict(t, svc); v.Result != ComplianceResultCompliant {
			t.Errorf("結果 %s／%s, want compliant", v.Result, v.Reason)
		}
	})
	t.Run("電支組仍只看開關", func(t *testing.T) {
		policies, svc := newSignoffComplianceStack(t)
		enable(t, policies)
		svc.SetSignoffSource(&fakeSignoffSource{err: errors.New("db down")})
		snap, err := svc.Snapshot(ePaymentGroupCode, nil)
		if err != nil {
			t.Fatal(err)
		}
		vs := snap.VerdictsForKey(PolicyDailyReviewEnabled)
		if len(vs) == 0 {
			t.Fatal("電支組沒有每日審閱簽核的判定")
		}
		for _, v := range vs {
			if v.Comparator != model.PolicyControlComparatorEquals || v.Result != ComplianceResultCompliant {
				t.Errorf("電支組 %s %s／%s, want equals 符合", v.ClauseNo, v.Comparator, v.Result)
			}
		}
	})
}
