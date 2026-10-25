package asset

import (
	"errors"
	"strings"
	"testing"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/policy"
)

// stubAccessDefault 全域預設讀取替身，並計數讀取次數（驗「只讀一次」）。
type stubAccessDefault struct {
	value string
	reads int
}

func (s *stubAccessDefault) Get(key string) string {
	if key == policy.PolicyAccessPolicyDefault {
		s.reads++
	}
	return s.value
}

func apStr(s string) *string { return &s }

func setAccessPolicyRow(t *testing.T, db *gorm.DB, id uint, v *string) {
	t.Helper()
	if err := db.Model(&model.Asset{}).Where("id = ?", id).Update("access_policy", v).Error; err != nil {
		t.Fatalf("設定前置覆寫: %v", err)
	}
}

func storedAccessPolicy(t *testing.T, db *gorm.DB, id uint) *string {
	t.Helper()
	var row model.Asset
	if err := db.First(&row, id).Error; err != nil {
		t.Fatalf("讀資產: %v", err)
	}
	return row.AccessPolicy
}

func countAuditByCorrelation(db *gorm.DB, corr string) int64 {
	var n int64
	db.Model(&model.AuditLog{}).Where("details LIKE ?", `%"correlation_id":"`+corr+`"%`).Count(&n)
	return n
}

// TestAccessPolicyDowngradeAlert 單台覆寫降級各產生恰一筆事件；收緊、不變、新建皆 0 筆。
func TestAccessPolicyDowngradeAlert(t *testing.T) {
	type tc struct {
		name     string
		prior    *string
		def      string
		req      *string
		wantType string // 空＝不應產生事件
		before   string
		after    string
	}
	cases := []tc{
		{"覆寫調低 approval 到 reason", apStr("approval"), "open", apStr("reason"), "override_lowered", "approval", "reason"},
		{"覆寫調低 reason 到 open", apStr("reason"), "approval", apStr("open"), "override_lowered", "reason", "open"},
		{"清除回落到較低預設", apStr("reason"), "open", apStr(""), "override_cleared", "reason", "open"},
		{"覆寫 approval 清除回落到 reason 預設", apStr("approval"), "reason", apStr(""), "override_cleared", "approval", "reason"},
		{"收緊 reason 到 approval", apStr("reason"), "open", apStr("approval"), "", "", ""},
		{"未覆寫新增與預設相同的 open", nil, "open", apStr("open"), "", "", ""},
		{"未覆寫新增較高覆寫", nil, "open", apStr("approval"), "", "", ""},
		{"清除回落到較高預設", apStr("reason"), "approval", apStr(""), "", "", ""},
		{"值相同的送出", apStr("reason"), "open", apStr("reason"), "", "", ""},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			db := setupAccountDB(t)
			assets, _ := newAccountServices(t)
			rec := &recordingAlertSink{}
			assets.SetSecurityChangeAlertSink(rec)
			def := &stubAccessDefault{value: c.def}
			assets.SetAccessPolicyDefaultReader(def)
			a := mustCreateAsset(t, assets, "ap-"+strings.ReplaceAll(c.name, " ", "-"), "10.0.0.1")
			setAccessPolicyRow(t, db, a.ID, c.prior)
			def.reads = 0

			// 操作者為 adminCtx（超管路徑也要產生事件）
			if _, err := assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{AccessPolicy: c.req}); err != nil {
				t.Fatalf("更新: %v", err)
			}
			if c.wantType == "" {
				if len(rec.events) != 0 {
					t.Fatalf("不應產生事件，實得 %d：%+v", len(rec.events), rec.events)
				}
				return
			}
			if len(rec.events) != 1 {
				t.Fatalf("應恰一筆事件，實得 %d", len(rec.events))
			}
			ev := rec.events[0]
			if string(ev.Type) != "access_policy_relaxed" {
				t.Fatalf("事件類型 %q", ev.Type)
			}
			if ev.Target.Kind != port.SystemAlertTargetAsset || ev.AssetID == nil || *ev.AssetID != a.ID ||
				ev.Actor.UserID != 1 || ev.Actor.Username != "admin" {
				t.Fatalf("目標或操作者不符：%+v", ev)
			}
			p := ev.Params
			if p["relax_type"] != c.wantType || p["before_level"] != c.before || p["after_level"] != c.after ||
				p["asset_name"] != a.Name || len(p) != 4 {
				t.Fatalf("參數不符：%v", p)
			}
			if def.reads != 1 {
				t.Fatalf("全域預設應只讀一次，實得 %d", def.reads)
			}
			// 事件與審計列同一交易：關聯識別在審計明細出現恰一筆
			if ev.CorrelationID == "" || countAuditByCorrelation(db, ev.CorrelationID) != 1 {
				t.Fatalf("審計列應恰一筆帶關聯識別 %q", ev.CorrelationID)
			}
		})
	}

	t.Run("新建資產帶 open 不產生事件", func(t *testing.T) {
		setupAccountDB(t)
		assets, _ := newAccountServices(t)
		rec := &recordingAlertSink{}
		assets.SetSecurityChangeAlertSink(rec)
		assets.SetAccessPolicyDefaultReader(&stubAccessDefault{value: "approval"})
		if _, err := assets.Create(WithSystemCaller(adminCtx()), &CreateAssetRequest{
			Name: "ap-new", Protocol: model.ProtocolSSH, Host: "10.0.0.9", Port: 22, AccessPolicy: "open", CreatedBy: 1,
		}); err != nil {
			t.Fatalf("建立: %v", err)
		}
		if len(rec.events) != 0 {
			t.Fatalf("建立不應產生事件，實得 %d", len(rec.events))
		}
	})

	t.Run("不帶 access_policy 的更新不需要讀取面也不告警", func(t *testing.T) {
		setupAccountDB(t)
		assets, _ := newAccountServices(t)
		rec := &recordingAlertSink{}
		assets.SetSecurityChangeAlertSink(rec)
		a := mustCreateAsset(t, assets, "ap-noreq", "10.0.0.1")
		desc := "d"
		if _, err := assets.Update(adminCtx(), a.ID, &UpdateAssetRequest{Description: &desc}); err != nil {
			t.Fatalf("更新: %v", err)
		}
		if len(rec.events) != 0 {
			t.Fatalf("不應產生事件，實得 %d", len(rec.events))
		}
	})
}

// TestAccessPolicyDowngradeAtomicity 降級的告警與審計任一寫不進去，整筆回滾。
func TestAccessPolicyDowngradeAtomicity(t *testing.T) {
	prepare := func(t *testing.T, sink port.SystemAlertSink) (*AssetService, *gorm.DB, *model.Asset) {
		db := setupAccountDB(t)
		assets, _ := newAccountServices(t)
		assets.SetSecurityChangeAlertSink(sink)
		assets.SetAccessPolicyDefaultReader(&stubAccessDefault{value: "open"})
		a := mustCreateAsset(t, assets, "ap-atomic", "10.0.0.1")
		setAccessPolicyRow(t, db, a.ID, apStr("approval"))
		return assets, db, a
	}

	t.Run("注入告警寫入失敗", func(t *testing.T) {
		injected := errors.New("injected alert failure")
		assets, db, a := prepare(t, &recordingAlertSink{err: injected})
		var before int64
		db.Model(&model.AuditLog{}).Count(&before)

		_, err := assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{AccessPolicy: apStr("reason")})
		if !errors.Is(err, injected) {
			t.Fatalf("應回告警錯誤，實得 %v", err)
		}
		if got := storedAccessPolicy(t, db, a.ID); got == nil || *got != "approval" {
			t.Fatalf("覆寫值應維持 approval，實得 %v", got)
		}
		var after int64
		db.Model(&model.AuditLog{}).Count(&after)
		if after != before {
			t.Fatalf("審計列不應留下：前 %d 後 %d", before, after)
		}
	})

	t.Run("注入審計寫入失敗", func(t *testing.T) {
		rec := &recordingAlertSink{}
		assets, db, a := prepare(t, rec)
		fail := false
		name := "inject-audit-fail-" + t.Name()
		if err := db.Callback().Create().Before("gorm:create").Register(name, func(tx *gorm.DB) {
			if fail && tx.Statement.Table == "audit_logs" {
				_ = tx.AddError(errors.New("injected audit failure"))
			}
		}); err != nil {
			t.Fatalf("註冊注入器: %v", err)
		}
		t.Cleanup(func() { _ = db.Callback().Create().Remove(name) })
		fail = true

		_, err := assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{AccessPolicy: apStr("reason")})
		if err == nil {
			t.Fatal("審計寫入失敗時應回錯")
		}
		fail = false
		if got := storedAccessPolicy(t, db, a.ID); got == nil || *got != "approval" {
			t.Fatalf("覆寫值應維持 approval，實得 %v", got)
		}
		if len(rec.events) != 0 {
			t.Fatalf("審計失敗時不應有告警事件，實得 %d", len(rec.events))
		}
	})

	t.Run("讀取面未注入即回錯並回滾", func(t *testing.T) {
		db := setupAccountDB(t)
		assets, _ := newAccountServices(t)
		assets.SetSecurityChangeAlertSink(&recordingAlertSink{})
		a := mustCreateAsset(t, assets, "ap-nodef", "10.0.0.1")
		setAccessPolicyRow(t, db, a.ID, apStr("approval"))
		_, err := assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{AccessPolicy: apStr("open")})
		if !errors.Is(err, ErrAccessPolicyDefaultMissing) {
			t.Fatalf("應回 ErrAccessPolicyDefaultMissing，實得 %v", err)
		}
		if got := storedAccessPolicy(t, db, a.ID); got == nil || *got != "approval" {
			t.Fatalf("覆寫值應維持 approval，實得 %v", got)
		}
	})
}
