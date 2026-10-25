package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 映射重新驗證時限的放寬路徑：真處理器、真政策服務、組裝根的放寬告警轉接器與真實
// 系統告警落地面。放寬（調長、改 0）必須寫入成功，且告警列記的是實際操作者；
// 轉接器若傳零值操作者，落地面會拒收而整筆政策寫入回滾，這支測試即轉紅。
func TestPolicyRelaxAlertRealAdapterRecordsOperator(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(append(baselineExtraModels(),
		&model.AuditLog{}, &model.SecurityPolicy{}, &model.SecurityPolicyHistory{},
		&model.PolicyGroup{}, &model.PolicyClause{}, &model.PolicyClauseControl{},
		&model.PolicyClauseAnnotation{})...); err != nil {
		t.Fatal(err)
	}

	policies := policy.NewSecurityPolicyService(db)
	policies.SetHighRiskAlertRaiser(policyHighRiskAlertAdapter{sink: audit.NewSystemAlertSink(nil)})
	if err := policies.HighRiskAlertSinkReady(); err != nil {
		t.Fatal(err)
	}
	groups := policy.NewPolicyGroupRepository(db)
	h := api.NewSecurityPolicyHandler(policies, nil, policy.NewComplianceService(policies, groups), groups)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "policy-admin")
	})
	r.PUT("/api/v1/security-policies", h.Update)

	key := policy.PolicyMappingRevalidationHours
	for i, to := range []string{"24", "0"} {
		w := doJSON(r, http.MethodPut, "/api/v1/security-policies", `{"policies":{"`+key+`":"`+to+`"}}`)
		if w.Code != http.StatusOK {
			t.Fatalf("放寬到 %s 應回 200，得 %d: %s", to, w.Code, w.Body.String())
		}
		if got := policies.GetInt(key); got != map[string]int{"24": 24, "0": 0}[to] {
			t.Fatalf("放寬到 %s 後現值 = %d", to, got)
		}
		var actors []uint
		if err := db.Model(&model.CommandAlert{}).
			Where("reason_code = ?", string(port.SystemAlertMappingRevalidationRelaxed)).
			Order("id").Pluck("user_id", &actors).Error; err != nil {
			t.Fatal(err)
		}
		if len(actors) != i+1 {
			t.Fatalf("放寬到 %s 後告警 %d 筆，want %d", to, len(actors), i+1)
		}
		if last := actors[len(actors)-1]; last != 7 {
			t.Fatalf("告警操作者 = %d，want 實際操作者 7", last)
		}
	}
	var details int64
	db.Model(&model.SystemAlertDetail{}).Where("alert_type = ?", string(port.SystemAlertMappingRevalidationRelaxed)).Count(&details)
	if details != 2 {
		t.Fatalf("告警明細 %d 筆，want 2", details)
	}

	// 存量列不合法（人工改庫、還原殘留）時，高危分類以讀取路徑的有效舊值為準：
	// 合法修復照常儲存並以有效值告警，不把非法原字串塞進告警參數而被真落地面拒收
	lastAlert := func(typ port.SystemAlertType) map[string]string {
		t.Helper()
		var rows []model.SystemAlertDetail
		db.Where("alert_type = ?", string(typ)).Order("alert_id").Find(&rows)
		if len(rows) == 0 {
			return nil
		}
		out := map[string]string{}
		_ = json.Unmarshal([]byte(rows[len(rows)-1].Params), &out)
		return out
	}
	put := func(key, value string) int {
		return doJSON(r, http.MethodPut, "/api/v1/security-policies", `{"policies":{"`+key+`":"`+value+`"}}`).Code
	}
	rec := policy.PolicyRetentionRecordingDays
	db.Save(&model.SecurityPolicy{Key: rec, Value: "broken", UpdatedBy: "sql"})
	if code := put(rec, "30"); code != http.StatusOK {
		t.Fatalf("錄影保留存量為非法字串時修為 30 應成功，得 %d", code)
	}
	if p := lastAlert(port.SystemAlertRetentionShortened); p["days_before"] != "90" || p["days_after"] != "30" {
		t.Fatalf("告警前值應為有效值 90（出廠），得 %v", p)
	}
	if policies.GetInt(rec) != 30 {
		t.Fatal("前提：讀取路徑讀到 30 並記為最後已知合法值")
	}
	db.Save(&model.SecurityPolicy{Key: rec, Value: "3", UpdatedBy: "sql"})
	var shortened int64
	db.Model(&model.SystemAlertDetail{}).Where("alert_type = ?", string(port.SystemAlertRetentionShortened)).Count(&shortened)
	if code := put(rec, "60"); code != http.StatusOK {
		t.Fatalf("錄影保留存量為 3 時改 60 應成功，得 %d", code)
	}
	// 有效舊值是最後已知合法值 30，30→60 為調長：不得新增告警（原值 3 比 60 才是「調長」以外的誤判來源）
	var after int64
	db.Model(&model.SystemAlertDetail{}).Where("alert_type = ?", string(port.SystemAlertRetentionShortened)).Count(&after)
	if after != shortened {
		t.Fatalf("有效舊值 30 改 60 是調長，不得新增告警（%d→%d）", shortened, after)
	}
	_ = policies.GetInt(rec) // 讀到 60，記為最後已知合法值
	db.Save(&model.SecurityPolicy{Key: rec, Value: "4", UpdatedBy: "sql"})
	if policies.GetInt(rec) != 60 {
		t.Fatal("前提：讀取路徑記得最後已知合法值 60")
	}
	if code := put(rec, "30"); code != http.StatusOK {
		t.Fatalf("存量 4、有效值 60 時改 30 應成功，得 %d", code)
	}
	if p := lastAlert(port.SystemAlertRetentionShortened); p["days_before"] != "60" || p["days_after"] != "30" {
		t.Fatalf("有效值 60 改 30 是下調，告警前值應為 60，得 %v", p)
	}
	fc := policy.PolicyRecordingFailCloseEnabled
	if code := put(fc, "true"); code != http.StatusOK {
		t.Fatalf("開啟錄影故障阻擋失敗 %d", code)
	}
	if !policies.GetBool(fc) {
		t.Fatal("前提：讀取路徑記得最後已知合法值 true")
	}
	db.Save(&model.SecurityPolicy{Key: fc, Value: "garbled", UpdatedBy: "sql"})
	if code := put(fc, "false"); code != http.StatusOK {
		t.Fatalf("錄影故障阻擋存量非法時關閉應成功，得 %d", code)
	}
	var off int64
	db.Model(&model.SystemAlertDetail{}).Where("alert_type = ?", string(port.SystemAlertRecordingFailcloseDisabled)).Count(&off)
	if off != 1 {
		t.Fatalf("有效舊值 true 改 false 應告警一筆，得 %d", off)
	}
}
