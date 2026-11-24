package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type dayAlertWire struct {
	ID         uint              `json:"id"`
	RuleName   string            `json:"rule_name"`
	ReasonCode string            `json:"reason_code"`
	UserID     uint              `json:"user_id"`
	Username   *string           `json:"username"`
	AssetName  *string           `json:"asset_name"`
	TargetKind *string           `json:"target_kind"`
	TargetID   *string           `json:"target_id"`
	Params     map[string]string `json:"params"`
}

func getDayAlerts(t *testing.T, db *gorm.DB, now time.Time) ([]dayAlertWire, []map[string]json.RawMessage) {
	t.Helper()
	svc := audit.NewDailyReviewService(db, policy.NewSecurityPolicyService(db), nil)
	svc.SetClock(func() time.Time { return now })
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/daily-reviews/days/:date", NewDailyReviewHandler(svc, nil).Day)
	w := doJSON(r, "GET", "/daily-reviews/days/2026-10-10", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("單日明細 = %d (%s)", w.Code, w.Body.String())
	}
	var typed struct {
		Data struct {
			Alerts []dayAlertWire `json:"unreviewed_alerts"`
		} `json:"data"`
	}
	var raw struct {
		Data struct {
			Alerts []map[string]json.RawMessage `json:"unreviewed_alerts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &typed); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	return typed.Data.Alerts, raw.Data.Alerts
}

// TestDailyReviewDayAlertItemsCarryReadFields 單日明細的每一筆告警看得出是什麼事。
//
// 擋的威脅：明細只回編號與規則名，畫面只能以「系統告警」泛稱呈現，審閱者無從判斷就勾選確認；
// 或參數投影把操作者名快照與觸發等級混進宣告參數（與系統告警明細的投影不一致）；
// 或使用者列被刪除時整列消失，使抽屜筆數與簽核前檢查的未審閱筆數對不上。
func TestDailyReviewDayAlertItemsCarryReadFields(t *testing.T) {
	_, db, now := setupDailyReviewRouter(t)
	if err := db.AutoMigrate(&model.User{}, &model.Asset{}, &model.SystemAlertDetail{}); err != nil {
		t.Fatal(err)
	}
	taipei, _ := time.LoadLocation("Asia/Taipei")
	day := func(h int) time.Time { return time.Date(2026, 10, 10, h, 0, 0, 0, taipei).UTC() }

	admin := model.User{Username: "ops-admin", Password: "x"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	asset := model.Asset{Name: "db-prod-01", Host: "10.0.0.5", Port: 22, Protocol: "ssh", CreatedBy: 1}
	if err := db.Create(&asset).Error; err != nil {
		t.Fatal(err)
	}
	// 系統告警：發放管理類角色，帶 role_name 參數與兩個保留鍵
	if err := db.Exec(`INSERT INTO command_alerts (rule_name, kind, reason_code, user_id, severity, triggered_at, command)
		VALUES ('management_role_granted', ?, 'management_role_granted', ?, 'high', ?, '')`,
		model.AlertKindSystemSecurity, admin.ID, day(3)).Error; err != nil {
		t.Fatal(err)
	}
	var sysID uint
	db.Raw("SELECT max(id) FROM command_alerts").Scan(&sysID)
	if err := db.Create(&model.SystemAlertDetail{AlertID: sysID, AlertType: "management_role_granted",
		TargetKind: "user", TargetID: "42",
		Params:        `{"actor":"ops-admin","severity":"high","role_name":"asset_admin","target_username":"lee"}`,
		CorrelationID: "corr-1"}).Error; err != nil {
		t.Fatal(err)
	}
	// 連線指令告警
	if err := db.Exec(`INSERT INTO command_alerts (rule_name, kind, user_id, asset_id, severity, triggered_at, command)
		VALUES ('rm -rf 偵測', 'rule', ?, ?, 'high', ?, 'rm -rf /data')`, admin.ID, asset.ID, day(4)).Error; err != nil {
		t.Fatal(err)
	}

	items, raw := getDayAlerts(t, db, now)
	if len(items) != 2 {
		t.Fatalf("未審閱告警 %d 筆, want 2", len(items))
	}
	sys, cmd := items[0], items[1]
	if sys.ID != sysID || sys.Username == nil || *sys.Username != "ops-admin" || sys.ReasonCode != "management_role_granted" ||
		*sys.TargetKind != "user" || *sys.TargetID != "42" || *sys.AssetName != "" {
		t.Fatalf("系統告警欄位不符: %+v", sys)
	}
	if sys.Params["role_name"] != "asset_admin" || sys.Params["target_username"] != "lee" || len(sys.Params) != 2 {
		t.Fatalf("系統告警 params = %v, want 只有 role_name、target_username", sys.Params)
	}
	for _, k := range []string{"actor", "severity"} {
		if _, ok := sys.Params[k]; ok {
			t.Fatalf("系統告警 params 不得含保留鍵 %q: %v", k, sys.Params)
		}
	}
	if *cmd.Username != "ops-admin" || *cmd.AssetName != "db-prod-01" || *cmd.TargetKind != "" || *cmd.TargetID != "" {
		t.Fatalf("指令告警欄位不符: %+v", cmd)
	}
	if string(raw[1]["params"]) != "{}" {
		t.Fatalf("指令告警 params 線上形狀 = %s, want {}", raw[1]["params"])
	}
	for _, k := range []string{"reason_code", "username", "asset_name", "target_kind", "target_id", "params"} {
		if _, ok := raw[1][k]; !ok {
			t.Fatalf("指令告警缺少鍵 %q（空值也要出現）", k)
		}
	}

	// 使用者列被刪除：列仍在、username 為空字串
	if err := db.Unscoped().Delete(&model.User{}, admin.ID).Error; err != nil {
		t.Fatal(err)
	}
	items, _ = getDayAlerts(t, db, now)
	if len(items) != 2 {
		t.Fatalf("刪除使用者後未審閱告警 %d 筆, want 2", len(items))
	}
	for _, it := range items {
		if it.Username == nil || *it.Username != "" || it.UserID != admin.ID {
			t.Fatalf("刪除使用者後 username 應為空字串、user_id 保留: %+v", it)
		}
	}
}
