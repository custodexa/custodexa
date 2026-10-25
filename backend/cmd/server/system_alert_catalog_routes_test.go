package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 系統告警目錄與明細三個端點的案例（由 TestSystemAlertManagementRoutes 呼叫）。

// recordingAuditTx 交易內審計替身：把審計列寫進同一個交易；failNext 時回錯。
type recordingAuditTx struct{ failNext bool }

func (r *recordingAuditTx) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	if r.failNext {
		r.failNext = false
		return errors.New("注入的審計失敗")
	}
	return tx.Create(&model.AuditLog{
		UserID: ev.Actor.UserID, Username: ev.Actor.Username,
		Action: model.AuditAction(ev.Action), Resource: model.AuditResource(ev.Resource),
		Status: model.AuditStatus(ev.Status), Details: ev.Details,
	}).Error
}

func newSystemAlertRouteDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.Exec(`CREATE TABLE command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL,
		session_id INTEGER, user_id INTEGER NOT NULL, asset_id INTEGER,
		command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
		blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT ''
	)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.SystemAlertDetail{}, &model.SystemAlertOutbox{},
		&model.SystemAlertSeverityOverride{}, &model.NotificationChannel{}, &model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	return db
}

func newSystemAlertRouteEngine(h *api.SystemAlertHandler, p *authz.Principal) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "route-test")
		middleware.SetPrincipal(c, p)
	})
	// 與 RegisterRoutes 同一組端點與同一支登錄執行中介層；沒有 DELETE 與啟停路由。
	v1 := r.Group("/api/v1")
	types := v1.Group("/system-alert-types")
	types.Use(middleware.EnforceRegistry())
	types.GET("", h.List)
	types.PUT("/:key", h.UpdateSeverity)
	v1.GET("/command-alerts/:id/system-detail", middleware.EnforceRegistry(), h.SystemDetail)
	return r
}

func doJSON(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func errorCodeOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return body.Code
}

func runSystemAlertCatalogRouteCases(t *testing.T) {
	newEnv := func(t *testing.T) (*gorm.DB, *recordingAuditTx, *api.SystemAlertHandler) {
		db := newSystemAlertRouteDB(t)
		tx := &recordingAuditTx{}
		return db, tx, api.NewSystemAlertHandler(audit.NewSystemAlertCatalogService(db, tx), nil)
	}
	superAdmin := principalWith(model.BuiltinSuperAdmin, model.RoleAdmin)
	securityAdmin := principalWith(model.BuiltinSecurityAdmin, "系統安全管理員")
	identityAdmin := principalWith(model.BuiltinIdentityAdmin, "身分管理員")
	auditor := principalWith(model.BuiltinAuditor, model.RoleAuditor)
	assetOnly := assetManagerCustomPrincipal(t)
	severityCustom := customRolePrincipal("alert-severity-custom", authz.PermSystemAlertManage)
	channelCustom := customRolePrincipal("channel-manager-custom", authz.PermNotificationChannel)

	t.Run("目錄與明細三條路由登錄於分級權限點與稽核檢視，且沒有 DELETE", func(t *testing.T) {
		for _, c := range []struct {
			method, path string
			perm         authz.Permission
		}{
			{"GET", "/api/v1/system-alert-types", authz.PermSystemAlertManage},
			{"PUT", "/api/v1/system-alert-types/:key", authz.PermSystemAlertManage},
			{"GET", "/api/v1/command-alerts/:id/system-detail", authz.PermAuditView},
		} {
			e, ok := authz.LookupRoute(c.method, c.path)
			if !ok || e.Base != authz.BasePerm || e.Perm != c.perm {
				t.Fatalf("%s %s 登錄不符: %+v ok=%v", c.method, c.path, e, ok)
			}
		}
		if _, ok := authz.LookupRoute("DELETE", "/api/v1/system-alert-types/:key"); ok {
			t.Fatal("系統告警類型不得有 DELETE 路由")
		}
	})

	t.Run("目錄、改分級與明細依主體權限放行或拒絕", func(t *testing.T) {
		_, _, h := newEnv(t)
		cases := []struct {
			name           string
			p              *authz.Principal
			catalog, audit bool
		}{
			{"超管", superAdmin, true, true},
			{"系統安全管理員範本", securityAdmin, true, false},
			{"身分管理員範本", identityAdmin, false, false},
			{"稽核員", auditor, false, true},
			{"只持資產管理權的自訂角色", assetOnly, false, false},
			{"只持通道管理權的自訂角色", channelCustom, false, false},
			{"被授予告警分級權的自訂角色", severityCustom, true, false},
		}
		for _, c := range cases {
			r := newSystemAlertRouteEngine(h, c.p)
			if w := doJSON(r, "GET", "/api/v1/system-alert-types", ""); (w.Code == 200) != c.catalog {
				t.Errorf("%s 讀目錄：%d，應%v", c.name, w.Code, c.catalog)
			}
			w := doJSON(r, "PUT", "/api/v1/system-alert-types/management_role_granted", `{"severity":"low"}`)
			if (w.Code == 200) != c.catalog {
				t.Errorf("%s 改分級：%d，應%v", c.name, w.Code, c.catalog)
			}
			if !c.catalog && w.Code != http.StatusForbidden {
				t.Errorf("%s 改分級拒絕應為 403，實為 %d", c.name, w.Code)
			}
			// 明細的權限與告警列表同一個（稽核檢視）；告警不存在時放行者得 404、拒絕者得 403。
			w = doJSON(r, "GET", "/api/v1/command-alerts/999/system-detail", "")
			if c.audit && w.Code != http.StatusNotFound {
				t.Errorf("%s 讀明細：%d，應放行（告警不存在得 404）", c.name, w.Code)
			}
			if !c.audit && w.Code != http.StatusForbidden {
				t.Errorf("%s 讀明細：%d，應 403", c.name, w.Code)
			}
		}
	})

	t.Run("目錄得 19 種且與登錄一致，筆數只在具稽核檢視時出現", func(t *testing.T) {
		db, _, h := newEnv(t)
		var want []string
		for _, d := range audit.SystemAlertCatalog() {
			want = append(want, string(d.Type))
		}
		if len(want) != 19 {
			t.Fatalf("登錄應為 19 種，實為 %d", len(want))
		}
		if err := db.Create(&model.SystemAlertSeverityOverride{AlertType: "management_role_granted", Severity: "low", UpdatedBy: 1}).Error; err != nil {
			t.Fatal(err)
		}
		type listResp struct {
			Types []struct {
				Key       string `json:"key"`
				Effective string `json:"effective_severity"`
				Default   string `json:"default_severity"`
				Adjusted  bool   `json:"adjusted"`
				Recent    *int64 `json:"recent_30d"`
			} `json:"types"`
		}
		var withoutAudit, withAudit listResp
		w := doJSON(newSystemAlertRouteEngine(h, securityAdmin), "GET", "/api/v1/system-alert-types", "")
		if err := json.Unmarshal(w.Body.Bytes(), &withoutAudit); err != nil || w.Code != 200 {
			t.Fatalf("解析失敗 %d %v", w.Code, err)
		}
		w = doJSON(newSystemAlertRouteEngine(h, superAdmin), "GET", "/api/v1/system-alert-types", "")
		if err := json.Unmarshal(w.Body.Bytes(), &withAudit); err != nil || w.Code != 200 {
			t.Fatalf("解析失敗 %d %v", w.Code, err)
		}
		if len(withoutAudit.Types) != 19 || len(withAudit.Types) != 19 {
			t.Fatalf("目錄筆數 %d／%d，應皆為 19", len(withoutAudit.Types), len(withAudit.Types))
		}
		for i, k := range want {
			if withoutAudit.Types[i].Key != k || withAudit.Types[i].Key != k {
				t.Fatalf("第 %d 列鍵不同於登錄: %s", i, k)
			}
			if withoutAudit.Types[i].Recent != nil {
				t.Fatalf("無稽核檢視者不應看到筆數: %s", k)
			}
			if withAudit.Types[i].Recent == nil {
				t.Fatalf("具稽核檢視者應看到筆數: %s", k)
			}
		}
		for _, e := range withAudit.Types {
			if e.Key == "management_role_granted" && (e.Effective != "low" || !e.Adjusted || e.Default != "medium") {
				t.Fatalf("覆寫列視圖不符: %+v", e)
			}
		}
	})

	t.Run("改分級與審計同交易，審計失敗則分級不變", func(t *testing.T) {
		db, sink, h := newEnv(t)
		r := newSystemAlertRouteEngine(h, securityAdmin)
		sink.failNext = true
		w := doJSON(r, "PUT", "/api/v1/system-alert-types/self_privilege_decreased", `{"severity":"high"}`)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("審計失敗應回 500，實為 %d", w.Code)
		}
		var n int64
		db.Model(&model.SystemAlertSeverityOverride{}).Count(&n)
		if n != 0 {
			t.Fatalf("審計失敗後不應留下覆寫列，實為 %d", n)
		}
		w = doJSON(r, "PUT", "/api/v1/system-alert-types/self_privilege_decreased", `{"severity":"high"}`)
		if w.Code != 200 {
			t.Fatalf("改分級應成功: %d %s", w.Code, w.Body.String())
		}
		var logs []model.AuditLog
		db.Where("resource = ?", string(model.ResourceSystemAlertType)).Find(&logs)
		if len(logs) != 1 || logs[0].Action != model.ActionUpdate ||
			!strings.Contains(logs[0].Details, `"severity_before":"low"`) || !strings.Contains(logs[0].Details, `"severity_after":"high"`) {
			t.Fatalf("審計列不符: %+v", logs)
		}
	})

	t.Run("只接受 severity：其他欄位、未知鍵與非法值各回專屬錯誤碼，DELETE 被拒", func(t *testing.T) {
		db, _, h := newEnv(t)
		r := newSystemAlertRouteEngine(h, securityAdmin)
		for _, body := range []string{`{"severity":"low","enabled":false}`, `{"enabled":false}`, `{"severity":"low","delete":true}`} {
			w := doJSON(r, "PUT", "/api/v1/system-alert-types/management_role_granted", body)
			if w.Code != 400 || errorCodeOf(t, w) != "VALIDATION_SYSTEM_ALERT_LOCKED" {
				t.Errorf("%s：%d %s，應 VALIDATION_SYSTEM_ALERT_LOCKED", body, w.Code, errorCodeOf(t, w))
			}
		}
		w := doJSON(r, "PUT", "/api/v1/system-alert-types/no_such_type", `{"severity":"low"}`)
		if w.Code != 404 || errorCodeOf(t, w) != "NOTFOUND_SYSTEM_ALERT_TYPE" {
			t.Errorf("未知鍵：%d %s", w.Code, errorCodeOf(t, w))
		}
		for _, body := range []string{`{"severity":"critical"}`, `{"severity":""}`, `{"severity":3}`, `{}`} {
			w = doJSON(r, "PUT", "/api/v1/system-alert-types/management_role_granted", body)
			code := errorCodeOf(t, w)
			if body == `{}` {
				continue // 空物件：沒有任何欄位，落在分級缺漏（下方斷言）
			}
			if w.Code != 400 || code != "VALIDATION_SYSTEM_ALERT_SEVERITY" {
				t.Errorf("%s：%d %s，應 VALIDATION_SYSTEM_ALERT_SEVERITY", body, w.Code, code)
			}
		}
		if w = doJSON(r, "PUT", "/api/v1/system-alert-types/management_role_granted", `{}`); w.Code != 400 {
			t.Errorf("空物件應 400，實為 %d", w.Code)
		}
		if w = doJSON(r, "DELETE", "/api/v1/system-alert-types/management_role_granted", ""); w.Code < 400 {
			t.Errorf("DELETE 不得成功: %d", w.Code)
		}
		var n int64
		db.Model(&model.SystemAlertSeverityOverride{}).Count(&n)
		if n != 0 {
			t.Fatalf("被拒絕的請求不得寫入覆寫列，實為 %d", n)
		}
	})

	t.Run("分級調為低後仍產生告警並排入投遞佇列，明細回投遞狀態與操作日誌", func(t *testing.T) {
		db, _, h := newEnv(t)
		if err := db.Create(&model.NotificationChannel{Name: "ops", Type: "webhook", URL: "https://hook.example.test/x",
			Enabled: true, Language: "zh-TW", MinSeverity: "high"}).Error; err != nil {
			t.Fatal(err)
		}
		w := doJSON(newSystemAlertRouteEngine(h, securityAdmin), "PUT", "/api/v1/system-alert-types/management_role_granted", `{"severity":"low"}`)
		if w.Code != 200 {
			t.Fatalf("改分級失敗: %d", w.Code)
		}
		corr := "c0ffee00c0ffee00c0ffee00c0ffee00"
		var alertID uint
		err := db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(&model.AuditLog{UserID: 7, Username: "alice", Action: model.ActionUpdate,
				Resource: model.ResourceUser, Status: model.StatusSuccess, ClientIP: "203.0.113.7",
				Details: `{"event":"x","correlation_id":"` + corr + `"}`}).Error; err != nil {
				return err
			}
			rc, err := audit.NewSystemAlertSink(nil).RaiseInTx(tx, port.SystemAlertEvent{
				Type:          port.SystemAlertManagementRoleGranted,
				Actor:         port.SystemAlertActor{UserID: 7, Username: "alice"},
				Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetUser, ID: "9"},
				CorrelationID: corr,
				Params:        map[string]string{"path": "direct_assign", "recipient": "bob", "role_name": "asset_admin"},
			})
			alertID = rc.AlertID
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		var alert model.CommandAlert
		if err := db.First(&alert, alertID).Error; err != nil || alert.Severity != "low" || alert.Kind != model.AlertKindSystemSecurity {
			t.Fatalf("調為低後仍應產生系統告警列: %+v %v", alert, err)
		}
		var outbox int64
		db.Model(&model.SystemAlertOutbox{}).Where("alert_id = ?", alertID).Count(&outbox)
		if outbox != 1 {
			t.Fatalf("調為低後 outbox 應有 1 列，實為 %d", outbox)
		}

		r := newSystemAlertRouteEngine(h, auditor)
		w = doJSON(r, "GET", "/api/v1/command-alerts/"+itoa(alertID)+"/system-detail", "")
		if w.Code != 200 {
			t.Fatalf("稽核員讀明細: %d %s", w.Code, w.Body.String())
		}
		var d struct {
			AlertType  string            `json:"alert_type"`
			Severity   string            `json:"severity"`
			Actor      string            `json:"actor"`
			Params     map[string]string `json:"params"`
			AuditLogID *uint             `json:"audit_log_id"`
			ClientIP   string            `json:"client_ip"`
			TargetKind string            `json:"target_kind"`
			TargetID   string            `json:"target_id"`
			Deliveries []struct {
				DestName string `json:"dest_name"`
				State    string `json:"state"`
			} `json:"deliveries"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		if d.AlertType != "management_role_granted" || d.Severity != "low" || d.Actor != "alice" ||
			d.AuditLogID == nil || len(d.Deliveries) != 1 || d.Deliveries[0].State == "" || d.Params["recipient"] != "bob" ||
			d.TargetKind != "user" || d.TargetID != "9" {
			t.Fatalf("明細不符: %s", w.Body.String())
		}
		// 來源位址取自同交易的審計列。
		if d.ClientIP != "203.0.113.7" {
			t.Fatalf("明細來源位址應取自對應審計列，實為 %q", d.ClientIP)
		}
		if _, leaked := d.Params["actor"]; leaked {
			t.Fatal("actor 是保留鍵，不應混在宣告參數裡")
		}
		if strings.Contains(w.Body.String(), "hook.example.test") {
			t.Fatal("明細不得含通道網址")
		}

		// 非系統告警列回 404。
		if err := db.Exec(`INSERT INTO command_alerts (id, rule_name, user_id, command, severity, triggered_at, kind, reason_code)
			VALUES (500, 'r', 1, 'ls', 'low', CURRENT_TIMESTAMP, 'rule', '')`).Error; err != nil {
			t.Fatal(err)
		}
		if w = doJSON(r, "GET", "/api/v1/command-alerts/500/system-detail", ""); w.Code != 404 {
			t.Fatalf("非系統告警列應 404，實為 %d", w.Code)
		}
		if w = doJSON(newSystemAlertRouteEngine(h, identityAdmin), "GET", "/api/v1/command-alerts/"+itoa(alertID)+"/system-detail", ""); w.Code != 403 {
			t.Fatalf("無稽核檢視者應 403，實為 %d", w.Code)
		}
	})
}

func itoa(n uint) string {
	b, _ := json.Marshal(n)
	return string(b)
}
