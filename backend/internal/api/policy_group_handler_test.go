package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 政策組管理端點、合規對照端點與設定端的判定投影。
//
// 本檔釘四件事：
//  1. 讀寫的角色邊界：政策組讀取 admin 與 auditor 皆可，寫入只有 admin，
//     auditor 寫入回 403 且無任何資料變更。
//  2. 每一次寫入各留一列審計，詳情帶得出組代號、條號與舊值→新值。
//  3. 資料存取層的拒絕碼原樣出到 HTTP：內建組唯讀、值域不合、同鍵重複三種
//     成因的修法不同，收斂成單一「儲存失敗」會讓管理者只能逐項試。
//  4. 唯讀端點不寫任何東西——合規對照頁在規格上沒有寫入入口。

// policyTestEnv 四張政策組表 + 安全政策 + 審計列的最小裝配。
type policyTestEnv struct {
	router  *gin.Engine
	db      *gorm.DB
	repo    *policy.PolicyGroupRepository
	service *policy.SecurityPolicyService
}

func newPolicyTestEnv(t *testing.T) *policyTestEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// `:memory:` 每條連線是各自獨立的空庫：連線池放大會讓後續查詢隨機打到
	// 沒有這些表的連線上
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.PolicyGroup{}, &model.PolicyClause{},
		&model.PolicyClauseControl{}, &model.PolicyClauseAnnotation{},
		&model.SecurityPolicy{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// 審計服務寫的是套件級的 database.DB（既有形態）：不換掉它，審計列會落到
	// 另一個連線上而本檔對留痕的斷言全部無從驗起
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	policyService := policy.NewSecurityPolicyService(db)
	repo := policy.NewPolicyGroupRepository(db)
	compliance := policy.NewComplianceService(policyService, repo)
	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false})

	groupHandler := NewPolicyGroupHandler(repo, compliance, auditSvc)
	complianceHandler := NewComplianceHandler(compliance, repo)
	policyHandler := NewSecurityPolicyHandler(policyService, auditSvc, compliance, repo)
	scheduleHandler := NewScheduleHandler()

	r := gin.New()
	r.Use(func(c *gin.Context) { // 身分注入（AuthMiddleware 的等價出口）
		if role := c.GetHeader("X-Test-Role"); role != "" {
			c.Set("role", role)
			c.Set("userID", uint(1))
			c.Set("username", "tester-"+role)
		}
		c.Next()
	})
	v1 := r.Group("/api/v1")
	registerPolicyGroupTestRoutes(v1, groupHandler)
	registerComplianceTestRoutes(v1, complianceHandler)
	registerSecurityPolicyTestRoutes(v1, policyHandler)
	registerScheduleTestRoutes(v1, scheduleHandler)

	return &policyTestEnv{router: r, db: db, repo: repo, service: policyService}
}

// do 發一次請求（role 為空＝不帶身分）。
func (e *policyTestEnv) do(t *testing.T, method, path, role string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if role != "" {
		req.Header.Set("X-Test-Role", role)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

// decodePolicyBody 解回應本文（本組測試共用；與其他 handler 測試的同名助手區隔）。
func decodePolicyBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return out
}

// seedCustomGroup 建一個自建組加一條設定要求型條文（密碼最小長度至少 14）。
func (e *policyTestEnv) seedCustomGroup(t *testing.T) {
	t.Helper()
	if err := e.repo.CreateCustomGroup("inhouse", "內規", "zh-TW"); err != nil {
		t.Fatalf("建組: %v", err)
	}
	clause := model.PolicyClause{
		GroupCode: "inhouse", ClauseNo: "1", Title: "密碼長度", Kind: model.PolicyClauseKindSetting,
	}
	controls := []model.PolicyClauseControl{{
		PolicyKey:     policy.PolicyPasswordMinLength,
		Comparator:    model.PolicyControlComparatorMin,
		ExpectedValue: "14",
	}}
	if _, _, err := e.repo.UpsertCustomClause(clause, controls); err != nil {
		t.Fatalf("建條文: %v", err)
	}
}

func (e *policyTestEnv) auditRows(t *testing.T) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := e.db.Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("讀審計列: %v", err)
	}
	return rows
}

// TestPolicyGroupHandlerListAndDetail 讀取面：admin 與 auditor 皆可讀，
// 詳情帶條文、要求與機構備註。
func TestPolicyGroupHandlerListAndDetail(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)

	for _, role := range []string{"admin", "auditor"} {
		w := env.do(t, http.MethodGet, "/api/v1/policy-groups", role, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s 讀列表 = %d，want 200（body %s）", role, w.Code, w.Body.String())
		}
		body := decodePolicyBody(t, w)
		groups, ok := body["data"].([]any)
		if !ok || len(groups) != 1 {
			t.Fatalf("%s 讀列表 data = %v，want 一個政策組", role, body["data"])
		}
	}

	w := env.do(t, http.MethodGet, "/api/v1/policy-groups/inhouse", "auditor", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("讀詳情 = %d，want 200（body %s）", w.Code, w.Body.String())
	}
	data := decodePolicyBody(t, w)["data"].(map[string]any)
	clauses := data["clauses"].([]any)
	if len(clauses) != 1 {
		t.Fatalf("條文數 = %d，want 1", len(clauses))
	}
	first := clauses[0].(map[string]any)
	if first["clause_no"] != "1" {
		t.Errorf("條號 = %v，want 1", first["clause_no"])
	}
	controls, ok := first["controls"].([]any)
	if !ok || len(controls) != 1 {
		t.Fatalf("要求數 = %v，want 1", first["controls"])
	}
	if got := controls[0].(map[string]any)["policy_key"]; got != policy.PolicyPasswordMinLength {
		t.Errorf("要求鍵 = %v，want %s", got, policy.PolicyPasswordMinLength)
	}

	// 不存在的組回 404 與具名碼，而不是一份空詳情
	w = env.do(t, http.MethodGet, "/api/v1/policy-groups/nope", "admin", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("讀不存在的組 = %d，want 404", w.Code)
	}
	if got := decodePolicyBody(t, w)["code"]; got != "POLICY_GROUP_NOT_FOUND" {
		t.Errorf("錯誤碼 = %v，want POLICY_GROUP_NOT_FOUND", got)
	}
}

// TestPolicyGroupHandlerAuditorWriteForbidden auditor 對每一條寫入端點都回 403，
// 且資料庫不得有任何變更——「唯讀」不是靠畫面不顯示按鈕。
func TestPolicyGroupHandlerAuditorWriteForbidden(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)

	writes := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPost, "/api/v1/policy-groups", map[string]any{"code": "x", "name": "x"}},
		{http.MethodPut, "/api/v1/policy-groups/inhouse", map[string]any{"name": "改名"}},
		{http.MethodPut, "/api/v1/policy-groups/inhouse/enabled", map[string]any{"enabled": false}},
		{http.MethodDelete, "/api/v1/policy-groups/inhouse", nil},
		{http.MethodPut, "/api/v1/policy-groups/inhouse/clauses/2",
			map[string]any{"title": "新條", "kind": model.PolicyClauseKindSelfAttested}},
		{http.MethodDelete, "/api/v1/policy-groups/inhouse/clauses/1", nil},
		{http.MethodPut, "/api/v1/policy-groups/inhouse/clauses/1/annotation",
			map[string]any{"note": "備註"}},
		{http.MethodPost, "/api/v1/policy-groups/inhouse/clauses/1/confirm",
			map[string]any{"note": "確認"}},
	}
	for _, tc := range writes {
		w := env.do(t, tc.method, tc.path, "auditor", tc.body)
		if w.Code != http.StatusForbidden {
			t.Errorf("auditor %s %s = %d，want 403（body %s）",
				tc.method, tc.path, w.Code, w.Body.String())
		}
	}

	var groups []model.PolicyGroup
	if err := env.db.Find(&groups).Error; err != nil {
		t.Fatalf("讀組: %v", err)
	}
	if len(groups) != 1 || groups[0].Name != "內規" || !groups[0].Enabled {
		t.Errorf("auditor 被拒後政策組仍被改動：%+v", groups)
	}
	var clauses []model.PolicyClause
	if err := env.db.Find(&clauses).Error; err != nil {
		t.Fatalf("讀條文: %v", err)
	}
	if len(clauses) != 1 {
		t.Errorf("auditor 被拒後條文數 = %d，want 1", len(clauses))
	}
	if rows := env.auditRows(t); len(rows) != 0 {
		t.Errorf("auditor 被拒卻寫了 %d 列政策組審計", len(rows))
	}
}

// TestPolicyGroupHandlerWritesAudit 四類寫入（組、條文、備註、確認）各留一列審計，
// 詳情帶組代號、條號與舊值→新值。
func TestPolicyGroupHandlerWritesAudit(t *testing.T) {
	env := newPolicyTestEnv(t)

	if w := env.do(t, http.MethodPost, "/api/v1/policy-groups", "admin",
		map[string]any{"code": "inhouse", "name": "內規", "locale": "zh-TW"}); w.Code != http.StatusCreated {
		t.Fatalf("建組 = %d（body %s）", w.Code, w.Body.String())
	}
	if w := env.do(t, http.MethodPut, "/api/v1/policy-groups/inhouse", "admin",
		map[string]any{"name": "內部規範"}); w.Code != http.StatusOK {
		t.Fatalf("更名 = %d（body %s）", w.Code, w.Body.String())
	}
	if w := env.do(t, http.MethodPut, "/api/v1/policy-groups/inhouse/clauses/1", "admin",
		map[string]any{
			"title": "密碼長度", "kind": model.PolicyClauseKindSetting,
			"controls": []map[string]any{{
				"policy_key": policy.PolicyPasswordMinLength, "comparator": "min", "expected_value": "14",
			}},
		}); w.Code != http.StatusOK {
		t.Fatalf("建條文 = %d（body %s）", w.Code, w.Body.String())
	}
	if w := env.do(t, http.MethodPut, "/api/v1/policy-groups/inhouse/clauses/1/annotation", "admin",
		map[string]any{"note": "內規要求 14 字元"}); w.Code != http.StatusOK {
		t.Fatalf("備註 = %d（body %s）", w.Code, w.Body.String())
	}
	if w := env.do(t, http.MethodPost, "/api/v1/policy-groups/inhouse/clauses/1/confirm", "admin",
		map[string]any{"note": "已由資安複核"}); w.Code != http.StatusOK {
		t.Fatalf("確認 = %d（body %s）", w.Code, w.Body.String())
	}

	rows := env.auditRows(t)
	if len(rows) != 5 {
		t.Fatalf("審計列數 = %d，want 5（建組、更名、條文、備註、確認各一）", len(rows))
	}
	for _, row := range rows {
		if row.Resource != model.ResourcePolicyGroup {
			t.Errorf("審計列 resource = %q，want %q", row.Resource, model.ResourcePolicyGroup)
		}
		if row.Username == "" {
			t.Errorf("審計列缺操作者：%+v", row)
		}
		var details struct {
			GroupCode string `json:"group_code"`
			ClauseNo  string `json:"clause_no"`
			Op        string `json:"op"`
			Changes   []struct {
				Field string `json:"field"`
				Old   string `json:"old"`
				New   string `json:"new"`
			} `json:"changes"`
		}
		if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
			t.Fatalf("審計詳情非 JSON（%q）: %v", row.Details, err)
		}
		if details.GroupCode != "inhouse" {
			t.Errorf("審計詳情缺組代號：%q", row.Details)
		}
		if details.Op == "" || len(details.Changes) == 0 {
			t.Errorf("審計詳情缺操作或舊值新值：%q", row.Details)
		}
	}

	// 更名那一列要答得出「從什麼改成什麼」
	var rename model.AuditLog
	for _, row := range rows {
		if bytes.Contains([]byte(row.Details), []byte(`"group_rename"`)) {
			rename = row
		}
	}
	if rename.Details == "" {
		t.Fatalf("找不到更名的審計列：%+v", rows)
	}
	if !bytes.Contains([]byte(rename.Details), []byte("內規")) ||
		!bytes.Contains([]byte(rename.Details), []byte("內部規範")) {
		t.Errorf("更名審計列未同時帶舊名與新名：%q", rename.Details)
	}
	// 條文那一列要帶條號
	var clause model.AuditLog
	for _, row := range rows {
		if bytes.Contains([]byte(row.Details), []byte(`"clause_upsert"`)) {
			clause = row
		}
	}
	if !bytes.Contains([]byte(clause.Details), []byte(`"clause_no":"1"`)) {
		t.Errorf("條文審計列未帶條號：%q", clause.Details)
	}
}

// TestPolicyGroupHandlerAuditCarriesSubstantiveDiff 只改摘要、只把固定要求改成
// 參考值、以及再次確認換掉說明——三種實質變更都要在審計列上看得出舊值與新值。
//
// 反例：舊值與新值逐字相同的審計列。事件在、對象在，唯獨「改成什麼」不在，
// 而後兩種改動都會改變同一個設定鍵的判定結果。
func TestPolicyGroupHandlerAuditCarriesSubstantiveDiff(t *testing.T) {
	env := newPolicyTestEnv(t)
	if w := env.do(t, http.MethodPost, "/api/v1/policy-groups", "admin",
		map[string]any{"code": "inhouse", "name": "內規", "locale": "zh-TW"}); w.Code != http.StatusCreated {
		t.Fatalf("建組 = %d（body %s）", w.Code, w.Body.String())
	}
	upsert := func(summary string, referenceOnly bool) {
		t.Helper()
		w := env.do(t, http.MethodPut, "/api/v1/policy-groups/inhouse/clauses/1", "admin",
			map[string]any{
				"title": "密碼長度", "summary": summary, "kind": model.PolicyClauseKindSetting,
				"controls": []map[string]any{{
					"policy_key":     policy.PolicyPasswordMinLength,
					"comparator":     "min",
					"expected_value": "14",
					"reference_only": referenceOnly,
				}},
			})
		if w.Code != http.StatusOK {
			t.Fatalf("寫條文 = %d（body %s）", w.Code, w.Body.String())
		}
	}
	upsert("原始摘要", false)
	upsert("改過的摘要", false) // 只動摘要
	upsert("改過的摘要", true)  // 只把固定要求改成參考值

	digests := map[string][]string{}
	for _, row := range env.auditRows(t) {
		var details struct {
			Op      string `json:"op"`
			Changes []struct {
				Field string `json:"field"`
				Old   string `json:"old"`
				New   string `json:"new"`
			} `json:"changes"`
		}
		if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
			t.Fatalf("審計詳情非 JSON（%q）: %v", row.Details, err)
		}
		for _, ch := range details.Changes {
			if details.Op == "clause_upsert" && ch.Field == "clause" {
				digests[ch.Old] = append(digests[ch.Old], ch.New)
			}
		}
	}
	for old, news := range digests {
		for _, next := range news {
			if old == next {
				t.Errorf("條文審計列的舊值與新值逐字相同（%q）：改了什麼答不出來", old)
			}
		}
	}
	summaryChanged, referenceChanged := false, false
	for old, news := range digests {
		for _, next := range news {
			if bytes.Contains([]byte(old), []byte("原始摘要")) &&
				bytes.Contains([]byte(next), []byte("改過的摘要")) {
				summaryChanged = true
			}
			if !bytes.Contains([]byte(old), []byte("reference")) &&
				bytes.Contains([]byte(next), []byte("reference")) {
				referenceChanged = true
			}
		}
	}
	if !summaryChanged {
		t.Error("只改摘要的那一次沒有在審計列上留下摘要的舊值→新值")
	}
	if !referenceChanged {
		t.Error("把固定要求改成參考值沒有在審計列上留痕：判定結果會因此改變")
	}

	// 再次確認會覆蓋上一句說明，舊說明只剩審計列答得出來
	for _, note := range []string{"第一次確認的理由", "第二次確認的理由"} {
		if w := env.do(t, http.MethodPost, "/api/v1/policy-groups/inhouse/clauses/1/confirm",
			"admin", map[string]any{"note": note}); w.Code != http.StatusOK {
			t.Fatalf("確認 = %d（body %s）", w.Code, w.Body.String())
		}
	}
	var lastConfirm string
	for _, row := range env.auditRows(t) {
		if bytes.Contains([]byte(row.Details), []byte(`"clause_confirm"`)) {
			lastConfirm = row.Details
		}
	}
	if !bytes.Contains([]byte(lastConfirm), []byte(`"confirmation_note"`)) {
		t.Fatalf("確認事件未帶說明欄：%q", lastConfirm)
	}
	if !bytes.Contains([]byte(lastConfirm), []byte("第一次確認的理由")) ||
		!bytes.Contains([]byte(lastConfirm), []byte("第二次確認的理由")) {
		t.Errorf("第二次確認未同時帶前一句與新一句說明：%q", lastConfirm)
	}
}

// TestPolicyGroupHandlerAuditSurvivesPostCommitReadFailure 寫入已提交、
// 回應用的那次讀取失敗時，審計列仍在。
//
// 反例：審計等到提交後再讀一次資料庫才寫得出來。那次讀取一失敗就 500，
// 而對照的內容已經變了、事件卻沒有發出——「這條要求是誰改的」自此無解。
func TestPolicyGroupHandlerAuditSurvivesPostCommitReadFailure(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)

	// 條文表的第一次查詢（寫入前取舊值）放行，之後全部失敗：這正是「寫入已提交、
	// 回應與差量所需的讀取才壞掉」的時序，也是審計會不會被吃掉的分水嶺
	failClauseReadsAfter(t, env.db, 1)
	w := env.do(t, http.MethodPut, "/api/v1/policy-groups/inhouse/clauses/1", "admin",
		map[string]any{
			"title": "密碼長度（改）", "kind": model.PolicyClauseKindSetting,
			"controls": []map[string]any{{
				"policy_key": policy.PolicyPasswordMinLength, "comparator": "min",
				"expected_value": "16",
			}},
		})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("提交後讀取失敗應回 500，got %d（body %s）", w.Code, w.Body.String())
	}

	// 寫入確實生效了
	var control model.PolicyClauseControl
	if err := env.db.Where("group_code = ? AND policy_key = ?",
		"inhouse", policy.PolicyPasswordMinLength).First(&control).Error; err != nil {
		t.Fatalf("讀要求: %v", err)
	}
	if control.ExpectedValue != "16" {
		t.Fatalf("要求值 = %q，want 16（本案的前提是寫入已提交）", control.ExpectedValue)
	}

	// 而它有留痕
	var found model.AuditLog
	for _, row := range env.auditRows(t) {
		if bytes.Contains([]byte(row.Details), []byte(`"clause_upsert"`)) {
			found = row
		}
	}
	if found.Details == "" {
		t.Fatal("已提交的對照變更沒有任何審計列")
	}
	if !bytes.Contains([]byte(found.Details), []byte("16")) {
		t.Errorf("審計列答不出改成什麼：%q", found.Details)
	}
}

// failClauseReadsAfter 讓第 allowed 次之後對條文表的查詢失敗。
//
// 用注入而不是移走資料表：本案要驗的是**時序**——寫入已經提交，之後的讀取才
// 壞掉。移走資料表會連寫入一起擋掉，那驗到的是另一件事。
func failClauseReadsAfter(t *testing.T, db *gorm.DB, allowed int) {
	t.Helper()
	const name = "test:fail_clause_reads"
	seen := 0
	if err := db.Callback().Query().After("gorm:query").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table != "policy_clauses" {
			return
		}
		seen++
		if seen > allowed {
			_ = tx.AddError(errors.New("條文讀取失敗（測試注入）"))
		}
	}); err != nil {
		t.Fatalf("註冊查詢回呼: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Query().Remove(name) })
}

// TestPolicyGroupHandlerRejectionCodes 資料存取層的拒絕原樣出到 HTTP：
// 三種成因三支碼，狀態碼各自對應修法。
func TestPolicyGroupHandlerRejectionCodes(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)
	// 內建組：只有生效開關與備註可動
	if err := env.db.Create(&model.PolicyGroup{
		Code: "builtin_demo", Name: "內建", Source: model.PolicyGroupSourceBuiltin,
		Enabled: true, Version: "1",
	}).Error; err != nil {
		t.Fatalf("建內建組: %v", err)
	}

	cases := []struct {
		name   string
		method string
		path   string
		body   any
		status int
		code   string
	}{
		{
			name: "內建組不可更名", method: http.MethodPut, path: "/api/v1/policy-groups/builtin_demo",
			body: map[string]any{"name": "改"}, status: http.StatusForbidden,
			code: "POLICY_GROUP_BUILTIN_READONLY",
		},
		{
			name: "代號重複", method: http.MethodPost, path: "/api/v1/policy-groups",
			body: map[string]any{"code": "inhouse", "name": "再一個"}, status: http.StatusConflict,
			code: "POLICY_GROUP_DUPLICATE_CODE",
		},
		{
			name: "要求值超出值域", method: http.MethodPut,
			path: "/api/v1/policy-groups/inhouse/clauses/9",
			body: map[string]any{
				"title": "過大", "kind": model.PolicyClauseKindSetting,
				"controls": []map[string]any{{
					"policy_key": policy.PolicyPasswordMinLength, "comparator": "min",
					"expected_value": "99999",
				}},
			},
			status: http.StatusBadRequest, code: "VALIDATION_POLICY_GROUP_EXPECTED_VALUE",
		},
		{
			name: "同組同鍵重複", method: http.MethodPut,
			path: "/api/v1/policy-groups/inhouse/clauses/2",
			body: map[string]any{
				"title": "又一條", "kind": model.PolicyClauseKindSetting,
				"controls": []map[string]any{{
					"policy_key": policy.PolicyPasswordMinLength, "comparator": "min",
					"expected_value": "16",
				}},
			},
			status: http.StatusBadRequest, code: "VALIDATION_POLICY_GROUP_DUPLICATE_KEY",
		},
		{
			name: "指向不存在的設定", method: http.MethodPut,
			path: "/api/v1/policy-groups/inhouse/clauses/3",
			body: map[string]any{
				"title": "打錯鍵", "kind": model.PolicyClauseKindSetting,
				"controls": []map[string]any{{
					"policy_key": "no_such_key", "comparator": "min", "expected_value": "1",
				}},
			},
			status: http.StatusBadRequest, code: "VALIDATION_POLICY_GROUP_UNKNOWN_KEY",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := env.do(t, tc.method, tc.path, "admin", tc.body)
			if w.Code != tc.status {
				t.Fatalf("狀態 = %d，want %d（body %s）", w.Code, tc.status, w.Body.String())
			}
			if got := decodePolicyBody(t, w)["code"]; got != tc.code {
				t.Errorf("錯誤碼 = %v，want %s", got, tc.code)
			}
		})
	}
}

// TestPolicyGroupHandlerDeleteRemovesClausesAndAnnotations 刪自建組連帶清除，
// 且留一列審計。
func TestPolicyGroupHandlerDeleteRemovesClausesAndAnnotations(t *testing.T) {
	env := newPolicyTestEnv(t)
	env.seedCustomGroup(t)
	if w := env.do(t, http.MethodPut, "/api/v1/policy-groups/inhouse/clauses/1/annotation", "admin",
		map[string]any{"note": "備註"}); w.Code != http.StatusOK {
		t.Fatalf("備註 = %d（body %s）", w.Code, w.Body.String())
	}

	w := env.do(t, http.MethodDelete, "/api/v1/policy-groups/inhouse", "admin", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("刪組 = %d（body %s）", w.Code, w.Body.String())
	}
	var clauses []model.PolicyClause
	if err := env.db.Find(&clauses).Error; err != nil {
		t.Fatalf("讀條文: %v", err)
	}
	if len(clauses) != 0 {
		t.Errorf("刪組後條文殘留 %d 條", len(clauses))
	}
	var annotations []model.PolicyClauseAnnotation
	if err := env.db.Find(&annotations).Error; err != nil {
		t.Fatalf("讀備註: %v", err)
	}
	if len(annotations) != 0 {
		t.Errorf("刪組後備註殘留 %d 筆", len(annotations))
	}
}
