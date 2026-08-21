package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 檢查點 API 與 RBAC（audit-checkpoint-chain tasks 8.1／8.2／8.5）。
//
// **三支端點都是唯讀且對 auditor 開放**（D-3）；設定寫入端點維持 admin only。
// 兩個方向都測：只測「auditor 可讀」會漏掉「auditor 也能改設定」這種擴權。

// fakeCheckpointSigner 測試用 Ed25519 簽章器（同時充當公鑰出口）
type fakeCheckpointSigner struct {
	priv ed25519.PrivateKey
}

func newFakeCheckpointSigner(t *testing.T) *fakeCheckpointSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成簽章鑰: %v", err)
	}
	return &fakeCheckpointSigner{priv: priv}
}

func (s *fakeCheckpointSigner) ActiveVersion() int { return 1 }

func (s *fakeCheckpointSigner) Sign(data []byte) (int, string) {
	return 1, base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, data))
}

func (s *fakeCheckpointSigner) Verify(version int, data []byte, sigBase64 string) (bool, error) {
	if version != 1 {
		return false, nil
	}
	sig, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(s.priv.Public().(ed25519.PublicKey), data, sig), nil
}

func (s *fakeCheckpointSigner) ActivePublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.priv.Public().(ed25519.PublicKey))
}

func (s *fakeCheckpointSigner) PublicKeyFingerprint(version int) (string, error) {
	sum := sha256.Sum256(s.priv.Public().(ed25519.PublicKey))
	return hex.EncodeToString(sum[:8]), nil
}

// setupCheckpointAPIEnv 經完整 RegisterRoutes（真 AuthMiddleware＋真 JWT＋真 sqlite）
// 的檢查點路由環境，另註冊安全政策路由充當「設定寫入端點」的對照
func setupCheckpointAPIEnv(t *testing.T) (*gin.Engine, *crypto.JWTManager, *gorm.DB, *audit.CheckpointService) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.AuditLog{}, &model.AuditCheckpoint{},
		&model.AuditCheckpointTrim{}, &model.IntegrityBaseline{}, &model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Create(&model.IntegrityBaseline{
		ID: 1, BaselineAt: time.Now().Add(-time.Hour), MaxLogID: 0}).Error; err != nil {
		t.Fatalf("baseline: %v", err)
	}

	// AuthMiddleware 的憑證世代閘走 database.DB（fail-close），不注入則全數 401
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	for id, r := range map[uint]string{1: "admin", 2: "normaluser", 3: "auditor1", 4: "multirole"} {
		u := &model.User{Username: r, Password: "x", Active: true}
		u.ID = id
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("user: %v", err)
		}
	}

	signer := newFakeCheckpointSigner(t)
	seal := audit.NewCheckpointService(db, signer, nil, nil)
	if err := seal.EnsureGenesis(); err != nil {
		t.Fatalf("genesis: %v", err)
	}
	purger := audit.NewCheckpointPurger(db, signer)
	verifier := audit.NewCheckpointVerifier(db, seal, purger, nil, nil)

	jwtSecret := "checkpoint-api-secret"
	authService := identity.NewAuthService(jwtSecret, time.Minute)

	r := gin.New()
	group := r.Group("/api/v1")
	// signing 欄位以 fake 注入（建構子只吃具體型別；本測不需要真的 keyvault）
	h := &AuditCheckpointHandler{verifier: verifier, signing: signer}
	h.RegisterRoutes(group, authService)
	NewSecurityPolicyHandler(policy.NewSecurityPolicyService(db), nil).RegisterRoutes(group, authService)

	return r, crypto.NewJWTManager(jwtSecret, time.Minute), db, seal
}

func cpReq(t *testing.T, r *gin.Engine, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	rd := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rd, req)
	return rd
}

// tokenFor 依角色簽一張 JWT（角色為單一字串：primaryRoleOf 已在登入時
// 把多角色收斂為最高階，故「多角色帳號以較高角色為準」在此層即為 auditor）
func tokenFor(t *testing.T, mgr *crypto.JWTManager, id uint, name, role string) string {
	t.Helper()
	tok, err := mgr.GenerateToken(id, name, name+"@t.local", role, crypto.AuthContext{})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	return tok
}

// TestAuditCheckpointHandler 三支端點的回應骨架（8.1）
func TestAuditCheckpointHandler(t *testing.T) {
	r, mgr, db, seal := setupCheckpointAPIEnv(t)
	admin := tokenFor(t, mgr, 1, "admin", model.RoleAdmin)

	// 造一個有列的區間
	for i := 0; i < 3; i++ {
		row := model.AuditLog{Username: "u", Action: model.ActionExecute,
			Resource: model.ResourceAuditLog, Status: model.StatusSuccess,
			CreatedAt: time.Now(), KeyVersion: 1, IntegrityHMAC: "aa"}
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	cp, err := seal.SealNow()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	t.Run("列表", func(t *testing.T) {
		w := cpReq(t, r, http.MethodGet, "/api/v1/audit-checkpoints", admin, "")
		if w.Code != http.StatusOK {
			t.Fatalf("狀態碼 = %d, body=%s", w.Code, w.Body.String())
		}
		var resp struct {
			Data struct {
				Items []map[string]any `json:"items"`
				Total int64            `json:"total"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("解析: %v", err)
		}
		if resp.Data.Total != 2 || len(resp.Data.Items) != 2 {
			t.Fatalf("total=%d items=%d, want 2/2", resp.Data.Total, len(resp.Data.Items))
		}
		// seq 倒序＋狀態欄齊備
		if resp.Data.Items[0]["seq"].(float64) != float64(cp.Seq) {
			t.Errorf("首項 seq = %v, want %d（seq 倒序）", resp.Data.Items[0]["seq"], cp.Seq)
		}
		for _, k := range []string{"anchor_status", "agg_hash", "signature", "id_from", "id_to"} {
			if _, ok := resp.Data.Items[0][k]; !ok {
				t.Errorf("列表項缺欄位 %s", k)
			}
		}
		t.Logf("列表骨架: %v", resp.Data.Items[0])
	})

	t.Run("結構層驗證（不帶範圍）", func(t *testing.T) {
		w := cpReq(t, r, http.MethodGet, "/api/v1/audit-checkpoints/verify", admin, "")
		if w.Code != http.StatusOK {
			t.Fatalf("狀態碼 = %d, body=%s", w.Code, w.Body.String())
		}
		var resp struct {
			Data struct {
				Chain   map[string]any `json:"chain"`
				Content map[string]any `json:"content"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("解析: %v", err)
		}
		if resp.Data.Content != nil {
			t.Error("不帶範圍時不得回內容層（那會啟動 audit_logs 全掃）")
		}
		if resp.Data.Chain["status"] != "passed" {
			t.Fatalf("鏈狀態 = %v, want passed", resp.Data.Chain["status"])
		}
		for _, k := range []string{"total", "latest_seq", "unsealed_rows", "anchor_disabled",
			"seal_interval_seconds", "seal_row_threshold"} {
			if _, ok := resp.Data.Chain[k]; !ok {
				t.Errorf("結構層報告缺欄位 %s", k)
			}
		}
		t.Logf("結構層骨架: %v", resp.Data.Chain)
	})

	t.Run("內容層（帶 seq 範圍）", func(t *testing.T) {
		w := cpReq(t, r, http.MethodGet,
			"/api/v1/audit-checkpoints/verify?seq_from=1&seq_to=2", admin, "")
		if w.Code != http.StatusOK {
			t.Fatalf("狀態碼 = %d, body=%s", w.Code, w.Body.String())
		}
		var resp struct {
			Data struct {
				Content struct {
					Intervals    []map[string]any  `json:"intervals"`
					StatusCounts map[string]int64  `json:"status_counts"`
				} `json:"content"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("解析: %v", err)
		}
		if len(resp.Data.Content.Intervals) != 2 {
			t.Fatalf("區間數 = %d, want 2", len(resp.Data.Content.Intervals))
		}
		if resp.Data.Content.StatusCounts["passed"] != 2 {
			t.Fatalf("status_counts = %v, want passed:2", resp.Data.Content.StatusCounts)
		}
	})

	t.Run("公鑰", func(t *testing.T) {
		w := cpReq(t, r, http.MethodGet, "/api/v1/audit-checkpoints/public-key", admin, "")
		if w.Code != http.StatusOK {
			t.Fatalf("狀態碼 = %d, body=%s", w.Code, w.Body.String())
		}
		var resp struct {
			Data struct {
				Algorithm   string `json:"algorithm"`
				Version     int    `json:"version"`
				PublicKey   string `json:"public_key"`
				Fingerprint string `json:"fingerprint"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("解析: %v", err)
		}
		if resp.Data.Algorithm != "Ed25519" || resp.Data.Version != 1 {
			t.Fatalf("骨架不符: %+v", resp.Data)
		}
		raw, err := base64.StdEncoding.DecodeString(resp.Data.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			t.Fatalf("公鑰非 32 byte Ed25519: err=%v len=%d", err, len(raw))
		}
		if len(resp.Data.Fingerprint) != 16 {
			t.Errorf("指紋 = %q，want hex(SHA-256[:8])＝16 字元", resp.Data.Fingerprint)
		}
		// **公鑰端點不得洩漏私鑰材料**（body 全文掃描）
		if body := w.Body.String(); len(body) > 0 {
			for _, banned := range []string{"private", "priv_key", "seed"} {
				if strings.Contains(strings.ToLower(body), banned) {
					t.Errorf("回應含疑似私鑰欄位 %q", banned)
				}
			}
		}
	})
}

// TestCheckpointContentLayerRejectsNoRange 內容層不帶範圍即拒（8.2）。
//
// 另斷言耗時：拒絕必須發生在任何 audit_logs 掃描之前
func TestCheckpointContentLayerRejectsNoRange(t *testing.T) {
	r, mgr, db, seal := setupCheckpointAPIEnv(t)
	admin := tokenFor(t, mgr, 1, "admin", model.RoleAdmin)
	// 造 2000 列讓「真的掃了」在耗時上可辨識
	rows := make([]model.AuditLog, 0, 2000)
	for i := 0; i < 2000; i++ {
		rows = append(rows, model.AuditLog{Username: "u", Action: model.ActionExecute,
			Resource: model.ResourceAuditLog, Status: model.StatusSuccess,
			CreatedAt: time.Now(), KeyVersion: 1, IntegrityHMAC: "aa"})
	}
	if err := db.CreateInBatches(rows, 200).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := seal.SealNow(); err != nil {
		t.Fatalf("seal: %v", err)
	}

	start := time.Now()
	w := cpReq(t, r, http.MethodGet, "/api/v1/audit-checkpoints/verify?content=true", admin, "")
	elapsed := time.Since(start)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("狀態碼 = %d, want 400（body=%s）", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析: %v", err)
	}
	if resp["code"] != "VALIDATION_CHECKPOINT_RANGE_REQUIRED" {
		t.Fatalf("機器碼 = %v, want VALIDATION_CHECKPOINT_RANGE_REQUIRED", resp["code"])
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("耗時 %v > 100ms：疑似已啟動 audit_logs 掃描", elapsed)
	}
	t.Logf("8.2 拒絕耗時 %v，機器碼 %v", elapsed, resp["code"])

	// 格式錯誤走另一碼（seq 非正整數）
	w = cpReq(t, r, http.MethodGet, "/api/v1/audit-checkpoints/verify?seq_from=abc&seq_to=2", admin, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("狀態碼 = %d, want 400", w.Code)
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "VALIDATION_CHECKPOINT_RANGE_FORMAT" {
		t.Fatalf("機器碼 = %v, want VALIDATION_CHECKPOINT_RANGE_FORMAT", resp["code"])
	}
}

// TestCheckpointRBACMatrix 三角色 × 四端點（8.5）。
//
// 第四支端點是**設定寫入**（PUT /security-policies）：只測讀取端點的話，
// 「auditor 可驗」與「auditor 不可改」只證了一半
func TestCheckpointRBACMatrix(t *testing.T) {
	r, mgr, _, _ := setupCheckpointAPIEnv(t)

	identities := []struct {
		name  string
		token string
	}{
		{"admin", tokenFor(t, mgr, 1, "admin", model.RoleAdmin)},
		{"auditor", tokenFor(t, mgr, 3, "auditor1", model.RoleAuditor)},
		{"user", tokenFor(t, mgr, 2, "normaluser", model.RoleUser)},
		// 多角色帳號：登入時 primaryRoleOf 取三階中最高者，故 JWT 帶 auditor
		{"user+auditor", tokenFor(t, mgr, 4, "multirole", model.RoleAuditor)},
	}
	endpoints := []struct {
		name   string
		method string
		path   string
		body   string
		want   map[string]int
	}{
		{"列表", http.MethodGet, "/api/v1/audit-checkpoints", "", map[string]int{
			"admin": 200, "auditor": 200, "user": 403, "user+auditor": 200}},
		{"驗證", http.MethodGet, "/api/v1/audit-checkpoints/verify", "", map[string]int{
			"admin": 200, "auditor": 200, "user": 403, "user+auditor": 200}},
		{"公鑰", http.MethodGet, "/api/v1/audit-checkpoints/public-key", "", map[string]int{
			"admin": 200, "auditor": 200, "user": 403, "user+auditor": 200}},
		{"設定寫入", http.MethodPut, "/api/v1/security-policies",
			`{"policies":{"retention_checkpoint_days":"3650"}}`, map[string]int{
				"admin": 400, "auditor": 403, "user": 403, "user+auditor": 403}},
	}

	for _, ep := range endpoints {
		for _, id := range identities {
			w := cpReq(t, r, ep.method, ep.path, id.token, ep.body)
			want := ep.want[id.name]
			// 設定寫入的 admin 期望值是「非 403」：出廠 audit_logs 保留為 0（永久），
			// 跨鍵約束會以 400 拒絕該組合——重點在**它不是授權失敗**
			if ep.name == "設定寫入" && id.name == "admin" {
				if w.Code == http.StatusForbidden {
					t.Errorf("[%s/%s] admin 不該被授權擋下（得 403）", ep.name, id.name)
				}
				continue
			}
			if w.Code != want {
				t.Errorf("[%s/%s] 狀態碼 = %d, want %d（body=%s）",
					ep.name, id.name, w.Code, want, w.Body.String())
			}
		}
	}

	// 未帶 token：一律 401（授權之前先認證）
	for _, ep := range endpoints {
		w := cpReq(t, r, ep.method, ep.path, "", ep.body)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("[%s] 匿名狀態碼 = %d, want 401", ep.name, w.Code)
		}
	}
}

// TestAuditIntegrityOpenToAuditor 列級驗證端點一併開放 auditor（D-3）。
//
// **這條是 D-3 裁決的核心**：若 auditor 只能證序列（檢查點）而內容真偽仍須
// 請 admin 代驗，「被監督者代為出具監督證明」的角色錯配只解一半
func TestAuditIntegrityOpenToAuditor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.AuditLog{}, &model.IntegrityBaseline{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	for id, name := range map[uint]string{1: "admin", 2: "normaluser", 3: "auditor1"} {
		u := &model.User{Username: name, Password: "x", Active: true}
		u.ID = id
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("user: %v", err)
		}
	}
	jwtSecret := "integrity-role-secret"
	r := gin.New()
	group := r.Group("/api/v1")
	NewAuditIntegrityHandler(db, nil).RegisterRoutes(group, identity.NewAuthService(jwtSecret, time.Minute))
	mgr := crypto.NewJWTManager(jwtSecret, time.Minute)

	cases := map[string]struct {
		token string
		want  int
	}{
		"admin":   {tokenFor(t, mgr, 1, "admin", model.RoleAdmin), http.StatusInternalServerError},
		"auditor": {tokenFor(t, mgr, 3, "auditor1", model.RoleAuditor), http.StatusInternalServerError},
		"user":    {tokenFor(t, mgr, 2, "normaluser", model.RoleUser), http.StatusForbidden},
	}
	// 註：integrity 服務注入 nil，故通過授權者會走到 500（handler 內部）——
	// 本測只判「授權有沒有擋住」，500 即代表已越過授權進入 handler
	for name, c := range cases {
		w := cpReq(t, r, http.MethodGet, "/api/v1/audit-integrity/verify", c.token, "")
		if name == "user" {
			if w.Code != http.StatusForbidden {
				t.Errorf("user 狀態碼 = %d, want 403", w.Code)
			}
			continue
		}
		if w.Code == http.StatusForbidden {
			t.Errorf("%s 被授權擋下（403），D-3 要求開放", name)
		}
	}
}
