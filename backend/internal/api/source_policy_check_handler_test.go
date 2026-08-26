package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
)

// 判定端點：與強制點共用同一份實作，故以**同一份測試向量**逐條比對。
//
// 向量檔（`internal/sourceip/testdata/policy_vectors.json`）同時餵給 sourceip 的
// 單元測試、本端點測試與前端的格式提示測試——「兩套實作在已知輸入上一致」
// 是這個檔存在的全部理由。端點若自行推導 allowed／status，向量再多也擋不住分歧，
// 故本測試斷言的是回覆值，不是內部呼叫。

// checkVector 向量檔的一條（欄位子集，只取端點回覆得出來的）
type checkVector struct {
	Name       string   `json:"name"`
	List       []string `json:"list"`
	Address    string   `json:"address"`
	Valid      bool     `json:"valid"`
	Normalized []string `json:"normalized"`
	Allowed    bool     `json:"allowed"`
	Status     string   `json:"status"`
	Families   []string `json:"families"`
}

// loadCheckVectors 讀共用向量。**找不到即 Fatal 不 Skip**：
// 「向量沒跑」與「向量全過」必須可分辨
func loadCheckVectors(t *testing.T) []checkVector {
	t.Helper()
	path := filepath.Join("..", "sourceip", "testdata", "policy_vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀共用向量 %s 失敗: %v", path, err)
	}
	var out []checkVector
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("解析共用向量失敗: %v", err)
	}
	if len(out) < 20 {
		t.Fatalf("向量只有 %d 條（下限 20）：檔案被縮減即本測試射程歸零", len(out))
	}
	return out
}

// setupSourcePolicyCheckEnv 經完整 RegisterRoutes（真 AuthMiddleware＋真 RequireRole）
// 的環境：權限姿態與判定結果都要打到真鏈上
func setupSourcePolicyCheckEnv(t *testing.T, mws ...gin.HandlerFunc) (*gin.Engine, *crypto.JWTManager, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	for _, name := range []string{model.RoleAdmin, "user"} {
		if err := db.Create(&model.Role{Name: name}).Error; err != nil {
			t.Fatalf("建立角色 %s: %v", name, err)
		}
	}

	r := gin.New()
	// 選填的前置中介層必須掛在建 group **之前**：gin 的 group 只繼承建立當下
	// 已註冊的 handler 鏈，掛在後面對這條路由不生效（會安靜地什麼都沒攔到）
	for _, mw := range mws {
		r.Use(mw)
	}
	group := r.Group("/api/v1")
	NewUserHandler(identity.NewUserService(db, authz.NewAssetAuthorizationService(db))).
		RegisterRoutes(group, identity.NewAuthService("source-policy-check-secret", time.Minute))
	return r, crypto.NewJWTManager("source-policy-check-secret", time.Minute), db
}

// sourcePolicyTokenFor 建一個帶指定角色的帳號並發 token
func sourcePolicyTokenFor(t *testing.T, db *gorm.DB, jwt *crypto.JWTManager, username, roleName string) string {
	t.Helper()
	u := &model.User{Username: username, Password: "hashed", Active: true,
		ProvisioningOrigin: model.AuthSourceLocal}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("建立帳號: %v", err)
	}
	var role model.Role
	if err := db.Where("name = ?", roleName).First(&role).Error; err != nil {
		t.Fatalf("取角色: %v", err)
	}
	if err := db.Model(u).Association("Roles").Append(&role); err != nil {
		t.Fatalf("掛角色: %v", err)
	}
	tok, err := jwt.GenerateToken(u.ID, u.Username, username+"@example.com", roleName, crypto.AuthContext{})
	if err != nil {
		t.Fatalf("發 token: %v", err)
	}
	return tok
}

func postSourcePolicyCheck(t *testing.T, r *gin.Engine, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/source-policy/check", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestSourcePolicyCheckMatchesSharedVectors(t *testing.T) {
	r, jwt, db := setupSourcePolicyCheckEnv(t)
	token := sourcePolicyTokenFor(t, db, jwt, "vec-admin", model.RoleAdmin)

	for _, v := range loadCheckVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			w := postSourcePolicyCheck(t, r, token,
				SourcePolicyCheckRequest{AllowedCIDRs: v.List, Address: v.Address})
			if w.Code != http.StatusOK {
				t.Fatalf("狀態碼 = %d（body=%s）", w.Code, w.Body.String())
			}
			var got SourcePolicyCheckResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("回應非預期 JSON: %q", w.Body.String())
			}
			if got.Valid != v.Valid {
				t.Errorf("valid = %v, want %v", got.Valid, v.Valid)
			}
			if got.Allowed != v.Allowed {
				t.Errorf("allowed = %v, want %v（端點與強制點必須同一個 fail-close 判準）",
					got.Allowed, v.Allowed)
			}
			if !equalStrings(got.Normalized, v.Normalized) {
				t.Errorf("normalized = %v, want %v", got.Normalized, v.Normalized)
			}
			// status 只在清單合法時有定義（向量對不合法者寫空字串）
			if v.Valid && got.Status != v.Status {
				t.Errorf("status = %q, want %q", got.Status, v.Status)
			}
			if v.Valid && !equalStrings(got.Families, v.Families) {
				t.Errorf("families = %v, want %v", got.Families, v.Families)
			}
			// 逐項結果與輸入等長：介面要能把錯誤標回**該一項**
			if len(got.Items) != len(v.List) {
				t.Errorf("items 長度 = %d, want %d（逐項就近提示需要一一對應）",
					len(got.Items), len(v.List))
			}
		})
	}
}

// TestSourcePolicyCheckUsesRequestSourceWhenAddressOmitted address 省略時
// 以本請求來源判定——表單的自鎖預警走的正是這條，判錯的後果是
// 「介面說你還進得來」而下一次登入被擋在門外
func TestSourcePolicyCheckUsesRequestSourceWhenAddressOmitted(t *testing.T) {
	r, jwt, db := setupSourcePolicyCheckEnv(t)
	token := sourcePolicyTokenFor(t, db, jwt, "self-admin", model.RoleAdmin)

	// httptest 的預設 RemoteAddr 為 192.0.2.1:1234
	w := postSourcePolicyCheck(t, r, token,
		SourcePolicyCheckRequest{AllowedCIDRs: []string{"192.0.2.0/24"}})
	var got SourcePolicyCheckResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("回應非預期 JSON: %q", w.Body.String())
	}
	if got.Source.Address == nil || *got.Source.Address != "192.0.2.1" {
		t.Fatalf("省略 address 時應回本請求來源，實得 %+v", got.Source)
	}
	if got.Source.Reason != sourceReasonRequest {
		t.Errorf("source.reason = %q, want %q", got.Source.Reason, sourceReasonRequest)
	}
	if !got.Allowed {
		t.Error("本請求來源落在清單內，allowed 應為 true")
	}

	// 同一個來源、換一份不含它的清單 → 自鎖預警的那一態
	w2 := postSourcePolicyCheck(t, r, token,
		SourcePolicyCheckRequest{AllowedCIDRs: []string{"10.0.0.0/8"}})
	var got2 SourcePolicyCheckResponse
	if err := json.Unmarshal(w2.Body.Bytes(), &got2); err != nil {
		t.Fatalf("回應非預期 JSON: %q", w2.Body.String())
	}
	if got2.Allowed {
		t.Error("本請求來源不在清單內，allowed 應為 false（自鎖預警即消費本欄）")
	}

	// 呼叫端指定位址時來源標記換成 provided（管理者預演「某位址進不進得來」）
	w3 := postSourcePolicyCheck(t, r, token,
		SourcePolicyCheckRequest{AllowedCIDRs: []string{"10.0.0.0/8"}, Address: "10.1.2.3"})
	var got3 SourcePolicyCheckResponse
	if err := json.Unmarshal(w3.Body.Bytes(), &got3); err != nil {
		t.Fatalf("回應非預期 JSON: %q", w3.Body.String())
	}
	if got3.Source.Reason != sourceReasonProvided || !got3.Allowed {
		t.Errorf("指定位址判定失準: %+v", got3)
	}

	// 指定的位址不可解析：顯式 null＋原因，且清單非空即不放行
	w4 := postSourcePolicyCheck(t, r, token,
		SourcePolicyCheckRequest{AllowedCIDRs: []string{"10.0.0.0/8"}, Address: "not-an-address"})
	if !bytes.Contains(w4.Body.Bytes(), []byte(`"address":null`)) {
		t.Errorf("不可解析的來源應回顯式 null，實得 %s", w4.Body.String())
	}
	var got4 SourcePolicyCheckResponse
	if err := json.Unmarshal(w4.Body.Bytes(), &got4); err != nil {
		t.Fatalf("回應非預期 JSON: %q", w4.Body.String())
	}
	if got4.Source.Reason != sourceReasonUnresolvable || got4.Allowed {
		t.Errorf("清單非空而來源不可解析應 fail-close: %+v", got4)
	}
}

// TestSourcePolicyCheckRequiresAdmin 判定端點是 admin 專屬：它接受任意清單並
// 回答「這個位址進不進得來」，對非管理者是一支免費的政策探測面
func TestSourcePolicyCheckRequiresAdmin(t *testing.T) {
	r, jwt, db := setupSourcePolicyCheckEnv(t)
	userToken := sourcePolicyTokenFor(t, db, jwt, "plain-user", "user")

	w := postSourcePolicyCheck(t, r, userToken,
		SourcePolicyCheckRequest{AllowedCIDRs: []string{"10.0.0.0/8"}})
	if w.Code != http.StatusForbidden {
		t.Errorf("非 admin 應 403，實得 %d（body=%s）", w.Code, w.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/source-policy/check", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("未認證應 401，實得 %d", w2.Code)
	}
}

// TestSourcePolicyCheckWritesNothing 純判定：不得留下任何使用者狀態變更。
// 端點若順手寫了什麼，自鎖預演就變成自鎖本身
func TestSourcePolicyCheckWritesNothing(t *testing.T) {
	r, jwt, db := setupSourcePolicyCheckEnv(t)
	token := sourcePolicyTokenFor(t, db, jwt, "nowrite-admin", model.RoleAdmin)

	var before []model.User
	if err := db.Order("id").Find(&before).Error; err != nil {
		t.Fatalf("讀回帳號: %v", err)
	}
	for i := 0; i < 3; i++ {
		postSourcePolicyCheck(t, r, token,
			SourcePolicyCheckRequest{AllowedCIDRs: []string{"10.0.0.0/8", "0.0.0.0/0"}})
	}
	var after []model.User
	if err := db.Order("id").Find(&after).Error; err != nil {
		t.Fatalf("讀回帳號: %v", err)
	}
	if len(before) != len(after) {
		t.Fatalf("帳號列數變動：%d → %d", len(before), len(after))
	}
	for i := range before {
		if before[i].AllowedCIDRs != after[i].AllowedCIDRs {
			t.Errorf("帳號 %d 的清單被端點改寫：%q → %q",
				before[i].ID, before[i].AllowedCIDRs, after[i].AllowedCIDRs)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSourcePolicyCheckAuditDetailsAreShapeNotContent 判定端點的讀取留痕摘要。
//
// 兩件事一起釘：
//
//  1. **摘要存在且答得出「查了什麼」**。訂正前這支端點的審計列 details 全空，
//     只說得出「有人打了判定端點」；配上 POST→create 的動詞推導，稽核工作台上
//     它與真正的建帳號完全同形。
//  2. **摘要記形狀不記內容**。草稿清單與被試算的位址不得逐字進 details——
//     那是一份從未儲存的草稿與呼叫端任意指定的位址，寫進去等於把試算輸入永久
//     封存在刪不掉的紀錄裡（audit_logs 受檢查點鏈保護），卻換不到任何課責。
//     反面斷言用的三個字串刻意取自本次請求的輸入，故它不是「找不到就過」的空斷言。
func TestSourcePolicyCheckAuditDetailsAreShapeNotContent(t *testing.T) {
	var captured map[string]string
	capture := func(c *gin.Context) {
		c.Next()
		if v, ok := c.Get("audit_details"); ok {
			m, isMap := v.(map[string]string)
			if !isMap {
				t.Errorf("audit_details 型別為 %T，中介層只認 map[string]string——"+
					"型別不合會被安靜略過，details 欄照樣是空的", v)
				return
			}
			captured = m
		}
	}
	r, jwt, db := setupSourcePolicyCheckEnv(t, capture)
	token := sourcePolicyTokenFor(t, db, jwt, "audit-detail-admin", model.RoleAdmin)

	// 情境一：指定位址預演，草稿合法且該位址不落入
	captured = nil
	w := postSourcePolicyCheck(t, r, token, SourcePolicyCheckRequest{
		AllowedCIDRs: []string{"10.0.0.0/8", "198.51.100.0/24"},
		Address:      "203.0.113.7",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("狀態碼 = %d（body=%s）", w.Code, w.Body.String())
	}
	if captured == nil {
		t.Fatal("handler 未設 audit_details：中介層那一列會只說得出「有人打了判定端點」")
	}
	for k, want := range map[string]string{
		"check":          "source_policy",
		"cidr_count":     "2",
		"valid":          "true",
		"address_source": sourceReasonProvided,
		"status":         "restricted",
		"allowed":        "false",
	} {
		if captured[k] != want {
			t.Errorf("details[%q] = %q, want %q（摘要少一鍵，稽核就少答一個問題）",
				k, captured[k], want)
		}
	}
	blob, err := json.Marshal(captured)
	if err != nil {
		t.Fatalf("序列化 details: %v", err)
	}
	for _, leak := range []string{"10.0.0.0/8", "198.51.100.0/24", "203.0.113.7"} {
		if bytes.Contains(blob, []byte(leak)) {
			t.Errorf("details 逐字帶了 %q：%s——試算輸入不得進不可刪除的審計紀錄",
				leak, blob)
		}
	}

	// 情境二：省略 address 走本請求來源，來源標記須跟著換
	captured = nil
	postSourcePolicyCheck(t, r, token,
		SourcePolicyCheckRequest{AllowedCIDRs: []string{"10.0.0.0/8"}})
	if captured["address_source"] != sourceReasonRequest {
		t.Errorf("省略 address 時 details[address_source] = %q, want %q",
			captured["address_source"], sourceReasonRequest)
	}

	// 情境三：草稿不合法時不得寫出涵蓋狀態——算得出來也不具意義，
	// 留在審計裡會讓讀者以為那份草稿是好的
	captured = nil
	postSourcePolicyCheck(t, r, token,
		SourcePolicyCheckRequest{AllowedCIDRs: []string{"not-a-cidr"}})
	if captured["valid"] != "false" {
		t.Errorf("不合法草稿的 details[valid] = %q, want false", captured["valid"])
	}
	if v, ok := captured["status"]; ok {
		t.Errorf("不合法草稿仍寫出 status = %q，應整個不寫該鍵", v)
	}
}
