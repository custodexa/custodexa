package api

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// newKeyMgmtTestHandler 建立含真 KeyManagerService 的 handler（sqlite、
// 信封遷移目標表全建空表使 EnvelopePendingCount=0，重包前置守衛可通過）
func newKeyMgmtTestHandler(t *testing.T) *KeyManagementHandler {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x5A
	}
	return newKeyMgmtTestHandlerWithKey(t, key)
}

// newKeyMgmtTestHandlerWithMaterial 以**合格 KEK 材料**建 handler：現行 KEK
// 亦可被 NewLocalRewrapTarget 構造，才測得到「目標＝現行 KEK」那一格
func newKeyMgmtTestHandlerWithMaterial(t *testing.T, material string) *KeyManagementHandler {
	t.Helper()
	return newKeyMgmtTestHandlerWithKey(t, []byte(material))
}

func newKeyMgmtTestHandlerWithKey(t *testing.T, key []byte) *KeyManagementHandler {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.DataKey{}, &model.Asset{}, &model.AssetAccount{}, &model.User{},
		&model.ExportSigningKey{}, &model.CheckpointSigningKey{}, &model.OIDCProvider{}, &model.LDAPDirectory{},
		&model.NotificationChannel{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	kek, err := crypto.NewEnvKEKProvider(key)
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	km, err := keyvault.InitKeyManager(db, kek)
	if err != nil {
		t.Fatalf("InitKeyManager: %v", err)
	}
	return NewKeyManagementHandler(db, km, nil, "test-fp", nil)
}

// TestRewrapResponseNoStore 重包回應禁止任何快取層留存。
//
// **D7 之後保護的對象變了**：回應已不含任何 KEK 明文（材料由請求體帶入），
// no-store 現在防的是**請求／回應被中間層留存後重放**，而非回應洩漏明文。
// 「回應無明文」由 TestRewrapResponseCarriesNoPlaintext 另行釘住。
func TestRewrapResponseNoStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newKeyMgmtTestHandler(t)

	w, _ := doRewrap(t, h, localRewrapBody(apiTestKEKMaterial(1)))

	if w.Code != http.StatusOK {
		t.Fatalf("Rewrap 應成功，got %d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
	var body struct {
		TargetMode    string `json:"target_mode"`
		NewKEKID      string `json:"new_kek_id"`
		RewrappedKeys int    `json:"rewrapped_keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("回應非 JSON: %v", err)
	}
	// 打在成功路徑上的下界：確有重包發生，否則後面的「無明文」斷言是空氣
	if body.TargetMode != "local" || body.NewKEKID == "" || body.RewrappedKeys == 0 {
		t.Fatalf("回應形制不符（測試須打在真正成功的重包上）: %+v", body)
	}
}

// TestKeyConflictsUseMachineCodes 金鑰管理的使用者可見 409 一律走機器碼
// （全域 i18n 規範：不得以 RespondError 回裸中文 Go error 訊息）。
// AST 掃本 handler，凡 StatusConflict 的回應必須是 apierror.Respond 呼叫
func TestKeyConflictsUseMachineCodes(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "key_management_handler.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 handler 失敗: %v", err)
	}
	var bareConflicts []string
	found := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "RespondError" || len(call.Args) < 2 {
			return true
		}
		sel, ok := call.Args[1].(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "StatusConflict" {
			return true
		}
		found++
		bareConflicts = append(bareConflicts, fset.Position(call.Pos()).String())
		return true
	})
	if len(bareConflicts) > 0 {
		t.Fatalf("金鑰管理有 %d 處 409 走 RespondError 裸訊息（應改 apierror.Respond＋機器碼，"+
			"並於三語 apiError 段補譯文）: %v", found, bareConflicts)
	}
	// 守衛有效性下界：本檔須確實存在 apierror.Respond 的 409 使用，否則掃描邏輯已失效
	uses := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Respond" || len(call.Args) < 3 {
			return true
		}
		if arg, ok := call.Args[1].(*ast.SelectorExpr); ok && arg.Sel.Name == "StatusConflict" {
			uses++
		}
		return true
	})
	if uses < 6 {
		t.Fatalf("預期至少 6 處機器碼 409（鎖忙／未收斂／過期／重包待切換／已有 pending／backlog…），得 %d——掃描邏輯可能失效", uses)
	}
}

// TestInventoryHasNoMigrationFields 清冊 SHALL NOT 含任何 legacy 遷移狀態欄位
// （release-transitional-cleanup 3.3／key-management spec）。
//
// 為何以「欄位不在」為斷言而非「值為 0」：留著恆為 0/null 的欄位會讓前端
// 繼續依它做禁用判斷，而那個判斷永遠不會成立——死條件比缺欄位更難察覺。
func TestInventoryHasNoMigrationFields(t *testing.T) {
	h := newKeyMgmtTestHandler(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/keys", h.Inventory)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/keys", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("清冊回 %d：%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析清冊: %v", err)
	}
	for _, field := range []string{"migration", "migration_pending"} {
		if _, ok := body[field]; ok {
			t.Errorf("清冊 MUST NOT 含 legacy 遷移欄位 %q（機制已整組拆除）", field)
		}
	}
	// 下界：確認回應本身正常（否則「欄位不在」可由空回應假綠）
	for _, field := range []string{"keys", "env_keys", "rotation_pending"} {
		if _, ok := body[field]; !ok {
			t.Fatalf("清冊回應缺 %q，本測試的負向斷言將由空回應假綠：%s", field, w.Body.String())
		}
	}
}
