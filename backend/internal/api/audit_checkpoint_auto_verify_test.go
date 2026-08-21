package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// 自動驗證營運狀態的揭露面（audit-chain-scheduled-verification tasks 5.1）。
//
// **零新增路由**：狀態掛在既有結構層報告上（GET /audit-checkpoints/verify），
// 故本組不動端點索引與路由 golden。這裡釘的是兩件事：狀態真的到得了回應，
// 以及失敗區間的序號清單不隨之外流（與告警出站同一條去識別紅線）。

// autoVerifyEngine 建一個只掛 Verify 的引擎（授權面由既有 RBAC 測試覆蓋，
// 本組專注在回應形狀），並回傳 handler 與 db 供注入與 seed
func autoVerifyEngine(t *testing.T, withStatus bool) (*gin.Engine, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	_, _, db, seal := setupCheckpointAPIEnv(t)

	if err := db.AutoMigrate(&model.AuditChainVerifyState{}); err != nil {
		t.Fatalf("migrate state: %v", err)
	}
	signer := newFakeCheckpointSigner(t)
	purger := audit.NewCheckpointPurger(db, signer)
	verifier := audit.NewCheckpointVerifier(db, seal, purger, nil, nil)
	h := &AuditCheckpointHandler{verifier: verifier, signing: signer}
	if withStatus {
		h.SetAutoVerifyStatus(audit.NewChainVerifyService(db, verifier, seal, signer, nil, nil, nil))
	}

	r := gin.New()
	r.GET("/verify", h.Verify)
	return r, db
}

func autoVerifyBody(t *testing.T, r *gin.Engine) (string, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/verify", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("狀態碼 = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			Chain map[string]any `json:"chain"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析: %v", err)
	}
	return w.Body.String(), resp.Data.Chain
}

// TestVerifyCarriesAutoVerifyStatusWithoutLeakingSeqs 狀態隨既有報告一起回，
// 且只帶計數——受影響的區間序號不出現在回應中
func TestVerifyCarriesAutoVerifyStatusWithoutLeakingSeqs(t *testing.T) {
	r, db := autoVerifyEngine(t, true)

	at := time.Now().Add(-90 * time.Second)
	if err := db.Create(&model.AuditChainVerifyState{
		ID:                        model.AuditChainVerifyStateID,
		RecentLastRunAt:           &at,
		RecentLastStatus:          audit.ChainVerifyStatusPassed,
		RecentWindowDaysEffective: 7,
		FullLastRunAt:             &at,
		FullLastStatus:            audit.ChainVerifyStatusFailed,
		ContentCursorSeq:          42,
		OpenFailedSeqs:            `{"4711":"count_mismatch","4712":"hash_mismatch"}`,
	}).Error; err != nil {
		t.Fatalf("seed state: %v", err)
	}

	raw, chain := autoVerifyBody(t, r)
	av, ok := chain["auto_verify"].(map[string]any)
	if !ok {
		t.Fatalf("回應缺 auto_verify：畫面上將看不出自動驗證是否存在。body=%s", raw)
	}
	for _, k := range []string{"recent_last_run_at", "recent_last_status",
		"recent_window_days_effective", "full_last_run_at", "full_last_status",
		"full_interval_seconds", "content_cursor_seq", "open_failed_intervals",
		"rows_per_hour", "cycle_estimate_hours"} {
		if _, ok := av[k]; !ok {
			t.Errorf("auto_verify 缺欄位 %s（tasks 5.2 的顯示項）", k)
		}
	}
	if av["open_failed_intervals"].(float64) != 2 {
		t.Errorf("未結案失敗區間數 = %v, want 2", av["open_failed_intervals"])
	}
	// 去識別紅線：計數足以驅動「有人得去看」，序號會告訴攻擊者被發現的邊界在哪
	for _, leak := range []string{"open_failed_seqs", "4711", "4712", "count_mismatch", "hash_mismatch"} {
		if strings.Contains(raw, leak) {
			t.Errorf("回應外流 %q：狀態揭露只得帶計數。body=%s", leak, raw)
		}
	}
	t.Logf("auto_verify = %v", av)
}

// TestVerifyOmitsAutoVerifyWhenReaderAbsent 未注入狀態來源時該區塊缺席，
// 由前端顯示為「狀態無法取得」而非靜默隱藏整個區塊
func TestVerifyOmitsAutoVerifyWhenReaderAbsent(t *testing.T) {
	r, _ := autoVerifyEngine(t, false)
	raw, chain := autoVerifyBody(t, r)
	if _, ok := chain["auto_verify"]; ok {
		t.Errorf("未注入狀態來源時不得憑空生出狀態：%s", raw)
	}
	// 主流程不受影響：鏈健康總覽仍在
	if _, ok := chain["status"]; !ok {
		t.Errorf("結構層報告本體缺席：一張營運狀態表不得拖垮驗證頁主體。%s", raw)
	}
}
