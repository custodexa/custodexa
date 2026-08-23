package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
)

// 取走錄影本體必須留痕。
//
// # 缺陷
//
// `GET /api/v1/recordings/stream` 註冊於**未套 AuthMiddleware** 的 v1 群組
// （`recording_handler.go` 的 RegisterRoutes；理由是播放器只持短時效不透明 token，
// 不把長效 JWT 放進 URL query）。代價從未被補償：`AuditLogMiddleware` 在 context
// 沒有 userID／username 時整筆跳過（`internal/middleware/audit_log.go:52-56`），
// 而該路由鏈中沒有任何東西會設定它們，handler 又零審計呼叫。
//
// 結果是**取走錄影本體在 `audit_logs` 是零列**。實測（2026-08-13，dev 環境）：
// 對 session 551 簽發 rtoken 後打一次完整取流（200，612 bytes）＋一次 Range
// （206，100 bytes），`audit_logs` 總數自 22844 → 22844，
// `path like '%recordings/stream%'` 計數 0。
//
// 錄影是最敏感的證物——完整終端畫面、憑證輸入、跳板後的一切操作。取走它完全不
// 留痕，等於稽核鏈對這個動作全盲；這比剪貼簿留痕缺口嚴重：剪貼簿至少有一筆
// 紀錄（只是不夠精確），錄影是零。
//
// # 本檔守的四件事
//
//  1. 成功取流**必然**產生一列，且欄位可回答「誰、取走了哪一場連線的錄影、經哪條路徑」。
//  2. 「一次取證」的邊界是 **grant**：HTTP Range 分塊不得各記一列
//     （否則審計量正比於傳輸分塊，且熱路徑「不碰 DB」的前提作廢）。
//  3. 重新簽發即是新的一次取證：不得因去重而把後續調閱吞掉。
//  4. 無效 token 不得寫列：未認證的第三方不得以亂打 token 灌爆 `audit_logs`。
//
// # 為什麼掛真的 AuditLogMiddleware
//
// 讓「中介層自己不會記這條路由」成為本檔的機器事實而非讀者的推論：斷言**恰好一列**
// 同時證明了列來自 handler、且中介層確實跳過。若哪天有人把該路由移進認證群組，
// 列數會變成 2，本檔轉紅並提醒重新設計去重邊界。
//
// # 突變自證（2026-08-13 實跑）
//
// 拿掉 `StreamRecordingByToken` 內的 `h.auditRecordingRetrieval(...)` 一行
// ⇒ 本檔四格中的三格轉紅（第四格是「不得寫列」的反向格，本就該綠）。

// recStreamEnv 取流審計的測試環境：真 middleware ＋ 真 handler ＋ 真 audit service
// ＋ 真 sqlite，斷言 `audit_logs` 實列。
type recStreamEnv struct {
	*recTokenEnv
	router     *gin.Engine
	handler    *RecordingHandler
	sessionID  uint
	userID     uint
	username   string
	recordSize int
}

// setupRecordingStreamEnv 組出與生產同構的最小鏈路。
//
// 審計服務刻意設 `AsyncAuditEnabled: false`：生產走非同步 channel，測試若也走，
// 斷言就得靠輪詢等待，而「等不到」與「根本沒寫」在失敗訊息上無從分辨。
// 同步寫入使本檔的每一次紅都是真的缺列。
func setupRecordingStreamEnv(t *testing.T) *recStreamEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	base := setupRecordingTokenEnv(t)
	username := "recording-viewer"
	userID := base.seedPlainUser(t, username)

	// 真的錄影檔：`.cast` 走 serveCastFile → http.ServeContent（支援 Range），
	// 與生產的文字錄影回放同一條路徑
	body := []byte(`{"version":2,"width":80,"height":24}` + "\n" +
		`[0.1,"o","secret-credential-typed-here\r\n"]` + "\n")
	castPath := filepath.Join(t.TempDir(), "session-guard.cast")
	if err := os.WriteFile(castPath, body, 0o600); err != nil {
		t.Fatalf("寫測試錄影檔: %v", err)
	}
	sess := model.Session{UserID: userID, RecordingPath: castPath, RecordingSize: int64(len(body))}
	if err := base.db.Create(&sess).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}

	auditService := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	h := NewRecordingHandler(session.NewRecordingService(t.TempDir()), session.NewSessionService(nil), auditService)
	// 與生產同構：manager 是 handler 自建的那一個，測試不得另立一個影子 manager
	base.mgr = h.recordingTokens

	r := gin.New()
	// 真的審計中介層，位置與 cmd/server/main.go:464 同（全域、v1 之外）
	r.Use(middleware.AuditLogMiddleware(auditService))
	// 路徑逐字對齊生產註冊（`r.GET("/recordings/stream", …)` 掛在 v1 群組上），
	// c.FullPath() 因此與生產一致，審計列的 path 欄可直接比對
	r.GET("/api/v1/recordings/stream", h.StreamRecordingByToken)

	return &recStreamEnv{
		recTokenEnv: base, router: r, handler: h,
		sessionID: sess.ID, userID: userID, username: username, recordSize: len(body),
	}
}

// issueToken 走與生產同一支簽發函式（含世代閘），不手工塞 grant
func (e *recStreamEnv) issueToken(t *testing.T) string {
	t.Helper()
	tok, err := e.handler.recordingTokens.Issue(e.userID, e.sessionID, e.username, crypto.AuthContext{})
	if err != nil {
		t.Fatalf("簽發錄影 token: %v", err)
	}
	return tok
}

// fetch 打一次取流；rangeHeader 非空時發 Range 請求。回傳狀態碼與實得位元組數。
func (e *recStreamEnv) fetch(t *testing.T, token, rangeHeader string) (int, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/recordings/stream?rtoken="+token, nil)
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w.Code, w.Body.Len()
}

// retrievalRows 取本場連線的錄影取證列（依 id 排序，便於逐列斷言）
func (e *recStreamEnv) retrievalRows(t *testing.T) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := e.db.Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("查 audit_logs: %v", err)
	}
	return rows
}

// TestRecordingBodyRetrievalIsAudited 取走錄影本體必然留痕，且該列可回答
// 「誰、取走了哪一場連線的錄影、經哪條路徑」。
func TestRecordingBodyRetrievalIsAudited(t *testing.T) {
	env := setupRecordingStreamEnv(t)
	tok := env.issueToken(t)

	code, n := env.fetch(t, tok, "")

	if code != http.StatusOK || n != env.recordSize {
		t.Fatalf("前提不成立：取流應回 200 且交付 %d bytes，實得 %d／%d bytes",
			env.recordSize, code, n)
	}
	rows := env.retrievalRows(t)
	if len(rows) != 1 {
		t.Fatalf("取走錄影本體後 audit_logs 應恰有 1 列，實得 %d 列。\n"+
			"  0 列＝缺陷復辟：/recordings/stream 未套 AuthMiddleware，審計中介層因無身分整筆跳過，"+
			"取走最敏感的證物完全不留痕，稽核鏈對這個動作全盲。\n"+
			"  2 列＝路由的認證處置已變（中介層也記了一筆），去重邊界須重新設計。", len(rows))
	}

	row := rows[0]
	if row.Resource != model.ResourceRecording {
		t.Errorf("resource 應為 %q（取證動作須可以資源分類篩出），實得 %q",
			model.ResourceRecording, row.Resource)
	}
	if row.Action != model.ActionRead {
		t.Errorf("action 應為 %q，實得 %q", model.ActionRead, row.Action)
	}
	if row.ResourceID == nil || *row.ResourceID != env.sessionID {
		t.Errorf("resource_id 應為連線 id %d（取證的範圍鍵），實得 %v", env.sessionID, row.ResourceID)
	}
	if row.UserID != env.userID || row.Username != env.username {
		t.Errorf("身分應取自 grant 的簽發時快照（%d／%q），實得 %d／%q。\n"+
			"  兌換端點無認證中介層，context 內沒有任何身分——身分若不在簽發時存進 grant，"+
			"這一列就只能是匿名的，等於沒回答「誰取走了證物」",
			env.userID, env.username, row.UserID, row.Username)
	}
	if row.Status != model.StatusSuccess {
		t.Errorf("status 應為 %q，實得 %q", model.StatusSuccess, row.Status)
	}
	if row.AssetID != nil {
		t.Errorf("asset_id 應留空（取證的主體是連線不是資產；填了即把不相干事件掛到某台機器上），實得 %v", row.AssetID)
	}

	var details map[string]string
	if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
		t.Fatalf("details 應為 JSON 物件，實得 %q（err=%v）", row.Details, err)
	}
	if got := details["session_id"]; got != fmt.Sprint(env.sessionID) {
		t.Errorf("details.session_id 應為 %d，實得 %q", env.sessionID, got)
	}
	if got := details["via"]; got != "rtoken" {
		t.Errorf(`details.via 應為 "rtoken"（使本條無認證中介層的取證路徑可與 `+
			`/sessions/:id/recording/stream 區分），實得 %q`, got)
	}
}

// TestRecordingRangeRequestsAuditedOncePerGrant 「一次取證」的邊界是 grant。
//
// 播放器以 HTTP Range 分塊取流，一次調閱會打出多次請求。逐請求記列會讓審計量
// 正比於傳輸分塊——訊號被自己的重複淹沒，且 Resolve 熱路徑「不碰 DB」的設計前提作廢。
func TestRecordingRangeRequestsAuditedOncePerGrant(t *testing.T) {
	env := setupRecordingStreamEnv(t)
	tok := env.issueToken(t)

	if code, n := env.fetch(t, tok, ""); code != http.StatusOK || n != env.recordSize {
		t.Fatalf("前提不成立：完整取流應回 200／%d bytes，實得 %d／%d", env.recordSize, code, n)
	}
	for i, rng := range []string{"bytes=0-9", "bytes=10-19"} {
		code, n := env.fetch(t, tok, rng)
		if code != http.StatusPartialContent || n != 10 {
			t.Fatalf("前提不成立：第 %d 次 Range(%s) 應回 206／10 bytes，實得 %d／%d",
				i+1, rng, code, n)
		}
	}

	if rows := env.retrievalRows(t); len(rows) != 1 {
		t.Errorf("同一 grant 的 1 次完整取流＋2 次 Range 應合計 1 列取證紀錄，實得 %d 列。\n"+
			"  >1＝去重失效：審計量將正比於播放器的分塊次數，「誰取走了這場錄影」被自己的重複淹沒，"+
			"且每個 Range 都多一次審計寫入，錄影愈大審計愈重——審計不得成為傳輸瓶頸。\n"+
			"  0＝取證整個無痕。", len(rows))
	}
}

// TestRecordingNewGrantIsAuditedAgain 去重不得跨 grant——否則第二次調閱被吞掉。
//
// 沒有這一格，「永遠只記第一列」也會讓上一格全綠
func TestRecordingNewGrantIsAuditedAgain(t *testing.T) {
	env := setupRecordingStreamEnv(t)

	first := env.issueToken(t)
	if code, _ := env.fetch(t, first, ""); code != http.StatusOK {
		t.Fatalf("前提不成立：第一次取流應回 200，實得 %d", code)
	}
	second := env.issueToken(t)
	if second == first {
		t.Fatal("前提不成立：兩次簽發應得到不同 token")
	}
	if code, _ := env.fetch(t, second, ""); code != http.StatusOK {
		t.Fatalf("前提不成立：第二次取流應回 200，實得 %d", code)
	}

	if rows := env.retrievalRows(t); len(rows) != 2 {
		t.Errorf("兩次獨立簽發各取走一次錄影，應得 2 列取證紀錄，實得 %d 列。\n"+
			"  去重若跨 grant 生效，同一人反覆調閱同一場錄影只會留下第一次的痕跡——"+
			"「他取了幾次」在稽核上答不出來。grant 的 TTL 僅 120 秒且不可續期，"+
			"故它是取證的自然邊界，重新簽發即是新的一次取證（簽發本身另有一列）。", len(rows))
	}
}

// TestInvalidRecordingTokenIsNotAudited 無效 token 不得寫列。
//
// 該路由無認證中介層，任何人都能打。若失敗也記列，未認證的第三方就能以亂打
// token 灌爆 `audit_logs`——把審計表變成 DoS 面，並把真正的取證列淹掉。
func TestInvalidRecordingTokenIsNotAudited(t *testing.T) {
	env := setupRecordingStreamEnv(t)

	if code, _ := env.fetch(t, "deadbeefdeadbeefdeadbeefdeadbeef", ""); code != http.StatusUnauthorized {
		t.Fatalf("前提不成立：無效 token 應回 401，實得 %d", code)
	}
	if code, _ := env.fetch(t, "", ""); code != http.StatusUnauthorized {
		t.Fatalf("前提不成立：缺 token 應回 401，實得 %d", code)
	}

	if rows := env.retrievalRows(t); len(rows) != 0 {
		t.Errorf("token 無效／缺漏時不得寫審計列（無身分可歸屬，且該路由未認證、"+
			"任何人可打），實得 %d 列", len(rows))
	}
}
