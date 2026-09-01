package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
)

// 離機來源的取流：本機檔已被保留政策清除之後，
// 播放與 Range 仍走同一個 rtoken 收口，交付的是**驗過的**暫存檔內容，
// 且審計列記得出「這一次的位元組來自哪裡、為何不是本機」。

// stubOffsiteRetriever session.OffsiteRetriever 的測試替身。
type stubOffsiteRetriever struct {
	row       *model.OffsiteObject
	spoolPath string
	calls     int
	err       error
}

func (s *stubOffsiteRetriever) Object(uint) (*model.OffsiteObject, error) { return s.row, nil }

func (s *stubOffsiteRetriever) Fetch(context.Context, uint) (*offsite.FetchedObject, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &offsite.FetchedObject{Path: s.spoolPath, Size: s.row.Size,
		UploadedAt: time.Now(), Kind: offsite.KindRecording, OwnerID: s.row.OwnerID}, nil
}

// wireOffsite 讓本場連線「已離機」，並把本機檔刪掉。
func wireOffsite(t *testing.T, env *recStreamEnv, body []byte) *stubOffsiteRetriever {
	t.Helper()
	var sess model.Session
	if err := env.db.First(&sess, env.sessionID).Error; err != nil {
		t.Fatalf("讀取測試連線: %v", err)
	}
	objID := uint(4242)
	if err := env.db.Model(&model.Session{}).Where("id = ?", env.sessionID).
		Updates(map[string]any{
			"offsite_object_id": objID,
			"offsite_status":    offsite.StateUploaded,
		}).Error; err != nil {
		t.Fatalf("寫入離機快取欄: %v", err)
	}

	spool := filepath.Join(t.TempDir(), "4242.cast")
	if err := os.WriteFile(spool, body, 0o600); err != nil {
		t.Fatalf("寫暫存檔: %v", err)
	}
	sum := sha256.Sum256(body)
	stub := &stubOffsiteRetriever{
		row: &model.OffsiteObject{ID: objID, Kind: offsite.KindRecording, OwnerID: env.sessionID,
			State: offsite.StateUploaded, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))},
		spoolPath: spool,
	}
	env.handler.recordingService.SetOffsiteRetriever(stub)

	// 本機檔清除（保留政策的快取清除段做的正是這件事）
	if err := os.Remove(sess.RecordingPath); err != nil {
		t.Fatalf("刪除本機錄影檔: %v", err)
	}
	return stub
}

// recordingBody 與 setupRecordingStreamEnv 寫入的內容逐位元組相同。
func recordingBody() []byte {
	return []byte(`{"version":2,"width":80,"height":24}` + "\n" +
		`[0.1,"o","secret-credential-typed-here\r\n"]` + "\n")
}

// TestStreamServesOffsiteCopyWhenLocalPurged 本機檔已清除：取流回 200 且內容
// 逐位元組等於離機副本；Range 回 206（自暫存檔 ServeContent，故 Range 也是驗過的內容）。
func TestStreamServesOffsiteCopyWhenLocalPurged(t *testing.T) {
	env := setupRecordingStreamEnv(t)
	body := recordingBody()
	stub := wireOffsite(t, env, body)

	code, n := env.fetch(t, env.issueToken(t), "")
	if code != http.StatusOK || n != len(body) {
		t.Fatalf("本機檔清除後仍應以離機副本交付 200／%d bytes，實得 %d／%d",
			len(body), code, n)
	}
	if stub.calls == 0 {
		t.Fatal("應實際走過離機取回")
	}

	// Range：**自暫存檔** ServeContent，206 與位元組數由標準庫處理
	code, n = env.fetch(t, env.issueToken(t), "bytes=0-9")
	if code != http.StatusPartialContent || n != 10 {
		t.Fatalf("離機來源的 Range 應回 206／10 bytes，實得 %d／%d", code, n)
	}
}

// TestOffsiteRetrievalAuditCarriesSourceAndFallback 審計列記來源與退路原因。
//
// 本機檔被清除之後，「我看到的這一份是從哪裡拿出來的」不再是顯而易見的事——
// 沒有這兩個欄位，稽核員無從分辨「播的是本機原檔」與「播的是遠端取回並驗過的副本」。
func TestOffsiteRetrievalAuditCarriesSourceAndFallback(t *testing.T) {
	env := setupRecordingStreamEnv(t)
	wireOffsite(t, env, recordingBody())

	if code, _ := env.fetch(t, env.issueToken(t), ""); code != http.StatusOK {
		t.Fatalf("前提不成立：取流應回 200，實得 %d", code)
	}
	rows := env.retrievalRows(t)
	if len(rows) != 1 {
		t.Fatalf("應恰有一列取證審計，實得 %d", len(rows))
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(rows[0].Details), &details); err != nil {
		t.Fatalf("details 應為 JSON 物件，實得 %q", rows[0].Details)
	}
	if got := details["source"]; got != "offsite" {
		t.Errorf(`details.source 應為 "offsite"，實得 %q`, got)
	}
	if got := details["fallback_reason"]; got != "local_missing" {
		t.Errorf(`details.fallback_reason 應為 "local_missing"，實得 %q`, got)
	}
	if got := details["via"]; got != "rtoken" {
		t.Errorf(`details.via 應維持 "rtoken"（既有欄位不得因新增欄位而消失），實得 %q`, got)
	}
}

// TestLocalSourceAuditDetailsUnchanged 本機來源（未接離機）的審計列 Details
// 與本功能上線前**逐位元組相同**——「未設定＝行為完全不變」在審計面的落點。
func TestLocalSourceAuditDetailsUnchanged(t *testing.T) {
	env := setupRecordingStreamEnv(t)

	if code, _ := env.fetch(t, env.issueToken(t), ""); code != http.StatusOK {
		t.Fatalf("前提不成立：取流應回 200，實得 %d", code)
	}
	rows := env.retrievalRows(t)
	if len(rows) != 1 {
		t.Fatalf("應恰有一列取證審計，實得 %d", len(rows))
	}
	want := `{"session_id":"` + strconv.FormatUint(uint64(env.sessionID), 10) + `","via":"rtoken"}`
	if rows[0].Details != want {
		t.Errorf("未接離機時 Details 應逐位元組維持原形狀\n  期望 %s\n  實得 %s",
			want, rows[0].Details)
	}
}

// TestStreamRefusesTamperedOffsiteCopy 取回被判完整性不符：**零位元組交付**，
// 回機器碼而非退回「盡力播本機」（本機已無檔）。
func TestStreamRefusesTamperedOffsiteCopy(t *testing.T) {
	env := setupRecordingStreamEnv(t)
	stub := wireOffsite(t, env, recordingBody())
	stub.err = offsite.ErrIntegrityMismatch

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/recordings/stream?rtoken="+env.issueToken(t), nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("完整性不符應回 409（不是 404「沒有這個東西」），實得 %d", w.Code)
	}
	body := w.Body.String()
	for _, fragment := range []string{"secret-credential-typed-here", `"version":2`} {
		if strings.Contains(body, fragment) {
			t.Fatalf("拒絕交付時不得夾帶任何錄影位元組（命中 %q）", fragment)
		}
	}
	if !strings.Contains(body, string(apierror.CodeOffsiteIntegrityMismatch)) {
		t.Errorf("回應應帶可辨識的機器碼 %s，實得 %s",
			apierror.CodeOffsiteIntegrityMismatch, body)
	}
}
