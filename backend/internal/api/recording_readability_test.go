package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/gin-gonic/gin"
)

// 錄影可讀性的一致判定：metadata、JWT 串流、rtoken 串流、下載四個請求，
// 對同一份本機錄影回同一個狀態碼與機器碼；讀不到時一律是錯誤信封，不交付任何位元組。
//
// 權限變體用真的權限位元：容器內測試行程是 root 但不具 DAC override，
// 每個變體先以 os.ReadFile／os.Stat 證明檔案系統確實拒絕，前提不成立即 Fatal。

const (
	codeUnreadable = "INTERNAL_RECORDING_FILE_UNREADABLE"
	codeNotFound   = "NOTFOUND_RECORDING_FILE"
)

// readabilityEnv 在取流審計環境上補掛 JWT 路徑三支端點（模擬認證中介層設定身分），
// 審計中介層仍是同一個真的實例。
type readabilityEnv struct {
	*recStreamEnv
	body []byte
}

func setupReadabilityEnv(t *testing.T) *readabilityEnv {
	t.Helper()
	env := setupRecordingStreamEnv(t)
	var sess model.Session
	if err := env.db.First(&sess, env.sessionID).Error; err != nil {
		t.Fatalf("讀 session: %v", err)
	}
	body, err := os.ReadFile(sess.RecordingPath)
	if err != nil {
		t.Fatalf("讀測試錄影檔: %v", err)
	}
	fakeAuth := func(c *gin.Context) {
		c.Set("userID", env.userID)
		c.Set("username", env.username)
		c.Next()
	}
	g := env.router.Group("/api/v1/sessions", fakeAuth)
	g.GET("/:id/recording", env.handler.GetRecordingMetadata)
	g.GET("/:id/recording/download", env.handler.DownloadRecording)
	g.GET("/:id/recording/stream", env.handler.StreamRecording)
	return &readabilityEnv{recStreamEnv: env, body: body}
}

func (e *readabilityEnv) setRecordingPath(t *testing.T, path string) {
	t.Helper()
	if err := e.db.Model(&model.Session{}).Where("id = ?", e.sessionID).
		Update("recording_path", path).Error; err != nil {
		t.Fatalf("改 recording_path: %v", err)
	}
}

func (e *readabilityEnv) do(t *testing.T, path, rangeHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

// fourRequests 四個請求：名稱 → 請求路徑（rtoken 每次重新簽發）
func (e *readabilityEnv) fourRequests(t *testing.T) []struct{ name, path string } {
	base := fmt.Sprintf("/api/v1/sessions/%d/recording", e.sessionID)
	return []struct{ name, path string }{
		{"metadata", base},
		{"jwt-stream", base + "/stream"},
		{"rtoken-stream", "/api/v1/recordings/stream?rtoken=" + e.issueToken(t)},
		{"download", base + "/download"},
	}
}

func chmodBack(t *testing.T, path string, mode, restore os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, restore) })
}

// assertErrorEnvelope 斷言回應是指定狀態碼的錯誤信封，且不含錄影位元組。
func assertErrorEnvelope(t *testing.T, label string, w *httptest.ResponseRecorder, status int, code string, body []byte) {
	t.Helper()
	if w.Code != status {
		t.Errorf("%s：狀態碼應為 %d，實得 %d（本文 %q）", label, status, w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("%s：Content-Type 應為 application/json（錯誤信封），實得 %q", label, ct)
	}
	var env struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Errorf("%s：本文應為 JSON 錯誤信封，實得 %q", label, w.Body.String())
	}
	if env.Code != code {
		t.Errorf("%s：code 應為 %q，實得 %q", label, code, env.Code)
	}
	if strings.Contains(w.Body.String(), "secret-credential") || (len(body) > 0 && strings.Contains(w.Body.String(), string(body[:20]))) {
		t.Errorf("%s：錯誤回應不得含錄影位元組", label)
	}
	if w.Header().Get("Content-Disposition") != "" {
		t.Errorf("%s：錯誤回應不得帶下載檔頭", label)
	}
}

// TestRecordingReadabilityVariantsConsistent 三變體＋缺檔 × 四請求逐格一致。
func TestRecordingReadabilityVariantsConsistent(t *testing.T) {
	variants := []struct {
		name   string
		setup  func(t *testing.T, dir string, body []byte) string
		status int
		code   string
	}{
		{"A 檔案 0200", func(t *testing.T, dir string, body []byte) string {
			p := filepath.Join(dir, "session-a.cast")
			if err := os.WriteFile(p, body, 0o600); err != nil {
				t.Fatal(err)
			}
			chmodBack(t, p, 0o200, 0o600)
			if _, err := os.ReadFile(p); err == nil {
				t.Fatal("前提不成立：0200 的檔案仍讀得到（行程具 DAC override）")
			}
			return p
		}, http.StatusInternalServerError, codeUnreadable},
		{"B stat 失敗", func(t *testing.T, dir string, body []byte) string {
			parent := filepath.Join(dir, "locked")
			if err := os.Mkdir(parent, 0o755); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(parent, "session-b.cast")
			if err := os.WriteFile(p, body, 0o600); err != nil {
				t.Fatal(err)
			}
			chmodBack(t, parent, 0o000, 0o755)
			if _, err := os.Stat(p); err == nil || os.IsNotExist(err) {
				t.Fatalf("前提不成立：父目錄 000 時 stat 應失敗且不是「不存在」，實得 %v", err)
			}
			return p
		}, http.StatusInternalServerError, codeUnreadable},
		{"C 路徑是目錄", func(t *testing.T, dir string, _ []byte) string {
			p := filepath.Join(dir, "session-c.cast")
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
			return p
		}, http.StatusInternalServerError, codeUnreadable},
		{"缺檔", func(t *testing.T, dir string, _ []byte) string {
			return filepath.Join(dir, "session-gone.cast")
		}, http.StatusNotFound, codeNotFound},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			env := setupReadabilityEnv(t)
			env.setRecordingPath(t, v.setup(t, t.TempDir(), env.body))
			for _, rq := range env.fourRequests(t) {
				w := env.do(t, rq.path, "")
				assertErrorEnvelope(t, v.name+"／"+rq.name, w, v.status, v.code, env.body)
			}
		})
	}
}

// TestRecordingDownloadHealthyKeepsAttachmentAndRange 正常檔：下載仍為附件，Range 回 206。
func TestRecordingDownloadHealthyKeepsAttachmentAndRange(t *testing.T) {
	env := setupReadabilityEnv(t)
	path := fmt.Sprintf("/api/v1/sessions/%d/recording/download", env.sessionID)

	w := env.do(t, path, "")
	if w.Code != http.StatusOK {
		t.Fatalf("正常下載應回 200，實得 %d（%q）", w.Code, w.Body.String())
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, "session-guard.cast") {
		t.Errorf("Content-Disposition 應為附件且帶會話檔名，實得 %q", cd)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-asciicast" {
		t.Errorf("Content-Type 應為 application/x-asciicast，實得 %q", ct)
	}
	if w.Body.String() != string(env.body) {
		t.Errorf("下載內容應與錄影檔逐位元組相同")
	}

	w = env.do(t, path, "bytes=0-9")
	if w.Code != http.StatusPartialContent || w.Body.Len() != 10 {
		t.Errorf("Range 下載應回 206 且 10 bytes，實得 %d／%d", w.Code, w.Body.Len())
	}
}

// TestRecordingDeliveryWindowClassifies 判定為可讀後、交付開檔前檔案被刪或被換：
// 交付端自己分類，不沿用判定結果，也不回 2xx 空內容。
func TestRecordingDeliveryWindowClassifies(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, path string)
		status int
		code   string
	}{
		{"刪檔", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}, http.StatusNotFound, codeNotFound},
		{"換成目錄", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}, http.StatusInternalServerError, codeUnreadable},
	}
	for _, tc := range cases {
		for _, endpoint := range []string{"stream", "download"} {
			t.Run(tc.name+"／"+endpoint, func(t *testing.T) {
				env := setupReadabilityEnv(t)
				path := filepath.Join(t.TempDir(), "session-window.cast")
				if err := os.WriteFile(path, env.body, 0o600); err != nil {
					t.Fatal(err)
				}
				env.setRecordingPath(t, path)

				calls := 0
				orig := beforeRecordingDeliverOpen
				beforeRecordingDeliverOpen = func(p string) {
					calls++
					if p == path {
						tc.mutate(t, p)
					}
				}
				t.Cleanup(func() { beforeRecordingDeliverOpen = orig })

				w := env.do(t, fmt.Sprintf("/api/v1/sessions/%d/recording/%s", env.sessionID, endpoint), "")
				if calls != 1 {
					t.Fatalf("測試縫應恰被呼叫 1 次（證明走到判定與開檔之間的窗口），實得 %d", calls)
				}
				assertErrorEnvelope(t, tc.name+"／"+endpoint, w, tc.status, tc.code, env.body)
			})
		}
	}
}

// TestRecordingTypescriptCastCacheIsDirectory `.typescript` 錄影改交付旁邊的轉檔快取
// `.cast`；快取是目錄時回無法讀取，不回 200 空內容。
func TestRecordingTypescriptCastCacheIsDirectory(t *testing.T) {
	env := setupReadabilityEnv(t)
	dir := t.TempDir()
	ts := filepath.Join(dir, "session-legacy.typescript")
	if err := os.WriteFile(ts, []byte("script output"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "session-legacy.cast"), 0o755); err != nil {
		t.Fatal(err)
	}
	env.setRecordingPath(t, ts)

	for _, rq := range []struct{ name, path string }{
		{"jwt-stream", fmt.Sprintf("/api/v1/sessions/%d/recording/stream", env.sessionID)},
		{"rtoken-stream", "/api/v1/recordings/stream?rtoken=" + env.issueToken(t)},
	} {
		w := env.do(t, rq.path, "")
		assertErrorEnvelope(t, ".cast 快取為目錄／"+rq.name, w, http.StatusInternalServerError, codeUnreadable, nil)
	}
}

// TestRecordingUnreadableAuditRows 審計不變性：讀不到時 rtoken 路徑逐次寫失敗列、
// JWT 路徑中介層落列 status_code=500；本機可讀的成功列 Details 與改動前逐位元組相同。
func TestRecordingUnreadableAuditRows(t *testing.T) {
	t.Run("rtoken 失敗逐次留列", func(t *testing.T) {
		env := setupReadabilityEnv(t)
		path := filepath.Join(t.TempDir(), "session-a.cast")
		if err := os.WriteFile(path, env.body, 0o600); err != nil {
			t.Fatal(err)
		}
		chmodBack(t, path, 0o200, 0o600)
		env.setRecordingPath(t, path)
		tok := env.issueToken(t)

		for i := 0; i < 2; i++ {
			if code, _ := env.fetch(t, tok, ""); code != http.StatusInternalServerError {
				t.Fatalf("第 %d 次取流應回 500，實得 %d", i+1, code)
			}
		}
		rows := env.retrievalRows(t)
		if len(rows) != 2 {
			t.Fatalf("兩次失敗取流應各留一列，實得 %d 列", len(rows))
		}
		for _, row := range rows {
			if row.Status != model.StatusFailure || row.StatusCode != http.StatusInternalServerError {
				t.Errorf("失敗列應為 status=failure、status_code=500，實得 %s／%d", row.Status, row.StatusCode)
			}
		}
	})

	t.Run("本機可讀成功列 Details 不變", func(t *testing.T) {
		env := setupReadabilityEnv(t)
		if code, _ := env.fetch(t, env.issueToken(t), ""); code != http.StatusOK {
			t.Fatalf("前提不成立：正常取流應回 200，實得 %d", code)
		}
		rows := env.retrievalRows(t)
		if len(rows) != 1 {
			t.Fatalf("成功取流應恰一列，實得 %d", len(rows))
		}
		want := fmt.Sprintf(`{"session_id":"%d","via":"rtoken"}`, env.sessionID)
		if rows[0].Details != want {
			t.Errorf("本機來源成功列 Details 應逐位元組等於 %s，實得 %s", want, rows[0].Details)
		}
	})

	t.Run("JWT 路徑中介層落列 500", func(t *testing.T) {
		env := setupReadabilityEnv(t)
		path := filepath.Join(t.TempDir(), "session-a.cast")
		if err := os.WriteFile(path, env.body, 0o600); err != nil {
			t.Fatal(err)
		}
		chmodBack(t, path, 0o200, 0o600)
		env.setRecordingPath(t, path)

		for _, endpoint := range []string{"stream", "download"} {
			w := env.do(t, fmt.Sprintf("/api/v1/sessions/%d/recording/%s", env.sessionID, endpoint), "")
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("%s 應回 500，實得 %d", endpoint, w.Code)
			}
		}
		rows := env.retrievalRows(t)
		if len(rows) != 2 {
			t.Fatalf("兩次 JWT 請求應由審計中介層各落一列，實得 %d 列", len(rows))
		}
		for _, row := range rows {
			if row.StatusCode != http.StatusInternalServerError || row.Resource != model.ResourceRecording {
				t.Errorf("中介層列應為 status_code=500、resource=recording，實得 %d／%s（path=%s）",
					row.StatusCode, row.Resource, row.Path)
			}
		}
	})
}
