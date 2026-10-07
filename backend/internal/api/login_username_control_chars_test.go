package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
)

// 登入帳號含控制字元或非法 UTF-8 時的回應與留痕。
//
// 正式環境的資料庫拒收含 NUL 的文字參數；測試用的 sqlite 不會，故本檔以 gorm
// callback 模擬同一行為（查詢或寫入的字串參數含 NUL 即回錯誤）。少了這層模擬，
// 「查詢前即拒」與「查到資料庫才失敗」在 sqlite 上不可區分。
//
// 守三件事：
//
//	(a) 回 401 INVALID_CREDENTIALS，與不存在的帳號逐字相同（不回 500、不帶出資料層）；
//	(b) 失敗仍留一筆登入失敗審計列，帳號欄可落庫（不含 NUL 與其他控制字元）；
//	(c) 一般帳號（含非 ASCII 字元）不受影響。

// rejectNULLikeProductionDB 讓 db 對含 NUL 的字串參數回錯誤，比照正式環境資料庫。
func rejectNULLikeProductionDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	errNUL := errors.New(`invalid byte sequence for encoding "UTF8": 0x00`)
	hasNUL := func(v any) bool {
		s, ok := v.(string)
		return ok && strings.ContainsRune(s, 0)
	}
	onQuery := func(tx *gorm.DB) {
		for _, v := range tx.Statement.Vars {
			if hasNUL(v) {
				_ = tx.AddError(errNUL)
				return
			}
		}
	}
	// 審計服務以 []*model.AuditLog 批次寫入；單筆形態一併涵蓋。
	onCreate := func(tx *gorm.DB) {
		var rows []*model.AuditLog
		switch d := tx.Statement.Dest.(type) {
		case *model.AuditLog:
			rows = []*model.AuditLog{d}
		case []*model.AuditLog:
			rows = d
		}
		for _, row := range rows {
			if hasNUL(row.Username) {
				_ = tx.AddError(errNUL)
				return
			}
		}
	}
	if err := db.Callback().Query().After("gorm:query").Register("test:reject_nul_query", onQuery); err != nil {
		t.Fatalf("register query callback: %v", err)
	}
	if err := db.Callback().Create().Before("gorm:create").Register("test:reject_nul_create", onCreate); err != nil {
		t.Fatalf("register create callback: %v", err)
	}
}

func postRawLogin(t *testing.T, h *AuthHandler, raw string) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	r.POST("/auth/login", h.Login)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = authSrcRemoteAddr
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestLoginControlCharUsernameIsInvalidCredentials(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"只有 NUL", `{"username":"\u0000","password":"x"}`},
		{"既有帳號尾綴 NUL", `{"username":"source-subject\u0000","password":"` + authSrcPassword + `"}`},
		{"換行", `{"username":"source-\nsubject","password":"x"}`},
		{"DEL", `{"username":"source-subject\u007f","password":"x"}`},
		{"C1 控制字元", `{"username":"source-subject\u0085","password":"x"}`},
		// 非法 UTF-8 位元組：encoding/json 會換成 U+FFFD，故此例驗的是「不因此出錯」。
		{"非法 UTF-8 位元組", "{\"username\":\"source-subject\xff\",\"password\":\"x\"}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := setupAuthSourceEnv(t)
			rejectNULLikeProductionDB(t, env.db)

			baseline := postRawLogin(t, env.h, `{"username":"no-such-user","password":"x"}`)
			if baseline.Code != http.StatusUnauthorized ||
				codeOf(t, baseline) != string(apierror.CodeInvalidCredentials) {
				t.Fatalf("前置：不存在的帳號應回 401/INVALID_CREDENTIALS，得 %d %s",
					baseline.Code, baseline.Body.String())
			}
			env.clearAudit(t)

			w := postRawLogin(t, env.h, tc.raw)
			if w.Code != http.StatusUnauthorized || codeOf(t, w) != string(apierror.CodeInvalidCredentials) {
				t.Fatalf("應回 401/INVALID_CREDENTIALS，得 %d %s", w.Code, w.Body.String())
			}
			if w.Body.String() != baseline.Body.String() {
				t.Fatalf("回應與不存在的帳號可區分：\n%s\n%s", baseline.Body.String(), w.Body.String())
			}

			rows := env.rows(t)
			if len(rows) != 1 {
				t.Fatalf("應留恰好一筆登入失敗審計列，得 %d 筆", len(rows))
			}
			row := rows[0]
			if row.Action != model.ActionLogin || row.Status != model.StatusFailure ||
				row.StatusCode != http.StatusUnauthorized {
				t.Fatalf("審計列不是 401 的登入失敗：%+v", row)
			}
			if !utf8.ValidString(row.Username) || strings.IndexFunc(row.Username, unicode.IsControl) >= 0 {
				t.Fatalf("審計列的帳號欄仍含無法落庫的字元：%q", row.Username)
			}
			if row.Username == "" {
				t.Fatal("審計列的帳號欄不應為空：要留下「送了什麼樣的帳號」的痕跡")
			}
		})
	}
}

// TestLoginNonASCIIUsernameUnaffected 字元判定只擋控制字元：非 ASCII 帳號照常登入。
func TestLoginNonASCIIUsernameUnaffected(t *testing.T) {
	env := setupAuthSourceEnv(t)
	rejectNULLikeProductionDB(t, env.db)
	if err := env.db.Model(&model.User{}).Where("id = ?", env.uid).
		Update("username", "王小明").Error; err != nil {
		t.Fatalf("改帳號名稱: %v", err)
	}
	w := postRawLogin(t, env.h, `{"username":"王小明","password":"`+authSrcPassword+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("非 ASCII 帳號＋正確密碼應登入成功，得 %d %s", w.Code, w.Body.String())
	}
	w = postRawLogin(t, env.h, `{"username":"王小明","password":"wrong-password"}`)
	if w.Code != http.StatusUnauthorized || codeOf(t, w) != string(apierror.CodeInvalidCredentials) {
		t.Fatalf("非 ASCII 帳號＋錯誤密碼應回 401/INVALID_CREDENTIALS，得 %d %s", w.Code, w.Body.String())
	}
}

func TestAuditableLoginUsername(t *testing.T) {
	cases := map[string]string{
		"admin":         "admin",
		"王小明":           "王小明",
		"admin\x00":     "admin�",
		"a\nb":          "a�b",
		"bad\xffbyte":   "bad�byte",
		"\x00\x01\x7f":  "���",
		"tab\there":     "tab�here",
		"c1\u0085value": "c1�value",
	}
	for in, want := range cases {
		if got := auditableLoginUsername(in); got != want {
			t.Errorf("auditableLoginUsername(%q) = %q，期望 %q", in, got, want)
		}
	}
}
