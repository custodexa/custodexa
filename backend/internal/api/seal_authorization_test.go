package api

import (
	"context"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"io"
	"net/http/httptest"
	"testing"
	"time"
)

type unreadSealBody struct{ reads int }

func (b *unreadSealBody) Read(p []byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *unreadSealBody) Close() error               { return nil }

func TestRuntimeSealAuthorization(t *testing.T)   { testSealAuthorization(t, "/api/v1/seal/seal") }
func TestSealedRestoreAuthorization(t *testing.T) { testSealAuthorization(t, "/api/v1/seal/unseal") }
func testSealAuthorization(t *testing.T, path string) {
	for _, scenario := range []string{"anonymous", "scope", "expired", "revoked", "non-admin", "DB-unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			sqlDB, err := db.DB()
			if err != nil {
				t.Fatal(err)
			}
			sqlDB.SetMaxOpenConns(1)
			defer sqlDB.Close()
			if err = db.AutoMigrate(&model.User{}, &model.Role{}); err != nil {
				t.Fatal(err)
			}
			role := "admin"
			if scenario == "non-admin" {
				role = "user"
			}
			user := model.User{Username: "seal-fixture", Active: true, Roles: []model.Role{{Name: role}}}
			if err = db.Create(&user).Error; err != nil {
				t.Fatal(err)
			}
			manager := crypto.NewJWTManager("seal-authorization-test-key", time.Hour)
			token, err := manager.GenerateToken(user.ID, user.Username, "", role, crypto.AuthContext{})
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "anonymous":
				token = ""
			case "scope":
				token, err = manager.GenerateScopedToken(user.ID, user.Username, "", role, "mfa_pending", time.Hour, crypto.AuthContext{})
			case "expired":
				token, err = manager.GenerateScopedToken(user.ID, user.Username, "", role, "", -time.Hour, crypto.AuthContext{})
			case "revoked":
				err = db.Model(&user).Update("credential_epoch", 1).Error
			case "DB-unavailable":
				err = sqlDB.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			authorizer := identity.NewSealAuthorizer("seal-authorization-test-key", db)
			h := NewSealHandler(seal.NewUnsealed(nil), nil)
			h.SetAuthorizer("env", authorizer.Authorize)
			r := sourceTestRouter(t, h)
			body := &unreadSealBody{}
			req := httptest.NewRequest("POST", path, body)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			out := httptest.NewRecorder()
			r.ServeHTTP(out, req)
			if out.Code != 401 || body.reads != 0 {
				t.Fatalf("status=%d material_reads=%d", out.Code, body.reads)
			}
			t.Logf("%s: HTTP %d; material_reads=%d", scenario, out.Code, body.reads)
		})
	}
	// **語義變更（委託拓撲與憑證改由介面管理）**：`ui` 模式的解封
	// 自本版起也要求解封授權脈絡。改前這裡守的是「ui 匿名解封不經 Bearer 授權器」
	// ——那條性質仍成立（Bearer 授權器不被呼叫），但「匿名可送出」已被明確推翻：
	// 三模式一律先過管理者帳密，解封頁在那之後才顯示材料或憑證欄位。
	// 故本案改守兩件事：無脈絡即 401 且不觸及材料；帶有效脈絡即放行且**仍不**
	// 呼叫 Bearer 授權器（兩套授權不互相代償）。
	t.Run("ui-requires-grant", func(t *testing.T) {
		h := NewSealHandler(seal.NewUnsealed(nil), nil)
		calls := 0
		h.SetAuthorizer("ui", func(context.Context, string) (uint, error) { calls++; return 0, nil })
		r := sourceTestRouter(t, h)

		body := &unreadSealBody{}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/seal/unseal", body))
		if w.Code != 401 || body.reads != 0 {
			t.Fatalf("無脈絡的 ui 解封應 401 且不讀材料：status=%d material_reads=%d", w.Code, body.reads)
		}

		grants := NewSealGrantStore(0)
		h.SetSealAuthorization(grants, func(string, []byte) (uint, error) { return 1, nil })
		grant, _, err := grants.Issue(1, "admin")
		if err != nil {
			t.Fatal(err)
		}
		w2 := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/seal/unseal", nil)
		req.Header.Set("Authorization", "SealGrant "+grant)
		r.ServeHTTP(w2, req)
		if w2.Code == 401 {
			t.Fatalf("帶有效脈絡的 ui 解封仍被拒：status=%d", w2.Code)
		}
		if calls != 0 {
			t.Fatalf("解封脈絡不得經 Bearer 授權器驗證：calls=%d", calls)
		}
		t.Logf("ui unseal: no-grant=401(reads=0) with-grant=%d bearer_authorizer_calls=%d", w2.Code, calls)
	})
}
