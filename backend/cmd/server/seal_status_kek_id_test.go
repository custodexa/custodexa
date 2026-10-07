package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
)

// /seal/status 的 kek_id 在真的段 2 上與金鑰清冊同源。
//
// internal/api 的單元案例以假服務圖驗「哪些狀態回、哪些不回」；本檔跑真的段 2，
// 驗組裝根的服務圖確實提供識別，且值與管理介面金鑰清冊的 kek_id 是同一個——
// 少了這一層，介面斷言在正式路徑上失敗時欄位會靜默缺席而單元案例照樣全綠。

// sealStatusBody 經當前生效的 router 讀 /seal/status。
func sealStatusBody(t *testing.T, e *sealIntegrationEnv) map[string]any {
	t.Helper()
	w := e.do(http.MethodGet, "/api/v1/seal/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("/seal/status 回 %d：%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("/seal/status 回應非 JSON: %v", err)
	}
	return body
}

// inventoryKEKID 以初始管理員身分讀金鑰清冊的 kek_id。
func inventoryKEKID(t *testing.T, e *sealIntegrationEnv) string {
	t.Helper()
	var admin model.User
	if err := database.DB.Where("username = ?", testAdminUser).First(&admin).Error; err != nil {
		t.Fatalf("讀取初始管理員失敗: %v", err)
	}
	email := ""
	if admin.Email != nil {
		email = *admin.Email
	}
	token, err := crypto.NewJWTManager(e.s1.cfg.Security.JWTSecret, time.Hour).
		GenerateToken(admin.ID, admin.Username, email, "admin", crypto.AuthContext{})
	if err != nil {
		t.Fatalf("簽發管理員 token 失敗: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	e.swap.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("金鑰清冊回 %d：%s", w.Code, w.Body.String())
	}
	var inv struct {
		KEKID string `json:"kek_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &inv); err != nil {
		t.Fatalf("金鑰清冊回應非 JSON: %v", err)
	}
	if inv.KEKID == "" {
		t.Fatal("前置：金鑰清冊的 kek_id 為空")
	}
	return inv.KEKID
}

func TestSealStatusKEKIDMatchesRuntimeProvider(t *testing.T) {
	t.Run("ui 解封前無欄位、解封後等於金鑰清冊 kek_id", func(t *testing.T) {
		e := newSealIntegrationEnv(t)

		before := sealStatusBody(t, e)
		if before["state"] != string(seal.StateSealed) {
			t.Fatalf("前置：狀態為 %v，期望 sealed", before["state"])
		}
		if v, ok := before["kek_id"]; ok {
			t.Fatalf("封存中回了 kek_id=%v", v)
		}

		if w := e.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
			t.Fatalf("初始化解封回 %d：%s", w.Code, w.Body.String())
		}
		after := sealStatusBody(t, e)
		if after["state"] != string(seal.StateUnsealed) {
			t.Fatalf("前置：狀態為 %v，期望 unsealed", after["state"])
		}
		want := inventoryKEKID(t, e)
		if got := after["kek_id"]; got != want {
			t.Fatalf("解封後 /seal/status kek_id=%v，金鑰清冊 kek_id=%s，兩者應同源", got, want)
		}
	})

	t.Run("env 啟動後等於材料指紋", func(t *testing.T) {
		e, _, _ := modeFixture(t, "env")
		// 與組裝根的 env 啟動路徑相同：固定來源鍵直呼狀態機，再換上段 2 router。
		result, err := e.machine.Unseal(context.Background(), seal.UnsealRequest{
			SourceKey:    "startup",
			SourceDigest: fmt.Sprintf("%x", sha256.Sum256([]byte("startup"))),
		})
		if err != nil {
			t.Fatalf("env 啟動解封失敗: %v", err)
		}
		publishStage2(result.Services, e.machine, e.swap, e.s1.journal, &bootstrapPendingState{})

		key, reason := config.DecodeKEKMaterialKey(testInitialKEK)
		if reason != "" {
			t.Fatalf("前置：測試材料無法解碼：%s", reason)
		}
		want := crypto.Fingerprint(key)
		st := sealStatusBody(t, e)
		if st["state"] != string(seal.StateUnsealed) {
			t.Fatalf("前置：狀態為 %v，期望 unsealed", st["state"])
		}
		if got := st["kek_id"]; got != want {
			t.Fatalf("env 啟動後 kek_id=%v，期望設定檔材料解碼後的指紋 %s", got, want)
		}
		if inv := inventoryKEKID(t, e); inv != want {
			t.Fatalf("金鑰清冊 kek_id=%s 與材料指紋 %s 不符", inv, want)
		}
	})
}
