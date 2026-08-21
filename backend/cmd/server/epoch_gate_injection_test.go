package main

// 憑證世代閘的組裝根注入（modular-architecture W8 9.3／backlog B-32）。
//
// # 這支測試在防什麼
//
// `AuthService.epochDB()` 有兩條路：注入欄（`SetEpochGateDB`）與回退全域
// （`database.DB`）。兩條路在生產環境取到的是同一個 `*gorm.DB`，故**單看行為
// 分辨不出組裝根到底注入了沒有**——W8 初版就是這樣：四處文件宣稱「組裝根顯式
// 注入」，實際 `SetEpochGateDB` 全庫零呼叫者，生產一律靠回退默默補上，而沒有
// 任何測試會紅。
//
// 判別式：**把全域 `database.DB` 拔掉**再問世代閘。
//   - 有注入 ⇒ `epochDB()` 回注入欄，閘照常判定。
//   - 沒注入 ⇒ 回退取到 nil ⇒ `ErrEpochGateUnavailable`（fail-close）。
//
// 對照組（未注入的裸 `AuthService`）先跑，確認判別式本身會亮——否則主斷言
// 通過只證明「什麼都沒發生」。

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
)

// TestAssemblyInjectsEpochGateDB 組裝根建構的 AuthService，其世代閘取用的是
// 顯式注入的 DB，而非 identity 內部的全域回退。
func TestAssemblyInjectsEpochGateDB(t *testing.T) {
	env := newSealIntegrationEnv(t)

	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("初始化解封回 %d：%s", w.Code, w.Body.String())
	}

	snap := env.machine.Snapshot()
	g, ok := snap.Services.(*appGraph)
	if !ok || g == nil {
		t.Fatalf("服務圖型別為 %T，期望 *appGraph", snap.Services)
	}
	if g.deps.authService == nil {
		t.Fatal("服務圖上的 authService 為 nil")
	}

	// 取一個真實存在的使用者（seed 的管理者），並以其現行世代組出脈絡：
	// ProviderID 0 ⇒ 只走使用者維度，不需要任何 provider 列。
	var u model.User
	if err := database.DB.Order("id ASC").First(&u).Error; err != nil {
		t.Fatalf("讀取 seed 使用者失敗: %v", err)
	}
	authCtx := crypto.AuthContext{CredEpoch: u.CredentialEpoch}

	// 對照組：未經組裝根、未注入的 AuthService。
	bare := identity.NewAuthService(strings.Repeat("j", 48), time.Minute)

	real := database.DB
	database.DB = nil
	t.Cleanup(func() { database.DB = real })

	if err := bare.VerifyCredentialGenerationByUserID(authCtx, u.ID); !errors.Is(err, identity.ErrEpochGateUnavailable) {
		t.Fatalf("對照組（未注入）= %v，want ErrEpochGateUnavailable"+
			"——判別式不成立，本測試證明不了組裝根有沒有注入", err)
	}

	if err := g.deps.authService.VerifyCredentialGenerationByUserID(authCtx, u.ID); err != nil {
		t.Fatalf("組裝根建構的 AuthService 在全域 database.DB 被拔除後 = %v，want nil"+
			"——世代閘走的是回退全域，組裝根未顯式注入", err)
	}

	// 同一個 DB 才算「零行為變更」：注入的若是另一個句柄，世代不符會被判 stale。
	// 以「世代刻意錯開一格必被拒」反證閘確實讀到了 u 那一列。
	stale := crypto.AuthContext{CredEpoch: u.CredentialEpoch + 1}
	if err := g.deps.authService.VerifyCredentialGenerationByUserID(stale, u.ID); !errors.Is(err, identity.ErrCredentialGenerationStale) {
		t.Fatalf("世代錯開一格 = %v，want ErrCredentialGenerationStale"+
			"——注入的 DB 讀不到該使用者列", err)
	}
}
