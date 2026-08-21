package identity_test

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
)

// TestSessionCallSitesPassProviderAndUserInOrder session 的兩個跨模組呼叫點
// SHALL 把 providerID 與 userID 放在 `identity.WithCapabilityLocks` 的正確位置
// （`internal/modules/session/session_provider_termination.go` 的
// `SessionService.CreateWithGenerationGuard` 與 `JoinWithGenerationGuard`）。
//
// # 為何需要這一格（modular-architecture W9 10.3）
//
// 兩個引數同為 `uint`，**對調不會編譯失敗**；而鎖內的判定（重讀使用者、世代閘）
// 完全不看鎖是用哪個 key 取的，故對調後**既有測試無一轉紅**：
// 世代閘照樣攔、停用照樣掃、`TestCapabilityLockOrderingHasNoDeadlock` 因為
// 是直呼 `WithCapabilityLocks` 而完全繞過這兩個呼叫點。真正壞掉的是序列化本身
// ——provider 停用（持 provider 鎖）與兌換（誤持以 userID 為 key 的 provider 鎖）
// 不再互斥，3.8b 的 TOCTOU 窗口就此重開。
//
// 搬包波正是這種對調最容易發生的時候（呼叫點連同整個檔案換包、簽名以套件限定詞
// 重寫），故本波把它釘住。
//
// 判別式是**鎖的 key 身分**而非計時：於鎖內（`join` 回呼／pre-write 同步點）探測
// 四把鎖的持有狀態，正確配置下 `provider[P]` 與 `user[U]` 為持有、
// 而以角色互換的 key 取的 `provider[U]`／`user[P]` 必為未持有。
func TestSessionCallSitesPassProviderAndUserInOrder(t *testing.T) {
	db := revocationDB(t)
	env := newRevocationEnv(t, db)
	dto := seedRevocationProvider(t, env, "cid-lock-args")
	// 先建一個佔位使用者，使受測者的 userID 與 providerID 必不相同
	// （兩者都由各自的表自 1 起自增；同值時本測試的判別式失效，見下方前提檢查）
	seedRevocationUser(t, db, "lock-arg-filler")
	u := seedRevocationUser(t, db, "lock-arg-user")
	base := reloadProvider(t, db, dto.ID).AuthEpoch

	if dto.ID == u.ID {
		// 兩個 ID 相同時「以角色互換的 key」與正確 key 是同一把鎖，判別式失效
		t.Fatalf("前提不成立：providerID 與 userID 同為 %d，本測試無從分辨鎖的 key 身分", dto.ID)
	}

	authCtx := crypto.AuthContext{
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: dto.ID, AuthEpoch: base,
	}

	// probe 於鎖內取樣四把鎖的持有狀態
	type sample struct{ pP, uU, pU, uP bool }
	probe := func() sample {
		return sample{
			pP: identity.ProviderLockHeldForTest(dto.ID),
			uU: identity.UserCredentialLockHeldForTest(u.ID),
			pU: identity.ProviderLockHeldForTest(u.ID),
			uP: identity.UserCredentialLockHeldForTest(dto.ID),
		}
	}
	check := func(t *testing.T, site string, got sample) {
		t.Helper()
		if !got.pP {
			t.Errorf("%s：鎖內未持有 provider[%d] 鎖——providerID 沒有被當成 provider 引數傳入",
				site, dto.ID)
		}
		if !got.uU {
			t.Errorf("%s：鎖內未持有 user[%d] 鎖——userID 沒有被當成 user 引數傳入", site, u.ID)
		}
		if got.pU || got.uP {
			t.Errorf("%s：鎖內持有了角色互換的 key（provider[%d]=%v／user[%d]=%v）——"+
				"providerID 與 userID 在呼叫點被對調，序列化保護的對象因此錯位",
				site, u.ID, got.pU, dto.ID, got.uP)
		}
	}

	t.Run("JoinWithGenerationGuard", func(t *testing.T) {
		var got sample
		joined, err := session.JoinWithGenerationGuard(authCtx, u.ID, func() bool {
			got = probe()
			return true
		})
		if err != nil || !joined {
			t.Fatalf("Join 應成功（本測試的前提不成立）: joined=%v err=%v", joined, err)
		}
		check(t, "JoinWithGenerationGuard", got)
	})

	t.Run("CreateWithGenerationGuard", func(t *testing.T) {
		var got sample
		var fired int
		identity.SetPreWriteHookForTest(func(site string) {
			if site == identity.OIDCSiteSessionCreate {
				fired++
				got = probe()
			}
		})
		t.Cleanup(func() { identity.SetPreWriteHookForTest(nil) })

		assetID := uint(1)
		pid := dto.ID
		sess := &model.Session{
			SessionID: "sess-lock-args", UserID: u.ID, AssetID: &assetID,
			Protocol: model.ProtocolSSH, StartTime: time.Now(), AuthEpoch: base,
			AuthProviderID: &pid,
		}
		if err := env.sessions.CreateWithGenerationGuard(authCtx, sess); err != nil {
			t.Fatalf("建 session 應成功（本測試的前提不成立）: %v", err)
		}
		if fired != 1 {
			t.Fatalf("鎖內同步點應恰觸發 1 次，實得 %d 次：取樣點沒被執行到，"+
				"下面的斷言會在空樣本上假綠", fired)
		}
		check(t, "CreateWithGenerationGuard", got)
	})
}
