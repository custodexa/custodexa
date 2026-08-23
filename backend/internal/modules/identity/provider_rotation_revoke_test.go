package identity_test

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/session"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// client secret 輪替的終斷語義。
//
// 既有的 TestProviderSecretRotationTriggersRevocation 已驗「輪替走五管道」，
// 但它從未讓任何訂閱**真的存在**過——fakeProviderHub 的 observers 集合是空的，
// 斷言只看 sweptProviders 有沒有被呼叫過。那擋得住「忘了呼叫」，擋不住
// 「呼叫了但述詞寫錯而一個也沒收到」。
//
// 本檔補三塊：
//
//	既有訂閱真的被逐出   輪替前先 join，輪替後斷言集合已清空且對照組完好
//	既有連線不因已建立而存活   進行中會話與其鎖外關閉逐一斷言
//	輪替不是萬用終斷      非輪替更新（改名、空白密鑰）不得誤殺任何連線與訂閱
//
// 突變自檢：把 oidc_provider_service.go 的
// `secretRotated := strings.TrimSpace(req.ClientSecret) != ""` 改成
// `req.ClientSecret != ""`，TestNonRotationUpdateTerminatesNothing 的空白密鑰格轉紅；
// 把 needsInvalidation 改成只看 disabling，本檔前兩個測試全紅。

// TestSecretRotationEvictsEstablishedSubscriptions 4.14h：
// 輪替前已建立的監看／分享訂閱必須被逐出，且只逐出該 provider 的。
//
// 訂閱不建 sessions 列，會話掃描完全掃不到它；而訂閱一旦建立就不再出示憑證，
// 對世代閘免疫——「連線已經建立」正是它得以存活的藉口，本測試就是要拆掉那個藉口
func TestSecretRotationEvictsEstablishedSubscriptions(t *testing.T) {
	db := revocationDB(t)
	env := newRevocationEnv(t, db)
	victim := seedRevocationProvider(t, env, "cid-rot-sub")
	other := seedRevocationProvider(t, env, "cid-rot-other")

	// 輪替前既有的三類訂閱
	env.hub.join(victim.ID)
	env.hub.join(victim.ID)
	env.hub.join(other.ID)
	env.hub.join(0) // 本地登入的觀察者（providerID=0 不是萬用字元）

	if _, err := env.svc.Update(victim.ID, &identity.OIDCProviderRequest{ClientSecret: "rotated-secret"}); err != nil {
		t.Fatalf("密鑰輪替: %v", err)
	}

	if n := env.hub.remaining(victim.ID); n != 0 {
		t.Errorf("輪替後該 provider 仍有 %d 個訂閱存活", n)
	}
	if n := env.hub.remaining(other.ID); n != 1 {
		t.Errorf("他 provider 的訂閱不應被牽連，實得剩餘 %d", n)
	}
	if n := env.hub.remaining(0); n != 1 {
		t.Errorf("本地登入的訂閱不應被牽連，實得剩餘 %d", n)
	}
	if swept := env.hub.sweptProviders(); len(swept) != 1 || swept[0] != victim.ID {
		t.Errorf("訂閱收線目標 = %v, want [%d]", swept, victim.ID)
	}
}

// TestSecretRotationTerminatesEstablishedProtocolSessions 4.14h：
// 輪替前建立的協議連線被終斷，且鎖外確有關閉 WS。
//
// 與既有測試的差別在對照組：他 provider 與本地會話必須完好，
// 否則「輪替＝全站斷線」也會讓五管道的斷言全綠
func TestSecretRotationTerminatesEstablishedProtocolSessions(t *testing.T) {
	db := revocationDB(t)
	env := newRevocationEnv(t, db)
	victim := seedRevocationProvider(t, env, "cid-rot-sess")
	other := seedRevocationProvider(t, env, "cid-rot-sess-other")
	base := reloadProvider(t, db, victim.ID).AuthEpoch
	otherBase := reloadProvider(t, db, other.ID).AuthEpoch
	u := seedRevocationUser(t, db, "mixed-rot")

	doomed := seedSession(t, db, u.ID, victim.ID, base, "sess-rot-victim")
	survivor := seedSession(t, db, u.ID, other.ID, otherBase, "sess-rot-other")
	local := seedSession(t, db, u.ID, 0, 0, "sess-rot-local")
	seedRefresh(t, db, u.ID, victim.ID, "hash-rot-victim")
	seedRefresh(t, db, u.ID, 0, "hash-rot-local")

	if _, err := env.svc.Update(victim.ID, &identity.OIDCProviderRequest{ClientSecret: "rotated-secret"}); err != nil {
		t.Fatalf("密鑰輪替: %v", err)
	}

	if s := reloadRevocationSession(t, db, doomed.ID); s.Status != model.SessionStatusDisconnected {
		t.Errorf("輪替後該 provider 的會話狀態 = %q, want %q", s.Status, model.SessionStatusDisconnected)
	}
	if closed := env.registry.closedIDs(); len(closed) != 1 || closed[0] != doomed.ID {
		t.Errorf("鎖外實際關閉的會話 = %v, want [%d]", closed, doomed.ID)
	}
	if s := reloadRevocationSession(t, db, survivor.ID); s.Status != model.SessionStatusActive {
		t.Errorf("他 provider 的會話不應被牽連: status=%q", s.Status)
	}
	if s := reloadRevocationSession(t, db, local.ID); s.Status != model.SessionStatusActive {
		t.Errorf("本地會話不應被牽連: status=%q", s.Status)
	}
	if r := reloadRefresh(t, db, "hash-rot-victim"); r.RevokedAt == nil {
		t.Error("該 provider 的 refresh 應被撤銷")
	} else if r.RevokedReason != model.RefreshRevokeProviderDisabled {
		t.Errorf("撤銷成因 = %q, want %q", r.RevokedReason, model.RefreshRevokeProviderDisabled)
	}
	if r := reloadRefresh(t, db, "hash-rot-local"); r.RevokedAt != nil {
		t.Error("本地 refresh 不應被輪替牽連")
	}
	// 輪替不停用：provider 仍可用，故「憑證失效」不可能是靠 enabled=false 達成的
	if p := reloadProvider(t, db, victim.ID); !p.Enabled {
		t.Error("密鑰輪替不應順帶停用 provider")
	} else if p.AuthEpoch <= base {
		t.Errorf("auth_epoch 未推進: %d → %d", base, p.AuthEpoch)
	}
}

// TestSecretRotationBlocksPreRotationCapabilityCreation 4.14h：
// 輪替前簽發的憑證不得再產生新的長效能力（訂閱 Join）。
//
// 上兩個測試處理「已存在的」；這一格處理「輪替後才送達、但持輪替前憑證的」——
// 收線掃描早已跑完，此類請求只剩世代閘擋得住。provider 仍 enabled，故這一格
// 只可能靠 auth_epoch 比對通過或失敗
func TestSecretRotationBlocksPreRotationCapabilityCreation(t *testing.T) {
	db := revocationDB(t)
	env := newRevocationEnv(t, db)
	p := seedRevocationProvider(t, env, "cid-rot-guard")
	u := seedRevocationUser(t, db, "guard-user")

	before := reloadProvider(t, db, p.ID)
	authCtx := crypto.AuthContext{
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: p.ID, AuthEpoch: before.AuthEpoch,
	}

	// 正向對照：輪替前同一份脈絡可以建立訂閱（否則本測試恆綠而無意義）
	joined, err := session.JoinWithGenerationGuard(authCtx, u.ID, func() bool { return true })
	if err != nil || !joined {
		t.Fatalf("輪替前應可建立訂閱: joined=%v err=%v", joined, err)
	}

	if _, err := env.svc.Update(p.ID, &identity.OIDCProviderRequest{ClientSecret: "rotated-secret"}); err != nil {
		t.Fatalf("密鑰輪替: %v", err)
	}

	joined, err = session.JoinWithGenerationGuard(authCtx, u.ID, func() bool { return true })
	if !errors.Is(err, identity.ErrCredentialGenerationStale) {
		t.Fatalf("輪替後持舊脈絡建立訂閱應被拒: err=%v", err)
	}
	if joined {
		t.Fatal("世代閘拒絕時不得已完成 Join")
	}
	// provider 仍啟用：拒絕確實來自世代比對而非 enabled 旗標
	if after := reloadProvider(t, db, p.ID); !after.Enabled {
		t.Error("前提不成立：輪替不應停用 provider")
	}
}

// TestNonRotationUpdateTerminatesNothing 4.14h 的反面：
// 不涉及輪替與停用的更新不得終斷任何東西。
//
// 缺這格時「每次更新都全面失效」也會讓上面三個測試全綠，而那會讓管理者連改個
// 顯示名稱都踢掉全部使用者——輪替的終斷力道必須恰好落在輪替上
func TestNonRotationUpdateTerminatesNothing(t *testing.T) {
	cases := map[string]*identity.OIDCProviderRequest{
		"僅改名":      {Name: "renamed"},
		"空白密鑰不算輪替": {ClientSecret: "   "},
	}
	for label, req := range cases {
		t.Run(label, func(t *testing.T) {
			db := revocationDB(t)
			env := newRevocationEnv(t, db)
			p := seedRevocationProvider(t, env, "cid-noop-"+label)
			base := reloadProvider(t, db, p.ID).AuthEpoch
			u := seedRevocationUser(t, db, "noop-user")

			sess := seedSession(t, db, u.ID, p.ID, base, "sess-noop")
			seedRefresh(t, db, u.ID, p.ID, "hash-noop")
			env.hub.join(p.ID)

			if _, err := env.svc.Update(p.ID, req); err != nil {
				t.Fatalf("更新: %v", err)
			}

			if after := reloadProvider(t, db, p.ID); after.AuthEpoch != base {
				t.Errorf("非輪替更新不應推進世代: %d → %d", base, after.AuthEpoch)
			}
			if s := reloadRevocationSession(t, db, sess.ID); s.Status != model.SessionStatusActive {
				t.Errorf("非輪替更新不應終斷會話: status=%q", s.Status)
			}
			if r := reloadRefresh(t, db, "hash-noop"); r.RevokedAt != nil {
				t.Error("非輪替更新不應撤銷 refresh")
			}
			if n := env.hub.remaining(p.ID); n != 1 {
				t.Errorf("非輪替更新不應收線訂閱，實得剩餘 %d", n)
			}
			if calls := env.tokens.called(); len(calls) != 0 {
				t.Errorf("非輪替更新不應撤銷錄影 token，實得 %v", calls)
			}
		})
	}
}

// TestRotationInvalidationReasonIsDistinct 4.14h：失效成因機器碼可區分。
//
// 停用與輪替走同一套管道，事後追查「這批連線為什麼斷」只剩 reason 這一個線索；
// 兩者共用同一個字串即等於稽核上分不出成因
func TestRotationInvalidationReasonIsDistinct(t *testing.T) {
	cases := []struct {
		disabling, rotated bool
		want               string
	}{
		{false, true, "provider_secret_rotated"},
		{true, false, "provider_disabled"},
		{true, true, "provider_disabled_and_secret_rotated"},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		got := invalidationReason(c.disabling, c.rotated)
		if got != c.want {
			t.Errorf("invalidationReason(%v, %v) = %q, want %q", c.disabling, c.rotated, got, c.want)
		}
		if seen[got] {
			t.Errorf("成因 %q 重複，三種情形須可區分", got)
		}
		seen[got] = true
	}
}
