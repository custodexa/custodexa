package api

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/identity"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 錄影 token 簽發的序列化世代閘。
//
// 缺陷：簽發完全不看世代，也不與撤銷序列化。攻擊窗如下——
//
//	舊請求通過 AuthMiddleware（世代仍有效）→ 執行緒暫停 →
//	管理者停用帳號／provider，RevokeByUser／RevokeByProvider 掃完整張表 →
//	舊請求才簽出新 token → 該 token 錯過掃描，可讀錄影達 120 秒。
//
// 錄影是全系統最敏感的稽核資產（完整終端畫面、憑證輸入、跳板後的一切操作），
// 120 秒的殘留窗口不可接受。
//
// 修法採**鎖內簽發**而非「簽發時現查 DB 世代」：後者只把窗口從 120 秒縮到
// 一次 DB 往返，並未關閉——現查通過後仍可能停在掃描之後才寫入 map。
// 鎖內簽發使兩種交錯都安全：
//
//	簽發先取到鎖 → 寫入 map 發生在撤銷取鎖之前，故必在其（鎖外）掃描之前 → 被掃到。
//	撤銷先取到鎖 → 世代已推進並提交，簽發於鎖內重讀即拒。
//
// 本檔逐條釘住這三件事：世代不符要拒、provider 停用要拒、簽發確實在鎖內。

// bumpCredEpoch 直接改 DB 模擬「帳號停用／解綁等推進 credential_epoch 的操作」，
// 不經 service——本檔要驗的是簽發側的判定，不是推進側的流程
func bumpCredEpoch(t *testing.T, db *gorm.DB, userID uint) {
	t.Helper()
	if err := db.Model(&model.User{}).Where("id = ?", userID).
		UpdateColumn("credential_epoch", gorm.Expr("credential_epoch + 1")).Error; err != nil {
		t.Fatalf("推進 credential_epoch: %v", err)
	}
}

func (e *recTokenEnv) grantCount() int {
	e.mgr.mu.Lock()
	defer e.mgr.mu.Unlock()
	return len(e.mgr.grants)
}

// TestRecordingTokenIssueRejectsStaleCredEpoch 使用者憑證世代已推進 → 不得簽出。
//
// 這一格對應「停用／解綁後，手上仍握著舊 access token 的人來要錄影 token」
func TestRecordingTokenIssueRejectsStaleCredEpoch(t *testing.T) {
	env := setupRecordingTokenEnv(t)
	uid := env.seedPlainUser(t, "stale-cred")
	stale := crypto.AuthContext{} // 簽發當下 claims 帶的是 cred_epoch=0

	bumpCredEpoch(t, env.db, uid)

	tok, err := env.mgr.Issue(uid, 100, "stale-cred", stale)

	if err == nil {
		t.Errorf("世代已推進仍簽出 token %q——撤銷後 120 秒的錄影讀取窗口未關閉", tok)
	}
	if n := env.grantCount(); n != 0 {
		t.Errorf("拒發時不得留下任何 grant，表內尚有 %d 筆", n)
	}
}

// TestRecordingTokenIssueRejectsDisabledProvider provider 已停用 → 不得簽出。
//
// 與 cred_epoch 是兩個獨立維度：只驗其中一維，另一維的撤銷就對簽發無效
func TestRecordingTokenIssueRejectsDisabledProvider(t *testing.T) {
	env := setupRecordingTokenEnv(t)
	pid := env.seedProvider(t, "cid-disabled")
	uid := env.seedPlainUser(t, "victim-provider")
	issued := crypto.AuthContext{AuthMethod: crypto.AuthMethodOIDC, ProviderID: pid}

	enabled := false
	if _, err := env.providers.Update(pid, &identity.OIDCProviderRequest{Enabled: &enabled}); err != nil {
		t.Fatalf("停用 provider: %v", err)
	}

	tok, err := env.mgr.Issue(uid, 100, "victim-provider", issued)

	if err == nil {
		t.Errorf("provider 已停用仍簽出 token %q", tok)
	}
	if n := env.grantCount(); n != 0 {
		t.Errorf("拒發時不得留下任何 grant，表內尚有 %d 筆", n)
	}
}

// TestRecordingTokenIssueAcceptsCurrentGeneration 誤傷防護：世代相符即應簽出。
// 沒有這一格，「一律拒發」也會讓上面兩格全綠
func TestRecordingTokenIssueAcceptsCurrentGeneration(t *testing.T) {
	env := setupRecordingTokenEnv(t)
	pid := env.seedProvider(t, "cid-ok")
	uid := env.seedPlainUser(t, "healthy")

	tok, err := env.mgr.Issue(uid, 100, "healthy", crypto.AuthContext{
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: pid})
	if err != nil {
		t.Fatalf("世代相符卻拒發: %v", err)
	}
	if _, ok := env.mgr.Resolve(tok); !ok {
		t.Error("簽出的 token 應可兌換")
	}
}

// TestRecordingTokenIssueRunsInsideCapabilityLock 序列化本身的守衛。
//
// 前兩格只證明「簽發會看世代」——那用一次鎖外現查也能通過，而現查關不掉窗口
// （讀到有效 → 撤銷掃描跑完 → 才寫入 map）。本格改為斷言**互斥**：
// 外部持有同一把 user capability lock 期間，Issue 必須阻塞。
//
// 這是確定性的（不靠時間競賽製造交錯），把「改回鎖外現查」的突變擋在門外
func TestRecordingTokenIssueRunsInsideCapabilityLock(t *testing.T) {
	env := setupRecordingTokenEnv(t)
	uid := env.seedPlainUser(t, "lock-probe")

	held := make(chan struct{})
	release := make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- identity.WithCapabilityLocks(database.DB, 0, uid, func(tx *gorm.DB) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	issueDone := make(chan error, 1)
	go func() {
		_, err := env.mgr.Issue(uid, 100, "lock-probe", crypto.AuthContext{})
		issueDone <- err
	}()

	select {
	case err := <-issueDone:
		t.Fatalf("持有 user capability lock 期間 Issue 仍完成（err=%v）——"+
			"簽發未於鎖內進行，撤銷掃描與簽發之間的競態窗口仍在", err)
	case <-time.After(200 * time.Millisecond):
		// 預期：被鎖擋住
	}

	close(release)
	if err := <-lockDone; err != nil {
		t.Fatalf("外部持鎖流程失敗: %v", err)
	}
	select {
	case err := <-issueDone:
		if err != nil {
			t.Fatalf("釋放鎖後 Issue 應成功: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("釋放鎖後 Issue 未在時限內完成（可能死鎖）")
	}
}

// TestRecordingTokenIssueSurfacesStaleAsTypedError 拒發成因須可被呼叫端辨識，
// handler 才能回 401（憑證已撤銷、請重新登入）而不是 500
func TestRecordingTokenIssueSurfacesStaleAsTypedError(t *testing.T) {
	env := setupRecordingTokenEnv(t)
	uid := env.seedPlainUser(t, "typed-error")
	bumpCredEpoch(t, env.db, uid)

	_, err := env.mgr.Issue(uid, 100, "typed-error", crypto.AuthContext{})

	if !errors.Is(err, identity.ErrCredentialGenerationStale) {
		t.Errorf("拒發應回 ErrCredentialGenerationStale（供 handler 映射 401），實得 %v", err)
	}
}
