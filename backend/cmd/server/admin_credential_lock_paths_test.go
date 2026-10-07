package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
)

// 以管理員帳密驗證的三條組裝根路徑，對既有帳號鎖定的唯讀尊重。
//
// 三條路徑共用 identity.VerifyInitialAdminCredential，鎖定判定在那裡（由
// identity 套件的 initial_admin_verifier_lock_test.go 逐條守）。本檔守的是
// **路徑真的接到那個判定**：每條各一組「鎖定中＋正確密碼即拒」與「未鎖定即通過」，
// 後者證明拒絕來自鎖定，而不是夾具本身就過不去。

func lockAdminUntil(t *testing.T, db *gorm.DB, username string, until *time.Time) {
	t.Helper()
	res := db.Model(&model.User{}).Where("username = ?", username).Update("locked_until", until)
	if res.Error != nil || res.RowsAffected != 1 {
		t.Fatalf("設定 %s 的 locked_until 失敗：err=%v rows=%d", username, res.Error, res.RowsAffected)
	}
}

// TestInstanceGuardHaltConfirmRejectsLockedAdmin 攔下頁確認：鎖定中的管理員即使三要件皆對也被拒，
// 回應與帳密錯相同，且守衛狀態不變。
func TestInstanceGuardHaltConfirmRejectsLockedAdmin(t *testing.T) {
	db := installHaltAdminDB(t)
	code := installHaltGuard(t)
	future := time.Now().Add(30 * time.Minute)
	lockAdminUntil(t, db, "halt-admin", &future)

	res := instanceGuardHaltConfirm(db, api.InstanceGuardAckRequest{
		ConfirmedPrimaryDown: true, Code: code, Username: "halt-admin", Password: haltAdminPassword})
	if res.Outcome != api.AckOutcomeInvalidCredential {
		t.Fatalf("鎖定中的管理員 MUST 被拒且與帳密錯同一結果，實得 %s", res.Outcome)
	}
	if st := database.InstanceGuardSnapshot().State; st != database.GuardStateHalted {
		t.Fatalf("被拒的確認不得改變守衛狀態，實得 %s", st)
	}

	// 鎖定到期後同一組輸入即被接受：拒絕確實來自鎖定。
	past := time.Now().Add(-time.Minute)
	lockAdminUntil(t, db, "halt-admin", &past)
	res = instanceGuardHaltConfirm(db, api.InstanceGuardAckRequest{
		ConfirmedPrimaryDown: true, Code: code, Username: "halt-admin", Password: haltAdminPassword})
	if res.Outcome != api.AckOutcomeAccepted {
		t.Fatalf("鎖定到期後三要件相符 MUST 接受，實得 %s", res.Outcome)
	}
}

// TestDelegatedBootstrapRejectsLockedAdmin 委託模式全新安裝：鎖定中的初始管理員不得宣告主金鑰。
func TestDelegatedBootstrapRejectsLockedAdmin(t *testing.T) {
	db := bootstrapTestDB(t)
	future := time.Now().Add(30 * time.Minute)
	lockAdminUntil(t, db, bootstrapAdminUser, &future)

	built := 0
	s1 := bootstrapStage1(t, vaulttransit.ProviderVault, func(context.Context, *credentialOwner) (crypto.KEKProvider, error) {
		built++
		return bootstrapFakeProvider{}, nil
	})
	pending := &bootstrapPendingState{}
	v, err := verifyDelegatedUnseal(context.Background(), s1, []byte(bootstrapVaultBody()), pending)
	if err == nil {
		v.credentials.Close()
		t.Fatal("鎖定中的初始管理員 MUST NOT 通過全新安裝的驗證段")
	}
	if !errors.Is(err, identity.ErrSealInitialAdminInvalid) {
		t.Fatalf("拒絕應為憑證不符（與密碼錯同一錯誤），得 %v", err)
	}
	if armed, _ := pending.snapshot(); armed {
		t.Fatal("被拒的請求不得武裝初始化待決")
	}
	if built != 0 {
		t.Fatalf("帳密未過不得以輸入憑證建構保管處連線，實際建構 %d 次", built)
	}

	// 解除鎖定後同一請求即通過：拒絕確實來自鎖定。
	lockAdminUntil(t, db, bootstrapAdminUser, nil)
	v, err = verifyDelegatedUnseal(context.Background(), s1, []byte(bootstrapVaultBody()), &bootstrapPendingState{})
	if err != nil {
		t.Fatalf("未鎖定時全新安裝的驗證段應通過: %v", err)
	}
	v.credentials.Close()
}

// TestInitializeUnsealRejectsLockedAdmin 本地材料的初始化解封：鎖定中的初始管理員不得宣告主金鑰。
func TestInitializeUnsealRejectsLockedAdmin(t *testing.T) {
	db := bootstrapTestDB(t)
	body := fmt.Sprintf(`{"kek":%q,"kek_confirm":%q,"confirm_saved":true,"username":%q,"password":%q}`,
		testInitialKEK, testInitialKEK, bootstrapAdminUser, bootstrapAdminPassword)
	decode := func() *api.SealUnsealPayload {
		t.Helper()
		p, err := api.DecodeSealMaterial([]byte(body))
		if err != nil {
			t.Fatalf("前置：請求體解析失敗: %v", err)
		}
		t.Cleanup(p.Zeroize)
		return p
	}

	future := time.Now().Add(30 * time.Minute)
	lockAdminUntil(t, db, bootstrapAdminUser, &future)
	v, err := verifyInitializeUnseal(decode())
	if err == nil {
		v.owner.Destroy()
		t.Fatal("鎖定中的初始管理員 MUST NOT 通過初始化解封")
	}
	if !errors.Is(err, identity.ErrSealInitialAdminInvalid) {
		t.Fatalf("拒絕應為憑證不符（與密碼錯同一錯誤），得 %v", err)
	}

	lockAdminUntil(t, db, bootstrapAdminUser, nil)
	v, err = verifyInitializeUnseal(decode())
	if err != nil {
		t.Fatalf("未鎖定時初始化解封的驗證應通過: %v", err)
	}
	if !v.bootstrap || v.adminUsername != bootstrapAdminUser {
		t.Fatalf("應標示為初始化路徑並記下宣告者: %+v", v)
	}
	v.owner.Destroy()
}
