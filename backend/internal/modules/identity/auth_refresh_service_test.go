package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// loginForRefresh 走完整登入流程取得 refresh 憑證（重用 lockout 測試的 sqlite 環境）
func loginForRefresh(t *testing.T, auth *AuthService, username, password string) *LoginResponse {
	t.Helper()
	resp, err := auth.Login(&LoginRequest{Username: username, Password: password})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if resp.RefreshToken == "" {
		t.Fatal("登入回應應含 refresh_token")
	}
	return resp
}

// TestRefreshRotationAndReuseDetection 刷新輪替＋已輪替憑證重放觸發家族撤銷（RFC 9700）
func TestRefreshRotationAndReuseDetection(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")

	first := loginForRefresh(t, auth, "bob", "right-pass-1")

	// 正常刷新：換發新 access 與新 refresh，且與舊值不同
	rotated, err := auth.RefreshSession(first.RefreshToken)
	if err != nil {
		t.Fatalf("刷新 = %v, want nil", err)
	}
	if rotated.Token == "" || rotated.RefreshToken == "" {
		t.Fatal("刷新應回新 access 與新 refresh")
	}
	if rotated.RefreshToken == first.RefreshToken {
		t.Fatal("rotation 應換發不同的 refresh 憑證")
	}
	claims, err := auth.ValidateToken(rotated.Token)
	if err != nil || claims.Scope != "" {
		t.Fatalf("刷新換發的 access 應為正式 token（無 scope）: err=%v", err)
	}

	// 已輪替的舊憑證重放：typed error（供審計）＋家族撤銷
	_, err = auth.RefreshSession(first.RefreshToken)
	var reuse *RefreshReuseError
	if !errors.As(err, &reuse) {
		t.Fatalf("舊憑證重放 = %v, want RefreshReuseError", err)
	}
	if reuse.UserID != user.ID {
		t.Errorf("reuse.UserID = %d, want %d", reuse.UserID, user.ID)
	}

	// 家族撤銷後：攻擊面上「換到新憑證的一方」也一併失效
	if _, err := auth.RefreshSession(rotated.RefreshToken); !errors.Is(err, ErrRefreshInvalid) {
		t.Errorf("家族撤銷後新憑證 = %v, want ErrRefreshInvalid", err)
	}

	var revoked int64
	db.Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked_reason = ?", user.ID, model.RefreshRevokeReuseDetected).
		Count(&revoked)
	if revoked == 0 {
		t.Error("應有憑證標記 reuse_detected")
	}
}

// TestRefreshIdleTimeoutRequiresRelogin 8.2.8：距上次活動逾政策閒置窗口，刷新被拒
func TestRefreshIdleTimeoutRequiresRelogin(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	seedLockoutUser(t, db, "right-pass-1")
	policies.Update(policy.PolicyWebIdleMinutes, "15", "admin")

	resp := loginForRefresh(t, auth, "bob", "right-pass-1")

	// 模擬閒置 16 分：把 last_used_at 撥回過去（絕對壽命仍充裕）
	db.Model(&model.RefreshToken{}).Where("user_id = ?", 1).
		Update("last_used_at", time.Now().Add(-16*time.Minute))

	if _, err := auth.RefreshSession(resp.RefreshToken); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatalf("閒置逾時刷新 = %v, want ErrRefreshInvalid", err)
	}

	var row model.RefreshToken
	db.Where("revoked_reason = ?", model.RefreshRevokeIdleTimeout).First(&row)
	if row.ID == 0 {
		t.Error("閒置逾時應標記 idle_timeout")
	}
}

// TestRefreshAbsoluteLifetimeExceeded 達絕對壽命即使持續活動也須重登
func TestRefreshAbsoluteLifetimeExceeded(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	seedLockoutUser(t, db, "right-pass-1")

	resp := loginForRefresh(t, auth, "bob", "right-pass-1")

	// 剛活動過（last_used_at=now）但登入起算已逾上限
	db.Model(&model.RefreshToken{}).Where("user_id = ?", 1).
		Updates(map[string]interface{}{
			"last_used_at": time.Now(),
			"expires_at":   time.Now().Add(-time.Minute),
		})

	if _, err := auth.RefreshSession(resp.RefreshToken); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatalf("逾絕對壽命刷新 = %v, want ErrRefreshInvalid", err)
	}
}

// TestRefreshRejectsDisabledOrLockedUser 深度防禦：刷新這關複查用戶狀態
func TestRefreshRejectsDisabledOrLockedUser(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")

	resp := loginForRefresh(t, auth, "bob", "right-pass-1")

	// 停用（繞過撤銷點，模擬競態殘留的未撤銷憑證）
	db.Model(&model.User{}).Where("id = ?", user.ID).Update("active", false)
	if _, err := auth.RefreshSession(resp.RefreshToken); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatalf("停用後刷新 = %v, want ErrRefreshInvalid", err)
	}

	// 鎖定中同樣拒絕
	db.Model(&model.User{}).Where("id = ?", user.ID).Updates(map[string]interface{}{
		"active":       true,
		"locked_until": time.Now().Add(10 * time.Minute),
	})
	if _, err := auth.RefreshSession(resp.RefreshToken); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatalf("鎖定中刷新 = %v, want ErrRefreshInvalid", err)
	}
}

// TestLogoutRevokesOnlyCurrentRefresh 登出撤目前憑證；他裝置會話不受波及、也不觸發家族撤銷
func TestLogoutRevokesOnlyCurrentRefresh(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	seedLockoutUser(t, db, "right-pass-1")

	deviceA := loginForRefresh(t, auth, "bob", "right-pass-1")
	deviceB := loginForRefresh(t, auth, "bob", "right-pass-1")

	if err := auth.RevokeRefreshToken(deviceA.RefreshToken, model.RefreshRevokeLogout); err != nil {
		t.Fatalf("登出撤銷 = %v", err)
	}

	// 已登出憑證重放：拒絕但不是 reuse（不得誤殺 deviceB）
	_, err := auth.RefreshSession(deviceA.RefreshToken)
	if !errors.Is(err, ErrRefreshInvalid) {
		t.Fatalf("登出後刷新 = %v, want ErrRefreshInvalid", err)
	}
	var reuse *RefreshReuseError
	if errors.As(err, &reuse) {
		t.Fatal("登出憑證重放不應觸發家族撤銷")
	}

	if _, err := auth.RefreshSession(deviceB.RefreshToken); err != nil {
		t.Errorf("他裝置刷新 = %v, want nil", err)
	}

	var row model.RefreshToken
	db.Where("revoked_reason = ?", model.RefreshRevokeLogout).First(&row)
	if row.ID == 0 {
		t.Error("登出應標記 logout")
	}
}

// TestLogoutStaleRotatedTokenTriggersFamilyRevoke：登出提交「已 rotated」憑證
// （分叉訊號）觸發家族撤銷，攻擊者的分叉鏈一併失效
func TestLogoutStaleRotatedTokenTriggersFamilyRevoke(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")

	// 受害者登入取得 R0
	victim := loginForRefresh(t, auth, "bob", "right-pass-1")
	// 攻擊者竊 R0 並刷新 → 分叉出 R2（R0 標 rotated）
	rotated, err := auth.RefreshSession(victim.RefreshToken)
	if err != nil {
		t.Fatalf("attacker refresh: %v", err)
	}

	// 受害者登出，前端送出其 localStorage 的舊憑證 R0（已 rotated）
	if err := auth.RevokeRefreshToken(victim.RefreshToken, model.RefreshRevokeLogout); err == nil {
		t.Fatal("登出提交已 rotated 憑證應回 RefreshReuseError（分叉訊號）")
	} else {
		var reuse *RefreshReuseError
		if !errors.As(err, &reuse) {
			t.Fatalf("登出分叉 = %v, want RefreshReuseError", err)
		}
		if reuse.UserID != user.ID {
			t.Errorf("reuse.UserID = %d, want %d", reuse.UserID, user.ID)
		}
	}

	// 攻擊者的分叉鏈 R2 一併失效
	if _, err := auth.RefreshSession(rotated.RefreshToken); !errors.Is(err, ErrRefreshInvalid) {
		t.Errorf("家族撤銷後攻擊者 R2 = %v, want ErrRefreshInvalid", err)
	}
	var cnt int64
	db.Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked_reason = ?", user.ID, model.RefreshRevokeReuseDetected).Count(&cnt)
	if cnt == 0 {
		t.Error("登出分叉應標記 reuse_detected 家族撤銷")
	}
}

// TestLogoutCurrentTokenNoFamilyRevoke 對照組：登出提交「目前有效」憑證只單撤、不誤觸家族撤銷
func TestLogoutCurrentTokenNoFamilyRevoke(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	seedLockoutUser(t, db, "right-pass-1")

	deviceA := loginForRefresh(t, auth, "bob", "right-pass-1")
	deviceB := loginForRefresh(t, auth, "bob", "right-pass-1")

	// 正常登出：提交未 rotated 的目前憑證 → 單撤、不 reuse
	if err := auth.RevokeRefreshToken(deviceA.RefreshToken, model.RefreshRevokeLogout); err != nil {
		t.Fatalf("正常登出 = %v, want nil", err)
	}
	// 他裝置不受影響
	if _, err := auth.RefreshSession(deviceB.RefreshToken); err != nil {
		t.Errorf("他裝置刷新 = %v, want nil（登出不應誤觸家族撤銷）", err)
	}
}

// TestPasswordChangeRevokesAllRefresh 改密撤銷該使用者全部既存 refresh（各裝置須重登）
func TestPasswordChangeRevokesAllRefresh(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-11")

	deviceA := loginForRefresh(t, auth, "bob", "right-pass-11")
	deviceB := loginForRefresh(t, auth, "bob", "right-pass-11")

	users := NewUserService(db, authz.NewAssetAuthorizationService(db))
	users.SetSecurityPolicies(policies)
	if err := users.SelfChangePassword(user.ID, "right-pass-11", "brand-new-pass-22"); err != nil {
		t.Fatalf("改密 = %v", err)
	}

	for name, tok := range map[string]string{"deviceA": deviceA.RefreshToken, "deviceB": deviceB.RefreshToken} {
		if _, err := auth.RefreshSession(tok); !errors.Is(err, ErrRefreshInvalid) {
			t.Errorf("改密後 %s 刷新 = %v, want ErrRefreshInvalid", name, err)
		}
	}
}

// TestLockoutRevokesAllRefresh 自動鎖定撤銷全部 refresh（Web 會話不得續命；協議會話不砍，不在此測）
func TestLockoutRevokesAllRefresh(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	seedLockoutUser(t, db, "right-pass-1")
	policies.Update(policy.PolicyLockoutMaxAttempts, "3", "admin")

	resp := loginForRefresh(t, auth, "bob", "right-pass-1")

	for i := 0; i < 3; i++ {
		auth.Login(&LoginRequest{Username: "bob", Password: "wrong"})
	}

	if _, err := auth.RefreshSession(resp.RefreshToken); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatalf("鎖定後刷新 = %v, want ErrRefreshInvalid", err)
	}
	var row model.RefreshToken
	db.Where("revoked_reason = ?", model.RefreshRevokeLocked).First(&row)
	if row.ID == 0 {
		t.Error("鎖定應標記 locked")
	}
}

// fakeTerminator 記錄停用收線呼叫
type fakeTerminator struct {
	calledWith []uint
}

func (f *fakeTerminator) TerminateAllByUser(userID uint) (int, error) {
	f.calledWith = append(f.calledWith, userID)
	return 1, nil
}

// TestDisableRevokesRefreshAndTerminatesSessions 停用：撤全部 refresh＋強制收線協議會話
func TestDisableRevokesRefreshAndTerminatesSessions(t *testing.T) {
	auth, policies, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")

	resp := loginForRefresh(t, auth, "bob", "right-pass-1")

	users := NewUserService(db, authz.NewAssetAuthorizationService(db))
	users.SetSecurityPolicies(policies)
	term := &fakeTerminator{}
	users.SetSessionTerminator(term)

	if err := users.UpdateStatus(user.ID, false); err != nil {
		t.Fatalf("停用 = %v", err)
	}

	if len(term.calledWith) != 1 || term.calledWith[0] != user.ID {
		t.Errorf("停用應觸發 TerminateAllByUser(%d)，got %v", user.ID, term.calledWith)
	}
	if _, err := auth.RefreshSession(resp.RefreshToken); !errors.Is(err, ErrRefreshInvalid) {
		t.Errorf("停用後刷新 = %v, want ErrRefreshInvalid", err)
	}
	var row model.RefreshToken
	db.Where("revoked_reason = ?", model.RefreshRevokeDisabled).First(&row)
	if row.ID == 0 {
		t.Error("停用應標記 disabled")
	}
}
