package identity_test

import (
	"github.com/custodexa/backend/internal/modules/identity"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 帳號生命週期三動作的憑證失效（idp-oidc-integration D2/D9；對抗審查 H1／H2）。
//
// spec（oidc-auth 行 84）明列「帳號停用、刪除、改為僅外部登入、解除外部身分綁定
// 與使用者自身的密碼變更」皆 SHALL 推進使用者憑證世代。後兩者由
// external_identity_service.go 的 (b)(c)(d) 實作並已有測試；**前三者（停用、刪除、
// 改密）落在 user_service.go，原本一個都沒推進**——後果是：
//
//	改密   攻擊者手上的 access token 仍可用滿一個 TTL（改密的整個目的落空）
//	停用   同上，且未兌換的 ticket／MFA pending／connect grant 全部存活
//	刪除   同上
//
// 停用與刪除另缺兩條收線管道（H2）：DisconnectByUser（監看／分享訂閱不建 sessions
// 列，SessionTerminator 完全掃不到）與 RevokeByUser（錄影 token 為 in-memory、
// 不做世代比對，唯一失效途徑是直接撤銷）。
//
// 邊界（既有測試 TestLockoutIsNotADisconnectWeapon／
// TestLockoutDoesNotCloseMonitorWebSocket 釘住，本檔不得使其鬆動）：
// **自動鎖定不在此列**——它可由未認證第三方觸發，推進世代即使其成為遠端斷線武器。

// reloadUserUnscoped 連軟刪除列一併讀出（Delete 之後 reloadUser 查不到）
func reloadUserUnscoped(t *testing.T, db *gorm.DB, userID uint) *model.User {
	t.Helper()
	var u model.User
	if err := db.Unscoped().First(&u, userID).Error; err != nil {
		t.Fatalf("unscoped reload user %d: %v", userID, err)
	}
	return &u
}

// lifecycleEnv 一組接齊四條管道的服務＋兩位 admin（停用／刪除須留下另一位，
// 否則被「最後一個本地 admin」不變式擋下而測不到失效路徑）
type lifecycleEnv struct {
	*revMatrixEnv
	victim *model.User
	keeper *model.User
}

const lifecyclePassword = "Str0ng-Passw0rd!v"

func setupLifecycleEnv(t *testing.T, db *gorm.DB) *lifecycleEnv {
	t.Helper()
	env := newRevMatrixEnv(t, db)

	victim := revMatrixLocalUser(t, db, "victim", lifecyclePassword, nil)
	revMatrixAttachAdminRole(t, db, victim.ID)
	keeper := revMatrixLocalUser(t, db, "keeper", "Str0ng-Passw0rd!k", nil)
	revMatrixAttachAdminRole(t, db, keeper.ID)

	return &lifecycleEnv{revMatrixEnv: env, victim: victim, keeper: keeper}
}

// seedLiveAccess 為受測帳號布置「四件事」各自的觀測對象：
// 未撤銷的 refresh、進行中的協議會話、唯讀訂閱、以及 keeper 的對照訂閱
func (e *lifecycleEnv) seedLiveAccess(t *testing.T) (refreshHash string, sess *model.Session) {
	t.Helper()
	loggedIn, err := e.auth.Login(&identity.LoginRequest{
		Username: e.victim.Username, Password: lifecyclePassword})
	if err != nil {
		t.Fatalf("受測帳號登入應成功（前提不成立則本測試無意義）: %v", err)
	}
	if loggedIn.RefreshToken == "" {
		t.Fatalf("登入應發出 refresh，實得 %+v", loggedIn)
	}
	sess = seedSession(t, e.db, e.victim.ID, 0, 0, "sess-victim")
	// 被監看的會話由別人建立（監看的常態）：按 session 掃描與本帳號無關，
	// 唯一掃得到這條訂閱的是按-user 收線
	e.hub.join(e.victim.ID, 0, "victim-monitor")
	e.hub.join(e.keeper.ID, 0, "keeper-monitor")
	return hashRefreshToken(loggedIn.RefreshToken), sess
}

// assertFourChannels 停用／刪除的四件事逐條斷言（缺一即為 H1／H2 的殘留缺口）
func (e *lifecycleEnv) assertFourChannels(t *testing.T, epochBefore int,
	refreshHash string, sess *model.Session, wantRefreshReason string) {
	t.Helper()

	// (1) 推進 credential_epoch（H1）：既簽 access 與未兌換的能力憑證一併失效
	if got := reloadUserUnscoped(t, e.db, e.victim.ID).CredentialEpoch; got != epochBefore+1 {
		t.Errorf("應推進 credential_epoch: %d → %d, want %d", epochBefore, got, epochBefore+1)
	}
	// (2) 撤 refresh：阻既有 Web 會話續命
	if r := reloadRefresh(t, e.db, refreshHash); r.RevokedAt == nil {
		t.Error("應撤銷 refresh 憑證")
	} else if r.RevokedReason != wantRefreshReason {
		t.Errorf("refresh 撤銷成因 = %q, want %q", r.RevokedReason, wantRefreshReason)
	}
	// (3) 終斷進行中協議會話
	if s := reloadRevocationSession(t, e.db, sess.ID); s.Status != model.SessionStatusDisconnected {
		t.Errorf("應終斷進行中協議會話: status=%q end_reason=%q", s.Status, s.EndReason)
	}
	if closed := e.registry.closedIDs(); len(closed) != 1 || closed[0] != sess.ID {
		t.Errorf("應關閉該會話 WebSocket: %v, want [%d]", closed, sess.ID)
	}
	// (4a) 收線唯讀訂閱（H2）：監看／分享不建 sessions 列，會話掃描掃不到
	if sweeps := e.hub.userSweeps(); len(sweeps) != 1 || sweeps[0] != e.victim.ID {
		t.Errorf("應觸發按-user 訂閱收線 = %v, want [%d]", sweeps, e.victim.ID)
	}
	if e.hub.alive("victim-monitor") {
		t.Errorf("受測帳號的唯讀訂閱應被收線，存活集合 = %v", e.hub.aliveTags())
	}
	// (4b) 撤銷錄影 token（H2）：in-memory 且不做世代比對，唯一途徑是直接撤銷
	if calls := e.tokens.userCalls(); len(calls) != 1 || calls[0] != e.victim.ID {
		t.Errorf("應撤銷該使用者的錄影存取憑證 = %v, want [%d]", calls, e.victim.ID)
	}
	// 精準性：不得誤殺其他人的訂閱
	if !e.hub.alive("keeper-monitor") {
		t.Errorf("其他管理員的訂閱不應被牽連，存活集合 = %v", e.hub.aliveTags())
	}
}

// --- H1／H2 第一格：停用 ---

// TestAccountDisableInvalidatesCredentialsAndRevokesAllChannels
// 管理端停用帳號 SHALL 一次完成四件事：推進 credential_epoch、撤 refresh、
// 終斷協議會話、收線唯讀訂閱與錄影 token。
//
// 原實作只做了中間兩件：世代沒推進 → 攻擊者手上的 access 與未兌換的能力憑證
// 全部撐滿一個 TTL；訂閱沒收 → 被停用的管理員帳號正在進行的監看繼續讀他人終端
// 內容（訂閱建立後不再出示任何憑證，對停用完全免疫）。
func TestAccountDisableInvalidatesCredentialsAndRevokesAllChannels(t *testing.T) {
	db := revMatrixDB(t)
	e := setupLifecycleEnv(t, db)
	refreshHash, sess := e.seedLiveAccess(t)
	epochBefore := reloadUser(t, db, e.victim.ID).CredentialEpoch

	if err := e.users.UpdateStatus(e.victim.ID, false); err != nil {
		t.Fatalf("停用帳號: %v", err)
	}
	if reloadUser(t, db, e.victim.ID).Active {
		t.Fatal("帳號應已停用（前提不成立則本測試無意義）")
	}

	e.assertFourChannels(t, epochBefore, refreshHash, sess, model.RefreshRevokeDisabled)
}

// TestAccountEnableDoesNotInvalidateCredentials 反向護欄：啟用（active=true）
// 不得推進世代或收線任何東西——否則重新啟用一個帳號會順手切斷別人的連線，
// 且「停用→啟用」會變成一個把自己憑證打掉的操作
func TestAccountEnableDoesNotInvalidateCredentials(t *testing.T) {
	db := revMatrixDB(t)
	e := setupLifecycleEnv(t, db)
	e.hub.join(e.victim.ID, 0, "victim-monitor")
	epochBefore := reloadUser(t, db, e.victim.ID).CredentialEpoch

	if err := e.users.UpdateStatus(e.victim.ID, true); err != nil {
		t.Fatalf("啟用帳號: %v", err)
	}
	if got := reloadUser(t, db, e.victim.ID).CredentialEpoch; got != epochBefore {
		t.Errorf("啟用不得推進 credential_epoch: %d → %d", epochBefore, got)
	}
	if sweeps := e.hub.userSweeps(); len(sweeps) != 0 {
		t.Errorf("啟用不得觸發按-user 收線，實得 %v", sweeps)
	}
	if !e.hub.alive("victim-monitor") {
		t.Errorf("啟用不得收線既有訂閱，存活集合 = %v", e.hub.aliveTags())
	}
}

// --- H1／H2 第二格：刪除 ---

// TestAccountDeleteInvalidatesCredentialsAndRevokesAllChannels
// 刪除帳號 SHALL 與停用同樣完成四件事。
//
// 原實作**連 refresh 與協議會話都不動**（Delete 只做軟刪除與連動清理），
// 是三條路徑中缺口最大的一條：帳號已不存在，其持有者卻仍有一條活著的 shell、
// 一條活著的監看訂閱，以及可再撐一個 TTL 的 access token。
//
// 世代推進必須發生在軟刪除**之前**：軟刪後 `Model(&User{}).Where(id)` 帶
// `deleted_at IS NULL`，UpdateColumn 會匹配 0 列而靜默失敗
func TestAccountDeleteInvalidatesCredentialsAndRevokesAllChannels(t *testing.T) {
	db := revMatrixDB(t)
	e := setupLifecycleEnv(t, db)
	refreshHash, sess := e.seedLiveAccess(t)
	epochBefore := reloadUser(t, db, e.victim.ID).CredentialEpoch

	if err := e.users.Delete(e.victim.ID); err != nil {
		t.Fatalf("刪除帳號: %v", err)
	}
	if reloadUserUnscoped(t, db, e.victim.ID).DeletedAt.Time.IsZero() {
		t.Fatal("帳號應已軟刪除（前提不成立則本測試無意義）")
	}

	e.assertFourChannels(t, epochBefore, refreshHash, sess, model.RefreshRevokeCredentialEpoch)
}

// --- H1 第三格：改密 ---

// TestPasswordChangeAdvancesCredentialEpoch 改密（自助與管理員重設皆同）
// SHALL 推進 credential_epoch。
//
// 原實作只撤 refresh：**access token 是 stateless 的**，撤 refresh 對它毫無作用，
// 於是「密碼可能已洩漏所以改掉」之後，竊得舊 access 者仍可用滿一整個 TTL，
// 且未兌換的 connect grant／MFA pending 一併存活。
//
// 不收線既有連線是刻意的（spec 行 84 只要求推進世代）：改密是使用者自己的
// 例行操作，連帶砍掉自己正在進行的維運 shell 不是該條款的意圖；D12 的換發路徑
// 會以現查世代簽出新會話，故改密者本人不會被自己的 epoch 推進鎖在門外。
func TestPasswordChangeAdvancesCredentialEpoch(t *testing.T) {
	cases := []struct {
		name   string
		change func(t *testing.T, e *lifecycleEnv)
	}{
		{name: "self", change: func(t *testing.T, e *lifecycleEnv) {
			if err := e.users.SelfChangePassword(e.victim.ID,
				lifecyclePassword, "Rot4ted-Passw0rd!z"); err != nil {
				t.Fatalf("自助改密: %v", err)
			}
		}},
		{name: "admin-reset", change: func(t *testing.T, e *lifecycleEnv) {
			if err := e.users.ChangePassword(e.victim.ID, "Rot4ted-Passw0rd!z"); err != nil {
				t.Fatalf("管理員重設密碼: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := revMatrixDB(t)
			e := setupLifecycleEnv(t, db)
			refreshHash, sess := e.seedLiveAccess(t)
			epochBefore := reloadUser(t, db, e.victim.ID).CredentialEpoch

			tc.change(t, e)

			if got := reloadUser(t, db, e.victim.ID).CredentialEpoch; got != epochBefore+1 {
				t.Errorf("改密應推進 credential_epoch: %d → %d, want %d",
					epochBefore, got, epochBefore+1)
			}
			if r := reloadRefresh(t, db, refreshHash); r.RevokedAt == nil {
				t.Error("改密應撤銷 refresh 憑證")
			} else if r.RevokedReason != model.RefreshRevokePasswordChange {
				t.Errorf("refresh 撤銷成因 = %q, want %q",
					r.RevokedReason, model.RefreshRevokePasswordChange)
			}
			// 改密不是斷線動作：既有協議會話與唯讀訂閱不得被牽連
			if s := reloadRevocationSession(t, db, sess.ID); s.Status != model.SessionStatusActive {
				t.Errorf("改密不得終斷既有協議會話: status=%q", s.Status)
			}
			if !e.hub.alive("victim-monitor") {
				t.Errorf("改密不得收線既有唯讀訂閱，存活集合 = %v", e.hub.aliveTags())
			}
		})
	}
}

// --- C-1 第四格：角色變更 ---

// attachRoleByName 直接掛上一個角色（布置前提用，不經受測路徑）
func attachRoleByName(t *testing.T, db *gorm.DB, userID uint, roleName string) {
	t.Helper()
	var role model.Role
	if err := db.Where("name = ?", roleName).First(&role).Error; err != nil {
		t.Fatalf("load role %s: %v", roleName, err)
	}
	if err := db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
		userID, role.ID).Error; err != nil {
		t.Fatalf("attach role %s: %v", roleName, err)
	}
}

// currentRoleNames 讀回該使用者現行角色名（斷言前提是否真的變動）
func currentRoleNames(t *testing.T, db *gorm.DB, userID uint) []string {
	t.Helper()
	var names []string
	if err := db.Table("user_roles").
		Joins("JOIN roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Order("roles.name").Pluck("roles.name", &names).Error; err != nil {
		t.Fatalf("讀取現行角色: %v", err)
	}
	return names
}

// TestRoleChangeAdvancesCredentialEpoch 角色集實際變動 SHALL 推進 credential_epoch（C-1）。
//
// 原實作只做 Association("Roles").Replace 就回傳，一個世代推進都沒有。後果是**權限提升**：
// 管理面的權限判定讀的是 JWT 內的角色**快照**（middleware/auth.go 的 RequireRole、
// permission.go 的 RequirePermission），世代閘只比對 epoch、不重查角色。於是被撤除
// admin 的帳號，其既簽 access token 仍以 admin 通過管理端判定，可在 TTL 內呼叫
// `PUT /users/{自己}/roles` 把 admin 改回來——降權由當事人自行復原（紅隊 dev 環境實跑重現）。
//
// **兩條分支都必須覆蓋**：新角色集含 admin 走 identity.WithUserCredentialLock、不含 admin 走
// identity.WithLocalAdminInvariant（本地 admin 不變式的系統級鎖）。只修其中一條等於留一半漏洞，
// 故本測試以子案分別打進兩條路徑——只改 remove-admin 那條時，keeps-admin 子案必紅。
//
// 邊界（D5 裁決，以反向斷言釘住）：角色變更**不**終斷既有協議會話與唯讀訂閱。
// 角色縮減不等同「此帳號整體不該再有存取」（那是停用／刪除／解綁的語義）；
// 降權後**新的**特權連線已由 CPG-010-01 的 DB 現查角色擋下。
func TestRoleChangeAdvancesCredentialEpoch(t *testing.T) {
	cases := []struct {
		name      string
		roles     []string
		wantRoles []string
	}{
		// keepsAdmin=false：走 identity.WithLocalAdminInvariant（系統級鎖）
		{name: "remove-admin", roles: []string{model.RoleUser}, wantRoles: []string{model.RoleUser}},
		// keepsAdmin=true：走 identity.WithUserCredentialLock（僅使用者級鎖）
		{name: "keeps-admin", roles: []string{model.RoleAdmin, model.RoleUser},
			wantRoles: []string{model.RoleAdmin, model.RoleUser}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := revMatrixDB(t)
			e := setupLifecycleEnv(t, db)
			refreshHash, sess := e.seedLiveAccess(t)
			epochBefore := reloadUser(t, db, e.victim.ID).CredentialEpoch

			if err := e.users.AssignRoles(e.victim.ID, tc.roles); err != nil {
				t.Fatalf("變更角色為 %v: %v", tc.roles, err)
			}
			if got := currentRoleNames(t, db, e.victim.ID); !equalStrings(got, tc.wantRoles) {
				t.Fatalf("角色應已變更為 %v，實得 %v（前提不成立則本測試無意義）",
					tc.wantRoles, got)
			}

			if got := reloadUser(t, db, e.victim.ID).CredentialEpoch; got != epochBefore+1 {
				t.Errorf("角色變更應推進 credential_epoch: %d → %d, want %d",
					epochBefore, got, epochBefore+1)
			}
			if r := reloadRefresh(t, db, refreshHash); r.RevokedAt == nil {
				t.Error("角色變更應撤銷 refresh 憑證")
			} else if r.RevokedReason != model.RefreshRevokeCredentialEpoch {
				t.Errorf("refresh 撤銷成因 = %q, want %q",
					r.RevokedReason, model.RefreshRevokeCredentialEpoch)
			}
			// D5：不是斷線動作
			if s := reloadRevocationSession(t, db, sess.ID); s.Status != model.SessionStatusActive {
				t.Errorf("角色變更不得終斷既有協議會話: status=%q", s.Status)
			}
			if !e.hub.alive("victim-monitor") {
				t.Errorf("角色變更不得收線既有唯讀訂閱，存活集合 = %v", e.hub.aliveTags())
			}
		})
	}
}

// TestUnchangedRoleSetDoesNotAdvanceEpoch 反向護欄：角色集**沒有**變動時不得推進世代。
//
// 管理端以同一組角色重存是常態操作（表單原樣送出）。若無條件推進，一次無意義的重存
// 就把該使用者所有裝置踢下線——把安全修復變成拒絕服務。順序不同亦視為相同（集合語義）。
func TestUnchangedRoleSetDoesNotAdvanceEpoch(t *testing.T) {
	db := revMatrixDB(t)
	e := setupLifecycleEnv(t, db)
	attachRoleByName(t, db, e.victim.ID, model.RoleUser) // 現行＝{admin, user}
	refreshHash, sess := e.seedLiveAccess(t)
	epochBefore := reloadUser(t, db, e.victim.ID).CredentialEpoch

	// 相同集合、相反順序
	if err := e.users.AssignRoles(e.victim.ID, []string{model.RoleUser, model.RoleAdmin}); err != nil {
		t.Fatalf("以相同角色集重存: %v", err)
	}

	if got := reloadUser(t, db, e.victim.ID).CredentialEpoch; got != epochBefore {
		t.Errorf("角色集未變動不得推進 credential_epoch: %d → %d", epochBefore, got)
	}
	if r := reloadRefresh(t, db, refreshHash); r.RevokedAt != nil {
		t.Errorf("角色集未變動不得撤銷 refresh 憑證，成因 = %q", r.RevokedReason)
	}
	if s := reloadRevocationSession(t, db, sess.ID); s.Status != model.SessionStatusActive {
		t.Errorf("角色集未變動不得終斷既有協議會話: status=%q", s.Status)
	}
	// 重存本身仍須維持既有冪等語義：角色集不變
	if got := currentRoleNames(t, db, e.victim.ID); !equalStrings(got,
		[]string{model.RoleAdmin, model.RoleUser}) {
		t.Errorf("重存後角色集 = %v, want [admin user]", got)
	}
}

// equalStrings 逐項比對（currentRoleNames 已依名稱排序，故可直接比）
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
