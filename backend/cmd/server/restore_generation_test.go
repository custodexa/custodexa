package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/sshproxy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const restoreTestSecret = "restore-test-secret-0123456789abcdef"

// restoreTestDB 建一份「備份剛匯入」的資料庫：legacy 世代、version=5。
func restoreTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.SecurityPolicy{}, &model.PasswordHistory{},
		&model.RefreshToken{}, &model.UserRoleMappingRuleSupport{}, &model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.AgentToken{}, &model.AuditLog{}, &model.UserRole{}, &model.AuthzState{},
		&model.AssetAuthorization{}, &model.Asset{}))
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 5)").Error)
	return db
}

func claimKeys(t *testing.T, token string) []string {
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func authStateRow(t *testing.T, db *gorm.DB) model.AuthzState {
	var st model.AuthzState
	require.NoError(t, db.Where("id = 1").Take(&st).Error)
	return st
}

func TestPermissionRestoreGeneration(t *testing.T) {
	ctx := context.Background()

	t.Run("同機與他機由同份備份各產生新世代，version 加一", func(t *testing.T) {
		a, b := restoreTestDB(t), restoreTestDB(t)
		ga, fresh, err := authz.CommitRestoreOnce(a, "op-a", "digest-1")
		require.NoError(t, err)
		require.True(t, fresh)
		gb, _, err := authz.CommitRestoreOnce(b, "op-b", "digest-1")
		require.NoError(t, err)
		require.Len(t, ga, 64)
		require.NotEqual(t, ga, gb, "兩台機器各自產生不同世代")
		require.EqualValues(t, 6, authStateRow(t, a).Version)
		require.Equal(t, authz.RestoreStatusPending, authStateRow(t, a).RestoreStatus)
	})

	t.Run("舊 access／MFA／改密／解封中繼 JWT 拒絕，新登入成功，claims 形狀與 env 不變", func(t *testing.T) {
		db := restoreTestDB(t)
		legacy := crypto.NewJWTManager(restoreAwareJWTSecret(db, restoreTestSecret), time.Hour)
		ac := crypto.AuthContext{AuthMethod: crypto.AuthMethodLocalPassword}
		oldAccess, err := legacy.GenerateToken(1, "u", "u@x", "admin", ac)
		require.NoError(t, err)
		oldScoped := map[string]string{}
		for _, scope := range []string{crypto.ScopeMFAPending, crypto.ScopePasswordChange, crypto.ScopeMFAEnrollment} {
			tok, err := legacy.GenerateScopedToken(1, "u", "u@x", "admin", scope, time.Hour, ac)
			require.NoError(t, err)
			oldScoped[scope] = tok
		}
		_, err = legacy.ValidateToken(oldAccess)
		require.NoError(t, err, "還原前舊世代可驗")

		_, _, err = authz.CommitRestoreOnce(db, "op-1", "digest-1")
		require.NoError(t, err)

		effective := restoreAwareJWTSecret(db, restoreTestSecret)
		require.NotEqual(t, restoreTestSecret, effective)
		fresh := crypto.NewJWTManager(effective, time.Hour)
		_, err = fresh.ValidateToken(oldAccess)
		require.Error(t, err, "舊 access JWT 拒絕")
		for scope, tok := range oldScoped {
			_, err = fresh.ValidateToken(tok)
			require.Error(t, err, "舊中繼 JWT 拒絕: "+scope)
		}
		// 解封中繼：以派生鑰建的 SealAuthorizer 同樣拒絕舊 token（真驗證入口）
		_, err = identity.NewSealAuthorizer(effective, db).Authorize(ctx, oldAccess)
		require.Error(t, err)

		newAccess, err := fresh.GenerateToken(1, "u", "u@x", "admin", ac)
		require.NoError(t, err)
		_, err = fresh.ValidateToken(newAccess)
		require.NoError(t, err, "新登入成功")
		require.Equal(t, claimKeys(t, oldAccess), claimKeys(t, newAccess), "JWT claims 形狀不變")
		require.Equal(t, restoreTestSecret, authz.DeriveRestoreJWTKey(restoreTestSecret, ""), "空世代沿用原 JWT_SECRET，env 不需改")
		require.Equal(t, effective, restoreAwareJWTSecret(db, restoreTestSecret), "派生是決定性的（重啟後同一把）")
	})

	t.Run("只有備份 version 加一的反例仍被新世代擋住", func(t *testing.T) {
		db := restoreTestDB(t)
		old := crypto.NewJWTManager(restoreAwareJWTSecret(db, restoreTestSecret), time.Hour)
		tok, err := old.GenerateToken(1, "u", "u@x", "admin", crypto.AuthContext{})
		require.NoError(t, err)
		require.NoError(t, db.Exec("UPDATE authz_state SET version = version + 1").Error) // 反例：只加一
		_, err = crypto.NewJWTManager(restoreAwareJWTSecret(db, restoreTestSecret), time.Hour).ValidateToken(tok)
		require.NoError(t, err, "僅 version+1 不足以擋舊票證（這就是需要世代的原因）")
		_, _, err = authz.CommitRestoreOnce(db, "op-1", "d")
		require.NoError(t, err)
		_, err = crypto.NewJWTManager(restoreAwareJWTSecret(db, restoreTestSecret), time.Hour).ValidateToken(tok)
		require.Error(t, err)
	})

	t.Run("交易失敗不提交；提交後 resume 不重換；重啟與重跑不換；另一次匯入換", func(t *testing.T) {
		db := restoreTestDB(t)
		boom := errors.New("injected")
		err := db.Transaction(func(tx *gorm.DB) error {
			if _, _, err := authz.CommitRestoreOnce(tx, "op-x", "d"); err != nil {
				return err
			}
			return boom
		})
		require.ErrorIs(t, err, boom)
		st := authStateRow(t, db)
		require.Empty(t, st.RestoreGeneration, "交易失敗不提交")
		require.EqualValues(t, 5, st.Version)

		g1, fresh, err := authz.CommitRestoreOnce(db, "op-1", "d1")
		require.NoError(t, err)
		require.True(t, fresh)
		g1b, fresh, err := authz.CommitRestoreOnce(db, "op-1", "d1")
		require.NoError(t, err)
		require.False(t, fresh, "提交後遺失腳本確認的 resume 不重換")
		require.Equal(t, g1, g1b)
		require.EqualValues(t, 6, authStateRow(t, db).Version)

		_, _, err = authz.CommitRestoreOnce(db, "op-2", "d2")
		require.ErrorIs(t, err, authz.ErrRestoreOpConflict, "pending 時另一操作識別：停下，不猜")

		done, err := authz.CompletePendingRestore(ctx, db)
		require.NoError(t, err)
		require.True(t, done)
		done, err = authz.CompletePendingRestore(ctx, db) // 一般重啟
		require.NoError(t, err)
		require.False(t, done)
		require.NoError(t, db.AutoMigrate(&model.AuthzState{})) // migration 重跑
		got, err := authz.RestoreGeneration(db)
		require.NoError(t, err)
		require.Equal(t, g1, got, "重啟與 migration 重跑不換世代")

		g2, fresh, err := authz.CommitRestoreOnce(db, "op-2", "d2") // 另一次實際匯入
		require.NoError(t, err)
		require.True(t, fresh)
		require.NotEqual(t, g1, g2)
	})

	t.Run("世代讀取失敗時 fail-close，不退回原鑰", func(t *testing.T) {
		db := restoreTestDB(t)
		old := crypto.NewJWTManager(restoreTestSecret, time.Hour)
		tok, err := old.GenerateToken(1, "u", "u@x", "admin", crypto.AuthContext{})
		require.NoError(t, err)
		sqlDB, _ := db.DB()
		require.NoError(t, sqlDB.Close())
		eff := restoreAwareJWTSecret(db, restoreTestSecret)
		require.NotEqual(t, restoreTestSecret, eff)
		_, err = crypto.NewJWTManager(eff, time.Hour).ValidateToken(tok)
		require.Error(t, err)
	})

	t.Run("refresh／agent／臨時授權：舊世代拒絕，新發證可用，常設授權不動", func(t *testing.T) {
		db := restoreTestDB(t)
		require.NoError(t, db.AutoMigrate(&model.UserGroup{}, &model.UserGroupMember{}))
		oldDB := database.DB
		database.DB = db
		t.Cleanup(func() { database.DB = oldDB })

		hash, _ := bcrypt.GenerateFromPassword([]byte("right-pass-1"), bcrypt.MinCost)
		email := "b@x"
		human := &model.User{Username: "bob", Email: &email, Password: string(hash), Active: true, Kind: model.KindHuman}
		require.NoError(t, db.Create(human).Error)
		agentEmail := "agent@x"
		agent := &model.User{Username: "agent1", Email: &agentEmail, Password: string(hash), Active: true, Kind: model.KindAgent, OwnerUserID: &human.ID}
		require.NoError(t, db.Create(agent).Error)

		auth := identity.NewAuthService(restoreAwareJWTSecret(db, restoreTestSecret), 15*time.Minute)
		auth.SetSecurityPolicies(policy.NewSecurityPolicyService(db))
		auth.SetRestoreGenerationSource(authz.RestoreGeneration)
		auth.SetEpochGateDB(db)
		agents := identity.NewAgentTokenService(db, nil)
		auth.SetAgentTokenService(agents)

		// 還原前（legacy 世代）簽出的 refresh 與 agent token
		oldLogin, err := auth.Login(&identity.LoginRequest{Username: "bob", Password: "right-pass-1"})
		require.NoError(t, err)
		require.NotEmpty(t, oldLogin.RefreshToken)
		plain, digest, err := identity.GenerateAgentToken()
		require.NoError(t, err)
		require.NoError(t, db.Create(&model.AgentToken{UserID: agent.ID, Name: "old", TokenHash: digest, CreatedBy: human.ID, ExpiresAt: time.Now().Add(time.Hour)}).Error)
		id, why := auth.ValidateAgentToken(plain, "")
		require.NotNil(t, id, why)
		before, err := agents.List(agent.ID)
		require.NoError(t, err)
		require.Len(t, before, 1)
		require.False(t, before[0].RestoreInvalidated, "還原前列表不標失效")

		// 常設與臨時授權各一
		uid := human.ID
		assetID := uint(1)
		past, future := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
		manual := model.AssetAuthorization{UserID: &uid, AssetID: &assetID, Permission: model.PermissionConnect, Source: model.AuthorizationSourceManual}
		ticket := model.AssetAuthorization{UserID: &uid, AssetID: &assetID, Permission: model.PermissionConnect, Source: model.AuthorizationSourceTicket, DateStart: &past, DateExpired: &future}
		require.NoError(t, db.Create(&manual).Error)
		require.NoError(t, db.Create(&ticket).Error)

		_, _, err = authz.CommitRestoreOnce(db, "op-1", "digest-1")
		require.NoError(t, err)
		gen, err := authz.RestoreGeneration(db)
		require.NoError(t, err)

		// 重新建構（模擬重啟後行程）：舊世代全拒
		auth2 := identity.NewAuthService(restoreAwareJWTSecret(db, restoreTestSecret), 15*time.Minute)
		auth2.SetSecurityPolicies(policy.NewSecurityPolicyService(db))
		auth2.SetRestoreGenerationSource(authz.RestoreGeneration)
		auth2.SetEpochGateDB(db)
		agents2 := identity.NewAgentTokenService(db, nil)
		auth2.SetAgentTokenService(agents2)

		_, err = auth2.RefreshSession(oldLogin.RefreshToken, "")
		require.ErrorIs(t, err, identity.ErrRefreshInvalid, "備份帶回的舊世代 refresh 拒絕")
		_, err = auth2.ValidateToken(oldLogin.Token)
		require.Error(t, err)
		id, _ = auth2.ValidateAgentToken(plain, "")
		require.Nil(t, id, "舊世代 agent token 拒絕")
		listed, err := agents2.List(agent.ID)
		require.NoError(t, err)
		require.Len(t, listed, 1)
		require.True(t, listed[0].RestoreInvalidated, "入口已拒絕的舊世代鑰匙，列表如實標示失效")
		raw, err := json.Marshal(listed[0])
		require.NoError(t, err)
		require.Contains(t, string(raw), `"restore_invalidated":true`)
		var kept model.RefreshToken
		require.NoError(t, db.Where("user_id = ?", human.ID).First(&kept).Error)
		require.Nil(t, kept.RevokedAt, "歷史列不被改撤銷旗標")

		var m2, t2 model.AssetAuthorization
		require.NoError(t, db.First(&m2, manual.ID).Error)
		require.NoError(t, db.First(&t2, ticket.ID).Error)
		require.Nil(t, m2.DateExpired, "常設授權不改")
		require.True(t, t2.DateExpired.Before(time.Now().Add(time.Second)), "舊世代臨時授權已到期（記錄留存）")

		// 還原後新登入／新發證可用
		newLogin, err := auth2.Login(&identity.LoginRequest{Username: "bob", Password: "right-pass-1"})
		require.NoError(t, err)
		_, err = auth2.RefreshSession(newLogin.RefreshToken, "")
		require.NoError(t, err, "新世代 refresh 可用")
		plain2, digest2, err := identity.GenerateAgentToken()
		require.NoError(t, err)
		require.NoError(t, db.Create(&model.AgentToken{UserID: agent.ID, Name: "new", TokenHash: digest2, CreatedBy: human.ID, ExpiresAt: time.Now().Add(time.Hour), RestoreGeneration: gen}).Error)
		id, why = auth2.ValidateAgentToken(plain2, "")
		require.NotNil(t, id, why)
		listed, err = agents2.List(agent.ID)
		require.NoError(t, err)
		require.Len(t, listed, 2)
		require.True(t, listed[0].RestoreInvalidated)
		require.False(t, listed[1].RestoreInvalidated, "新世代鑰匙不標失效")
		raw, err = json.Marshal(listed[1])
		require.NoError(t, err)
		require.NotContains(t, string(raw), "restore_invalidated", "為假時不出現在回應")
	})

	t.Run("行程內連線票：重啟後真兌換入口拒舊票", func(t *testing.T) {
		before := proxy.NewConnectTokenManager()
		tok, err := before.IssueConnectToken(ctx, proxy.ConnectGrant{UserID: 1, AssetID: 1})
		require.NoError(t, err)
		after := proxy.NewConnectTokenManager() // 完整停機後的新服務圖
		_, ok := after.RedeemConnectToken(ctx, tok)
		require.False(t, ok)
		_, reason := after.RedeemConnectTokenWithReason(ctx, tok)
		require.NotEmpty(t, string(reason))
		rec := api.NewRecordingTokenManager()
		rt, err := rec.Issue(1, 1, "u", crypto.AuthContext{}, authz.TokenFacts{})
		require.NoError(t, err)
		_, ok = api.NewRecordingTokenManager().Resolve(rt)
		require.False(t, ok, "錄影播放／下載票於新服務圖無效")
		obs := proxy.NewObserverTicketManager()
		ot, err := obs.IssueObserverTicket(ctx, proxy.ObserverGrant{UserID: 1})
		require.NoError(t, err)
		_, reason = proxy.NewObserverTicketManager().RedeemObserverTicketWithReason(ctx, ot)
		require.NotEmpty(t, string(reason))
	})

	t.Run("待完成的恢復在段 2 任何服務之前完成，封章在檢查點步驟之後，一般重啟不動", func(t *testing.T) {
		db := oneShotDB(t)
		oldDB := database.DB
		database.DB = db
		t.Cleanup(func() { database.DB = oldDB })
		_, _, err := authz.CommitRestoreOnce(db, "op-p", "d")
		require.NoError(t, err)
		require.Equal(t, authz.RestoreStatusPending, authStateRow(t, db).RestoreStatus)

		var calls []string
		sealer := &recordingSealer{calls: &calls}
		step := func(s1 *stage1) func() error {
			return sealAfterRestore(s1, sealer, func() error { calls = append(calls, "checkpoint"); return nil })
		}
		s1 := &stage1{}
		require.NoError(t, completeRestoreBeforeStage2(ctx, s1))
		require.Equal(t, authz.RestoreStatusSealPending, authStateRow(t, db).RestoreStatus, "段 2 開始前 restore 事件已記，待封狀態持久化")
		require.True(t, s1.restoreSealPending)
		require.NoError(t, step(s1)())
		require.Equal(t, authz.RestoreStatusDone, authStateRow(t, db).RestoreStatus, "封章成功後待封狀態清除")
		require.Equal(t, []string{"checkpoint", "seal"}, calls, "先檢查點步驟、後立即封章")
		require.False(t, s1.restoreSealPending)

		// 一般重啟：沒有 pending，兩個步驟都不多做事。
		calls = nil
		s2 := &stage1{}
		require.NoError(t, completeRestoreBeforeStage2(ctx, s2))
		require.NoError(t, step(s2)())
		require.Equal(t, []string{"checkpoint"}, calls)

		// 封章失敗：不阻擋開放（不回錯），資料庫維持待封供下次啟動補封。
		_, _, err = authz.CommitRestoreOnce(db, "op-q", "d2")
		require.NoError(t, err)
		s3 := &stage1{}
		require.NoError(t, completeRestoreBeforeStage2(ctx, s3))
		sealer.fail = true
		require.NoError(t, step(s3)())
		require.False(t, s3.restoreSealPending)
		require.Equal(t, authz.RestoreStatusSealPending, authStateRow(t, db).RestoreStatus)

		// 第一個背景工作（starts[0]）啟動前就先封章：新附證先於任何排程器。
		calls = nil
		_, _, err = authz.CommitRestoreOnce(db, "op-r", "d3")
		require.NoError(t, err)
		s4 := &stage1{}
		require.NoError(t, completeRestoreBeforeStage2(ctx, s4))
		sealer.fail = false
		require.NoError(t, sealBeforeFirstStart(s4, sealer, func() error { calls = append(calls, "first-scheduler"); return nil })())
		require.Equal(t, []string{"genesis", "seal", "first-scheduler"}, calls, "封章先於第一個排程器")
		require.False(t, s4.restoreSealPending)
		calls = nil
		require.NoError(t, step(s4)())
		require.Equal(t, []string{"checkpoint"}, calls, "已封章後檢查點步驟不重複封")
		calls = nil
		require.NoError(t, sealBeforeFirstStart(&stage1{}, sealer, func() error { calls = append(calls, "first-scheduler"); return nil })())
		require.Equal(t, []string{"first-scheduler"}, calls, "一般重啟不多做事")
		st2, err := os.ReadFile("stage2.go")
		require.NoError(t, err)
		require.Contains(t, string(st2), "starts[0].start, starts[0].stop = sealBeforeFirstStart(s1, restoreSealWrap(checkpointService, auditFailureAdapter{auditFailureService}, auditService), retentionScheduler.Start)")

		// 呼叫順序：runStage2Graph 先完成恢復、才進 runStage2（任何排程器、路由都在它裡面或之後）。
		src, err := os.ReadFile("sealwire.go")
		require.NoError(t, err)
		text := string(src)
		require.Less(t, strings.Index(text, "completeRestoreBeforeStage2(ctx, s1)"), strings.Index(text, "runStage2(ctx, s1, v.kek"))
	})

	t.Run("一次性子命令 permission-restore：原狀態核對、拒絕不提交，通過換新世代，同操作不重換", func(t *testing.T) {
		run := func(db *gorm.DB, op, in string) (int, string) {
			code, meta := oneShot(db, "permission-meta")
			require.Equal(t, oneShotOK, code, meta)
			return oneShot(db, "permission-restore", "--op-id", op, "--input-digest", in, "--expect-digest", kvLines(meta)["authz.digest"])
		}
		// 權限模型遷移前的資料庫：不碰任何新表，直接回 legacy。
		legacy, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		code, out := oneShot(legacy, "permission-restore", "--op-id", "op-1", "--input-digest", "d1", "--expect-digest", "ab")
		require.Equal(t, oneShotOK, code)
		require.Equal(t, "legacy", kvLines(out)["restore.model"])

		// 用法錯誤與不合法字元（防參數注入）。
		for _, args := range [][]string{
			{"permission-restore"},
			{"permission-restore", "--op-id", "x", "--input-digest", "d"},
			{"permission-restore", "--op-id", "a b", "--input-digest", "d", "--expect-digest", "e"},
			{"permission-restore", "--op-id", "x", "--input-digest", "d", "--expect-digest", "e", "--extra", "1"},
		} {
			code, _ = oneShot(oneShotDB(t), args...)
			require.Equal(t, oneShotUsage, code, args)
		}

		// 匯入後的權限狀態與備份摘要不符：拒絕，不提交。
		drift := oneShotDB(t)
		code, out = oneShot(drift, "permission-restore", "--op-id", "op-1", "--input-digest", "d1", "--expect-digest", "00ff")
		require.Equal(t, oneShotMismatch, code)
		require.Contains(t, out, "mismatch.expected=00ff")
		require.Empty(t, authStateRow(t, drift).RestoreGeneration)
		require.EqualValues(t, 5, authStateRow(t, drift).Version)

		// 懸空參照：拒絕，且不提交（世代空、version 不動）。
		bad := oneShotDB(t)
		require.NoError(t, bad.Exec("INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (1, 99, 'manual', 'global')").Error)
		code, out = run(bad, "op-1", "d1")
		require.Equal(t, oneShotRefused, code)
		require.Contains(t, out, "finding=dangling_user_role_role:")
		st := authStateRow(t, bad)
		require.Empty(t, st.RestoreGeneration)
		require.EqualValues(t, 5, st.Version)

		// 角色定義內容無效（未知權限鍵）：拒絕，不提交、不換世代。
		badDef := oneShotDB(t)
		require.NoError(t, badDef.Exec("INSERT INTO roles (name, definition_version) VALUES ('c', 1)").Error)
		require.NoError(t, badDef.Exec("INSERT INTO role_permissions (role_id, permission_key) SELECT id, 'nope:key' FROM roles WHERE name = 'c'").Error)
		code, out = run(badDef, "op-1", "d1")
		require.Equal(t, oneShotRefused, code)
		require.Contains(t, out, "finding=unknown_role_permission_key:")
		require.Empty(t, authStateRow(t, badDef).RestoreGeneration)
		require.EqualValues(t, 5, authStateRow(t, badDef).Version)

		// 零本地超管：拒絕，不自動建帳號、不提交。
		none := oneShotDB(t)
		require.NoError(t, none.Exec("DELETE FROM user_roles").Error)
		code, out = run(none, "op-1", "d1")
		require.Equal(t, oneShotRefused, code)
		require.Contains(t, out, "finding=no_local_super_admin:")
		require.Empty(t, authStateRow(t, none).RestoreGeneration)
		var users int64
		require.NoError(t, none.Model(&model.User{}).Count(&users).Error)
		require.EqualValues(t, 1, users)

		// 通過：換新世代、version 加一、pending；輸出只有指紋，不印世代本身。
		ok := oneShotDB(t)
		code, meta := oneShot(ok, "permission-meta")
		require.Equal(t, oneShotOK, code)
		expect := kvLines(meta)["authz.digest"]
		code, out = oneShot(ok, "permission-restore", "--op-id", "op-1", "--input-digest", "d1", "--expect-digest", expect)
		require.Equal(t, oneShotOK, code, out)
		kv := kvLines(out)
		require.Equal(t, "true", kv["restore.fresh"])
		require.Len(t, kv["restore.generation_fp"], 32)
		st = authStateRow(t, ok)
		require.EqualValues(t, 6, st.Version)
		require.Equal(t, authz.RestoreStatusPending, st.RestoreStatus)
		require.NotContains(t, out, st.RestoreGeneration)
		gen := st.RestoreGeneration

		// 同一操作（腳本落盤前中斷後的 resume）：資料已被該次恢復改過，不重核對、不重換；
		// 另一個操作卡在 pending：停下。
		code, out = oneShot(ok, "permission-restore", "--op-id", "op-1", "--input-digest", "d1", "--expect-digest", expect)
		require.Equal(t, oneShotOK, code, out)
		require.Equal(t, "false", kvLines(out)["restore.fresh"])
		require.Equal(t, kv["restore.generation_fp"], kvLines(out)["restore.generation_fp"])
		require.Equal(t, gen, authStateRow(t, ok).RestoreGeneration)
		require.EqualValues(t, 6, authStateRow(t, ok).Version)
		code, out = oneShot(ok, "permission-restore", "--op-id", "op-2", "--input-digest", "d2", "--expect-digest", expect)
		require.Equal(t, oneShotMismatch, code, "新操作須對得上目前資料的 digest；已被恢復改過的資料不再等於備份摘要")
		code, out = run(ok, "op-2", "d2")
		require.Equal(t, oneShotConflict, code)
		require.Contains(t, out, "error=op-conflict")
		require.Equal(t, gen, authStateRow(t, ok).RestoreGeneration)
	})

	t.Run("一次性子命令 permission-meta：legacy 與新模型的鍵集，同狀態同摘要", func(t *testing.T) {
		legacy, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		code, out := oneShot(legacy, "permission-meta")
		require.Equal(t, oneShotOK, code)
		require.Equal(t, map[string]string{"authz.model": "legacy"}, kvLines(out))

		db := oneShotDB(t)
		code, out = oneShot(db, "permission-meta")
		require.Equal(t, oneShotOK, code, out)
		kv := kvLines(out)
		for _, k := range []string{"authz.model", "authz.snapshot", "authz.catalog", "authz.digest", "authz.version", "authz.refs",
			"authz.count.roles", "authz.count.user_roles", "authz.count.group_roles", "authz.count.binding_nodes", "authz.count.nodes",
			"authz.count.role_maps", "authz.count.group_maps", "authz.count.members", "authz.count.groups", "authz.count.principals",
			"authz.count.role_defs", "authz.count.role_perms"} {
			require.Contains(t, kv, k)
		}
		require.Equal(t, "1", kv["authz.model"])
		require.Equal(t, "1", kv["authz.snapshot"], "摘要格式版本不動（管理腳本讀的鍵集沒變）；快照格式 2 的新內容只體現在兩條計數行與摘要值")
		require.Equal(t, "0", kv["authz.count.role_perms"])
		require.Equal(t, "5", kv["authz.version"])
		require.Equal(t, "ok", kv["authz.refs"])
		require.Equal(t, "4", kv["authz.count.roles"])
		require.Equal(t, "1", kv["authz.count.user_roles"])
		_, out2 := oneShot(db, "permission-meta")
		require.Equal(t, kv, kvLines(out2), "同狀態同摘要")

		// 自訂角色（定義版本 1、一個權限鍵）進摘要與筆數；摘要不含名稱。
		require.NoError(t, db.Exec("INSERT INTO roles (name, description, definition_version) VALUES ('custom-secret-name', 'free text', 1)").Error)
		var rid uint
		require.NoError(t, db.Raw("SELECT id FROM roles WHERE name = 'custom-secret-name'").Scan(&rid).Error)
		require.NoError(t, db.Exec("INSERT INTO role_permissions (role_id, permission_key) VALUES (?, 'asset:view')", rid).Error)
		_, outR := oneShot(db, "permission-meta")
		kvR := kvLines(outR)
		require.NotEqual(t, kv["authz.digest"], kvR["authz.digest"])
		require.Equal(t, "1", kvR["authz.count.role_perms"])
		require.Equal(t, "1", kvR["authz.count.role_defs"])
		require.Equal(t, "ok", kvR["authz.refs"])
		require.NotContains(t, outR, "custom-secret-name")
		// 角色定義內容無效（未知權限鍵）：refs 如實標示，不當成空集合。
		require.NoError(t, db.Exec("INSERT INTO role_permissions (role_id, permission_key) VALUES (?, 'nope:key')", rid).Error)
		_, outBad := oneShot(db, "permission-meta")
		require.True(t, strings.HasPrefix(kvLines(outBad)["authz.refs"], "findings:"), outBad)
		require.NoError(t, db.Exec("DELETE FROM role_permissions WHERE permission_key = 'nope:key'").Error)
		require.NoError(t, db.Exec("DELETE FROM role_permissions").Error)
		require.NoError(t, db.Exec("DELETE FROM roles WHERE id = ?", rid).Error)

		// 狀態改變（多一筆 binding）→ 摘要改變；參照有問題 → refs 如實標示（診斷備份可保存）。
		require.NoError(t, db.Exec("INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (1, 99, 'manual', 'global')").Error)
		_, out3 := oneShot(db, "permission-meta")
		require.NotEqual(t, kv["authz.digest"], kvLines(out3)["authz.digest"])
		require.True(t, strings.HasPrefix(kvLines(out3)["authz.refs"], "findings:"), out3)
	})

	t.Run("SSH／K8s／DB／圖形：舊票於新服務圖的真兌換入口拒絕，對外同一則 token 無效", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		old := proxy.NewConnectTokenManager()
		tok, err := old.IssueConnectToken(ctx, proxy.ConnectGrant{UserID: 1, AssetID: 1})
		require.NoError(t, err)
		sshH := sshproxy.NewHandler(nil, nil, nil, nil, nil, "", nil) // 完整停機後新建的服務圖：全新的連線票表
		connH := proxy.NewConnectionHandler("guacd", 4822, nil, nil, nil, nil, nil, nil)
		connH.ConnectTokens = proxy.NewConnectTokenManager()
		entries := []struct{ name, path string }{
			{"SSH", "/api/v1/ssh"},
			{"K8s（與 SSH 共用 /ssh 兌換入口）", "/api/v1/ssh"},
			{"DB", "/api/v1/db-console"},
			{"圖形（RDP／VNC）", "/api/v1/connect"},
		}
		r := gin.New()
		r.GET("/api/v1/ssh", sshH.HandleSSH)
		r.GET("/api/v1/db-console", sshH.HandleDBConsole)
		r.GET("/api/v1/connect", connH.HandleConnect)
		for _, e := range entries {
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, e.path+"?connect_token="+tok, nil))
			require.Equal(t, http.StatusUnauthorized, rec.Code, e.name)
			require.Contains(t, rec.Body.String(), string(apierror.CodeConnectTokenInvalid), e.name)
			// 偽票與舊票對外不可分辨。
			rec2 := httptest.NewRecorder()
			r.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, e.path+"?connect_token=forged", nil))
			require.Equal(t, rec.Body.String(), rec2.Body.String(), e.name)
		}
		// 對照：同一個服務圖內簽的新票可兌換（拒絕來自世代／新服務圖，而不是兌換入口壞了）。
		fresh, err := sshH.ConnectTokens.IssueConnectToken(ctx, proxy.ConnectGrant{UserID: 1, AssetID: 1})
		require.NoError(t, err)
		_, reason := sshH.ConnectTokens.RedeemConnectTokenWithReason(ctx, fresh)
		require.Equal(t, proxy.RedeemDenyNone, reason)
	})

	t.Run("SFTP：備份帶回的舊 access JWT 於檔案路由群組被認證層拒絕", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		db := restoreTestDB(t)
		oldTok, err := crypto.NewJWTManager(restoreAwareJWTSecret(db, restoreTestSecret), time.Hour).
			GenerateToken(1, "bob", "b@x", "admin", crypto.AuthContext{AuthMethod: crypto.AuthMethodLocalPassword})
		require.NoError(t, err)
		_, _, err = authz.CommitRestoreOnce(db, "op-sftp", "d")
		require.NoError(t, err)
		after := identity.NewAuthService(restoreAwareJWTSecret(db, restoreTestSecret), 15*time.Minute)
		r := gin.New()
		api.NewSFTPHandler(nil, nil, nil, after).RegisterRoutes(r.Group("/api/v1"), after)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assets/1/files?path=/", nil)
		req.Header.Set("Authorization", "Bearer "+oldTok)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}
