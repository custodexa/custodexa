package asset

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// pgHoldTopologyWhile 由另一交易先持有拓撲序列化鎖，再於背景執行 run：以 pg_locks 正向證明
// run 的連線在該鎖上排隊（granted=false，且 pg_blocking_pids 含持鎖者），此時 rowProbe 以
// NOWAIT 立刻鎖得到業務列（證明 run 尚未取任何列鎖）；持鎖者提交前 run 不得完成，提交後
// run 的結果交給 check。
func pgHoldTopologyWhile(t *testing.T, db *gorm.DB, run func() error,
	rowProbe func(tx *gorm.DB) error, check func(t *testing.T, err error)) {
	t.Helper()
	holder := db.Begin()
	require.NoError(t, holder.Error)
	var holderPID int64
	require.NoError(t, holder.Raw("SELECT pg_backend_pid()").Scan(&holderPID).Error)
	require.NoError(t, holder.Exec("SELECT pg_advisory_xact_lock(?, ?)", pgTopologyClassForTest, int32(1)).Error)

	errc := make(chan error, 1)
	go func() { errc <- run() }()
	waiterPID := waitTopologyWaiter(t, db, holderPID)

	var blockers []int64
	require.NoError(t, db.Raw("SELECT unnest(pg_blocking_pids(?))", waiterPID).Scan(&blockers).Error)
	t.Logf("EVIDENCE holder_pid=%d waiter_pid=%d blocking=%v class=%d objid=1 granted=false",
		holderPID, waiterPID, blockers, pgTopologyClassForTest)

	probe := db.Begin()
	require.NoError(t, probe.Error)
	probeErr := rowProbe(probe)
	require.NoError(t, probe.Rollback().Error)
	if probeErr != nil || !containsPID(blockers, holderPID) {
		_ = holder.Commit().Error
		<-errc
		require.NoError(t, probeErr, "等拓撲鎖期間，業務列必須尚未被鎖（NOWAIT 立刻成功）")
		t.Fatalf("排隊連線的 pg_blocking_pids 必須含持鎖者 %d，實得 %v", holderPID, blockers)
	}

	select {
	case err := <-errc:
		t.Fatalf("持鎖者未放行，操作不得完成：%v", err)
	case <-time.After(200 * time.Millisecond):
	}
	require.NoError(t, holder.Commit().Error)
	select {
	case err := <-errc:
		check(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("放行後操作未完成")
	}
}

func containsPID(pids []int64, want int64) bool {
	for _, p := range pids {
		if p == want {
			return true
		}
	}
	return false
}

// TestCredentialCommitTopologyLockPositionPG 宣告新秘密、整組輪替起始與單台脫離（拆分輪替的
// 起始交易）三者都以拓撲序列化鎖為交易第一個動作、其後才取憑證列鎖：另一交易持有拓撲鎖時，
// 三者都停在取鎖處，此刻其憑證列仍可被第三條連線以 NOWAIT 鎖走；放行後照常完成。
func TestCredentialCommitTopologyLockPositionPG(t *testing.T) {
	db := openPGTopologyDB(t)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	require.NoError(t, db.AutoMigrate(
		&model.CredentialRotation{}, &model.CredentialRotationMember{}, &model.CredentialJobAuthorization{},
		&model.AssetHostKey{}, &model.ChangeSecretRecord{},
	))

	codec := aesColumnCodec(t, make([]byte, 32))
	assets, err := NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	assets.SetTopologyPermissionPort(&pgTopologyPort{})
	creds := NewCredentialService(assets, codec, audit.NewTxSink()).WithOwnershipScope(globalOwnershipScopeForTest{}).
		WithManagementAuthorizer(newAllowAllAuthorizer()).WithSystemAlertSink(newFakeAlertSink())
	candidates, err := NewChangeSecretCandidateService(db, codec, assets, audit.NewTxSink())
	require.NoError(t, err)
	rotations := NewCredentialRotationService(db, assets, candidates, NewHostKeyService(db),
		codec, audit.NewTxSink(), newAllowAllAuthorizer()).WithSystemAlertSink(newFakeAlertSink())
	remote := newRotationRecorder()
	rotations.executors = func(string) rotationExecutor { return remote }
	rotations.keyApplier = remote.applyKey

	sharedOn := func(t *testing.T, name, host string) (uint, uint) {
		t.Helper()
		cred, cerr := creds.Create(adminCtx(), &CreateCredentialRequest{
			Name: name, Username: "ops", ProtocolFamily: model.ProtocolFamilySSH, Password: "pw-" + name,
		})
		require.NoError(t, cerr)
		a := newSSHAsset(t, assets, host, host)
		binding, berr := creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: a.ID})
		require.NoError(t, berr)
		return cred.ID, binding.ID
	}
	credProbe := func(id uint) func(tx *gorm.DB) error {
		return func(tx *gorm.DB) error {
			return tx.Exec("SELECT id FROM credentials WHERE id = ? FOR UPDATE NOWAIT", id).Error
		}
	}
	mustSucceed := func(t *testing.T, err error) { require.NoError(t, err) }

	t.Run("set_secret_lock_before_credential_row", func(t *testing.T) {
		credID, _ := sharedOn(t, "pg-set-secret", "10.8.0.1")
		pgHoldTopologyWhile(t, db, func() error {
			_, err := creds.SetSecret(adminCtx(), credID, &SetCredentialSecretRequest{Password: "pw-declared"})
			return err
		}, credProbe(credID), mustSucceed)
	})

	t.Run("rotation_start_lock_before_credential_row", func(t *testing.T) {
		credID, _ := sharedOn(t, "pg-rotate", "10.8.0.2")
		pgHoldTopologyWhile(t, db, func() error {
			_, err := rotations.Start(adminCtx(), credID, StartRotationRequest{})
			return err
		}, credProbe(credID), mustSucceed)
	})

	t.Run("detach_start_lock_before_credential_row", func(t *testing.T) {
		credID, accountID := sharedOn(t, "pg-detach", "10.8.0.3")
		pgHoldTopologyWhile(t, db, func() error {
			_, err := rotations.Detach(adminCtx(), credID, accountID, DetachCredentialRequest{Source: DetachSourceRandom})
			return err
		}, credProbe(credID), func(t *testing.T, err error) {
			// 本案只釘起始交易的鎖序：遠端結果（成功或脫離未完成）不在此判定，其他錯誤即失敗
			var failed *CredentialDetachFailedError
			if err != nil && !errors.As(err, &failed) {
				t.Fatalf("放行後脫離起始失敗：%v", err)
			}
			var n int64
			require.NoError(t, db.Model(&model.CredentialRotation{}).Where("credential_id = ?", credID).Count(&n).Error)
			require.Equal(t, int64(1), n, "放行後起始交易建立恰一筆輪替")
		})
	})

}
