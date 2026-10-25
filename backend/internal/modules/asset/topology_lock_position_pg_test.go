package asset

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// 與 authz.TopologySerializationLockClass 同值（asset 不 import authz；兩處的 SQL 形狀一致由
// authz 套件的 PG 測試釘住）。
const pgTopologyClassForTest int32 = 0x6F74_6B04

var pgTopologySchemaSeq atomic.Int64

// pgTopologyPort 在 PostgreSQL 上以與 authz 相同的語句取拓撲鎖，並在 BeginPermissionChange
// 時以 pg_locks 讀回「本連線已持有該鎖」的正向證據。
type pgTopologyPort struct {
	heldAtBegin []int64
}

const pgHeldTopologyLockSQL = `SELECT count(*) FROM pg_locks
 WHERE locktype = 'advisory' AND granted AND pid = pg_backend_pid()
   AND classid::bigint = ? AND objid::bigint = 1 AND objsubid = 2
   AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`

func (p *pgTopologyPort) LockTopology(tx *gorm.DB) error {
	return tx.Exec("SELECT pg_advisory_xact_lock(?, ?)", pgTopologyClassForTest, int32(1)).Error
}

func (p *pgTopologyPort) BeginPermissionChange(tx *gorm.DB) error {
	var n int64
	if err := tx.Raw(pgHeldTopologyLockSQL, pgTopologyClassForTest).Scan(&n).Error; err != nil {
		return err
	}
	p.heldAtBegin = append(p.heldAtBegin, n)
	return nil
}
func (p *pgTopologyPort) AdvanceVersion(*gorm.DB) error         { return nil }
func (p *pgTopologyPort) SettlePermissionChange(*gorm.DB) error { return nil }

func openPGTopologyDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := pgLockTestDSN(t)
	admin := openPGLockDB(t, dsn)
	schema := fmt.Sprintf("p3a_topo_%d_%d", time.Now().UnixNano(), pgTopologySchemaSeq.Add(1))
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() { _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error })
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{
		Logger: logger.Discard, DisableForeignKeyConstraintWhenMigrating: true})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(8)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(
		&model.Asset{}, &model.AssetAccount{}, &model.Credential{},
		&model.CredentialSecretVersion{}, &model.ChangeSecretCandidate{},
		&model.AuditLog{}, &model.AssetGroup{}, &model.AssetNode{},
	))
	return db
}

// waitTopologyWaiter 等到有一條連線在拓撲鎖上排隊（granted=false），回傳其 pid。
func waitTopologyWaiter(t *testing.T, db *gorm.DB, holderPID int64) int64 {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var pids []int64
		require.NoError(t, db.Raw(`SELECT pid FROM pg_locks
 WHERE locktype = 'advisory' AND NOT granted AND classid::bigint = ? AND objid::bigint = 1 AND objsubid = 2
   AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`,
			pgTopologyClassForTest).Scan(&pids).Error)
		for _, pid := range pids {
			if pid != holderPID {
				return pid
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("等不到在拓撲鎖上排隊的連線")
	return 0
}

// TestTopologyLockPositionPG 取拓撲鎖早於憑證列鎖與資產列鎖：另一交易持有拓撲鎖時，
// 單筆建立、批次匯入與掛載更新都停在取鎖處，此時它們的憑證列與資產列仍可被第三條連線鎖走
// （NOWAIT 立刻成功）；放行後取鎖者在 BeginPermissionChange 時以 pg_locks 讀回本連線持有該鎖。
func TestTopologyLockPositionPG(t *testing.T) {
	db := openPGTopologyDB(t)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	assets, _, creds := newCredentialServices(t)
	port := &pgTopologyPort{}
	assets.SetTopologyPermissionPort(port)
	node := &model.AssetGroup{Name: "pg-node"}
	require.NoError(t, db.Create(node).Error)
	shared := newSharedCredential(t, creds, "pg-shared", "ops", "pw-1")
	seed := newBareAsset(t, assets, "pg-seed", "10.7.0.9")

	// holder：持有拓撲鎖的交易
	holdAndRun := func(t *testing.T, run func() error, rowProbe func(tx *gorm.DB) error) {
		t.Helper()
		holder := db.Begin()
		require.NoError(t, holder.Error)
		defer holder.Rollback() // 提交後為 no-op；中途失敗時釋放拓撲鎖
		var holderPID int64
		require.NoError(t, holder.Raw("SELECT pg_backend_pid()").Scan(&holderPID).Error)
		require.NoError(t, holder.Exec("SELECT pg_advisory_xact_lock(?, ?)", pgTopologyClassForTest, int32(1)).Error)

		errc := make(chan error, 1)
		go func() { errc <- run() }()
		waiterPID := waitTopologyWaiter(t, db, holderPID)
		t.Logf("EVIDENCE holder_pid=%d waiter_pid=%d class=%d objid=1 granted=false", holderPID, waiterPID, pgTopologyClassForTest)

		probe := db.Begin()
		require.NoError(t, probe.Error)
		probeErr := rowProbe(probe)
		require.NoError(t, probe.Rollback().Error)
		if probeErr != nil {
			// 先放行持鎖者並等操作結束，免得失敗時留下卡住的交易
			_ = holder.Commit().Error
			<-errc
			t.Fatalf("等鎖期間，業務列必須尚未被鎖（NOWAIT 立刻成功）：%v", probeErr)
		}

		select {
		case err := <-errc:
			t.Fatalf("持鎖者未放行，操作不得完成：%v", err)
		case <-time.After(200 * time.Millisecond):
		}
		require.NoError(t, holder.Commit().Error)
		select {
		case err := <-errc:
			require.NoError(t, err)
		case <-time.After(15 * time.Second):
			t.Fatal("放行後操作未完成")
		}
	}
	credProbe := func(tx *gorm.DB) error {
		return tx.Exec("SELECT id FROM credentials WHERE id = ? FOR UPDATE NOWAIT", shared.ID).Error
	}
	assetProbe := func(tx *gorm.DB) error {
		return tx.Exec("SELECT id FROM assets WHERE id = ? FOR UPDATE NOWAIT", seed.ID).Error
	}

	t.Run("create_lock_before_credential_row", func(t *testing.T) {
		port.heldAtBegin = nil
		holdAndRun(t, func() error {
			_, err := assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
				Name: "pg-create", Protocol: model.ProtocolSSH, Host: "10.7.0.1", Port: 22,
				CredentialID: shared.ID, NodeIDs: []uint{node.ID}, CreatedBy: 1, CreatedByName: "admin"})
			return err
		}, credProbe)
		require.Equal(t, []int64{1}, port.heldAtBegin, "BeginPermissionChange 時 pg_locks 讀回本連線持有拓撲鎖")
	})

	t.Run("import_lock_before_credential_row", func(t *testing.T) {
		port.heldAtBegin = nil
		cid := int64(shared.ID)
		holdAndRun(t, func() error {
			_, err := assets.ImportAssets(WithSystemCaller(adminCtx()), &ImportBatch{Source: ImportSourceForm, Rows: []ImportRow{
				{Name: "pg-imp-1", Protocol: "ssh", Host: "10.7.1.1", CredentialID: &cid, NodeIDs: []uint{node.ID}},
				{Name: "pg-imp-2", Protocol: "ssh", Host: "10.7.1.2", CredentialID: &cid, NodeIDs: []uint{node.ID}},
			}}, 1, "admin")
			return err
		}, credProbe)
		require.Equal(t, []int64{1}, port.heldAtBegin)
	})

	t.Run("update_lock_before_asset_row", func(t *testing.T) {
		port.heldAtBegin = nil
		holdAndRun(t, func() error {
			ids := []uint{node.ID}
			_, err := assets.Update(WithSystemCaller(adminCtx()), seed.ID, &UpdateAssetRequest{NodeIDs: &ids})
			return err
		}, assetProbe)
		require.Equal(t, []int64{1}, port.heldAtBegin)
	})
}
