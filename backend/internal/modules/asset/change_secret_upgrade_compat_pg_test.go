package asset

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
)

// dbAccountRotationVersion 為改密紀錄加傳輸風險欄的那一支增量。
const dbAccountRotationVersion = "20261102_db_account_rotation"

// TestChangeSecretUpgradeCompatPG 升級相容：上一版 schema（change_secret_records 沒有 transport_risk 欄）
// 上已有一份涵蓋 mysql 資產與 ssh 資產的計畫與一筆既有紀錄；套用本版 migration 後換新程式執行該計畫，
// mysql 資產未設通道仍記為跳過且不碰任何執行器，ssh 資產的處理結果不變，既有紀錄不被改寫。
// 需要 PG（TEST_PG_DSN；REQUIRE_INTEGRATION=1 時缺值轉 fail）。
func TestChangeSecretUpgradeCompatPG(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	e := newPGIdentityEnv(t, dsn)
	f := e.f
	require.Equal(t, "postgres", f.db.Dialector.Name(), "本測試不得回退 SQLite")

	// 上一版 schema：除了本版新增的 transport_risk 欄，其餘與現行 model 一致
	require.NoError(t, f.db.Exec(`ALTER TABLE change_secret_records DROP COLUMN transport_risk`).Error)
	require.False(t, f.db.Migrator().HasColumn(&model.ChangeSecretRecord{}, "transport_risk"), "起點必須是沒有該欄的 schema")

	// 升級前就存在的資產與計畫：mysql 資產沒有設定改密通道
	mysqlID := f.addRotationAsset(t, &CreateAssetRequest{
		Name: "legacy-mysql", Protocol: model.ProtocolMySQL, Host: "10.41.0.1", Port: 3306,
		Username: "app", Password: "p",
	})
	plan := f.planForAssets(t, []uint{f.assetID, mysqlID}, nil)
	require.NoError(t, f.db.Exec(`INSERT INTO change_secret_records
		(plan_id, asset_id, status, error, executed_at) VALUES (?, ?, 'success', '', ?)`,
		plan.ID, f.assetID, time.Now()).Error, "上一版 schema 寫入的既有紀錄")

	// 走真正的 migration 路徑：其餘增量視為已套用，只剩本版這一支待執行
	require.NoError(t, f.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version varchar(50) NOT NULL, applied_at timestamp with time zone NOT NULL,
		CONSTRAINT schema_migrations_pkey PRIMARY KEY (version))`).Error)
	found := false
	for _, v := range database.MigrationVersions() {
		if v == dbAccountRotationVersion {
			found = true
			continue
		}
		require.NoError(t, f.db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, now())`, v).Error)
	}
	require.True(t, found, "未登記 %s", dbAccountRotationVersion)
	require.NoError(t, database.RunMigrations())

	require.True(t, f.db.Migrator().HasColumn(&model.ChangeSecretRecord{}, "transport_risk"))
	var legacyRisks []string
	require.NoError(t, f.db.Raw(`SELECT transport_risk FROM change_secret_records WHERE plan_id = ?`, plan.ID).
		Scan(&legacyRisks).Error)
	require.Equal(t, []string{""}, legacyRisks, "既有紀錄的 transport_risk 為空字串")

	// 換新程式執行同一份計畫；替身執行器記下被要求的通道與每台主機的呼叫數
	rec := newRotationRecorder()
	channels := &channelRecorder{inner: func(string) rotationExecutor { return rec }}
	f.runner.executors = channels.factory
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 2)

	var mysql model.Asset
	require.NoError(t, f.db.First(&mysql, mysqlID).Error)
	my := recordByAsset(records, mysqlID)
	require.NotNil(t, my)
	assert.Equal(t, model.ChangeSecretSkipped, my.Status)
	assert.Equal(t, model.ChangeSecretReasonChannelNotConfigured, my.Error)
	assert.Empty(t, my.TransportRisk)
	assert.False(t, channels.sawChannel(model.RotationChannelDBNative), "沒有為 mysql 資產取過資料庫執行器")
	_, rotateCalls, verifyCalls := rec.snapshot()
	assert.Zero(t, rotateCalls[mysql.Host]+verifyCalls[mysql.Host], "沒有對 mysql 主機做任何呼叫（替身執行器呼叫數 0）")

	var ssh model.Asset
	require.NoError(t, f.db.First(&ssh, f.assetID).Error)
	sr := recordByAsset(records, f.assetID)
	require.NotNil(t, sr)
	assert.Equal(t, model.ChangeSecretSuccess, sr.Status, "錯誤: %s", sr.Error)
	assert.Empty(t, sr.Error)
	assert.Empty(t, sr.TransportRisk)
	assert.Equal(t, 1, rotateCalls[ssh.Host], "ssh 資產照舊改密一次")
	assert.True(t, channels.sawChannel(model.RotationChannelPosixSSH))

	// 落庫後的列也一致，且既有紀錄未被改寫
	var stored []model.ChangeSecretRecord
	require.NoError(t, f.db.Where("plan_id = ?", plan.ID).Order("id ASC").Find(&stored).Error)
	require.Len(t, stored, 3, "1 筆既有紀錄加本次 2 筆")
	for _, r := range stored {
		assert.Empty(t, r.TransportRisk, "紀錄 %d", r.ID)
	}
	assert.Equal(t, model.ChangeSecretSuccess, stored[0].Status)
	assert.Equal(t, "", stored[0].Error)

	t.Logf("EVIDENCE dialect=postgres mysql=%s/%s rotate_calls_mysql=%d ssh=%s rotate_calls_ssh=%d legacy_transport_risk=%q",
		my.Status, my.Error, rotateCalls[mysql.Host]+verifyCalls[mysql.Host], sr.Status, rotateCalls[ssh.Host], legacyRisks[0])
}
