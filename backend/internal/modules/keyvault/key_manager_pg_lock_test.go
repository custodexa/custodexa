package keyvault

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// data_keys 跨實例互斥的 postgres 真路徑整合測試。
//
// sqlite 分流走 package 級 try-mutex，與生產不同碼路；`pg_try_advisory_xact_lock`
// 的 try 語義（不阻塞、落敗即 ErrKeyOpBusy）只有連真 postgres 才覆蓋得到。
//
// gating：未設 TEST_PG_DSN 即 t.Skip——`go test ./...` 在無 DB 環境維持全綠。
// 跑法（compose 內）：
//
//	docker compose exec -T backend sh -c \
//	  'TEST_PG_DSN="host=postgres user=postgres password=postgres dbname=postgres port=5432 sslmode=disable" \
//	   go test ./internal/service -run TestPGAdvisoryLockMutex -v'
//
// DSN 選擇注意：advisory lock 的命名空間是**每 database**，schema 隔不掉。
// 因此 DSN 應指向非生產 database（上例用維護庫 postgres，非 custodexa），
// 避免與同機執行中的後端實例共用 lock 命名空間而互相干擾。
const pgLockTestSchema = "kek_lock_test"

// pgLockTestDSN 回傳帶隔離 schema 的 DSN；未設 TEST_PG_DSN 則跳過。
func pgLockTestDSN(t *testing.T) string {
	t.Helper()
	// gating 語義集中於 internal/testgate（REQUIRE_INTEGRATION=1 時 skip 轉 fail）
	return testgate.Value(t, testgate.EnvPGDSN)
}

// openPGLockDB 以獨立連線池開啟 DB——一個 *gorm.DB ＝ 模擬一個後端實例。
func openPGLockDB(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Discard,
		// 本測試只需 data_keys 與遷移守衛掃描的欄位；不建外鍵約束以免
		// AutoMigrate 連帶拉入關聯表
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("postgres 連線失敗（TEST_PG_DSN 是否正確？）: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// setupPGLockSchema 建立專用 schema 並回傳 search_path 已指向該 schema 的 DSN。
// 隔離法：測前 DROP ... CASCADE 再 CREATE（故可重複執行）、測後再 DROP，
// 全部物件落在專用 schema，不動目標 database 既有資料。
func setupPGLockSchema(t *testing.T, baseDSN string) string {
	t.Helper()
	admin := openPGLockDB(t, baseDSN)
	drop := "DROP SCHEMA IF EXISTS " + pgLockTestSchema + " CASCADE"
	if err := admin.Exec(drop).Error; err != nil {
		t.Fatalf("清理舊測試 schema 失敗: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + pgLockTestSchema).Error; err != nil {
		t.Fatalf("建立測試 schema 失敗: %v", err)
	}
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v", pgLockTestSchema, err)
		}
	})

	scoped := baseDSN + " search_path=" + pgLockTestSchema
	mig := openPGLockDB(t, scoped)
	// 遷移守衛 EnvelopePendingCount 會掃 envelopeMigrationTargets 的各表，
	// 故一併建表（空表 → pending 0）
	if err := mig.AutoMigrate(&model.Asset{}, &model.AssetAccount{}, &model.User{}, &model.ExportSigningKey{}, &model.CheckpointSigningKey{}, &model.OIDCProvider{},
		&model.LDAPDirectory{}, &model.NotificationChannel{}, &model.AuditLog{}, &model.DataKey{},
		&model.OffsiteProfile{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	// 生產等價索引語義（migration 20260801_kek_soft_retire）：唯一索引轉 partial
	for _, stmt := range []string{
		"DROP INDEX IF EXISTS idx_data_keys_purpose_version_kek",
		"CREATE UNIQUE INDEX idx_data_keys_purpose_version_kek ON data_keys (purpose, version, kek_id) WHERE kek_retired_at IS NULL",
	} {
		if err := mig.Exec(stmt).Error; err != nil {
			t.Fatalf("partial index: %v", err)
		}
	}
	return scoped
}

// grantedDataKeysAdvisoryLocks 目前 database 上以 KEKDataKeysLockKey 取得的
// advisory lock 數（bigint 單參數形式 → classid 高 32 位、objid 低 32 位、
// objsubid=1）。直接查 pg_locks 是防假綠的機制斷言：證明 ErrKeyOpBusy 真的
// 來自 advisory lock 佔用，而非其他錯誤路徑碰巧同名。
func grantedDataKeysAdvisoryLocks(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	err := db.Raw(`SELECT count(*) FROM pg_locks
		WHERE locktype = 'advisory' AND granted
		  AND objsubid = 1
		  AND ((classid::bigint << 32) | objid::bigint) = ?
		  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`,
		KEKDataKeysLockKey).Scan(&n).Error
	if err != nil {
		t.Fatalf("查 pg_locks 失敗: %v", err)
	}
	return n
}

// TestPGAdvisoryLockMutex postgres advisory lock 真路徑：兩實例競鎖恰一得手，
// 落敗方立即（非阻塞）回 ErrKeyOpBusy，鎖釋放後可再取得。
func TestPGAdvisoryLockMutex(t *testing.T) {
	dsn := setupPGLockSchema(t, pgLockTestDSN(t))

	// 兩個獨立連線池 ＝ 兩個後端實例
	dbA := openPGLockDB(t, dsn)
	dbB := openPGLockDB(t, dsn)
	if name := dbA.Dialector.Name(); name != "postgres" {
		t.Fatalf("本測試必須跑在 postgres 分流，實得 dialect %q", name)
	}
	kmA := newTestKeyManager(t, dbA, 1)
	kmB := newTestKeyManager(t, dbB, 1)

	t.Run("持鎖期間他實例立即 busy", func(t *testing.T) {
		held := make(chan struct{})
		release := make(chan struct{})
		lockDone := make(chan error, 1)
		releasedOnce := false
		releaseLock := func() {
			if !releasedOnce {
				releasedOnce = true
				close(release)
			}
		}
		defer releaseLock()

		go func() {
			lockDone <- kmA.withDataKeysLock(func(tx *gorm.DB) error {
				close(held)
				<-release
				return nil
			})
		}()
		<-held

		// 機制斷言：A 確實在 DB 層持有該 advisory lock（非僅程式旗標）
		if n := grantedDataKeysAdvisoryLocks(t, dbB); n != 1 {
			t.Fatalf("A 持鎖期間 pg_locks 應恰有 1 筆 advisory lock，實得 %d", n)
		}

		busy := make(chan error, 1)
		start := time.Now()
		go func() {
			_, err := kmB.AbandonRewrap()
			busy <- err
		}()
		select {
		case err := <-busy:
			if !errors.Is(err, ErrKeyOpBusy) {
				t.Fatalf("A 持鎖時 B 應回 ErrKeyOpBusy，實得 %v", err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("try 語義應立即返回，實耗 %v", elapsed)
			}
		case <-time.After(3*time.Second + 500*time.Millisecond):
			t.Fatal("B 逾時未返回：advisory lock 疑似退化為阻塞語義")
		}

		releaseLock()
		if err := <-lockDone; err != nil {
			t.Fatalf("A 持鎖交易應成功結束，實得 %v", err)
		}
		// xact lock 隨交易結束自動釋放（無持有者殘留）
		if n := grantedDataKeysAdvisoryLocks(t, dbB); n != 0 {
			t.Fatalf("交易結束後 advisory lock 應已釋放，pg_locks 仍有 %d 筆", n)
		}

		// 鎖隨交易結束釋放：B 重試須真正進入鎖內（無 pending → ErrNoRewrapPending，
		// 不再是 ErrKeyOpBusy）
		if _, err := kmB.AbandonRewrap(); !errors.Is(err, ErrNoRewrapPending) {
			t.Fatalf("釋放後 B 應取得鎖並回 ErrNoRewrapPending，實得 %v", err)
		}
	})

	t.Run("兩實例同時重包恰一成功", func(t *testing.T) {
		kms := []*KeyManagerService{kmA, kmB}
		// 目標於開跑前構造：材料一律由呼叫端提供，且 t.Fatalf 不可在 goroutine 內呼叫
		targets := []*RewrapTarget{
			localTargetForTest(t, newTestKEKMaterial(t)),
			localTargetForTest(t, newTestKEKMaterial(t)),
		}
		errs := make([]error, len(kms))
		barrier := make(chan struct{})
		var wg sync.WaitGroup
		for i := range kms {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-barrier
				_, errs[i] = kms[i].RewrapKEK(context.Background(), targets[i])
			}(i)
		}
		close(barrier)
		wg.Wait()

		success := 0
		for i, err := range errs {
			switch {
			case err == nil:
				success++
			case errors.Is(err, ErrKeyOpBusy):
				// 競鎖落敗（try 語義不阻塞）
			case errors.Is(err, ErrRewrapPendingExists):
				// 落敗方在對手交易提交後才取得鎖：鎖內重讀已見 pending → 守衛 (a) 拒絕。
				// 兩者皆為「恰一成功」的合法表現，差別只在取鎖時序
			default:
				t.Fatalf("實例 %d 非預期錯誤: %v", i, err)
			}
		}
		if success != 1 {
			t.Fatalf("兩實例同時重包應恰一成功，實得 %d（errs=%v）", success, errs)
		}

		// 落庫狀態：pending 列只屬單一新 KEK 指紋（無交錯產生的混雜 campaign）
		var pending []model.DataKey
		if err := dbA.Where("kek_pending = ?", true).Find(&pending).Error; err != nil {
			t.Fatalf("讀 pending 列: %v", err)
		}
		if len(pending) == 0 {
			t.Fatal("成功方應留下待切換 pending 列")
		}
		kekIDs := map[string]struct{}{}
		for _, r := range pending {
			kekIDs[r.KEKID] = struct{}{}
		}
		if len(kekIDs) != 1 {
			t.Fatalf("pending 列應僅屬單一新 KEK 指紋，實得 %d 個: %v", len(kekIDs), kekIDs)
		}
	})
}
