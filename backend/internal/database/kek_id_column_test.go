package database

import (
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// data_keys 的 KEK 識別欄擴寬（kek-provider-modularization D4／tasks 1.4）。
//
// 為什麼要測：委託模式的金鑰引用（KMS 正規 ARN 約 75 字元、PKCS#11 token:label）
// 放不進 varchar(32)。擴寬本身無風險，**風險在唯一索引**——postgres 的
// ALTER COLUMN TYPE 會重寫依賴該欄的索引，若重建遺漏，升級後
// (purpose, version, kek_id) 的重複未退役列將可插入，重包狀態機的
// 「同 slot 至多一列帶材料」不變式即靜默失效（此不變式同時是 D5 的 AAD 完備性依賴）。

const longExternalKeyRef = "arn:aws:kms:ap-northeast-1:123456789012:key/12345678-1234-1234-1234-123456789012" +
	"/very/long/suffix/to/exceed/thirty/two/characters/by/a/wide/margin/for/regression"

func newKEKRow(kekID string, version int) model.DataKey {
	return model.DataKey{
		Purpose:    model.DataKeyPurposeData,
		Version:    version,
		WrappedKey: "d3JhcHBlZA==",
		KEKID:      kekID,
		Status:     model.DataKeyStatusActive,
		CreatedAt:  time.Now(),
	}
}

// TestKEKIDColumnWidthEquivalenceSQLite sqlite 路徑（AutoMigrate 依 gorm tag 建欄）：
// 長外部金鑰引用完整存放、不被截斷，且唯一索引仍生效。
func TestKEKIDColumnWidthEquivalenceSQLite(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite 開啟失敗: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1) // :memory: 連線池陷阱：多連線會拿到各自的空 DB
	t.Cleanup(func() { _ = sqlDB.Close() })

	if err := db.AutoMigrate(&model.DataKey{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	row := newKEKRow(longExternalKeyRef, 1)
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("寫入長金鑰引用失敗: %v", err)
	}
	var got model.DataKey
	if err := db.First(&got, row.ID).Error; err != nil {
		t.Fatalf("讀回失敗: %v", err)
	}
	if got.KEKID != longExternalKeyRef {
		t.Fatalf("金鑰引用被截斷：長度 %d != %d", len(got.KEKID), len(longExternalKeyRef))
	}
	// 唯一索引仍生效（同 purpose+version+kek_id 的第二列須被拒）
	dup := newKEKRow(longExternalKeyRef, 1)
	if err := db.Create(&dup).Error; err == nil {
		t.Fatal("唯一索引失效：可插入重複的 (purpose, version, kek_id) 列")
	}
}

// TestKEKIDColumnWidthAndUniquenessPostgres baseline 產出的 data_keys 形狀
// （gating：未設 TEST_PG_DSN 即 skip；REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
//
// **前身是 TestKEKIDColumnWidenPostgres**：那條走的是「舊 schema varchar(32)
// → 跑擴寬 migration → 斷言結果」的既有部署升級路徑。migration 隨壓縮退場，
// 升級路徑不再存在，但它守的三件事一件都沒消失，只是對象換成 baseline：
//
//  1. kek_id 放得下委託模式的長金鑰引用（KMS ARN、PKCS#11 token:label）
//  2. (purpose, version, kek_id) 的唯一索引仍生效——這是重包狀態機
//     「同 slot 至多一列帶材料」不變式的 DB 層承載，也是 AAD 完備性的依賴
//  3. 該索引是 partial 的：已退役列不佔用鍵位，故切換後可以同鍵重試
//
// 欄寬與索引若在 baseline 被改窄／改成非 partial，後果同樣無外顯症狀
// （寫入被截斷或重試被誤拒，都要等到實際切換 KEK 才發現），故仍需釘住。
func TestKEKIDColumnWidthAndUniquenessPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := freshSchema(t, dsn, "kek_id_column_test")

	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}

	// 欄寬：長外部引用可完整存放
	if err := db.Exec(`INSERT INTO data_keys (purpose, version, wrapped_key, kek_id, status, created_at)
		VALUES ('data', 2, 'd3JhcHBlZA==', ?, 'active', NOW())`, longExternalKeyRef).Error; err != nil {
		t.Fatalf("長金鑰引用寫入失敗（baseline 的 kek_id 欄寬不足？）: %v", err)
	}
	var readBack string
	if err := db.Raw("SELECT kek_id FROM data_keys WHERE version = 2").Scan(&readBack).Error; err != nil {
		t.Fatalf("讀回失敗: %v", err)
	}
	if readBack != longExternalKeyRef {
		t.Fatalf("金鑰引用被截斷：%d != %d", len(readBack), len(longExternalKeyRef))
	}

	// 唯一索引仍生效
	err := db.Exec(`INSERT INTO data_keys (purpose, version, wrapped_key, kek_id, status, created_at)
		VALUES ('data', 2, 'd3JhcHBlZA==', ?, 'active', NOW())`, longExternalKeyRef).Error
	if err == nil {
		t.Fatal("唯一索引失效：可插入重複的未退役 (purpose, version, kek_id) 列")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "duplicate") &&
		!strings.Contains(strings.ToLower(err.Error()), "unique") {
		t.Fatalf("重複插入的錯誤非唯一性違反: %v", err)
	}

	// partial 特性仍在：退役列不受索引拘束
	if err := db.Exec(`UPDATE data_keys SET kek_retired_at = NOW(), kek_retired_by = ?, kek_retired_reason = 'switched'
		WHERE version = 2`, longExternalKeyRef).Error; err != nil {
		t.Fatalf("退役更新失敗（kek_retired_by 欄寬不足？）: %v", err)
	}
	if err := db.Exec(`INSERT INTO data_keys (purpose, version, wrapped_key, kek_id, status, created_at)
		VALUES ('data', 2, 'd3JhcHBlZA==', ?, 'active', NOW())`, longExternalKeyRef).Error; err != nil {
		t.Fatalf("退役後同鍵重試應被 partial 索引放行: %v", err)
	}
}
