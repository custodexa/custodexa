package model

import (
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// audit-checkpoint-chain 的兩張表 ORM 守衛。
//
// 守衛擋的是什麼：檢查點鏈的全部價值在「系統自己也改不了已封的章」。
// 一旦存在任何可經 ORM 改寫被簽章欄位或刪除檢查點的路徑，「可以被系統改的
// 檢查點」在稽核面前一文不值——攻擊者刪列之後照樣可以把檢查點一併改到自洽。
//
// 本檔的斷言刻意涵蓋**放寬白名單**的方向（10.1 雙向突變自證的前提）：
// 只驗「刪除被拒」的守衛，在有人把 agg_hash 加進白名單時仍會全綠。

func newCheckpointGuardDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1) // :memory: 連線池陷阱：多連線各自拿到空 DB
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&AuditCheckpoint{}, &CheckpointSigningKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func seedCheckpoint(t *testing.T, db *gorm.DB, seq uint) *AuditCheckpoint {
	t.Helper()
	cp := &AuditCheckpoint{
		Seq: seq, IDFrom: 1, IDTo: 100, RowCount: 100,
		AggHash:   "aa11", // 測試值：守衛與雜湊內容無關
		AggScheme: AggSchemeV1, PrevCheckpointHash: "bb22",
		SealedAt: time.Now(), SigningKeyVersion: 1, Signature: "sig",
		AnchorStatus: AnchorStatusEnqueued,
	}
	if err := db.Create(cp).Error; err != nil {
		t.Fatalf("建立檢查點: %v", err)
	}
	return cp
}

// TestCheckpointDeleteGuard 任何 ORM 刪除路徑一律被拒（含 Where 條件式批刪）
func TestCheckpointDeleteGuard(t *testing.T) {
	db := newCheckpointGuardDB(t)
	cp := seedCheckpoint(t, db, 1)

	if err := db.Delete(cp).Error; !errors.Is(err, ErrCheckpointImmutable) {
		t.Errorf("Delete(單列) err = %v, want ErrCheckpointImmutable", err)
	}
	if err := db.Where("seq = ?", 1).Delete(&AuditCheckpoint{}).Error; !errors.Is(err, ErrCheckpointImmutable) {
		t.Errorf("Delete(批次) err = %v, want ErrCheckpointImmutable", err)
	}
	var n int64
	db.Model(&AuditCheckpoint{}).Count(&n)
	if n != 1 {
		t.Errorf("守衛後列數 = %d, want 1（列被刪掉了）", n)
	}
}

// TestCheckpointUpdateGuard 僅放行封章後狀態欄；任一被簽章欄位的更新必拒
func TestCheckpointUpdateGuard(t *testing.T) {
	db := newCheckpointGuardDB(t)
	cp := seedCheckpoint(t, db, 1)

	// 放行：錨定狀態與清除 tombstone（且只認 map 形式）
	now := time.Now()
	sig := "purge-sig"
	ver := 1
	allowed := []map[string]interface{}{
		{"anchor_status": AnchorStatusDropped},
		{"purged_at": now, "purge_signature": sig, "purge_signing_key_version": ver},
	}
	for _, upd := range allowed {
		if err := db.Model(&AuditCheckpoint{}).Where("id = ?", cp.ID).Updates(upd).Error; err != nil {
			t.Errorf("白名單欄位更新被誤拒 %v: %v", upd, err)
		}
	}

	// 拒絕：每一個被簽章欄位（逐欄斷言——只測一兩欄的守衛在白名單被放寬時仍會綠）
	signed := []map[string]interface{}{
		{"seq": 2}, {"id_from": 5}, {"id_to": 5}, {"row_count": 0},
		{"agg_hash": "deadbeef"}, {"agg_scheme": "cp-agg-v2"},
		{"prev_checkpoint_hash": "0"}, {"min_created_at": now}, {"max_created_at": now},
		{"sealed_at": now}, {"signing_key_version": 9}, {"signature": "forged"},
		// 混入一個白名單欄也不得使整批放行
		{"anchor_status": AnchorStatusEnqueued, "agg_hash": "deadbeef"},
	}
	for _, upd := range signed {
		if err := db.Model(&AuditCheckpoint{}).Where("id = ?", cp.ID).Updates(upd).Error; !errors.Is(err, ErrCheckpointImmutable) {
			t.Errorf("被簽章欄位更新 %v 未被拒，err = %v", upd, err)
		}
	}

	// 拒絕：結構體形式（Save／Updates(struct)）——全欄位寫入不得從結構體路徑溜過
	cp.AggHash = "deadbeef"
	if err := db.Save(cp).Error; !errors.Is(err, ErrCheckpointImmutable) {
		t.Errorf("Save(struct) 未被拒，err = %v", err)
	}
	if err := db.Model(&AuditCheckpoint{}).Where("id = ?", cp.ID).
		Updates(AuditCheckpoint{AnchorStatus: AnchorStatusDisabled}).Error; !errors.Is(err, ErrCheckpointImmutable) {
		t.Errorf("Updates(struct) 未被拒，err = %v", err)
	}

	var got AuditCheckpoint
	if err := db.First(&got, cp.ID).Error; err != nil {
		t.Fatalf("讀回: %v", err)
	}
	if got.AggHash != "aa11" || got.Signature != "sig" || got.Seq != 1 {
		t.Errorf("被簽章欄位遭改寫: agg_hash=%q signature=%q seq=%d", got.AggHash, got.Signature, got.Seq)
	}
	if got.AnchorStatus != AnchorStatusDropped || got.PurgedAt == nil || got.PurgeSignature == nil ||
		got.PurgeSigningKeyVersion == nil {
		t.Errorf("白名單欄位未寫入: anchor=%q purged_at=%v sig=%v ver=%v",
			got.AnchorStatus, got.PurgedAt, got.PurgeSignature, got.PurgeSigningKeyVersion)
	}
}

// TestCheckpointSigningKeyGuard 簽章鑰改刪一律被拒。
//
// 刪除任一曾用於簽章的版本＝以該版本簽的歷史檢查點永久不可驗，是單向不可逆的
// 證據損毀；更新同理（改公鑰欄即可讓偽造簽章驗過）
func TestCheckpointSigningKeyGuard(t *testing.T) {
	db := newCheckpointGuardDB(t)
	key := &CheckpointSigningKey{Version: 1, Active: true, PublicKey: "pub", PrivateKeyEnc: "enc:a1:x"}
	if err := db.Create(key).Error; err != nil {
		t.Fatalf("建立簽章鑰: %v", err)
	}

	if err := db.Delete(key).Error; !errors.Is(err, ErrCheckpointSigningKeyImmutable) {
		t.Errorf("Delete err = %v, want ErrCheckpointSigningKeyImmutable", err)
	}
	if err := db.Where("version = ?", 1).Delete(&CheckpointSigningKey{}).Error; !errors.Is(err, ErrCheckpointSigningKeyImmutable) {
		t.Errorf("Delete(批次) err = %v, want ErrCheckpointSigningKeyImmutable", err)
	}
	for _, upd := range []map[string]interface{}{
		{"public_key": "forged"}, {"private_key_enc": "x"}, {"active": false}, {"version": 2},
	} {
		if err := db.Model(&CheckpointSigningKey{}).Where("version = ?", 1).Updates(upd).Error; !errors.Is(err, ErrCheckpointSigningKeyImmutable) {
			t.Errorf("更新 %v 未被拒，err = %v", upd, err)
		}
	}
	key.PublicKey = "forged"
	if err := db.Save(key).Error; !errors.Is(err, ErrCheckpointSigningKeyImmutable) {
		t.Errorf("Save 未被拒，err = %v", err)
	}

	var got CheckpointSigningKey
	if err := db.First(&got, "version = ?", 1).Error; err != nil {
		t.Fatalf("讀回: %v", err)
	}
	if got.PublicKey != "pub" || !got.Active || got.PrivateKeyEnc != "enc:a1:x" {
		t.Errorf("簽章鑰遭改寫: %+v", got)
	}
}

// TestCheckpointUpdatableColumnsWhitelistIsExact 白名單本身的內容守衛。
//
// **雙向突變自證的另一半**：上面的測試證明「拿掉守衛會紅」，本測試證明
// 「悄悄把被簽章欄位加進白名單也會紅」。白名單是只會越放越寬的典型結構，
// 逐字釘住每一個成員是唯一擋得住的方式。
func TestCheckpointUpdatableColumnsWhitelistIsExact(t *testing.T) {
	want := map[string]bool{
		"anchor_status": true, "purged_at": true,
		"purge_signature": true, "purge_signing_key_version": true,
		// purge_policy_days：簽章的輸入必須隨簽章保存，
		// 否則政策一改全部歷史 tombstone 一起驗不過
		"purge_policy_days": true,
	}
	if len(checkpointUpdatableColumns) != len(want) {
		t.Fatalf("白名單成員數 = %d, want %d：%v",
			len(checkpointUpdatableColumns), len(want), checkpointUpdatableColumns)
	}
	for col := range checkpointUpdatableColumns {
		if !want[col] {
			t.Errorf("白名單多出 %q：僅封章後才發生且不在簽章涵蓋內的狀態欄可更新", col)
		}
	}
	for col := range want {
		if !checkpointUpdatableColumns[col] {
			t.Errorf("白名單缺少 %q：合法的錨定／清除狀態寫入會被誤擋", col)
		}
	}
}
