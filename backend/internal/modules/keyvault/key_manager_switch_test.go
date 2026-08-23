package keyvault

import (
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// KEK 切換狀態機（軟刪除退役、明確欄位狀態）核心轉移測試。
// 涵蓋審查揭露的關鍵轉移：正常切換不 fail-close（切換後 live 舊列合法）、
// 原子軟退役、backlog 重試、pending/backlog 精確區分、金鑰鏈完整性、非法形狀、退役史 from→to。

// setupKM 建立含 data v1 + audit v0/v1 的金鑰表（KEK=kmTestKey(1)）
func setupKM(t *testing.T) (*gorm.DB, *KeyManagerService) {
	t.Helper()
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)
	seedEnvelopeData(t, db, km)
	return db, km
}

// rewrapAndReinit 執行重包並以新 KEK 重啟（模擬改 env 重啟切換），回新 km 與新舊指紋。
// 切換那次 InitKeyManager 不應 fail-close——這是安全審查所列問題的回歸點：
// 切換後舊列 live 且 kek_id<>env 是合法的「待退役 predecessor」角色，不得誤判非法。
func rewrapAndReinit(t *testing.T, db *gorm.DB, km *KeyManagerService) (*KeyManagerService, string, string) {
	t.Helper()
	oldKEK := km.KEKKeyID()
	resMaterial, res := mustRewrapKEK(t, km)
	p, err := crypto.NewEnvKEKProvider([]byte(resMaterial))
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	km2, err := InitKeyManager(db, p)
	if err != nil {
		t.Fatalf("切換那次 InitKeyManager 不應 fail-close（HIGH-1）: %v", err)
	}
	return km2, oldKEK, res.NewKEKID
}

// makeBacklog 模擬退役收尾失敗殘留：把某舊 KEK 的退役列改回 live（未退役）
func makeBacklog(db *gorm.DB, oldKEK string) {
	// 還原為「收尾失敗殘留」的 live 形狀（未退役、無 reason、材料在）
	db.Model(&model.DataKey{}).Where("kek_id = ?", oldKEK).
		Updates(map[string]interface{}{"kek_retired_at": nil, "kek_retired_by": "",
			"kek_retired_reason": "", "wrapped_key": "restored-placeholder"})
}

// TestKEKSwitchSoftRetire 正常切換：舊列軟退役（保留列、**材料保留至顯式清理**、
// 記 replacement 與 reason=switched）、
// pending 轉正、LastKEKSwitch 正確、rewrapPending 歸零、資料仍可解
func TestKEKSwitchSoftRetire(t *testing.T) {
	db, km := setupKM(t)
	km2, oldKEK, newKEK := rewrapAndReinit(t, db, km)

	var oldRows []model.DataKey
	db.Where("kek_id = ?", oldKEK).Find(&oldRows)
	if len(oldRows) == 0 {
		t.Fatal("舊 KEK 列不應被硬刪，應軟退役保留")
	}
	for _, r := range oldRows {
		if r.KEKRetiredAt == nil || r.KEKRetiredBy != newKEK ||
			r.KEKRetiredReason != model.KEKRetireReasonSwitched {
			t.Fatalf("舊列應軟退役（retired_at 非空、retired_by=%s、reason=switched）：%+v", newKEK, r)
		}
		if r.WrappedKey == "" {
			t.Fatalf("退役不得清空材料（軟刪除：銷毀僅發生於顯式清理）：%+v", r)
		}
	}
	var newRows []model.DataKey
	db.Where("kek_id = ?", newKEK).Find(&newRows)
	if len(newRows) == 0 {
		t.Fatal("新 KEK 列應存在")
	}
	for _, r := range newRows {
		if r.KEKPending || r.KEKRetiredAt != nil {
			t.Fatalf("新列應轉正為現行（pending=false、未退役）：%+v", r)
		}
	}
	sw := km2.LastKEKSwitch()
	if sw == nil || sw.ToKEKID != newKEK || sw.RetiredCount != len(oldRows) {
		t.Fatalf("LastKEKSwitch 應記錄切換（to=%s, retired=%d）：%+v", newKEK, len(oldRows), sw)
	}
	if km2.RewrapPending() {
		t.Fatal("切換完成後 rewrapPending 應為 false")
	}
	var vals []string
	db.Raw("SELECT password_enc FROM assets WHERE name = 'a1'").Scan(&vals)
	if got, err := decryptColumn(km2, "assets", "password_enc", vals[0]); err != nil || got != "asset-password" {
		t.Fatalf("切換後資料應可解: %q err=%v", got, err)
	}
}

// TestKEKSwitchNoSwitchNoTrace 未切換的正常重啟不產生退役/切換結果（冪等）
func TestKEKSwitchNoSwitchNoTrace(t *testing.T) {
	db, _ := setupKM(t)
	km2 := newTestKeyManager(t, db, 1)
	if km2.LastKEKSwitch() != nil {
		t.Fatal("無切換不應有 LastKEKSwitch")
	}
	if km2.RewrapPending() {
		t.Fatal("無重包不應 rewrapPending")
	}
	var retired int64
	db.Model(&model.DataKey{}).Where("kek_retired_at IS NOT NULL").Count(&retired)
	if retired != 0 {
		t.Fatalf("無切換不應有退役列，得 %d", retired)
	}
}

// TestKEKSwitchBacklogRetry 退役 backlog（前次收尾未退役殘留）於下次啟動重試退役
func TestKEKSwitchBacklogRetry(t *testing.T) {
	db, km := setupKM(t)
	km2, oldKEK, _ := rewrapAndReinit(t, db, km)
	makeBacklog(db, oldKEK) // 模擬退役收尾失敗殘留

	// 以相同（新）KEK provider 重啟 → load 應重試退役 backlog
	km3, err := InitKeyManager(db, km2.kek)
	if err != nil {
		t.Fatalf("重啟 load 不應失敗: %v", err)
	}
	var stillLive int64
	db.Model(&model.DataKey{}).Where("kek_id = ? AND kek_retired_at IS NULL", oldKEK).Count(&stillLive)
	if stillLive != 0 {
		t.Fatalf("backlog 舊列應於重啟重試退役，仍有 %d 筆未退役", stillLive)
	}
	_ = km3
}

// TestRewrapRejectedWhenPendingExists 已有待切換 pending 時拒絕新重包（不覆蓋已交付 KEK）
func TestRewrapRejectedWhenPendingExists(t *testing.T) {
	db, km := setupKM(t)
	if _, err := rewrapKEKWith(t, km, newTestKEKMaterial(t)); err != nil {
		t.Fatalf("首次重包: %v", err)
	}
	if _, err := rewrapKEKWith(t, km, newTestKEKMaterial(t)); !errors.Is(err, ErrRewrapPendingExists) {
		t.Fatalf("已有 pending 應拒絕第二次重包，得 %v", err)
	}
	var pending int64
	db.Model(&model.DataKey{}).Where("kek_pending = ?", true).Count(&pending)
	if pending == 0 {
		t.Fatal("第一組 pending 應完整保留")
	}
}

// TestRewrapRejectedWhenBacklog 退役 backlog 未收斂時拒絕新重包
func TestRewrapRejectedWhenBacklog(t *testing.T) {
	db, km := setupKM(t)
	km2, oldKEK, _ := rewrapAndReinit(t, db, km) // 切換完成（舊列退役）
	makeBacklog(db, oldKEK)                      // 製造 backlog
	// km2 現行 KEK=新，直接呼叫 RewrapKEK：backlog 守衛應拒絕
	if _, err := rewrapKEKWith(t, km2, newTestKEKMaterial(t)); !errors.Is(err, ErrRetireBacklog) {
		t.Fatalf("退役 backlog 未收斂應拒絕重包，得 %v", err)
	}
}

// TestAbandonRejectsEnvPending 切換完成待轉正的 env pending 不被放棄誤刪
func TestAbandonRejectsEnvPending(t *testing.T) {
	db, km := setupKM(t)
	resMaterial, res := mustRewrapKEK(t, km)
	p, _ := crypto.NewEnvKEKProvider([]byte(resMaterial))
	km2, err := InitKeyManager(db, p)
	if err != nil {
		t.Fatalf("切換: %v", err)
	}
	// 手動製造「env pending 殘留」（模擬轉正失敗）：新列改回 pending
	db.Model(&model.DataKey{}).Where("kek_id = ?", res.NewKEKID).Update("kek_pending", true)
	km2.rewrapPending = true // 強制進入放棄路徑以測 DB 確認守衛
	if _, err := km2.AbandonRewrap(); !errors.Is(err, ErrNoRewrapPending) {
		t.Fatalf("env pending（待轉正）應拒絕放棄，得 %v", err)
	}
	var envPending int64
	db.Model(&model.DataKey{}).Where("kek_id = ? AND kek_pending = ?", res.NewKEKID, true).Count(&envPending)
	if envPending == 0 {
		t.Fatal("env pending 列不應被放棄刪除")
	}
}

// TestLoadFailCloseKeyChainGap 金鑰鏈斷號 → fail-close
func TestLoadFailCloseKeyChainGap(t *testing.T) {
	db, km := setupKM(t)
	if _, err := km.RotateDataDEK(); err != nil {
		t.Fatalf("rotate v2: %v", err)
	}
	if _, err := km.RotateDataDEK(); err != nil {
		t.Fatalf("rotate v3: %v", err)
	}
	db.Where("purpose = ? AND version = ?", model.DataKeyPurposeData, 2).Delete(&model.DataKey{})
	if _, err := reinitKM(t, db); !errors.Is(err, ErrKEKMismatch) {
		t.Fatalf("data 版本斷號應 fail-close，得 %v", err)
	}
}

// TestLoadFailCloseInvalidShape 非法欄位形狀（pending 且已退役）→ fail-close
func TestLoadFailCloseInvalidShape(t *testing.T) {
	db, _ := setupKM(t)
	now := time.Now()
	db.Model(&model.DataKey{}).Where("purpose = ? AND version = ?", model.DataKeyPurposeData, 1).
		Updates(map[string]interface{}{"kek_pending": true, "kek_retired_at": now, "kek_retired_by": "x"})
	if _, err := reinitKM(t, db); !errors.Is(err, ErrKEKMismatch) {
		t.Fatalf("非法形狀應 fail-close，得 %v", err)
	}
}

// TestLoadFailCloseMultiActive 同用途多 active → fail-close
func TestLoadFailCloseMultiActive(t *testing.T) {
	db, km := setupKM(t)
	if _, err := km.RotateDataDEK(); err != nil { // data v1 retired, v2 active
		t.Fatalf("rotate: %v", err)
	}
	db.Model(&model.DataKey{}).Where("purpose = ? AND version = ?", model.DataKeyPurposeData, 1).
		Update("status", model.DataKeyStatusActive)
	if _, err := reinitKM(t, db); !errors.Is(err, ErrKEKMismatch) {
		t.Fatalf("多 active 應 fail-close，得 %v", err)
	}
}

// TestMultiSwitchRetiredByChain 多次 A→B→C 切換退役史 from→to 正確（不誤配 A→C）
func TestMultiSwitchRetiredByChain(t *testing.T) {
	db, km := setupKM(t)
	kmA := km.KEKKeyID()
	kmB2, _, kmB := rewrapAndReinit(t, db, km) // A→B
	_, _, kmC := rewrapAndReinit(t, db, kmB2)  // B→C

	var aRow, bRow model.DataKey
	db.Where("kek_id = ? AND kek_retired_at IS NOT NULL", kmA).First(&aRow)
	db.Where("kek_id = ? AND kek_retired_at IS NOT NULL", kmB).First(&bRow)
	if aRow.KEKRetiredBy != kmB {
		t.Fatalf("A 的 replacement 應為 B(%s)，得 %s", kmB, aRow.KEKRetiredBy)
	}
	if bRow.KEKRetiredBy != kmC {
		t.Fatalf("B 的 replacement 應為 C(%s)，得 %s", kmC, bRow.KEKRetiredBy)
	}
}

// reinitKM 以同一把測試 KEK 重新載入金鑰表（模擬重啟）
func reinitKM(t *testing.T, db *gorm.DB) (*KeyManagerService, error) {
	t.Helper()
	kek, err := crypto.NewEnvKEKProvider(kmTestKey(1))
	if err != nil {
		return nil, err
	}
	return InitKeyManager(db, kek)
}
