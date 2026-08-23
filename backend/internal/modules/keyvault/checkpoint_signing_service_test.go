package keyvault_test

import (
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 檢查點簽章鑰服務（audit-checkpoint-chain）。
//
// 這把鑰是整條鏈的信任根：以它簽的檢查點若不可驗，鏈就只是一堆無意義的雜湊。
// 故本檔的斷言集中在三件事——(1) 私鑰只以 AAD 綁定的 `enc:a1` 落庫、
// (2) 任何載入不確定性一律 fail-close（不得帶病產生無法驗證的檢查點）、
// (3) 私鑰沒有任何出口。

func setupCheckpointSigningDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.CheckpointSigningKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// TestCheckpointSigningKeyGenerateAndSign 首啟生成 v1（active）→ 簽驗往返 → 版本欄落庫
func TestCheckpointSigningKeyGenerateAndSign(t *testing.T) {
	db := setupCheckpointSigningDB(t)
	svc, err := keyvault.NewCheckpointSigningService(db, aesColumnCodec(t, testEncryptionKey))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if svc.ActiveVersion() != 1 {
		t.Errorf("ActiveVersion = %d, want 1", svc.ActiveVersion())
	}

	payload := []byte(`{"seq":1,"id_from":1,"id_to":100}`)
	ver, sig := svc.Sign(payload)
	if ver != 1 {
		t.Errorf("Sign 版本 = %d, want 1", ver)
	}
	ok, err := svc.Verify(ver, payload, sig)
	if err != nil || !ok {
		t.Errorf("原始 payload 驗簽應通過（ok=%v err=%v）", ok, err)
	}
	tampered := append([]byte{}, payload...)
	tampered[5] ^= 1
	if ok, _ := svc.Verify(ver, tampered, sig); ok {
		t.Error("竄改 payload 後驗簽仍通過")
	}

	// 落庫形狀：version=1、active、公鑰明文、私鑰為 AAD 綁定的終態密文
	var row model.CheckpointSigningKey
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("讀回: %v", err)
	}
	if row.Version != 1 || !row.Active {
		t.Errorf("落庫版本語義錯：version=%d active=%v", row.Version, row.Active)
	}
	// 私鑰欄為密文：以正確欄位身分解得回 64 bytes 的 Ed25519 私鑰，
	// 且落庫值本身不是該明文（AAD 綁定的驗證另見 TestCheckpointSigningKeyAADBinding）
	plain, err := aesColumnCodec(t, testEncryptionKey).DecryptFor(
		context.Background(), keyvault.RefCheckpointSigningPrivateKey, row.PrivateKeyEnc)
	if err != nil {
		t.Fatalf("以欄位身分解包私鑰失敗: %v", err)
	}
	if raw, derr := base64.StdEncoding.DecodeString(plain); derr != nil || len(raw) != 64 {
		t.Errorf("解包結果非 Ed25519 私鑰（len=%d err=%v）", len(raw), derr)
	}
	if row.PrivateKeyEnc == plain {
		t.Error("私鑰以明文落庫")
	}
	if raw, err := base64.StdEncoding.DecodeString(row.PublicKey); err != nil || len(raw) != 32 {
		t.Errorf("公鑰欄非 base64 Ed25519 公鑰: %q", row.PublicKey)
	}
	if fp, err := svc.PublicKeyFingerprint(1); err != nil || len(fp) != 16 {
		t.Errorf("公鑰指紋 = %q err=%v, want 16 hex 字元（SHA-256 前 8 bytes）", fp, err)
	}
}

// TestCheckpointSigningKeyReloadStable 重啟載入同一把鑰：公鑰不變、舊簽章仍驗得過
func TestCheckpointSigningKeyReloadStable(t *testing.T) {
	db := setupCheckpointSigningDB(t)
	codec := aesColumnCodec(t, testEncryptionKey)
	first, err := keyvault.NewCheckpointSigningService(db, codec)
	if err != nil {
		t.Fatalf("首啟: %v", err)
	}
	payload := []byte("checkpoint-payload")
	ver, sig := first.Sign(payload)

	second, err := keyvault.NewCheckpointSigningService(db, codec)
	if err != nil {
		t.Fatalf("重啟載入: %v", err)
	}
	if second.ActivePublicKeyBase64() != first.ActivePublicKeyBase64() {
		t.Error("重啟後公鑰改變：歷史檢查點將全數不可驗")
	}
	if ok, err := second.Verify(ver, payload, sig); err != nil || !ok {
		t.Errorf("重啟後舊簽章驗證失敗（ok=%v err=%v）", ok, err)
	}
	var n int64
	db.Model(&model.CheckpointSigningKey{}).Count(&n)
	if n != 1 {
		t.Errorf("重啟後鑰列數 = %d, want 1（重複生成會使鏈換鑰）", n)
	}
}

// TestCheckpointSigningKeyFailClose 載入不確定性一律拒絕啟動（不得靜默改用新鑰）
func TestCheckpointSigningKeyFailClose(t *testing.T) {
	t.Run("KEK 不符", func(t *testing.T) {
		db := setupCheckpointSigningDB(t)
		if _, err := keyvault.NewCheckpointSigningService(db, aesColumnCodec(t, testEncryptionKey)); err != nil {
			t.Fatalf("首啟: %v", err)
		}
		wrong := aesColumnCodec(t, []byte("another-key-for-testing-32-bytes"))
		svc, err := keyvault.NewCheckpointSigningService(db, wrong)
		if err == nil {
			t.Fatal("KEK 不符仍成功載入：帶病啟動會產生一批無法驗證的檢查點")
		}
		if svc != nil {
			t.Error("失敗路徑不得回傳可用服務")
		}
		if !strings.Contains(err.Error(), "解密") {
			t.Errorf("錯誤訊息缺排查指引: %v", err)
		}
	})

	t.Run("公鑰欄遭竄改", func(t *testing.T) {
		db := setupCheckpointSigningDB(t)
		codec := aesColumnCodec(t, testEncryptionKey)
		if _, err := keyvault.NewCheckpointSigningService(db, codec); err != nil {
			t.Fatalf("首啟: %v", err)
		}
		// 繞過 ORM 守衛的直寫（模擬 DB 直接改欄）：公鑰與私鑰不再自洽
		if err := db.Exec("UPDATE checkpoint_signing_keys SET public_key = ? WHERE version = 1",
			base64.StdEncoding.EncodeToString(make([]byte, 32))).Error; err != nil {
			t.Fatalf("直寫: %v", err)
		}
		if _, err := keyvault.NewCheckpointSigningService(db, codec); err == nil {
			t.Fatal("公鑰欄與私鑰不符仍載入：改公鑰欄即可讓偽造簽章驗過")
		}
	})

	t.Run("無 active 版本", func(t *testing.T) {
		db := setupCheckpointSigningDB(t)
		codec := aesColumnCodec(t, testEncryptionKey)
		if _, err := keyvault.NewCheckpointSigningService(db, codec); err != nil {
			t.Fatalf("首啟: %v", err)
		}
		if err := db.Exec("UPDATE checkpoint_signing_keys SET active = 0 WHERE version = 1").Error; err != nil {
			t.Fatalf("直寫: %v", err)
		}
		if _, err := keyvault.NewCheckpointSigningService(db, codec); err == nil {
			t.Fatal("無 active 版本仍載入：無從決定以哪把鑰封章")
		}
	})
}

// TestCheckpointSigningKeyUnknownVersion 未知版本回明確錯誤，不得靜默略過
func TestCheckpointSigningKeyUnknownVersion(t *testing.T) {
	db := setupCheckpointSigningDB(t)
	svc, err := keyvault.NewCheckpointSigningService(db, aesColumnCodec(t, testEncryptionKey))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := svc.PublicKeyBase64(2); err == nil {
		t.Error("未知版本取公鑰應回錯")
	}
	ok, err := svc.Verify(2, []byte("x"), "c2ln")
	if err == nil || ok {
		t.Errorf("未知版本驗章應回錯（ok=%v err=%v）——回「驗不了所以算過」等於為改版本號免驗開後門", ok, err)
	}
}

// TestCheckpointSigningKeyAADBinding：私鑰密文綁定 checkpoint_signing_keys
// 的欄位身分，以其他欄位身分（含匯出簽章鑰）解包必失敗——AAD 錯配即拒解，
// 使「把匯出鑰的密文搬進本表冒充」這條路不通
func TestCheckpointSigningKeyAADBinding(t *testing.T) {
	db := setupCheckpointSigningDB(t)
	codec := aesColumnCodec(t, testEncryptionKey)
	if _, err := keyvault.NewCheckpointSigningService(db, codec); err != nil {
		t.Fatalf("new: %v", err)
	}
	var row model.CheckpointSigningKey
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("讀回: %v", err)
	}
	ctx := context.Background()

	if _, err := codec.DecryptFor(ctx, keyvault.RefCheckpointSigningPrivateKey, row.PrivateKeyEnc); err != nil {
		t.Errorf("以正確欄位身分解包失敗: %v", err)
	}
	for _, ref := range []crypto.CipherRef{
		keyvault.RefExportSigningPrivateKey,
		keyvault.RefUserTOTPSecret,
		{Table: "checkpoint_signing_keys", Column: "public_key"},
	} {
		if _, err := codec.DecryptFor(ctx, ref, row.PrivateKeyEnc); err == nil {
			t.Errorf("以錯誤欄位身分 %s|%s 解包竟成功：AAD 綁定失效", ref.Table, ref.Column)
		}
	}
}

// TestCheckpointSigningKeyHasNoPrivateKeyExit：型別層無任何私鑰出口。
//
// 路由層的守衛在第 8 組隨端點一併加；本測試釘住更根本的一層——**服務型別本身
// 沒有可以把私鑰交出去的方法**，故不存在「新增端點時不小心把它接出去」的素材。
func TestCheckpointSigningKeyHasNoPrivateKeyExit(t *testing.T) {
	typ := reflect.TypeOf(&keyvault.CheckpointSigningService{})
	privKeyType := reflect.TypeOf([]byte(nil))
	for i := 0; i < typ.NumMethod(); i++ {
		m := typ.Method(i)
		lower := strings.ToLower(m.Name)
		for _, banned := range []string{"private", "export", "download", "delete", "raw", "material"} {
			if strings.Contains(lower, banned) {
				t.Errorf("匯出方法 %s 的命名疑似私鑰出口（含 %q）", m.Name, banned)
			}
		}
		for j := 0; j < m.Type.NumOut(); j++ {
			out := m.Type.Out(j)
			if out == privKeyType || out.Kind() == reflect.Slice && out.Elem().Kind() == reflect.Uint8 {
				t.Errorf("匯出方法 %s 回傳原始位元組（%s）：私鑰材料不得有位元組出口", m.Name, out)
			}
		}
	}
	// 反向下界：方法真的被掃到（0 個方法會讓上面的迴圈空轉而假綠）
	if typ.NumMethod() < 5 {
		t.Fatalf("掃到的匯出方法只有 %d 個：反射掃描失真，本守衛在空集合下假綠", typ.NumMethod())
	}
}
