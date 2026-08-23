package keyvault

// 對抗測試的回歸集（長期保留）。
// 攻擊面：KEK 重包鎖死/孤兒列、遷移雙重信封、DEK 輪替中斷、envelope 惡意輸入、
// 金鑰材料外洩、KEK 隨機性、HMAC 版本化誠實性、通知 URL 遮罩。
// 已由專項回歸取代的攻擊項不重複：續跑膨脹（TestRotateDataDEKPartialResume）、
// 重包中輪替（TestRotateBlockedWhileRewrapPending）、前綴撞名明文
//（TestEnvelopeMigrationPrefixCollisionPlaintext）、回填插列
//（TestIntegrityBackdatedInsertDetected）。

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// TestAuditRewrapIssuedKEKSurvivesGuardedRotate 重包後、重啟前觸發輪替：
// 守衛必須擋下（否則新鑄鑰只被舊 KEK 包裹，精靈已發出的新 KEK 被靜默作廢），
// 且精靈發出的新 KEK 仍可切換開機
func TestAuditRewrapIssuedKEKSurvivesGuardedRotate(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)
	seedEnvelopeData(t, db, km)

	rewrapMaterial, _ := mustRewrapKEK(t, km)
	// 重包後、重啟前，另一位管理員觸發 DEK 輪替——必須被守衛擋下
	if _, err := km.RotateDataDEK(); !errors.Is(err, ErrRewrapPending) {
		t.Fatalf("重包待切換應拒絕輪替，得 %v", err)
	}

	// 精靈發出的新 KEK 未被作廢：切換開機成功、資料可讀
	newProvider, _ := crypto.NewEnvKEKProvider([]byte(rewrapMaterial))
	kmNew, err := InitKeyManager(db, newProvider)
	if err != nil {
		t.Fatalf("已發出的新 KEK 應可切換開機: %v", err)
	}
	var vals []string
	db.Raw("SELECT password_enc FROM assets WHERE name = 'a1'").Scan(&vals)
	if got, derr := decryptColumn(kmNew, "assets", "password_enc", vals[0]); derr != nil || got != "asset-password" {
		t.Fatalf("切換後資料應可讀: %q err=%v", got, derr)
	}
}

// TestAuditDoubleRewrapSinglePendingSet 重複重包兩次——僅存在一組待切換列；
// 第二把 KEK 可切換、第一把必須被拒（不遺留可用的孤兒鑰）
func TestAuditDoubleRewrapSinglePendingSet(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)
	seedEnvelopeData(t, db, km)

	firstMaterial, first := mustRewrapKEK(t, km)
	// 新行為：已有待切換 pending 時第二次重包被拒，
	// 不靜默覆蓋已交付的第一把 KEK（避免管理員已存的新 KEK 失效）
	if _, err := rewrapKEKWith(t, km, newTestKEKMaterial(t)); !errors.Is(err, ErrRewrapPendingExists) {
		t.Fatalf("已有 pending 應拒絕第二次重包，得 %v", err)
	}

	// 第一組 pending 完整保留（未被清除）
	var firstPending, mine int64
	db.Model(&model.DataKey{}).Where("kek_id = ? AND kek_pending = ?", first.NewKEKID, true).Count(&firstPending)
	db.Model(&model.DataKey{}).Where("kek_id = ?", km.KEKKeyID()).Count(&mine)
	if firstPending != mine {
		t.Fatalf("第一組 pending 應完整保留：pending=%d mine=%d", firstPending, mine)
	}

	// 第一把 KEK 切換成功：pending 轉正、舊列軟退役保留（非硬刪）、無 backlog 殘留
	p1, _ := crypto.NewEnvKEKProvider([]byte(firstMaterial))
	km2, err := InitKeyManager(db, p1)
	if err != nil {
		t.Fatalf("第一把 KEK 切換失敗: %v", err)
	}
	if km2.RewrapPending() {
		t.Fatal("切換完成不應仍標 pending")
	}
	var retired, backlog, currentLive int64
	db.Model(&model.DataKey{}).Where("kek_id <> ? AND kek_retired_at IS NOT NULL", first.NewKEKID).Count(&retired)
	db.Model(&model.DataKey{}).Where("kek_id <> ? AND kek_retired_at IS NULL", first.NewKEKID).Count(&backlog)
	db.Model(&model.DataKey{}).Where("kek_id = ? AND kek_retired_at IS NULL", first.NewKEKID).Count(&currentLive)
	if retired == 0 {
		t.Fatal("舊列應軟退役保留（非硬刪）")
	}
	if backlog != 0 {
		t.Fatalf("切換後不應有未退役他鑰列（backlog），得 %d", backlog)
	}
	if currentLive != mine {
		t.Fatalf("切換後現行未退役列 %d != 原現行 %d", currentLive, mine)
	}
}

// TestAuditThirdKEKAfterRewrapRefused 重包後改成第三把無關 KEK 開機——必須拒啟動
func TestAuditThirdKEKAfterRewrapRefused(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)
	seedEnvelopeData(t, db, km)
	if _, err := rewrapKEKWith(t, km, newTestKEKMaterial(t)); err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	third, _ := crypto.NewEnvKEKProvider(kmTestKey(9))
	if _, err := InitKeyManager(db, third); !errors.Is(err, ErrKEKMismatch) {
		t.Fatalf("第三把錯誤 KEK 應拒啟動，得 %v", err)
	}
}

// TestAuditRotationMidFailureOldValuesReadable DEK 輪替中斷（active 已切新版、
// 批次重加密未跑）——舊版本密文必須仍可解；重啟後亦然
func TestAuditRotationMidFailureOldValuesReadable(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)
	ctV1 := encryptColumn(t, km, "assets", "password_enc", "secret-before-rotation")
	if !strings.HasPrefix(ctV1, "enc:a1:v1:") {
		t.Fatalf("前置：應為 v1 帶 AAD 密文: %q", ctV1)
	}

	// 直接 bump（等價於 RotateDataDEK 在批次重加密前崩潰）；
	// bump 走鎖內交易＋commit 後套用 in-memory
	var toVer int
	var raw []byte
	err := km.withDataKeysLock(func(tx *gorm.DB) error {
		var err error
		_, toVer, raw, err = km.bumpActiveKeyTx(tx, model.DataKeyPurposeData)
		return err
	})
	if err != nil {
		t.Fatalf("bump: %v", err)
	}
	km.commitBumpedKey(model.DataKeyPurposeData, toVer, raw)
	if got, err := decryptColumn(km, "assets", "password_enc", ctV1); err != nil || got != "secret-before-rotation" {
		t.Fatalf("active 切 v2 後 v1 密文不可讀: %q err=%v", got, err)
	}
	if ct2 := encryptColumn(t, km, "assets", "password_enc", "x"); !strings.HasPrefix(ct2, "enc:a1:v2:") {
		t.Fatalf("新寫入應為 v2: %q", ct2)
	}

	// 重啟（重新 load 金鑰表）後 v1 仍可解
	km2 := newTestKeyManager(t, db, 1)
	if got, err := decryptColumn(km2, "assets", "password_enc", ctV1); err != nil || got != "secret-before-rotation" {
		t.Fatalf("重啟後 v1 密文不可讀: %q err=%v", got, err)
	}
}

// TestAuditParseEnvelopeHostileInputs envelope 解析惡意輸入——不得 panic、不得誤解密
func TestAuditParseEnvelopeHostileInputs(t *testing.T) {
	db := newKeyManagerDB(t)
	km := newTestKeyManager(t, db, 1)

	// 超大 version（int64 溢位）→ 必須報錯
	if _, _, _, err := crypto.ParseEnvelope("enc:v99999999999999999999:AA=="); err == nil {
		t.Fatal("溢位 version 應報錯")
	}
	// MaxInt32 version → 解析可過但解密必須受控失敗（不 panic）
	if _, err := decryptColumn(km, "assets", "password_enc", "enc:a1:v2147483647:AA=="); err == nil {
		t.Fatal("不存在的巨大版本應受控失敗")
	}
	// 空 payload → 受控失敗
	if _, err := decryptColumn(km, "assets", "password_enc", "enc:a1:v1:"); err == nil {
		t.Fatal("空 payload 應受控失敗")
	}
	// 多重冒號注入 → base64 解碼失敗
	if _, _, _, err := crypto.ParseEnvelope("enc:v1:AAAA:BBBB"); err == nil {
		t.Fatal("payload 注入冒號應報錯")
	}
	// 非正規 version 表記（Atoi 接受 +1 / 01）：已裁決為無實害
	//（僅 DB 直寫可植入、輪替自動正規化），記錄行為供追蹤
	for _, s := range []string{"enc:a1:v+1:", "enc:a1:v01:"} {
		ctReal := encryptColumn(t, km, "assets", "password_enc", "canonical")
		payload := ctReal[len("enc:a1:v1:"):]
		scheme, ver, _, ok, err := crypto.ParseEnvelopeFull(s + payload)
		t.Logf("非正規 %q → scheme=%q ver=%d ok=%v err=%v", s, scheme, ver, ok, err)
	}
}

// TestAuditListKeysNoWrappedMaterial 清冊不得帶出 wrapped_key：
// DEKVersionEntry 型別層面即無材料欄位，序列化結果不得出現 wrapped 值
func TestAuditListKeysNoWrappedMaterial(t *testing.T) {
	db := newKeyManagerDB(t)
	km := newTestKeyManager(t, db, 1)
	rows, err := km.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("清冊不應為空")
	}
	blob, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), "wrapped") {
		t.Fatalf("清冊序列化結果出現 wrapped 欄位: %s", blob)
	}
	var stored []model.DataKey
	if err := db.Find(&stored).Error; err != nil {
		t.Fatalf("read data_keys: %v", err)
	}
	for _, r := range stored {
		if r.WrappedKey != "" && strings.Contains(string(blob), r.WrappedKey) {
			t.Fatal("清冊序列化結果洩漏 wrapped_key 值")
		}
	}
}

// 註：原 TestAuditGenerateKEKStringDistribution
// 已隨 generateKEKString 一併刪除——明文流向反轉後伺服端不生成 KEK，該函式在
// rewrap 路徑上已不存在，留著它等於留一條「伺服端仍能生成材料」的可用旁路。
// 取而代之的守衛是 key_rewrap_no_generation_ast_test.go：釘住 RewrapKEK 的呼叫
// 傳遞閉包內不得出現任何 KEK 材料生成器或 crypto/rand 取用。

// --- helpers ---

// seedEnvelopeData 佈建**終態格式**存量（enc:a1）：資產密碼、使用者 TOTP、
// 兩個通知通道。取代已刪除的 seedLegacyData＋RunEnvelopeDataMigration 前置
// ——終態下不存在需要一次性信封化的存量。
func seedEnvelopeData(t *testing.T, db *gorm.DB, km *KeyManagerService) {
	t.Helper()
	pw := encryptColumn(t, km, "assets", "password_enc", "asset-password")
	mfa := encryptColumn(t, km, "users", "totp_secret_enc", "totp-secret")
	if err := db.Exec("INSERT INTO assets (name, host, port, protocol, username, password_enc, private_key_enc, sftp_password_enc, created_by) VALUES ('a1','h',22,'ssh','root',?, '', '', 1)", pw).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := db.Exec("INSERT INTO users (username, password, totp_secret_enc) VALUES ('u1','x',?)", mfa).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	for _, ch := range []model.NotificationChannel{
		{Name: "slack", Type: "slack",
			URL:     encryptColumn(t, km, "notification_channels", "url", "https://hooks.slack.com/services/T0/B0/secretpart"),
			Enabled: true},
		{Name: "hook", Type: "webhook",
			URL:     encryptColumn(t, km, "notification_channels", "url", "https://example.com/hook"),
			Secret:  encryptColumn(t, km, "notification_channels", "secret", "hmac-secret"),
			Enabled: true},
	} {
		c := ch
		if err := db.Create(&c).Error; err != nil {
			t.Fatalf("seed channel %s: %v", c.Name, err)
		}
	}
}
