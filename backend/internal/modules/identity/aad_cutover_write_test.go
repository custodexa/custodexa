package identity_test

import (
	"context"
	"github.com/custodexa/backend/internal/modules/identity"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// D5 AAD cutover 的**寫入端**驗收（kek-provider-modularization tasks 1.7）。
//
// 本檔鎖定資料層 cutover 最後三處信封欄位的不變式：
//
//	users.totp_secret_enc            （MFA）
//	export_signing_keys.private_key_enc（匯出簽章）
//	notification_channels.secret / url（通知通道）
//
// 每處各驗三件事：
//  1. 寫入落庫值帶 AAD 方案標記（`enc:a1:v<N>`），**不再可能**是 enc:v；
//  2. 以正確的 CipherRef 解得回原文（生產讀取路徑同源）；
//  3. 以**別欄的** CipherRef 解密必失敗——證明 AAD 真的綁進了 table|column
//     （定案 A2），而非只是換了個前綴。
//
// 守衛（結構保證）另見 aad_write_guard_test.go。

// assertAADCiphertext 落庫值須為帶 AAD 的信封密文
func assertAADCiphertext(t *testing.T, label, ct string) {
	t.Helper()
	if !strings.HasPrefix(ct, "enc:a1:v") {
		head := ct
		if len(head) > 16 {
			head = head[:16]
		}
		t.Fatalf("%s 落庫值應為帶 AAD 的信封密文（enc:a1:v...），得 %q", label, head)
	}
}

// assertCrossRefFails 以別欄身分解密必須失敗（AAD 綁定的實質驗證）
func assertCrossRefFails(t *testing.T, km *keyvault.KeyManagerService, wrong crypto.CipherRef, ct string) {
	t.Helper()
	if plain, err := km.DecryptFor(context.Background(), wrong, ct); err == nil {
		t.Fatalf("以別欄身分 %s 解密應失敗（AAD 未生效），卻解出 %q", wrong, plain)
	}
}

// TestMFASecretWrittenWithAAD MFA TOTP secret 寫入即帶 AAD（users.totp_secret_enc）
func TestMFASecretWrittenWithAAD(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)

	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	user := &model.User{Username: "aaduser", Password: "x", Active: true}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	auth, err := identity.NewAuthServiceWithMFA("secret", 15*time.Minute, km)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	setup, err := auth.GenerateMFASetup(user.ID)
	if err != nil {
		t.Fatalf("GenerateMFASetup: %v", err)
	}

	var stored string
	if err := db.Raw("SELECT totp_secret_enc FROM users WHERE id = ?", user.ID).
		Scan(&stored).Error; err != nil {
		t.Fatalf("raw: %v", err)
	}
	assertAADCiphertext(t, "users.totp_secret_enc", stored)

	plain, err := km.DecryptFor(context.Background(), keyvault.RefUserTOTPSecret, stored)
	if err != nil || plain != setup.Secret {
		t.Fatalf("以 users.totp_secret_enc 身分應解回原 secret: %q err=%v", plain, err)
	}
	assertCrossRefFails(t, km, keyvault.RefExportSigningPrivateKey, stored)

	// 服務自身的讀取路徑（loadTOTPSecret → DecryptFor）亦須解得回
	if _, got, err := auth.LoadTOTPSecretForTest(user.ID); err != nil || got != setup.Secret {
		t.Fatalf("loadTOTPSecret 應解回原 secret: %q err=%v", got, err)
	}
}

// TestExportSigningKeyWrittenWithAAD 匯出簽章私鑰寫入即帶 AAD
// （export_signing_keys.private_key_enc）
func TestExportSigningKeyWrittenWithAAD(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)

	svc, err := keyvault.NewExportSigningService(db, km)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	var row model.ExportSigningKey
	if err := db.First(&row, 1).Error; err != nil {
		t.Fatalf("read row: %v", err)
	}
	assertAADCiphertext(t, "export_signing_keys.private_key_enc", row.PrivateKeyEnc)

	if _, err := km.DecryptFor(context.Background(), keyvault.RefExportSigningPrivateKey, row.PrivateKeyEnc); err != nil {
		t.Fatalf("以 export_signing_keys.private_key_enc 身分應可解: %v", err)
	}
	assertCrossRefFails(t, km, keyvault.RefUserTOTPSecret, row.PrivateKeyEnc)

	// 重載服務（走 DecryptFor 讀取路徑）須得到同一把鑰，舊簽章仍可驗
	data := []byte("manifest-bytes")
	sig := svc.Sign(data)
	reloaded, err := keyvault.NewExportSigningService(db, km)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.VerifySignature(data, sig) {
		t.Fatal("帶 AAD 密文重載後應可驗第一代簽章")
	}
}

// TestNotificationChannelWrittenWithAAD 通知通道 secret／url 寫入即帶 AAD，
// 且**兩欄互換即解不開**——url 與 secret 同表不同欄，是 A2（綁 table|column）
// 唯一能擋、綁 pk 反而擋不到的搬移方向
func TestNotificationChannelWrittenWithAAD(t *testing.T) {
	svc, km, db := setupEnvelopeChannelSvcForAAD(t)

	created, err := svc.Create(&audit.NotificationChannelRequest{
		Name: "wh", URL: "https://example.com/hook/abcd", Secret: "hmac-secret",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	var stored struct{ URL, Secret string }
	if err := db.Raw("SELECT url, secret FROM notification_channels WHERE id = ?", created.ID).
		Scan(&stored).Error; err != nil {
		t.Fatalf("raw: %v", err)
	}
	assertAADCiphertext(t, "notification_channels.url", stored.URL)
	assertAADCiphertext(t, "notification_channels.secret", stored.Secret)

	ctx := context.Background()
	if plain, err := km.DecryptFor(ctx, keyvault.RefChannelURL, stored.URL); err != nil || plain != "https://example.com/hook/abcd" {
		t.Fatalf("url 應解回原值: %q err=%v", plain, err)
	}
	if plain, err := km.DecryptFor(ctx, keyvault.RefChannelSecret, stored.Secret); err != nil || plain != "hmac-secret" {
		t.Fatalf("secret 應解回原值: %q err=%v", plain, err)
	}
	// 同表跨欄搬移：url 密文以 secret 身分讀、secret 密文以 url 身分讀，皆須失敗
	assertCrossRefFails(t, km, keyvault.RefChannelSecret, stored.URL)
	assertCrossRefFails(t, km, keyvault.RefChannelURL, stored.Secret)

	// 服務自身的投遞讀取路徑須解得回
	delivery, err := svc.GetForDelivery(created.ID)
	if err != nil || delivery.URL != "https://example.com/hook/abcd" || delivery.Secret != "hmac-secret" {
		t.Fatalf("GetForDelivery 應解回明文: url=%q err=%v", delivery.URL, err)
	}

	// Update 帶值路徑同樣走 EncryptFor
	if _, err := svc.Update(created.ID, &audit.NotificationChannelRequest{
		Name: "wh", URL: "https://example.com/new", Secret: "new-secret",
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := db.Raw("SELECT url, secret FROM notification_channels WHERE id = ?", created.ID).
		Scan(&stored).Error; err != nil {
		t.Fatalf("raw2: %v", err)
	}
	assertAADCiphertext(t, "notification_channels.url（更新後）", stored.URL)
	assertAADCiphertext(t, "notification_channels.secret（更新後）", stored.Secret)
}

// TestChannelPlaintextRegistrationSemanticsPreserved plaintext:true 登記語義不變
// （envelopeMigrationTargets 對 notification_channels 的 url/secret 標記
// plaintext: true＝遷移前現值為明文）：非 `enc:` 前綴的殘值一律原樣讀出，
// 不得因 cutover 改走 DecryptFor 而被誤送解密
func TestChannelPlaintextRegistrationSemanticsPreserved(t *testing.T) {
	svc, _, db := setupEnvelopeChannelSvcForAAD(t)

	db.Create(&model.NotificationChannel{
		Name: "legacy-plain", Type: "webhook",
		URL: "https://old.example.com/x", Secret: "plain-secret", Enabled: true,
	})
	var row model.NotificationChannel
	if err := db.Where("name = 'legacy-plain'").First(&row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	delivery, err := svc.GetForDelivery(row.ID)
	if err != nil {
		t.Fatalf("GetForDelivery: %v", err)
	}
	if delivery.URL != "https://old.example.com/x" || delivery.Secret != "plain-secret" {
		t.Fatalf("明文殘值應原樣讀出: url=%q secret=%q", delivery.URL, delivery.Secret)
	}
}

// setupEnvelopeChannelSvcForAAD 通知通道信封測試夾具。
//
// **本地副本的理由（W4 4.11 搬包）**：原本共用 notification_channel_envelope_test.go
// 的 setupEnvelopeChannelSvc，該檔已隨 audit 模組搬入 internal/modules/audit。
// 本檔驗的是 keyvault 的 AAD cutover 寫入端（三張表的信封欄），與 audit 模組的
// 通道服務只是共用夾具而非共用主題，故就地複製 12 行夾具，不為此把 audit 的測試
// 檔案留在 internal/service。
func setupEnvelopeChannelSvcForAAD(t *testing.T) (*audit.NotificationChannelService, *keyvault.KeyManagerService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.NotificationChannel{}, &model.DataKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	km := newTestKeyManager(t, db, 1)
	return audit.NewNotificationChannelService(db, km), km, db
}
