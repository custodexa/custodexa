package audit

import (
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupEnvelopeChannelSvc 帶信封 codec 的通知服務（key-management-envelope G8）
func setupEnvelopeChannelSvc(t *testing.T) (*NotificationChannelService, *keyvault.KeyManagerService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.NotificationChannel{}, &model.DataKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	km := newTestKeyManager(t, db, 1)
	svc := NewNotificationChannelService(db, km)
	return svc, km, db
}

const testSlackURL = "https://hooks.slack.com/services/T000/B000/secretpart"

// TestChannelEncryptedAtRest secret 與 url 落庫為信封密文，DB 直查無明文
func TestChannelEncryptedAtRest(t *testing.T) {
	svc, _, db := setupEnvelopeChannelSvc(t)

	created, err := svc.Create(&NotificationChannelRequest{
		Name: "wh", URL: "https://example.com/hook/abcd", Secret: "hmac-secret",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	var stored struct{ URL, Secret string }
	if err := db.Raw("SELECT url, secret FROM notification_channels WHERE id = ?", created.ID).Scan(&stored).Error; err != nil {
		t.Fatalf("raw: %v", err)
	}
	// cutover（tasks 1.7）後寫入端一律產帶 AAD 的 enc:a1——**不再可能**是 enc:v
	if !strings.HasPrefix(stored.URL, "enc:a1:v") || !strings.HasPrefix(stored.Secret, "enc:a1:v") {
		t.Fatalf("落庫值應為帶 AAD 的信封密文: url=%q secret=%q", stored.URL[:12], stored.Secret[:12])
	}
	if strings.Contains(stored.URL, "example.com") || strings.Contains(stored.Secret, "hmac") {
		t.Fatal("落庫值含明文")
	}
}

// TestChannelURLMaskedInResponses 回應 url 遮罩：scheme+host+末 4 碼，全文不外洩
func TestChannelURLMaskedInResponses(t *testing.T) {
	svc, _, _ := setupEnvelopeChannelSvc(t)

	created, err := svc.Create(&NotificationChannelRequest{
		Name: "slack", Type: model.NotificationChannelTypeSlack, URL: testSlackURL,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	want := "https://hooks.slack.com/****part"
	if created.URL != want {
		t.Fatalf("Create 回應遮罩不符: got %q want %q", created.URL, want)
	}

	listed, _ := svc.List()
	if len(listed) != 1 || listed[0].URL != want {
		t.Fatalf("List 遮罩不符: %q", listed[0].URL)
	}
	got, _ := svc.GetByID(created.ID)
	if got.URL != want || strings.Contains(got.URL, "secretpart") == false && strings.Contains(got.URL, "T000") {
		t.Fatalf("GetByID 遮罩不符: %q", got.URL)
	}
}

// TestChannelEmptyURLPreserves Update 空 url 沿用既有值（與 secret 同語義）
func TestChannelEmptyURLPreserves(t *testing.T) {
	svc, km, db := setupEnvelopeChannelSvc(t)

	created, err := svc.Create(&NotificationChannelRequest{
		Name: "wh", URL: "https://example.com/hook/abcd", Secret: "sk",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := svc.Update(created.ID, &NotificationChannelRequest{Name: "renamed"}); err != nil {
		t.Fatalf("update: %v", err)
	}

	var storedURL string
	db.Raw("SELECT url FROM notification_channels WHERE id = ?", created.ID).Scan(&storedURL)
	plain, err := decryptColumn(km, "notification_channels", "url", storedURL)
	if err != nil || plain != "https://example.com/hook/abcd" {
		t.Fatalf("空 url 更新後應沿用原值: %q err=%v", plain, err)
	}

	// 帶值更新則生效
	if _, err := svc.Update(created.ID, &NotificationChannelRequest{Name: "renamed", URL: "https://example.com/new"}); err != nil {
		t.Fatalf("update url: %v", err)
	}
	db.Raw("SELECT url FROM notification_channels WHERE id = ?", created.ID).Scan(&storedURL)
	plain, _ = decryptColumn(km, "notification_channels", "url", storedURL)
	if plain != "https://example.com/new" {
		t.Fatalf("帶值更新未生效: %q", plain)
	}
}

// TestChannelGetForDelivery 投遞用通道取得明文 url/secret；亦相容遷移前明文殘值
func TestChannelGetForDelivery(t *testing.T) {
	svc, _, db := setupEnvelopeChannelSvc(t)

	created, err := svc.Create(&NotificationChannelRequest{
		Name: "wh", URL: "https://example.com/hook", Secret: "sk",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	delivery, err := svc.GetForDelivery(created.ID)
	if err != nil {
		t.Fatalf("GetForDelivery: %v", err)
	}
	if delivery.URL != "https://example.com/hook" || delivery.Secret != "sk" {
		t.Fatalf("投遞通道應為明文: url=%q", delivery.URL)
	}

	// 遷移前明文殘值（或遷移失敗保留列）仍可投遞
	db.Create(&model.NotificationChannel{Name: "legacy", Type: "webhook", URL: "https://old.example.com/x", Enabled: true})
	var legacy model.NotificationChannel
	db.Where("name = 'legacy'").First(&legacy)
	d2, err := svc.GetForDelivery(legacy.ID)
	if err != nil || d2.URL != "https://old.example.com/x" {
		t.Fatalf("明文殘值應可讀: %q err=%v", d2.URL, err)
	}
}

// TestNotifierCacheDecryptsChannels 推送快取載入時解密；解不開的通道跳過
func TestNotifierCacheDecryptsChannels(t *testing.T) {
	svc, km, db := setupEnvelopeChannelSvc(t)

	if _, err := svc.Create(&NotificationChannelRequest{
		Name: "wh", URL: "https://example.com/hook", Secret: "sk",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// 損毀密文通道：應被跳過不入快取
	db.Create(&model.NotificationChannel{Name: "broken", Type: "webhook", URL: "enc:v99:aGVsbG8=", Enabled: true})

	n := NewAlertNotifier(db, km)
	if err := n.LoadChannels(); err != nil {
		t.Fatalf("load: %v", err)
	}
	cached := n.snapshotChannels()
	if len(cached) != 1 {
		t.Fatalf("快取應僅含可解密通道，得 %d", len(cached))
	}
	if cached[0].URL != "https://example.com/hook" || cached[0].Secret != "sk" {
		t.Fatalf("快取應為投遞用明文: %q", cached[0].URL)
	}
}
