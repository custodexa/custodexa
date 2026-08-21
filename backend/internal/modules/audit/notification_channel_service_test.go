package audit

import (
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupChannelDB(t *testing.T) *NotificationChannelService {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.NotificationChannel{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewNotificationChannelService(db, nil)
}

func mustSecret(t *testing.T, svc *NotificationChannelService, id uint) string {
	t.Helper()
	channel, err := svc.GetByID(id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	return channel.Secret
}

// mustLanguage 讀回落庫的 language（method 掛在 service 上僅為呼叫端語意順口，
// 實際仍走 GetByID，與 mustSecret 同模式）
func (s *NotificationChannelService) mustLanguage(t *testing.T, id uint) string {
	t.Helper()
	channel, err := s.GetByID(id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	return channel.Language
}

func TestChannelUpdateSecretSemantics(t *testing.T) {
	svc := setupChannelDB(t)

	created, err := svc.Create(&NotificationChannelRequest{
		Name: "ops", URL: "https://hooks.example.com/x", Secret: "topsecret",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	t.Run("空 secret 沿用既有值（改名不清金鑰）", func(t *testing.T) {
		// Arrange & Act：只改名，secret 留空（等同編輯表單未重填/啟用開關 payload）
		if _, err := svc.Update(created.ID, &NotificationChannelRequest{
			Name: "ops-renamed", URL: "https://hooks.example.com/x",
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		// Assert
		if got := mustSecret(t, svc, created.ID); got != "topsecret" {
			t.Fatalf("secret 應沿用既有值，得到 %q", got)
		}
	})

	t.Run("非空 secret 覆寫", func(t *testing.T) {
		if _, err := svc.Update(created.ID, &NotificationChannelRequest{
			Name: "ops-renamed", URL: "https://hooks.example.com/x", Secret: "rotated",
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if got := mustSecret(t, svc, created.ID); got != "rotated" {
			t.Fatalf("secret 應被覆寫為 rotated，得到 %q", got)
		}
	})

	t.Run("clear_secret 顯式清除", func(t *testing.T) {
		if _, err := svc.Update(created.ID, &NotificationChannelRequest{
			Name: "ops-renamed", URL: "https://hooks.example.com/x", ClearSecret: true,
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if got := mustSecret(t, svc, created.ID); got != "" {
			t.Fatalf("secret 應被清除，得到 %q", got)
		}
	})

	t.Run("Create 空 secret 即不簽名（語義不變）", func(t *testing.T) {
		plain, err := svc.Create(&NotificationChannelRequest{
			Name: "plain", URL: "https://hooks.example.com/y",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if got := mustSecret(t, svc, plain.ID); got != "" {
			t.Fatalf("新建未帶 secret 應為空，得到 %q", got)
		}
	})
}

func TestChannelHasSecretFlag(t *testing.T) {
	svc := setupChannelDB(t)

	withSecret, err := svc.Create(&NotificationChannelRequest{
		Name: "signed", URL: "https://hooks.example.com/a", Secret: "sk",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !withSecret.HasSecret {
		t.Fatal("Create 帶 secret 應回 HasSecret=true")
	}

	plain, err := svc.Create(&NotificationChannelRequest{
		Name: "plain", URL: "https://hooks.example.com/b",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if plain.HasSecret {
		t.Fatal("Create 未帶 secret 應回 HasSecret=false")
	}

	// List 與 GetByID 都應正確反映（且不洩漏 secret 值本身）
	list, err := svc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, c := range list {
		want := c.ID == withSecret.ID
		if c.HasSecret != want {
			t.Fatalf("通道 %d HasSecret=%v，期望 %v", c.ID, c.HasSecret, want)
		}
	}

	// clear_secret 後 HasSecret 應轉 false
	cleared, err := svc.Update(withSecret.ID, &NotificationChannelRequest{
		Name: "signed", URL: "https://hooks.example.com/a", ClearSecret: true,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if cleared.HasSecret {
		t.Fatal("clear_secret 後 HasSecret 應為 false")
	}
}

// TestChannelLanguageSemantics per-channel 語系 CUD 四情境（backend-i18n-unification D5）：
// strPtr 小工具見 access_policy_service_test.go（同 package 共用，
// NotificationChannelRequest.Language 用 *string 區分「省略」與「顯式提供」）
// Create 未給預設 zh-TW／Update 省略保留舊值／顯式空值拒／白名單外值拒
func TestChannelLanguageSemantics(t *testing.T) {
	t.Run("Create 未給 language 預設 zh-TW", func(t *testing.T) {
		svc := setupChannelDB(t)
		created, err := svc.Create(&NotificationChannelRequest{
			Name: "ops", URL: "https://hooks.example.com/x",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if created.Language != model.NotificationChannelLanguageDefault {
			t.Fatalf("language = %q，期望預設 %q", created.Language, model.NotificationChannelLanguageDefault)
		}
	})

	t.Run("Create 顯式提供合法值採用", func(t *testing.T) {
		svc := setupChannelDB(t)
		created, err := svc.Create(&NotificationChannelRequest{
			Name: "ops-en", URL: "https://hooks.example.com/x",
			Language: strPtr(model.NotificationChannelLanguageEnUS),
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if created.Language != model.NotificationChannelLanguageEnUS {
			t.Fatalf("language = %q，期望 %q", created.Language, model.NotificationChannelLanguageEnUS)
		}
	})

	t.Run("Update 省略 language 保留舊值", func(t *testing.T) {
		svc := setupChannelDB(t)
		created, err := svc.Create(&NotificationChannelRequest{
			Name: "ops", URL: "https://hooks.example.com/x",
			Language: strPtr(model.NotificationChannelLanguageJaJP),
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		// 只改名，不帶 Language（nil）——比照 secret/url 的「未傳」語義
		updated, err := svc.Update(created.ID, &NotificationChannelRequest{
			Name: "ops-renamed", URL: "https://hooks.example.com/x",
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if updated.Language != model.NotificationChannelLanguageJaJP {
			t.Fatalf("language 應保留舊值 %q，得到 %q", model.NotificationChannelLanguageJaJP, updated.Language)
		}
	})

	t.Run("Update 顯式空字串拒絕", func(t *testing.T) {
		svc := setupChannelDB(t)
		created, err := svc.Create(&NotificationChannelRequest{
			Name: "ops", URL: "https://hooks.example.com/x",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		_, err = svc.Update(created.ID, &NotificationChannelRequest{
			Name: "ops", URL: "https://hooks.example.com/x",
			Language: strPtr(""),
		})
		if !errors.Is(err, ErrInvalidChannelLanguage) {
			t.Fatalf("Update 顯式空字串應回 ErrInvalidChannelLanguage，得到 %v", err)
		}
		// 拒絕後不落庫（沿用舊值）
		if got := svc.mustLanguage(t, created.ID); got != model.NotificationChannelLanguageDefault {
			t.Fatalf("拒絕後 language 不應變動，得到 %q", got)
		}
	})

	t.Run("Update 白名單外值拒絕", func(t *testing.T) {
		svc := setupChannelDB(t)
		created, err := svc.Create(&NotificationChannelRequest{
			Name: "ops", URL: "https://hooks.example.com/x",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		_, err = svc.Update(created.ID, &NotificationChannelRequest{
			Name: "ops", URL: "https://hooks.example.com/x",
			Language: strPtr("fr-FR"),
		})
		if !errors.Is(err, ErrInvalidChannelLanguage) {
			t.Fatalf("Update 白名單外值應回 ErrInvalidChannelLanguage，得到 %v", err)
		}
	})

	t.Run("Create 顯式空字串或白名單外值同拒", func(t *testing.T) {
		svc := setupChannelDB(t)
		if _, err := svc.Create(&NotificationChannelRequest{
			Name: "ops", URL: "https://hooks.example.com/x", Language: strPtr(""),
		}); !errors.Is(err, ErrInvalidChannelLanguage) {
			t.Fatalf("Create 顯式空字串應回 ErrInvalidChannelLanguage，得到 %v", err)
		}
		if _, err := svc.Create(&NotificationChannelRequest{
			Name: "ops", URL: "https://hooks.example.com/x", Language: strPtr("fr-FR"),
		}); !errors.Is(err, ErrInvalidChannelLanguage) {
			t.Fatalf("Create 白名單外值應回 ErrInvalidChannelLanguage，得到 %v", err)
		}
	})
}

func TestChannelSlackForcesEmptySecret(t *testing.T) {
	svc := setupChannelDB(t)

	t.Run("Create slack 帶 secret 也強制清空", func(t *testing.T) {
		ch, err := svc.Create(&NotificationChannelRequest{
			Name: "slack", Type: model.NotificationChannelTypeSlack,
			URL: "https://hooks.slack.com/services/x", Secret: "ignored",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if ch.HasSecret || mustSecret(t, svc, ch.ID) != "" {
			t.Fatal("slack 通道 secret 應恆空")
		}
	})

	t.Run("webhook→slack 轉換清掉殘留 secret", func(t *testing.T) {
		wh, err := svc.Create(&NotificationChannelRequest{
			Name: "wh", URL: "https://hooks.example.com/y", Secret: "sk",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		// 轉為 slack（不帶 secret、不帶 clear_secret）——原殘留 secret 應被清掉
		converted, err := svc.Update(wh.ID, &NotificationChannelRequest{
			Name: "wh", Type: model.NotificationChannelTypeSlack, URL: "https://hooks.slack.com/services/z",
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if converted.HasSecret || mustSecret(t, svc, wh.ID) != "" {
			t.Fatal("webhook→slack 後 secret 應被清空")
		}
	})
}
