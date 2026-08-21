package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// keyvault × audit／notification 的對抗測試（modular-architecture W2 2.5 自
// `key_management_adversarial_test.go` 分出）。
//
// **為何留在 internal/service**：這四項驗的是審計完整性鏈與通知通道的行為
// （AuditIntegrityService／NotificationChannelService／AlertNotifier），
// 只經由 keyvault 的**匯出**面取得 codec；而原檔其餘測試觸及 keyvault 未匯出
// 內部（bumpActiveKeyTx／commitBumpedKey／withDataKeysLock），必須隨包遷入。
// 斷言逐字未改，僅移動宣告位置。

// TestAuditContentTamperKeepingHMAC 竄改內容但不動 HMAC 必判不符
func TestAuditContentTamperKeepingHMAC(t *testing.T) {
	db := newVersionedDB(t)
	svc, _ := newVersionedIntegrity(t, db)
	l := versionedTestLog("v")
	svc.StampOne(l)
	db.Create(l)
	// 改內容、HMAC 原封不動
	db.Exec("UPDATE audit_logs SET client_ip = '6.6.6.6' WHERE id = ?", l.ID)
	report, _ := svc.Verify(db, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if report.Mismatched != 1 {
		t.Fatalf("改內容不改 HMAC 應不符: %+v", report)
	}
}

// TestAuditMaskURLNoLeakNoPanic maskChannelURL 各式惡意/邊界 URL——
// 不得洩漏完整路徑/secret，不得 panic
func TestAuditMaskURLNoLeakNoPanic(t *testing.T) {
	cases := []struct {
		name    string
		plain   string
		mustNot []string // 遮罩輸出不得包含
	}{
		{"slack", "https://hooks.slack.com/services/T0AA/B0BB/tokenSECRETvalue",
			[]string{"services", "T0AA", "B0BB", "tokenSECRET"}},
		{"no-path", "https://example.com", nil},
		{"slash-only", "https://example.com/", nil},
		{"short-path", "https://example.com/ab", nil},
		{"query-token", "https://example.com/cb?token=VERYSECRETQUERY",
			[]string{"VERYSECRETQ", "token="}},
		{"userinfo-pw", "https://alice:SUPERSECRETPW@example.com/hooktail",
			[]string{"SUPERSECRETPW", "alice:"}},
		{"ipv6", "http://[fd00::1]:8443/SECRETPATHVALUE", []string{"SECRETPATHVA"}},
		{"ipv6-zone", "http://[fe80::1%25en0]/SECRETPATHVALUE", []string{"SECRETPATHVA"}},
		{"illegal", "ht!tp://\x00bad url with spaces/SECRET", []string{"SECRET"}},
		{"empty", "", nil},
		{"just-scheme", "https://", nil},
		{"opaque", "mailto:secret@x.com", []string{"secret@x.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out string
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("maskChannelURL panic on %q: %v", tc.plain, r)
					}
				}()
				out = maskChannelURL(tc.plain)
			}()
			for _, bad := range tc.mustNot {
				if strings.Contains(out, bad) {
					t.Errorf("遮罩洩漏 %q -> %q 含 %q", tc.plain, out, bad)
				}
			}
		})
	}
}

// TestAuditToDisplayMasksUndecryptable toDisplay 對解不開的 url 全遮罩，不外洩密文
func TestAuditToDisplayMasksUndecryptable(t *testing.T) {
	svc, _, db := setupEnvelopeChannelSvc(t)
	db.Create(&model.NotificationChannel{Name: "bad", Type: "webhook", URL: "enc:v42:aGVsbG8=", Enabled: true})
	got, err := svc.GetByID(getChannelID(t, db, "bad"))
	if err != nil {
		t.Fatalf("getbyid: %v", err)
	}
	if strings.Contains(got.URL, "enc:v") || got.URL != "****" {
		t.Fatalf("解不開的 url 應全遮罩 ****，得 %q", got.URL)
	}
}

// TestAuditUndecryptableChannelSkipped 解不開的通道 url，setChannels 必須跳過
// （不以密文當 URL 投遞）
func TestAuditUndecryptableChannelSkipped(t *testing.T) {
	svc, km, db := setupEnvelopeChannelSvc(t)
	svc.Create(&NotificationChannelRequest{Name: "ok", URL: "https://example.com/hook", Secret: "sk"})
	// 密文引用不存在版本
	db.Create(&model.NotificationChannel{Name: "bad", Type: "webhook", URL: "enc:v42:aGVsbG8=", Enabled: true})
	n := NewAlertNotifier(db, km)
	if err := n.LoadChannels(); err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, ch := range n.snapshotChannels() {
		if strings.HasPrefix(ch.URL, "enc:v") {
			t.Fatalf("密文洩漏為投遞 URL: %q", ch.URL)
		}
		if ch.Name == "bad" {
			t.Fatal("解不開的通道不應進快取")
		}
	}
}

func getChannelID(t *testing.T, db *gorm.DB, name string) uint {
	t.Helper()
	var ch model.NotificationChannel
	if err := db.Where("name = ?", name).First(&ch).Error; err != nil {
		t.Fatalf("find channel %q: %v", name, err)
	}
	return ch.ID
}
