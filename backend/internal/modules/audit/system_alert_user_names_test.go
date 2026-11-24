package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 系統安全告警以目標使用者補登入帳號（特權 API token 建立帶 owner_username、安全管理帳號被操作帶 target_username），沿用錄影刪除告警的寫法：
// 落地面在同一交易查，產生點已帶的值不覆寫、查不到不帶。
func TestSystemAlertUserTargetNames(t *testing.T) {
	db := setupSystemAlertDB(t)
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL DEFAULT '', deleted_at DATETIME)`).Error; err != nil {
		t.Fatal(err)
	}
	db.Exec(`INSERT INTO users (id, username) VALUES (9, 'owner-login')`)
	sink := NewSystemAlertSink(nil)
	raise := func(ev port.SystemAlertEvent) map[string]string {
		t.Helper()
		var rec port.SystemAlertReceipt
		if err := db.Transaction(func(tx *gorm.DB) error {
			var err error
			rec, err = sink.RaiseInTx(tx, ev)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		var d model.SystemAlertDetail
		db.First(&d, rec.AlertID)
		out := map[string]string{}
		_ = json.Unmarshal([]byte(d.Params), &out)
		return out
	}
	user := port.SystemAlertTarget{Kind: port.SystemAlertTargetUser, ID: "9"}
	actor := port.SystemAlertActor{UserID: 1, Username: "admin"}

	tok := raise(port.SystemAlertEvent{Type: port.SystemAlertPrivilegedAPITokenCreated, Actor: actor, Target: user,
		Params: map[string]string{"privileged_roles": "super_admin", "privileged_role_levels": "read_write", "token_name": "ci",
			"granted_roles": "super_admin", "granted_role_levels": "read_write", "access": "read_write", "expiry": "never"}})
	if tok["owner_username"] != "owner-login" {
		t.Fatalf("特權 API token 建立告警應帶 token 擁有者的登入帳號: %v", tok)
	}
	sec := raise(port.SystemAlertEvent{Type: port.SystemAlertSecurityAdminAccountOperated, Actor: actor, Target: user,
		Params: map[string]string{"action": "password_change"}})
	if sec["target_username"] != "owner-login" {
		t.Fatalf("安全管理帳號被操作告警應帶被操作帳號的登入帳號: %v", sec)
	}
	// 產生點已帶的值不覆寫；查不到不帶
	kept := raise(port.SystemAlertEvent{Type: port.SystemAlertSecurityAdminAccountOperated, Actor: actor, Target: user,
		Params: map[string]string{"action": "rescue", "target_username": "given"}})
	if kept["target_username"] != "given" {
		t.Fatalf("產生點已帶的值不應覆寫: %v", kept)
	}
	missing := raise(port.SystemAlertEvent{Type: port.SystemAlertSecurityAdminAccountOperated, Actor: actor,
		Target: port.SystemAlertTarget{Kind: port.SystemAlertTargetUser, ID: "404"}, Params: map[string]string{"action": "rescue"}})
	if _, ok := missing["target_username"]; ok {
		t.Fatalf("查不到不應帶: %v", missing)
	}

	// 三語文字帶名稱；沒有名稱時不留空引號
	for _, lang := range []string{"zh-TW", "en-US", "ja-JP"} {
		in := map[string]string{"actor": "admin", "severity": "high", "action": "password_change", "target_username": "owner-login"}
		clean, err := notifycat.Validate(notifycat.EventSystemAlertSecurityAdminAccountOperated, in)
		if err != nil {
			t.Fatal(err)
		}
		_, text := notifycat.Render(lang, notifycat.EventSystemAlertSecurityAdminAccountOperated, clean)
		if !strings.Contains(text, "owner-login") {
			t.Fatalf("%s 文字應含被操作帳號: %s", lang, text)
		}
		delete(in, "target_username")
		clean, _ = notifycat.Validate(notifycat.EventSystemAlertSecurityAdminAccountOperated, in)
		_, text = notifycat.Render(lang, notifycat.EventSystemAlertSecurityAdminAccountOperated, clean)
		if strings.Contains(text, "「」") || strings.Contains(text, "()") {
			t.Fatalf("%s 沒有名稱時不應留空括號: %s", lang, text)
		}
		tin := map[string]string{"actor": "admin", "severity": "high", "privileged_roles": "super_admin", "privileged_role_levels": "read_write",
			"token_name": "ci", "granted_roles": "super_admin", "granted_role_levels": "read_write", "access": "read_write", "expiry": "never",
			"owner_username": "owner-login"}
		clean, err = notifycat.Validate(notifycat.EventSystemAlertPrivilegedAPITokenCreated, tin)
		if err != nil {
			t.Fatal(err)
		}
		_, text = notifycat.Render(lang, notifycat.EventSystemAlertPrivilegedAPITokenCreated, clean)
		if !strings.Contains(text, "owner-login") {
			t.Fatalf("%s token 文字應含擁有者: %s", lang, text)
		}
	}
}
