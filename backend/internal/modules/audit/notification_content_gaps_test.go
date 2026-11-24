package audit

import (
	"encoding/json"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// 通知內容的兩項規格行為：webhook 本文不隨通道語系改變，以及派送時保留已軟刪除資產的名稱。

// webhook 型的語系不影響本文：ja-JP、en-US 與 zh-TW 通道收到的指令告警與系統事件本文，去掉投遞識別後逐欄相同。
func TestWebhookBodyIgnoresChannelLanguage(t *testing.T) {
	e := newNDLEnv(t)
	stubs := map[string]*stubSrv{}
	for _, lang := range []string{"zh-TW", "en-US", "ja-JP"} {
		s := newStubSrv(t, e.clock, nil)
		ch := e.channel("hook-"+lang, "webhook", s.srv.URL, true, "low")
		e.db.Model(&model.NotificationChannel{}).Where("id = ?", ch.ID).Update("language", lang)
		stubs[lang] = s
	}
	a := e.alert(model.AlertSeverityHigh, 31, 1, nil)
	e.enqueueAlert(a)
	e.enqueueEvent(notifycat.EventAccessRequestApprovalProgress, map[string]string{"request_id": "12", "votes": "1", "required": "2"})
	e.w.RunOnce()
	norm := func(raw []byte) string {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if n, ok := m["notification"].(map[string]any); ok {
			delete(n, "delivery_id")
		}
		out, _ := json.Marshal(m)
		return string(out)
	}
	want := map[string]bool{}
	for i := 0; i < stubs["zh-TW"].count(); i++ {
		want[norm(stubs["zh-TW"].body(i))] = true
	}
	if len(want) != 2 {
		t.Fatalf("zh-TW 通道應收到兩則，得 %d", len(want))
	}
	for _, lang := range []string{"en-US", "ja-JP"} {
		s := stubs[lang]
		if s.count() != 2 {
			t.Fatalf("%s 通道應收到兩則，得 %d", lang, s.count())
		}
		for i := 0; i < s.count(); i++ {
			if !want[norm(s.body(i))] {
				t.Fatalf("%s 的 webhook 本文與 zh-TW 不同: %s", lang, s.body(i))
			}
		}
	}
}

// 已軟刪的資產在分派後仍帶原名（目標名稱解析含軟刪的列）。
func TestDispatchKeepsSoftDeletedAssetName(t *testing.T) {
	e := newNDLEnv(t)
	hook := newStubSrv(t, e.clock, nil)
	e.channel("hook", "webhook", hook.srv.URL, true, "low")
	e.db.Exec(`INSERT INTO assets (id, name, deleted_at) VALUES (7, 'retired-db', CURRENT_TIMESTAMP)`)
	asset := uint(7)
	a := e.alert(model.AlertSeverityHigh, 31, 1, &asset)
	e.enqueueAlert(a)
	e.w.dispatchPending()
	msgs := e.messages()
	if len(msgs) != 1 || msgs[0].TargetName != "retired-db" {
		t.Fatalf("已軟刪資產的名稱應保留: %+v", msgs)
	}
}
