package audit

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// TestChannelResponseDirectMessageURLAllowed 通道回應的 direct_message_url_allowed 依目前網址的主機是否在
// 允許清單（官方主機加 NOTIFY_DM_EXTRA_HOSTS）填入；建立、更新、單筆、列表四種回應一致；變更允許清單後讀取即反映。
func TestChannelResponseDirectMessageURLAllowed(t *testing.T) {
	e := newTNLChannelEnv(t) // 已以 t.Setenv 放行 127.0.0.1（替身）

	r := e.req("app")
	r.Type, r.URL, r.Secret, r.Target = model.NotificationChannelTypeSlackApp, e.slack.srv.URL, tnlToken, tnlTarget
	created, err := e.svc.Create(r)
	if err != nil {
		t.Fatal(err)
	}
	if !created.DirectMessageURLAllowed {
		t.Fatal("建立回應：允許清單內的主機應為真")
	}

	r2 := e.req("hook")
	r2.Type, r2.URL = model.NotificationChannelTypeWebhook, "https://hooks.example.test/x"
	hook, err := e.svc.Create(r2)
	if err != nil {
		t.Fatal(err)
	}
	if hook.DirectMessageURLAllowed {
		t.Fatal("建立回應：清單外的主機應為假")
	}

	official := e.req("app")
	official.URL, official.Secret = "https://slack.com/api", tnlToken
	updated, err := e.svc.Update(created.ID, official)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.DirectMessageURLAllowed {
		t.Fatal("更新回應：官方主機應為真")
	}
	if got, _ := e.svc.GetByID(created.ID); got == nil || !got.DirectMessageURLAllowed {
		t.Fatal("單筆回應：官方主機應為真")
	}

	t.Setenv(dmExtraHostsEnv, "hooks.example.test")
	list, err := e.svc.List()
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, ch := range list {
		switch ch.ID {
		case created.ID, hook.ID:
			seen++
			if !ch.DirectMessageURLAllowed {
				t.Fatalf("列表：通道 %d 的主機已在清單內，應為真", ch.ID)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("列表應含兩個通道，得 %d", seen)
	}
	t.Setenv(dmExtraHostsEnv, "")
	if got, _ := e.svc.GetByID(hook.ID); got == nil || got.DirectMessageURLAllowed {
		t.Fatal("移出清單後讀取應為假")
	}

	// 網址解不開時為假（以全遮罩呈現的同一路徑）
	e.db.Model(&model.NotificationChannel{}).Where("id = ?", hook.ID).Update("url", "enc:v1:broken")
	if got, _ := e.svc.GetByID(hook.ID); got == nil || got.DirectMessageURLAllowed {
		t.Fatal("網址解不開時應為假")
	}
}
