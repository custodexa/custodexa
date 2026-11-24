package audit

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// TestSpacedDirectMessageRejudgedWhenItsTurnComes 個人訊息因送出間隔被移到本輪最後送出時，輪到送出才重新判定：
// 等待期間收件人失去資格，該筆不送出，終態與原因與「送出前判定為不再有資格」相同（已取消、recipient_ineligible、
// 次數不變）。同一收件人的第二筆走帳號對應的快取，不經外部查詢之後的那次檢查。
func TestSpacedDirectMessageRejudgedWhenItsTurnComes(t *testing.T) {
	e := newTNLEnv(t)
	ch := e.dmChannel("dm")
	a := e.user("r1", emailOf("r1"))
	e.judge.recipients = []uint{a}
	e.created(42)
	e.created(43)
	e.w.dispatchPending()
	rows := e.userRows()
	if len(rows) != 2 {
		t.Fatalf("應有兩筆個人紀錄，得 %d", len(rows))
	}
	// 個人訊息目的地上次送出在 5 秒前：本輪有多筆名額，但連續兩次送出之間須滿 1/上限 秒，第二筆移到本輪最後
	e.w.markSent(deliveryDestKey{ChannelID: ch.ID, Audience: deliveryAudienceUser}, e.clock.now().Add(-5*time.Second))
	waits := 0
	e.w.sleep = func(d time.Duration) {
		waits++
		e.judge.setVerdict(a, TargetedIneligible) // 等待期間收回收件人的審核資格
		e.clock.advance(d)
	}
	e.w.RunOnce()
	if waits == 0 {
		t.Fatal("第二筆個人訊息應因送出間隔移到本輪最後，等待之後才送出")
	}
	if got := e.row(rows[0].ID); got.State != model.NotificationDeliveryDelivered {
		t.Fatalf("第一筆在資格收回前送出，應已送達: state=%s", got.State)
	}
	got := e.row(rows[1].ID)
	if got.State != model.NotificationDeliveryCanceled || got.EndReason != model.NotificationEndRecipientIneligible || got.Attempts != 0 {
		t.Fatalf("後送的那筆應以 recipient_ineligible 取消且次數不變: state=%s end=%q attempts=%d", got.State, got.EndReason, got.Attempts)
	}
	if n := dmPosts(t, e); n != 1 {
		t.Fatalf("替身只應收到資格收回前的一則個人訊息，得 %d", n)
	}
	if n := len(e.slack.callsOf(slackLookupByEmailMethod)); n != 1 {
		t.Fatalf("同一收件人的帳號對應只應查一次（第二筆走快取），得 %d", n)
	}
}
