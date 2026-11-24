package audit

import (
	"net/http"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 帶目的地快照的紀錄與送出時讀通道現值的紀錄分屬不同目的地。
//
// 通道的目的地版本從 0 起算，不帶快照的紀錄版本欄固定為 0；通道第一次改址之後，改址前排入、仍指向舊位址的
// 系統安全告警快照（版本 0）與改址後送往新位址的系統事件、指令告警（版本欄同為 0）在版本上無從區分。
// 這裡驗證兩者在取件、失敗計次、限流暫停上互不影響，而同一種紀錄、同一版本的目的地照舊一起計次與暫停。

// destSplitFixture 一個已改址一次的通道：舊位址的快照紀錄（版本 0）排在最前面，新位址有兩筆系統事件與一筆指令告警到期。
type destSplitFixture struct {
	e     *ndlEnv
	old   *stubSrv
	cur   *stubSrv
	snaps []model.NotificationDelivery
	live  []uint
}

func newDestSplitFixture(t *testing.T, e *ndlEnv, oldRespond func(int, http.ResponseWriter, *http.Request), snapshots int) destSplitFixture {
	t.Helper()
	old := newStubSrv(t, e.clock, oldRespond)
	cur := newStubSrv(t, e.clock, nil)
	c := e.channel("c", "webhook", old.srv.URL, true, "low")
	f := destSplitFixture{e: e, old: old, cur: cur}
	// 改址前排入的系統安全告警：快照指向舊位址、版本為改址前的 0
	for i := 0; i < snapshots; i++ {
		f.snaps = append(f.snaps, e.snapshotRow(c.ID, old.srv.URL, 0, 0))
	}
	// 改址：通道指向新位址，目的地版本遞增為 1
	if err := e.db.Model(&model.NotificationChannel{}).Where("id = ?", c.ID).
		Updates(map[string]any{"url": cur.srv.URL, "destination_version": 1}).Error; err != nil {
		t.Fatal(err)
	}
	// 改址後排入：送出時讀通道現值的系統事件與指令告警（版本欄固定為 0）
	f.live = append(f.live, e.liveRow(c.ID, model.AlertSeverityHigh, 0).ID, e.liveRow(c.ID, model.AlertSeverityHigh, 0).ID)
	e.enqueueAlert(e.alert(model.AlertSeverityHigh, 0, 1, nil))
	return f
}

// liveRows 所有不帶快照的紀錄（含 RunOnce 分派出的指令告警紀錄）。
func (f destSplitFixture) liveRows() []model.NotificationDelivery {
	var out []model.NotificationDelivery
	for _, r := range f.e.deliveries() {
		if r.Category != model.NotificationCategorySystemSecurityAlert {
			out = append(out, r)
		}
	}
	return out
}

func checkLiveDeliveredUntouched(t *testing.T, f destSplitFixture) {
	t.Helper()
	live := f.liveRows()
	if len(live) != 3 {
		t.Fatalf("新位址應有 3 筆不帶快照的紀錄（兩筆系統事件、一筆指令告警），得 %d", len(live))
	}
	if f.cur.count() != len(live) {
		t.Fatalf("新位址應在第一輪收到 %d 個請求，得 %d", len(live), f.cur.count())
	}
	for _, r := range live {
		if r.State != model.NotificationDeliveryDelivered || r.Attempts != 1 || r.ThrottledSince != nil {
			t.Fatalf("新位址的紀錄應送達且只計自己送出的一次、沒有限流延後: state=%s attempts=%d throttled=%v last_error=%q",
				r.State, r.Attempts, r.ThrottledSince, r.LastError)
		}
	}
}

func runDestSplitScenarios(t *testing.T, newEnv func(t *testing.T) *ndlEnv) {
	t.Run("舊位址持續 5xx：新位址的系統事件與指令告警照常送達、不被一起計次", func(t *testing.T) {
		e := newEnv(t)
		f := newDestSplitFixture(t, e, respondStatus(http.StatusInternalServerError), 1)
		e.w.RunOnce()
		checkLiveDeliveredUntouched(t, f)
		if r := e.row(f.snaps[0].ID); r.State != model.NotificationDeliveryRetrying || r.Attempts != 1 {
			t.Fatalf("舊位址的快照應計一次並重試: state=%s attempts=%d", r.State, r.Attempts)
		}
		// 之後的輪次：舊位址繼續失敗，新排入的通知仍照送
		for i := 0; i < 3; i++ {
			e.clock.advance(e.nextDue().Sub(e.clock.now()) + time.Second)
			before := f.cur.count()
			id := e.liveRow(*f.snaps[0].SourceChannelID, model.AlertSeverityHigh, 0).ID
			e.w.RunOnce()
			if r := e.row(id); r.State != model.NotificationDeliveryDelivered || r.Attempts != 1 || f.cur.count() != before+1 {
				t.Fatalf("第 %d 輪新排入的通知應送達: state=%s attempts=%d", i+2, r.State, r.Attempts)
			}
		}
	})

	t.Run("舊位址回 429：新位址的通知不被一起暫停或延後", func(t *testing.T) {
		e := newEnv(t)
		f := newDestSplitFixture(t, e, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
		}, 1)
		t0 := e.clock.now()
		e.w.RunOnce()
		checkLiveDeliveredUntouched(t, f)
		if r := e.row(f.snaps[0].ID); r.Attempts != 1 || !r.NextAttemptAt.Equal(t0.Add(30*time.Second)) {
			t.Fatalf("舊位址的快照應計一次並排在 30 秒後: attempts=%d next=%s", r.Attempts, r.NextAttemptAt.Sub(t0))
		}
		// 舊位址暫停期間，新排入的通知照送
		e.clock.advance(5 * time.Second)
		id := e.liveRow(*f.snaps[0].SourceChannelID, model.AlertSeverityHigh, 0).ID
		e.w.RunOnce()
		if r := e.row(id); r.State != model.NotificationDeliveryDelivered {
			t.Fatalf("舊位址暫停期間新排入的通知應送達: state=%s", r.State)
		}
		if f.old.count() != 1 {
			t.Fatalf("舊位址暫停期間不得再送出: %d", f.old.count())
		}
	})

	t.Run("同一快照版本的紀錄仍是同一個目的地：一起計次、一起暫停", func(t *testing.T) {
		e := newEnv(t)
		f := newDestSplitFixture(t, e, respondStatus(http.StatusInternalServerError), 2)
		e.w.RunOnce()
		checkLiveDeliveredUntouched(t, f)
		if f.old.count() != 1 {
			t.Fatalf("舊位址第一筆失敗後同目的地本輪不再送出，應只收到 1 個請求，得 %d", f.old.count())
		}
		for _, s := range f.snaps {
			if r := e.row(s.ID); r.State != model.NotificationDeliveryRetrying || r.Attempts != 1 {
				t.Fatalf("同一快照目的地的紀錄應一起計一次: id=%d state=%s attempts=%d", s.ID, r.State, r.Attempts)
			}
		}

		e2 := newEnv(t)
		f2 := newDestSplitFixture(t, e2, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
		}, 2)
		t0 := e2.clock.now()
		e2.w.RunOnce()
		checkLiveDeliveredUntouched(t, f2)
		first, second := e2.row(f2.snaps[0].ID), e2.row(f2.snaps[1].ID)
		if first.Attempts != 1 || second.Attempts != 0 || second.ThrottledSince == nil || second.NextAttemptAt.Before(t0.Add(30*time.Second)) {
			t.Fatalf("同一快照目的地：被拒那筆計一次、另一筆延後不計次: first=%d second=%d throttled=%v next=%s",
				first.Attempts, second.Attempts, second.ThrottledSince, second.NextAttemptAt.Sub(t0))
		}
	})
}

// TestSnapshotRowsDoNotShareDestinationWithLiveRows 通道第一次改址後，舊位址的快照紀錄與新位址的一般通知互不影響。
func TestSnapshotRowsDoNotShareDestinationWithLiveRows(t *testing.T) {
	runDestSplitScenarios(t, newNDLEnv)
}

// TestSnapshotRowsDoNotShareDestinationWithLiveRowsPG 同上，以 PostgreSQL 執行取件的視窗函式與條件更新。
func TestSnapshotRowsDoNotShareDestinationWithLiveRowsPG(t *testing.T) {
	runDestSplitScenarios(t, newNDLEnvPG)
}
