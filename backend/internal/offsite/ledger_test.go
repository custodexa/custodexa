package offsite

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 保管帳冊的行為層驗收。

// fixedClock 可推進的測試時鐘（退避與租約的時序斷言需要它；靠真實時間會 flaky）。
type fixedClock struct{ now time.Time }

func (c *fixedClock) Now() time.Time      { return c.now }
func (c *fixedClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newClockedRig(t *testing.T) (*offsiteTestRig, *fixedClock) {
	t.Helper()
	rig := newOffsiteRig(t)
	clk := &fixedClock{now: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)}
	rig.ledger.SetClockForTest(clk.Now)
	rig.svc.SetClockForTest(clk.Now)
	return rig, clk
}

// enqueue 以 EnqueueTx 排入一件（走真正的排隊路徑，不是直接插列）。
func enqueue(t *testing.T, rig *offsiteTestRig, kind string, ownerID uint, origin string) (*model.OffsiteObject, bool) {
	t.Helper()
	var (
		row     *model.OffsiteObject
		created bool
	)
	err := rig.db.Transaction(func(tx *gorm.DB) error {
		var e error
		row, created, e = rig.ledger.EnqueueTx(tx, kind, ownerID, origin)
		return e
	})
	if err != nil {
		t.Fatalf("EnqueueTx: %v", err)
	}
	return row, created
}

// TestOffsiteLedgerEnqueueTxIsIdempotent 同 (kind, owner_id, storage_generation_id)
// 重複排入回既有列。
//
// 冪等是回填與正常路徑走同一條路的前提：帳冊已有同鍵列時回既有列（含其 state），
// 呼叫端把擁有表快取寫成該列的 state 而非硬寫 pending。
func TestOffsiteLedgerEnqueueTxIsIdempotent(t *testing.T) {
	rig, _ := newClockedRig(t)
	gen := mustSave(t, rig, s3Settings("evidence")).View

	first, created := enqueue(t, rig, KindRecording, 42, OriginLive)
	if !created {
		t.Fatal("首次排入應回 created=true")
	}
	if first.StorageGenerationID != gen.GenerationID {
		t.Fatalf("storage_generation_id = %d, want %d", first.StorageGenerationID, gen.GenerationID)
	}
	if first.Provider != ProviderS3 || first.Bucket != "evidence" {
		t.Fatalf("帳冊未記下上傳當時的 provider／bucket: %+v", first)
	}

	// 把它推進到 uploaded，再排一次——回既有列且**帶既有 state**
	if err := rig.ledger.MarkUploaded(first.ID, "k", "v1", strings.Repeat("a", 64), 10); err != nil {
		t.Fatalf("MarkUploaded: %v", err)
	}
	second, created := enqueue(t, rig, KindRecording, 42, OriginBackfill)
	if created {
		t.Fatal("重複排入不應建新列")
	}
	if second.ID != first.ID {
		t.Fatalf("重複排入回了不同列：%d vs %d", second.ID, first.ID)
	}
	if second.State != StateUploaded {
		t.Fatalf("重複排入應回既有列的 state，實得 %q", second.State)
	}
	if n, _ := rig.ledger.TotalObjects(); n != 1 {
		t.Fatalf("帳冊列數 = %d, want 1", n)
	}

	// 切換世代後同一擁有者可有新物件（**唯一鍵含世代**）。
	// 帳冊已有存量，故切換走確認流程
	res, err := rig.svc.Save(context.Background(), s3Settings("evidence-v2"), OffsiteActor{ID: 1})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !res.NeedsConfirmation {
		t.Fatal("帳冊有存量時換落點應回「需確認」")
	}
	if _, err := rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
		Settings:                    s3Settings("evidence-v2"),
		ExpectedCurrentGenerationID: res.ExpectedCurrentGenerationID,
		SettingsDigest:              res.SettingsDigest,
	}, OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	third, created := enqueue(t, rig, KindRecording, 42, OriginLive)
	if !created || third.ID == first.ID {
		t.Fatal("新世代應可為同一擁有者建新物件（唯一鍵含世代）")
	}
}

// TestOffsiteLedgerEnqueueTxWithoutCurrentGenerationWritesNothing
// 無現行世代時回哨兵且零寫入。
func TestOffsiteLedgerEnqueueTxWithoutCurrentGenerationWritesNothing(t *testing.T) {
	rig, _ := newClockedRig(t)
	err := rig.db.Transaction(func(tx *gorm.DB) error {
		_, _, e := rig.ledger.EnqueueTx(tx, KindRecording, 1, OriginLive)
		return e
	})
	if err == nil || !strings.Contains(err.Error(), "沒有現行") {
		t.Fatalf("應回 ErrNoCurrentGeneration，實得 %v", err)
	}
	if n, _ := rig.ledger.TotalObjects(); n != 0 {
		t.Fatalf("不得建列，帳冊列數 = %d", n)
	}
}

// TestOffsiteLedgerClaimIsCAS 領件是 CAS：第二次領同一件回 false（不是錯誤）。
func TestOffsiteLedgerClaimIsCAS(t *testing.T) {
	rig, clk := newClockedRig(t)
	mustSave(t, rig, s3Settings("evidence"))
	row, _ := enqueue(t, rig, KindRecording, 1, OriginLive)

	ok, err := rig.ledger.Claim(row.ID, clk.Now().Add(time.Minute))
	if err != nil || !ok {
		t.Fatalf("首次領件應成功: ok=%v err=%v", ok, err)
	}
	ok, err = rig.ledger.Claim(row.ID, clk.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("第二次領件不應回錯（已被別人領走不是錯誤）: %v", err)
	}
	if ok {
		t.Fatal("第二次領件應回 false（CAS 失敗）")
	}
	got, _ := rig.ledger.Get(row.ID)
	if got.State != StateUploading || got.Attempts != 1 {
		t.Fatalf("領件後 state=%q attempts=%d, want uploading/1", got.State, got.Attempts)
	}
}

// TestOffsiteLedgerBackoffScheduleAndRetryCap 退避時序與重試上限。
func TestOffsiteLedgerBackoffScheduleAndRetryCap(t *testing.T) {
	rig, clk := newClockedRig(t)
	mustSave(t, rig, s3Settings("evidence"))
	row, _ := enqueue(t, rig, KindRecording, 1, OriginLive)

	want := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour}
	for i := 1; i <= 4; i++ {
		terminal, err := rig.ledger.MarkFailed(row.ID, i, ErrCodeUploadFailed)
		if err != nil {
			t.Fatalf("MarkFailed(%d): %v", i, err)
		}
		if terminal {
			t.Fatalf("第 %d 次失敗不應轉終態（上限 %d）", i, MaxUploadAttempts)
		}
		got, _ := rig.ledger.Get(row.ID)
		if got.State != StatePending {
			t.Fatalf("第 %d 次失敗後 state=%q, want pending", i, got.State)
		}
		if got.NextAttemptAt == nil {
			t.Fatalf("第 %d 次失敗後缺 next_attempt_at", i)
		}
		if delta := got.NextAttemptAt.Sub(clk.Now()); delta != want[i-1] {
			t.Fatalf("第 %d 次失敗的退避 = %v, want %v", i, delta, want[i-1])
		}
		if got.Attempts != i {
			t.Fatalf("第 %d 次失敗後 attempts=%d：panic 攔截路徑沒走過 Claim，"+
				"attempts 不落盤則重試上限永遠到不了", i, got.Attempts)
		}
	}
	terminal, err := rig.ledger.MarkFailed(row.ID, MaxUploadAttempts, ErrCodeUploadFailed)
	if err != nil || !terminal {
		t.Fatalf("第 %d 次失敗應轉終態: terminal=%v err=%v", MaxUploadAttempts, terminal, err)
	}
	got, _ := rig.ledger.Get(row.ID)
	if got.State != StateFailed || got.ErrorCode != ErrCodeUploadFailed || got.NextAttemptAt != nil {
		t.Fatalf("終態列不正確: %+v", got)
	}
}

// TestOffsiteLedgerListDueRespectsBackoffAndLane 取件面：退避未到不取、車道分立。
func TestOffsiteLedgerListDueRespectsBackoffAndLane(t *testing.T) {
	rig, clk := newClockedRig(t)
	mustSave(t, rig, s3Settings("evidence"))
	live, _ := enqueue(t, rig, KindRecording, 1, OriginLive)
	back, _ := enqueue(t, rig, KindRecording, 2, OriginBackfill)

	if rows, _ := rig.ledger.ListDue(OriginLive, 10); len(rows) != 1 || rows[0].ID != live.ID {
		t.Fatalf("live 車道應取到 1 件，實得 %v", rows)
	}
	if rows, _ := rig.ledger.ListDue(OriginBackfill, 10); len(rows) != 1 || rows[0].ID != back.ID {
		t.Fatalf("backfill 車道應取到 1 件，實得 %v", rows)
	}
	// 退避中不取
	if _, err := rig.ledger.MarkFailed(live.ID, 1, ErrCodeUploadFailed); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
	if rows, _ := rig.ledger.ListDue(OriginLive, 10); len(rows) != 0 {
		t.Fatalf("退避未到不應取件，實得 %d 件", len(rows))
	}
	clk.Advance(time.Minute)
	if rows, _ := rig.ledger.ListDue(OriginLive, 10); len(rows) != 1 {
		t.Fatalf("退避到期後應可取件，實得 %d 件", len(rows))
	}
}

// TestOffsiteLedgerReapExpiredLeaseAndStalled 租約回收與卡死判準。
//
// 重啟時的 uploading→pending 即租約回收的特例（attempts **保留**，不歸零）。
func TestOffsiteLedgerReapExpiredLeaseAndStalled(t *testing.T) {
	rig, clk := newClockedRig(t)
	mustSave(t, rig, s3Settings("evidence"))
	row, _ := enqueue(t, rig, KindRecording, 1, OriginLive)

	// 第一次：領件 → 租約過期 → 回收
	if ok, _ := rig.ledger.Claim(row.ID, clk.Now().Add(time.Minute)); !ok {
		t.Fatal("領件失敗")
	}
	clk.Advance(2 * time.Minute)
	reaped, err := rig.ledger.Reap()
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if len(reaped) != 1 || reaped[0].LeaseExpiries != 1 {
		t.Fatalf("第一次回收: %+v", reaped)
	}
	got, _ := rig.ledger.Get(row.ID)
	if got.State != StatePending || got.LeaseUntil != nil {
		t.Fatalf("回收後應回 pending 並清租約: %+v", got)
	}
	if got.Attempts != 1 {
		t.Fatalf("回收不得歸零 attempts，實得 %d", got.Attempts)
	}

	// 第二次：lease_expiries 達 2＝卡死判準（**不等到 attempts 上限**）
	if ok, _ := rig.ledger.Claim(row.ID, clk.Now().Add(time.Minute)); !ok {
		t.Fatal("再次領件失敗")
	}
	clk.Advance(2 * time.Minute)
	reaped, _ = rig.ledger.Reap()
	if len(reaped) != 1 || reaped[0].LeaseExpiries != StalledLeaseExpiries {
		t.Fatalf("第二次回收的 lease_expiries = %+v, want %d", reaped, StalledLeaseExpiries)
	}

	// 未到期的租約不被回收
	if ok, _ := rig.ledger.Claim(row.ID, clk.Now().Add(time.Hour)); !ok {
		t.Fatal("第三次領件失敗")
	}
	if reaped, _ = rig.ledger.Reap(); len(reaped) != 0 {
		t.Fatalf("未到期的租約不應被回收，實得 %d 件", len(reaped))
	}
}

// TestOffsiteLedgerMarkLocalPurgedStateTransitions 逐狀態到期轉移表**六格全覆蓋**。
//
// 缺表會留下「本機檔已刪卻仍被 worker 領取」的孤兒列。
func TestOffsiteLedgerMarkLocalPurgedStateTransitions(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before        string
		wantState     string
		wantDeferred  bool
		wantNever     bool
		wantPrior     string
		wantIdempotent bool
	}{
		{"uploaded → local_purged（主情境）", StateUploaded, StateLocalPurged, false, false, "", false},
		{"pending → local_purged 且註 never_uploaded", StatePending, StateLocalPurged, false, true, "", false},
		{"failed → local_purged 且註 never_uploaded", StateFailed, StateLocalPurged, false, true, "", false},
		{"uploading → 不動（待租約回收後下輪處置）", StateUploading, StateUploading, true, false, "", false},
		{"integrity_mismatch → local_purged 且註前態", StateIntegrityMismatch, StateLocalPurged, false, false, StateIntegrityMismatch, false},
		{"foreign → 維持 foreign（狀態語義保留供對帳）", StateForeign, StateForeign, false, false, "", false},
		{"local_purged → 冪等跳過", StateLocalPurged, StateLocalPurged, false, false, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig, _ := newClockedRig(t)
			gen := mustSave(t, rig, s3Settings("evidence")).View
			obj := seedObject(t, rig.db, gen.GenerationID, 1, tc.before)

			out, err := rig.ledger.MarkLocalPurged(obj.ID)
			if err != nil {
				t.Fatalf("MarkLocalPurged: %v", err)
			}
			if out.Deferred != tc.wantDeferred {
				t.Fatalf("Deferred = %v, want %v", out.Deferred, tc.wantDeferred)
			}
			if out.NewState != tc.wantState {
				t.Fatalf("NewState = %q, want %q", out.NewState, tc.wantState)
			}
			if out.NeverUploaded != tc.wantNever {
				t.Fatalf("NeverUploaded = %v, want %v（從未離機即到期銷毀是誠實邊界，"+
					"不註記即讓人以為那批證據都有遠端副本）", out.NeverUploaded, tc.wantNever)
			}
			if out.PriorState != tc.wantPrior {
				t.Fatalf("PriorState = %q, want %q", out.PriorState, tc.wantPrior)
			}
			if out.Idempotent != tc.wantIdempotent {
				t.Fatalf("Idempotent = %v, want %v", out.Idempotent, tc.wantIdempotent)
			}
			got, _ := rig.ledger.Get(obj.ID)
			if got.State != tc.wantState {
				t.Fatalf("落庫 state = %q, want %q", got.State, tc.wantState)
			}
			// **零遠端刪除**：到期處置不得發任何遠端呼叫
			if rig.factory.count() != 0 {
				t.Fatal("到期處置建構了 driver：產品對遠端物件不發 DeleteObject")
			}
			// 事件：deferred 不發、其餘各發一筆
			var retention *CustodyEvent
			for _, ev := range rig.journal.all() {
				if ev.Action == CustodyActionRetention {
					c := ev
					retention = &c
				}
			}
			// 延後處置與冪等跳過皆**不發事件**：前者本輪什麼都沒做，
			// 後者每輪重發會讓同一次到期在審計上出現無限多筆
			if tc.wantDeferred || tc.wantIdempotent {
				if retention != nil {
					t.Fatal("延後處置或冪等跳過不應發保留事件")
				}
				return
			}
			if retention == nil {
				t.Fatalf("缺保留到期事件（實得 %v）", rig.journal.actions())
			}
			for _, key := range []string{"object_id", "kind", "bucket", "key"} {
				if _, ok := retention.Details[key]; !ok {
					t.Errorf("保留事件缺欄位 %q", key)
				}
			}
			if tc.wantNever && retention.Details["never_uploaded"] != true {
				t.Error("保留事件缺 never_uploaded 註記")
			}
			if tc.wantPrior != "" && retention.Details["prior_state"] != tc.wantPrior {
				t.Errorf("保留事件的 prior_state = %v, want %q", retention.Details["prior_state"], tc.wantPrior)
			}
			if tc.before == StateForeign && retention.Details["result"] != "local_expired" {
				t.Errorf("foreign 的到期事件應記 local_expired，實得 %v", retention.Details["result"])
			}
			// 事件不得含端點
			if dump := formatDetails(retention.Details); strings.Contains(dump, "minio.example.internal") {
				t.Errorf("保留事件夾帶端點: %s", dump)
			}
		})
	}
}

// TestOffsiteLedgerCountsAndFailedList 各態計數（缺席與零是兩件事）與失敗清單。
func TestOffsiteLedgerCountsAndFailedList(t *testing.T) {
	rig, _ := newClockedRig(t)
	gen := mustSave(t, rig, s3Settings("evidence")).View
	seedObject(t, rig.db, gen.GenerationID, 1, StateUploaded)
	seedObject(t, rig.db, gen.GenerationID, 2, StateFailed)
	seedObject(t, rig.db, gen.GenerationID, 3, StateFailed)

	counts, err := rig.ledger.Counts()
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	for _, s := range AllStates() {
		if _, ok := counts[s]; !ok {
			t.Errorf("計數缺狀態鍵 %q：缺席與零在指標面是兩件事", s)
		}
	}
	if counts[StateFailed] != 2 || counts[StateUploaded] != 1 || counts[StatePending] != 0 {
		t.Fatalf("計數不正確: %v", counts)
	}
	if n, _ := rig.ledger.CountFailed(); n != 2 {
		t.Fatalf("CountFailed = %d, want 2", n)
	}
	rows, total, err := rig.ledger.ListFailed(1, 10)
	if err != nil || total != 2 || len(rows) != 2 {
		t.Fatalf("ListFailed: rows=%d total=%d err=%v", len(rows), total, err)
	}
	// 批次重試：failed → pending、attempts 歸零
	n, err := rig.ledger.RetryFailed(0)
	if err != nil || n != 2 {
		t.Fatalf("RetryFailed: n=%d err=%v", n, err)
	}
	if c, _ := rig.ledger.CountFailed(); c != 0 {
		t.Fatalf("重試後 failed 應歸零，實得 %d", c)
	}
}

// TestOffsiteLedgerCheckProfileContinuity 健檢語義（自世代拒啟降級）。
//
// 三格：帳冊世代皆有對應列→通過；查無對應列→建構失敗且指名該世代與物件數、
// **不含端點**；**已退役世代的物件不視為違反**（退役是合法歸屬，那正是 foreign 的常態）。
func TestOffsiteLedgerCheckProfileContinuity(t *testing.T) {
	t.Run("皆有對應世代→通過", func(t *testing.T) {
		rig, _ := newClockedRig(t)
		gen := mustSave(t, rig, s3Settings("evidence")).View
		seedObject(t, rig.db, gen.GenerationID, 1, StateUploaded)
		if err := rig.ledger.CheckProfileContinuity(); err != nil {
			t.Fatalf("應通過: %v", err)
		}
	})
	t.Run("已退役世代不視為違反", func(t *testing.T) {
		rig, _ := newClockedRig(t)
		old := mustSave(t, rig, s3Settings("bucket-old")).View
		seedObject(t, rig.db, old.GenerationID, 1, StateForeign)
		if _, err := rig.svc.Save(context.Background(), s3Settings("bucket-new"),
			OffsiteActor{ID: 1}); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if err := rig.ledger.CheckProfileContinuity(); err != nil {
			t.Fatalf("已退役世代是合法歸屬，健檢不得判為損壞: %v", err)
		}
	})
	t.Run("查無對應世代→建構失敗且指名", func(t *testing.T) {
		rig, _ := newClockedRig(t)
		gen := mustSave(t, rig, s3Settings("evidence")).View
		seedObject(t, rig.db, gen.GenerationID, 1, StateUploaded)
		seedObject(t, rig.db, 9911, 2, StateUploaded)
		seedObject(t, rig.db, 9911, 3, StateUploaded)

		err := rig.ledger.CheckProfileContinuity()
		if err == nil {
			t.Fatal("帳冊指向不存在的世代＝資料損壞，健檢應失敗")
		}
		var typed *ProfileContinuityError
		if !asProfileContinuityError(err, &typed) {
			t.Fatalf("錯誤型別不正確: %T", err)
		}
		if typed.Missing[9911] != 2 {
			t.Fatalf("缺漏世代的物件數 = %v, want {9911:2}", typed.Missing)
		}
		msg := err.Error()
		if !strings.Contains(msg, "9911") || !strings.Contains(msg, "2 個物件") {
			t.Fatalf("訊息應指名世代與物件數: %s", msg)
		}
		if strings.Contains(msg, "minio.example.internal") {
			t.Fatalf("健檢訊息夾帶端點: %s", msg)
		}
	})
}

func asProfileContinuityError(err error, target **ProfileContinuityError) bool {
	if e, ok := err.(*ProfileContinuityError); ok {
		*target = e
		return true
	}
	return false
}

// TestOffsiteLedgerMarkForeignSkipsTerminalRows MarkForeign 不動已 local_purged／已 foreign。
func TestOffsiteLedgerMarkForeignSkipsTerminalRows(t *testing.T) {
	rig, _ := newClockedRig(t)
	gen := mustSave(t, rig, s3Settings("evidence")).View
	uploaded := seedObject(t, rig.db, gen.GenerationID, 1, StateUploaded)
	purged := seedObject(t, rig.db, gen.GenerationID, 2, StateLocalPurged)
	already := seedObject(t, rig.db, gen.GenerationID, 3, StateForeign)

	var moved, never int64
	err := rig.db.Transaction(func(tx *gorm.DB) error {
		var e error
		moved, never, e = rig.ledger.MarkForeign(tx, gen.GenerationID)
		return e
	})
	if err != nil {
		t.Fatalf("MarkForeign: %v", err)
	}
	if moved != 1 {
		t.Fatalf("轉移數 = %d, want 1（local_purged 與已 foreign 不再轉）", moved)
	}
	if never != 0 {
		t.Fatalf("未上傳數 = %d, want 0", never)
	}
	if got, _ := rig.ledger.Get(uploaded.ID); got.State != StateForeign {
		t.Errorf("uploaded 應轉 foreign，實得 %q", got.State)
	}
	if got, _ := rig.ledger.Get(purged.ID); got.State != StateLocalPurged {
		t.Errorf("local_purged 不應被改寫，實得 %q", got.State)
	}
	if got, _ := rig.ledger.Get(already.ID); got.State != StateForeign {
		t.Errorf("已 foreign 應維持，實得 %q", got.State)
	}
}
