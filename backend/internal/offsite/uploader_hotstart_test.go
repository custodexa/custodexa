package offsite

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 首次完成設定後上傳 worker 的即時啟動。
//
// # 這一組要擋的失敗形態
//
// 服務啟動時設定表零列 ⇒ 不建 worker goroutine（那是「未設定＝行為完全不變」的
// 機械保證，本身正確）。管理員其後於管理介面完成設定，帳冊**開始排入**而沒有
// 任何人領件：全部停在待上傳，直到有人重啟服務才被撿走。
//
// 症狀完全安靜——沒有錯誤、沒有失敗件、佇列指標在該狀態下又缺席，而那條鏈上
// 積的是證據。故本組驗的不是「回呼有沒有被呼叫」（那可以靠讀程式碼看出來），
// 而是**排入的件最後有沒有被領走**。

// hotStartRig 一組「零列啟動」的裝配：worker 已建構但尚未跑，
// 啟動回呼以組裝根的同一形態（至多一次）接上設定服務。
type hotStartRig struct {
	*offsiteTestRig
	uploader *Uploader
	adapter  *fakeAdapter
	client   *FakeClient
	// calls 回呼被呼叫的次數；spawns 真正放出迴圈 goroutine 的次數。
	// 兩者分開才分得出「沒接線」與「接了線但重複起了第二條迴圈」
	calls  *atomic.Int64
	spawns *atomic.Int64
}

func newHotStartRig(t *testing.T) *hotStartRig {
	t.Helper()
	rig := newOffsiteRig(t)
	client := NewFakeClient("evidence")
	rig.factory.client = client
	adapter := newFakeAdapter(KindRecording)
	up := NewUploader(rig.ledger, rig.svc, &fakeReporter{}, adapter)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var (
		once   sync.Once
		calls  atomic.Int64
		spawns atomic.Int64
	)
	// **與組裝根同形**：一次性放出迴圈 goroutine，重複呼叫為 no-op。
	// 此處若寫成每次都 `go up.Run(ctx)`，兩條迴圈會各自領同一批件
	rig.svc.SetUploaderStarter(func() {
		calls.Add(1)
		once.Do(func() {
			spawns.Add(1)
			go up.Run(ctx)
		})
	})
	return &hotStartRig{offsiteTestRig: rig, uploader: up, adapter: adapter,
		client: client, calls: &calls, spawns: &spawns}
}

// waitForState 等帳冊列轉到期望狀態（上限內未到即 Fatal 並指名現況）。
//
// **上限給得比取件輪詢間隔寬裕**：worker 是定時取件，卡在慢機器上的偶發紅
// 會讓這一格被當成噪音而失去意義。
func waitForState(t *testing.T, rig *hotStartRig, id uint, want string) model.OffsiteObject {
	t.Helper()
	deadline := time.Now().Add(6 * uploadTickInterval)
	var last model.OffsiteObject
	for time.Now().Before(deadline) {
		got, err := rig.ledger.Get(id)
		if err != nil {
			t.Fatalf("讀取帳冊列 %d 失敗: %v", id, err)
		}
		last = *got
		if got.State == want {
			return *got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("帳冊列 %d 在 %v 內未轉為 %q（實得 state=%q attempts=%d）：\n"+
		"　　首次設定完成後上傳 worker 未被拉起，排入的證據要等到下次重啟才會離機",
		id, 6*uploadTickInterval, want, last.State, last.Attempts)
	return last
}

// TestOffsiteFirstSaveStartsUploaderAndDrainsPending 零列啟動 → 首次儲存 → 排入的件被領走。
func TestOffsiteFirstSaveStartsUploaderAndDrainsPending(t *testing.T) {
	rig := newHotStartRig(t)

	if n := currentCount(t, rig.db); n != 0 {
		t.Fatalf("前置條件不成立：設定表有 %d 列現行世代（本格要驗的是零列態）", n)
	}
	if got := rig.spawns.Load(); got != 0 {
		t.Fatalf("尚未設定就放出了 %d 條上傳迴圈", got)
	}

	mustSave(t, rig.offsiteTestRig, s3Settings("evidence"))

	if got := rig.spawns.Load(); got != 1 {
		t.Fatalf("首次儲存後放出的上傳迴圈 = %d, want 1（0＝設定服務未接上啟動回呼）", got)
	}

	// 儲存之後才發生的一次會話落地：排入 → 應被領走
	rig.adapter.put(1, &fakeFile{content: []byte("cast-content"), mtime: time.Now()})
	row, created := enqueue(t, rig.offsiteTestRig, KindRecording, 1, OriginLive)
	if !created {
		t.Fatal("前置條件不成立：本格要的是新排入的件")
	}

	got := waitForState(t, rig, row.ID, StateUploaded)
	if got.UploadedAt == nil || got.SHA256 == "" {
		t.Errorf("轉為 uploaded 但完整性欄未落地：uploaded_at=%v sha256=%q", got.UploadedAt, got.SHA256)
	}
	if _, _, ok := rig.client.ObjectData(ObjectRef{Bucket: "evidence", Key: got.ObjectKey}); !ok {
		t.Errorf("帳冊記為已上傳，遠端卻沒有 %q", got.ObjectKey)
	}
}

// TestOffsiteRepeatedSaveDoesNotSpawnSecondUploader 重複儲存不會多起一條迴圈。
//
// 回呼冪等是接線的硬要求：第二條迴圈會與第一條爭同一批件，
// 而 CAS 領件使症狀退化成「偶爾多一次無效取件」——不會有任何測試自然轉紅。
func TestOffsiteRepeatedSaveDoesNotSpawnSecondUploader(t *testing.T) {
	rig := newHotStartRig(t)

	mustSave(t, rig.offsiteTestRig, s3Settings("evidence"))   // 零 → 有：世代切換
	mustSave(t, rig.offsiteTestRig, s3Settings("evidence"))   // 指紋相同：就地更新
	mustSave(t, rig.offsiteTestRig, s3Settings("evidence-2")) // 指紋不同且無存量：再切一代

	if got := rig.calls.Load(); got != 3 {
		t.Errorf("三次成功寫入呼叫回呼 %d 次, want 3（少呼叫即代表某條寫入路徑沒接上）", got)
	}
	if got := rig.spawns.Load(); got != 1 {
		t.Fatalf("放出的上傳迴圈 = %d, want 1：重複呼叫必須是 no-op", got)
	}
}

// TestOffsiteSaveNeedingConfirmationDoesNotStartUploader 「需確認」分支什麼也沒寫，不叫醒 worker。
//
// 該分支的現行世代原封不動，此時起 worker 等於用一個**尚未被接受的設定**開始搬證據。
func TestOffsiteSaveNeedingConfirmationDoesNotStartUploader(t *testing.T) {
	rig := newHotStartRig(t)
	res := mustSave(t, rig.offsiteTestRig, s3Settings("evidence"))
	seedObject(t, rig.db, res.View.GenerationID, 1, StateUploaded)
	before := rig.calls.Load()

	out, err := rig.svc.Save(context.Background(), s3Settings("evidence-2"),
		OffsiteActor{ID: 1, Name: "admin"})
	if err != nil {
		t.Fatalf("Save 失敗: %v", err)
	}
	if !out.NeedsConfirmation {
		t.Fatalf("前置條件不成立：有存量時換落點應回「需確認」")
	}
	if got := rig.calls.Load(); got != before {
		t.Errorf("「需確認」分支（未寫入任何一列）竟呼叫了啟動回呼 %d 次", got-before)
	}
}

// TestOffsiteConfirmGenerationSwitchStartsUploader 確認流程也接上啟動回呼。
//
// 有存量時換落點必走確認流程，**寫入落在 ConfirmGenerationSwitch 而不是 Save**；
// 只接 Save 的話，這條路徑上的服務要等到重啟才會開始搬新落點的證據。
func TestOffsiteConfirmGenerationSwitchStartsUploader(t *testing.T) {
	rig := newHotStartRig(t)
	first := mustSave(t, rig.offsiteTestRig, s3Settings("evidence")).View
	seedObject(t, rig.db, first.GenerationID, 1, StateUploaded)

	pending, err := rig.svc.Save(context.Background(), s3Settings("evidence-2"),
		OffsiteActor{ID: 1, Name: "admin"})
	if err != nil {
		t.Fatalf("Save 失敗: %v", err)
	}
	if !pending.NeedsConfirmation {
		t.Fatalf("前置條件不成立：有存量時換落點應回「需確認」")
	}
	before := rig.calls.Load()

	if _, err := rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
		Settings:                    s3Settings("evidence-2"),
		SettingsDigest:              pending.SettingsDigest,
		ExpectedCurrentGenerationID: pending.ExpectedCurrentGenerationID,
	}, OffsiteActor{ID: 1, Name: "admin"}); err != nil {
		t.Fatalf("ConfirmGenerationSwitch 失敗: %v", err)
	}
	if got := rig.calls.Load(); got <= before {
		t.Error("確認世代切換（真正寫入的那一步）未呼叫啟動回呼：" +
			"以此路徑完成設定的服務要等到重啟才開始上傳")
	}
}
