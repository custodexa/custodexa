package offsite

import (
	"context"
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 世代退役時的擁有表快取批次寫回（`MarkForeignBatch` 的接線）。
//
// # 這一段在防什麼
//
// `offsite_status` 是給 UI 讀的快取欄，所有決策一律讀帳冊。但快取若在世代切換後
// 停在 `uploaded`，會話詳情會繼續顯示「已上傳到現行儲存」——那是錯的（物件在舊
// 世代的 bucket 裡，取回要用舊世代的憑證），而且它**不會自我修復**：帳冊的世代欄
// 已經換人，之後沒有任何一輪迴圈會回頭修這些列。
//
// 兩個 adapter 的 `MarkForeignBatch` 早已寫好，但**沒有任何呼叫者**——
// 實作存在不等於路徑接上了，這一組測試就是那條路徑的機器證據。

// recordingCacheMarker 記錄被呼叫的世代，並可注入失敗。
type recordingCacheMarker struct {
	calls []uint
	// txSeen 呼叫當下拿到的交易句柄（用來證明「與帳冊轉移同交易」）
	txSeen []*gorm.DB
	err    error
}

func (m *recordingCacheMarker) MarkForeignBatch(tx *gorm.DB, generationID uint) error {
	m.calls = append(m.calls, generationID)
	m.txSeen = append(m.txSeen, tx)
	return m.err
}

// TestOffsiteDisableMarksOwnerCachesForeign 停止離機：擁有表快取與帳冊一起轉 foreign。
func TestOffsiteDisableMarksOwnerCachesForeign(t *testing.T) {
	rig := newOffsiteRig(t)
	a, b := &recordingCacheMarker{}, &recordingCacheMarker{}
	rig.svc.SetOwnerCacheMarkers(a, b)

	gen := mustSave(t, rig, s3Settings("evidence")).View
	seedObject(t, rig.db, gen.GenerationID, 1, StateUploaded)

	if err := rig.svc.Disable(context.Background(), OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	// **每一個擁有者模組都要被呼叫到**：只呼叫第一個的話，證據包那一側的快取
	// 會永遠停在舊值，而下載中心正是靠它顯示「已離機保存」
	for i, m := range []*recordingCacheMarker{a, b} {
		if len(m.calls) != 1 || m.calls[0] != gen.GenerationID {
			t.Fatalf("第 %d 個擁有表快取面的呼叫 = %v, want 一次且世代為 %d",
				i+1, m.calls, gen.GenerationID)
		}
		if m.txSeen[0] == nil {
			t.Fatalf("第 %d 個擁有表快取面拿到 nil 交易句柄：快取與帳冊就不在同一交易內", i+1)
		}
	}
}

// TestOffsiteGenerationSwitchMarksOwnerCachesForeign 世代切換：同上，且帶的是**舊**世代。
//
// 帶錯世代（例如傳新世代）在單一擁有表的實作下看不出來——現行實作以快取狀態集合
// 圈選、世代只進錯誤訊息——但它會讓錯誤訊息指向錯的地方，且未來若有實作改以
// 世代欄圈選就會靜默清錯一批。
func TestOffsiteGenerationSwitchMarksOwnerCachesForeign(t *testing.T) {
	rig := newOffsiteRig(t)
	marker := &recordingCacheMarker{}
	rig.svc.SetOwnerCacheMarkers(marker)

	old := mustSave(t, rig, s3Settings("evidence")).View
	seedObject(t, rig.db, old.GenerationID, 1, StateUploaded)

	// 落點變更＋帳冊有存量＝需確認，故走 confirm 路徑
	next := s3Settings("evidence-2")
	res, err := rig.svc.Save(context.Background(), next, OffsiteActor{ID: 1})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !res.NeedsConfirmation {
		t.Fatal("前置條件不成立：落點變更且帳冊有存量時應回「需確認」")
	}
	if _, err := rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
		Settings:                    next,
		ExpectedCurrentGenerationID: res.ExpectedCurrentGenerationID,
		SettingsDigest:              res.SettingsDigest,
	}, OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("ConfirmGenerationSwitch: %v", err)
	}

	if len(marker.calls) != 1 || marker.calls[0] != old.GenerationID {
		t.Fatalf("擁有表快取面的呼叫 = %v, want 一次且世代為**舊**世代 %d",
			marker.calls, old.GenerationID)
	}
}

// TestOffsiteOwnerCacheFailureRollsBackWholeSwitch 快取寫回失敗＝整筆回滾（fail-close）。
//
// 允許它只記 log 繼續的話，終局是「世代已退役、帳冊已轉 foreign、擁有表仍宣稱
// 已上傳到現行儲存」——一個沒有任何機制會去修的不一致狀態。
func TestOffsiteOwnerCacheFailureRollsBackWholeSwitch(t *testing.T) {
	rig := newOffsiteRig(t)
	boom := errors.New("注入：擁有表快取寫回失敗")
	rig.svc.SetOwnerCacheMarkers(&recordingCacheMarker{err: boom})

	gen := mustSave(t, rig, s3Settings("evidence")).View
	obj := seedObject(t, rig.db, gen.GenerationID, 1, StateUploaded)

	err := rig.svc.Disable(context.Background(), OffsiteActor{ID: 1})
	if err == nil {
		t.Fatal("擁有表快取寫回失敗竟成功返回：不一致狀態會被留下且無人修復")
	}
	if n := currentCount(t, rig.db); n != 1 {
		t.Fatalf("回滾後現行世代數 = %d, want 1（退役須一併回捲）", n)
	}
	var row model.OffsiteObject
	if err := rig.db.Where("id = ?", obj.ID).First(&row).Error; err != nil {
		t.Fatalf("讀取帳冊列: %v", err)
	}
	if row.State != StateUploaded {
		t.Fatalf("回滾後帳冊列 state = %q, want uploaded（帳冊轉移須一併回捲）", row.State)
	}
}

// TestOffsiteWithoutOwnerCacheMarkersStillRetires 未接線時仍照常退役。
//
// 單元測試與尚未接上擁有者模組的裝配路徑不得因此壞掉：擁有表快取是顯示面，
// 帳冊才是事實源。
func TestOffsiteWithoutOwnerCacheMarkersStillRetires(t *testing.T) {
	rig := newOffsiteRig(t)
	gen := mustSave(t, rig, s3Settings("evidence")).View
	obj := seedObject(t, rig.db, gen.GenerationID, 1, StateUploaded)

	if err := rig.svc.Disable(context.Background(), OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if n := currentCount(t, rig.db); n != 0 {
		t.Fatalf("未接擁有表快取面時竟未退役，現行世代數 = %d", n)
	}
	var row model.OffsiteObject
	rig.db.Where("id = ?", obj.ID).First(&row)
	if row.State != StateForeign {
		t.Fatalf("帳冊列 state = %q, want foreign", row.State)
	}
}

// TestOffsiteGenerationCountDistinguishesNeverConfiguredFromDisabled
// 世代總列數是「從未設定」與「已停用」的分界（指標註冊的判準）。
func TestOffsiteGenerationCountDistinguishesNeverConfiguredFromDisabled(t *testing.T) {
	rig := newOffsiteRig(t)

	n, err := rig.svc.GenerationCount()
	if err != nil {
		t.Fatalf("GenerationCount: %v", err)
	}
	if n != 0 {
		t.Fatalf("從未設定時世代數 = %d, want 0（非零會讓離機指標整組被註冊起來）", n)
	}

	mustSave(t, rig, s3Settings("evidence"))
	if err := rig.svc.Disable(context.Background(), OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	n, err = rig.svc.GenerationCount()
	if err != nil {
		t.Fatalf("GenerationCount: %v", err)
	}
	if n != 1 {
		t.Fatalf("停用態世代數 = %d, want 1——它與「從未設定」不可混為一談，"+
			"停用態的存量與失敗面必須照常曝光", n)
	}
	if cur, err := rig.ledger.HasCurrentGeneration(); err != nil || cur {
		t.Fatalf("停用態應無現行世代，實得 cur=%v err=%v", cur, err)
	}
}
