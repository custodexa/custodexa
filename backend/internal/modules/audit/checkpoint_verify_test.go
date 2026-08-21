package audit

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

// 檢查點驗證的九態（audit-checkpoint-chain tasks 8.3／spec「兩層語義與逐區間狀態」）。
//
// **九態各造一例是硬性要求**：把不同成因壓成單一「失敗」正是本機制最想避免
// 的事——`purged_legal` 與 `purged_invalid` 若不可區分，合法清除就會天天發告警，
// 而真的抽列反而淹沒在噪音裡。

// verifyFixture 驗證測試夾具：完整鏈＋列級完整性服務＋驗證器
type verifyFixture struct {
	db        *gorm.DB
	seal      *CheckpointService
	purger    *CheckpointPurger
	verifier  *CheckpointVerifier
	integrity *AuditIntegrityService
	signer    *testSigner
}

func setupVerifyFixture(t *testing.T) *verifyFixture {
	t.Helper()
	db := setupCheckpointDB(t)
	if err := db.AutoMigrate(&model.AuditCheckpointTrim{}, &model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	integrity := newIntegrityServiceWithKey(t, db, "checkpoint-verify-key")
	seal, signer := newCheckpointService(t, db, nil, nil)
	if err := seal.EnsureGenesis(); err != nil {
		t.Fatalf("genesis: %v", err)
	}
	purger := NewCheckpointPurger(db, signer)
	return &verifyFixture{
		db: db, seal: seal, purger: purger, integrity: integrity, signer: signer,
		verifier: NewCheckpointVerifier(db, seal, purger, integrity, nil),
	}
}

// stampedRows 寫入 n 列**經列級蓋章服務蓋章**的審計列。
//
// 與 seedAuditRows（HMAC 自填假值）不同：本組要驗的正是「多出的列其列級
// HMAC 是否有效」，假 HMAC 會讓每一列都判不符而測不出差別
func (f *verifyFixture) stampedRows(t *testing.T, n int, createdAt time.Time) []uint {
	t.Helper()
	ids := make([]uint, 0, n)
	for i := 0; i < n; i++ {
		row := model.AuditLog{
			Username: "verify", Action: model.ActionExecute, Resource: model.ResourceAuditLog,
			Status: model.StatusSuccess, CreatedAt: createdAt.Add(time.Duration(i) * time.Millisecond),
		}
		f.integrity.StampOne(&row)
		if err := f.db.Create(&row).Error; err != nil {
			t.Fatalf("stamped row: %v", err)
		}
		ids = append(ids, row.ID)
	}
	return ids
}

// statusOf 取指定 seq 的內容層狀態
func (f *verifyFixture) statusOf(t *testing.T, seq uint) IntervalReport {
	t.Helper()
	rep, err := f.verifier.VerifyContentBySeq(seq, seq)
	if err != nil {
		t.Fatalf("VerifyContentBySeq(%d): %v", seq, err)
	}
	if len(rep.Intervals) != 1 {
		t.Fatalf("seq=%d 的區間數 = %d, want 1", seq, len(rep.Intervals))
	}
	return rep.Intervals[0]
}

// TestCheckpointVerifyStatuses 九態逐一造出。
//
// 每個子測試自建夾具：竄改鏈的子測試（chain_broken／seq_gap）會影響後續
// 檢查點的判定，共用夾具會讓狀態互相污染而看不出是誰造成的
func TestCheckpointVerifyStatuses(t *testing.T) {
	t.Run("passed", func(t *testing.T) {
		f := setupVerifyFixture(t)
		f.stampedRows(t, 3, time.Now())
		cp, err := f.seal.SealNow()
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPassed {
			t.Fatalf("狀態 = %s, want %s", got, IntervalStatusPassed)
		}
		t.Logf("passed: seq=%d row_count=%d", cp.Seq, cp.RowCount)
	})

	t.Run("purged_legal", func(t *testing.T) {
		f := setupVerifyFixture(t)
		f.stampedRows(t, 3, time.Now().Add(-400*24*time.Hour))
		cp, _ := f.seal.SealNow()
		if _, err := f.purger.PurgeInterval(cp, 365, time.Now().Add(-365*24*time.Hour)); err != nil {
			t.Fatalf("purge: %v", err)
		}
		if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPurgedLegal {
			t.Fatalf("狀態 = %s, want %s", got, IntervalStatusPurgedLegal)
		}
	})

	t.Run("purged_invalid", func(t *testing.T) {
		f := setupVerifyFixture(t)
		f.stampedRows(t, 3, time.Now())
		cp, _ := f.seal.SealNow()
		// 列全被抽走且無 tombstone＝竄改
		f.mustExec(t, "DELETE FROM audit_logs WHERE id >= ? AND id <= ?", cp.IDFrom, cp.IDTo)
		if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusPurgedInvalid {
			t.Fatalf("狀態 = %s, want %s", got, IntervalStatusPurgedInvalid)
		}
	})

	t.Run("count_mismatch", func(t *testing.T) {
		f := setupVerifyFixture(t)
		ids := f.stampedRows(t, 3, time.Now())
		cp, _ := f.seal.SealNow()
		f.mustExec(t, "DELETE FROM audit_logs WHERE id = ?", ids[1]) // 抽中段列
		res := f.statusOf(t, cp.Seq)
		if res.Status != IntervalStatusCountMismatch {
			t.Fatalf("狀態 = %s, want %s", res.Status, IntervalStatusCountMismatch)
		}
		if res.RemainRows != 2 {
			t.Errorf("殘留列數 = %d, want 2", res.RemainRows)
		}
	})

	t.Run("hash_mismatch", func(t *testing.T) {
		f := setupVerifyFixture(t)
		ids := f.stampedRows(t, 3, time.Now())
		cp, _ := f.seal.SealNow()
		// 改 key_version：列數不變，但聚合涵蓋該欄（D2 的新增覆蓋）
		f.mustExec(t, "UPDATE audit_logs SET key_version = 99 WHERE id = ?", ids[0])
		if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusHashMismatch {
			t.Fatalf("狀態 = %s, want %s", got, IntervalStatusHashMismatch)
		}
	})

	t.Run("extra_rows_valid_hmac", func(t *testing.T) {
		f := setupVerifyFixture(t)
		ids := f.stampedRows(t, 2, time.Now())
		// 封章上界取到「尚未存在的 id」，之後寫入的列即落在已封區間內
		// ——這正是誠實邊界 R1 的 straggler 形態
		cp, err := f.seal.SealUpTo(ids[len(ids)-1] + 2)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		f.stampedRows(t, 2, time.Now())
		res := f.statusOf(t, cp.Seq)
		if res.Status != IntervalStatusExtraRowsValidHMAC {
			t.Fatalf("狀態 = %s, want %s", res.Status, IntervalStatusExtraRowsValidHMAC)
		}
		if res.RemainRows <= cp.RowCount {
			t.Fatalf("殘留 %d 未多於封章主張 %d，前提不成立", res.RemainRows, cp.RowCount)
		}
		if len(res.InvalidHMACIDs) != 0 {
			t.Errorf("不應有 HMAC 無效列: %v", res.InvalidHMACIDs)
		}
	})

	t.Run("signature_invalid", func(t *testing.T) {
		f := setupVerifyFixture(t)
		f.stampedRows(t, 2, time.Now())
		cp, _ := f.seal.SealNow()
		// 原生 SQL 改簽章（ORM 白名單守衛會拒；攻擊者直寫 DB 不受守衛約束）
		f.mustExec(t, "UPDATE audit_checkpoints SET signature = ? WHERE seq = ?", "AAAA", cp.Seq)
		if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusSignatureInvalid {
			t.Fatalf("狀態 = %s, want %s", got, IntervalStatusSignatureInvalid)
		}
	})

	t.Run("chain_broken", func(t *testing.T) {
		f := setupVerifyFixture(t)
		f.stampedRows(t, 2, time.Now())
		cp2, _ := f.seal.SealNow()
		f.stampedRows(t, 2, time.Now())
		cp3, _ := f.seal.SealNow()

		// **持鑰者竄改**：改 cp2 的 agg_hash 並以同一把鑰重簽——cp2 自身
		// 簽章因此有效，但 cp3 的 prev_checkpoint_hash 已對不上重算值。
		// 這是 spec「局部竄改鏈接必現形」的情境；只改欄位不重簽只會得到
		// signature_invalid，測不到鏈接這一層
		tampered := *cp2
		tampered.AggHash = "0000000000000000000000000000000000000000000000000000000000000000"
		payload, err := CheckpointSignBytes(&tampered)
		if err != nil {
			t.Fatalf("payload: %v", err)
		}
		_, sig := f.signer.Sign(payload)
		f.mustExec(t, "UPDATE audit_checkpoints SET agg_hash = ?, signature = ? WHERE seq = ?",
			tampered.AggHash, sig, cp2.Seq)

		if got := f.statusOf(t, cp3.Seq).Status; got != ChainStatusChainBroken {
			t.Fatalf("後一點狀態 = %s, want %s", got, ChainStatusChainBroken)
		}
	})

	t.Run("chain_broken_genesis_anchor", func(t *testing.T) {
		f := setupVerifyFixture(t)
		// 動完整性基準＝genesis 的錨換了：genesis 的 prev hash 對不上
		f.mustExec(t, "UPDATE integrity_baselines SET max_log_id = 999 WHERE id = 1")
		rep, err := f.verifier.VerifyChain()
		if err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
		if rep.Status != ChainStatusChainBroken {
			t.Fatalf("鏈狀態 = %s, want %s", rep.Status, ChainStatusChainBroken)
		}
	})

	t.Run("seq_gap", func(t *testing.T) {
		f := setupVerifyFixture(t)
		f.stampedRows(t, 2, time.Now())
		cp2, _ := f.seal.SealNow()
		f.stampedRows(t, 2, time.Now())
		cp3, _ := f.seal.SealNow()
		// 挖掉中段檢查點（無修剪記錄）
		f.mustExec(t, "DELETE FROM audit_checkpoints WHERE seq = ?", cp2.Seq)
		if got := f.statusOf(t, cp3.Seq).Status; got != ChainStatusSeqGap {
			t.Fatalf("狀態 = %s, want %s", got, ChainStatusSeqGap)
		}
	})

	t.Run("seq_gap_head_without_trim", func(t *testing.T) {
		f := setupVerifyFixture(t)
		f.stampedRows(t, 2, time.Now())
		f.seal.SealNow()
		// 挖掉 genesis：鏈頭 seq=2 既非 genesis 亦無修剪記錄
		f.mustExec(t, "DELETE FROM audit_checkpoints WHERE seq = 1")
		rep, err := f.verifier.VerifyChain()
		if err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
		if rep.Status != ChainStatusSeqGap {
			t.Fatalf("鏈狀態 = %s, want %s（鏈頭被挖必須現形）", rep.Status, ChainStatusSeqGap)
		}
	})
}

// TestCheckpointExtraRowsVerifiesRowHMAC **8.3 的核心補齊**：
// `extra_rows_valid_hmac` 必須真的驗過列級 HMAC。
//
// 第 6 組的實作只判「多列」就掛這個狀態名——那等於系統替攻擊者背書：
// 一個宣稱「多出的列 HMAC 有效」的狀態，實際上從未驗過任何一列。
// 本測試以「讓多出的列 HMAC 無效」自證判定力：狀態必須改變
func TestCheckpointExtraRowsVerifiesRowHMAC(t *testing.T) {
	f := setupVerifyFixture(t)
	ids := f.stampedRows(t, 2, time.Now())
	cp, err := f.seal.SealUpTo(ids[len(ids)-1] + 2)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	extra := f.stampedRows(t, 2, time.Now())

	// 對照組：多出的列 HMAC 有效
	if got := f.statusOf(t, cp.Seq).Status; got != IntervalStatusExtraRowsValidHMAC {
		t.Fatalf("對照組狀態 = %s, want %s", got, IntervalStatusExtraRowsValidHMAC)
	}

	// 實驗組：把其中一列的內容改掉（HMAC 不再對應內容）
	f.mustExec(t, "UPDATE audit_logs SET username = ? WHERE id = ?", "forged", extra[0])
	res := f.statusOf(t, cp.Seq)
	if res.Status == IntervalStatusExtraRowsValidHMAC {
		t.Fatal("多出的列 HMAC 已無效，狀態仍宣稱 extra_rows_valid_hmac（狀態名在撒謊）")
	}
	if res.Status != IntervalStatusHashMismatch {
		t.Fatalf("狀態 = %s, want %s", res.Status, IntervalStatusHashMismatch)
	}
	if len(res.InvalidHMACIDs) == 0 {
		t.Error("未回報 HMAC 無效的列 id（研判無從下手）")
	}
	t.Logf("突變自證：多出列 HMAC 無效 → 狀態 %s，無效列 %v", res.Status, res.InvalidHMACIDs)
}

// TestCheckpointVerifyIsReadOnly 反覆驗證不改任何資料（spec「驗證不改資料」）
func TestCheckpointVerifyIsReadOnly(t *testing.T) {
	f := setupVerifyFixture(t)
	f.stampedRows(t, 3, time.Now())
	cp, _ := f.seal.SealNow()

	before := f.snapshot(t)
	for i := 0; i < 3; i++ {
		if _, err := f.verifier.VerifyChain(); err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
		if _, err := f.verifier.VerifyContentBySeq(1, cp.Seq); err != nil {
			t.Fatalf("VerifyContentBySeq: %v", err)
		}
	}
	if after := f.snapshot(t); after != before {
		t.Fatalf("驗證改動了資料:\n before=%s\n after =%s", before, after)
	}
}

// TestCheckpointContentRangeRequired 內容層必須帶範圍（8.2 的服務層側）
func TestCheckpointContentRangeRequired(t *testing.T) {
	f := setupVerifyFixture(t)
	for _, c := range []struct{ from, to uint }{{0, 0}, {0, 5}, {5, 0}, {5, 1}} {
		if _, err := f.verifier.VerifyContentBySeq(c.from, c.to); err == nil {
			t.Errorf("VerifyContentBySeq(%d,%d) 應拒絕", c.from, c.to)
		}
	}
}

// TestCheckpointChainReportUnsealedTail 尾段未封列數（R5 窗口）誠實呈現
func TestCheckpointChainReportUnsealedTail(t *testing.T) {
	f := setupVerifyFixture(t)
	f.stampedRows(t, 2, time.Now())
	cp, _ := f.seal.SealNow()
	f.stampedRows(t, 5, time.Now()) // 封章後又寫 5 列

	rep, err := f.verifier.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if rep.Status != IntervalStatusPassed {
		t.Fatalf("鏈狀態 = %s, want passed", rep.Status)
	}
	if rep.UnsealedRows != 5 {
		t.Errorf("未封尾段 = %d, want 5", rep.UnsealedRows)
	}
	if rep.UnsealedFromID != cp.IDTo+1 {
		t.Errorf("未封起始 id = %d, want %d", rep.UnsealedFromID, cp.IDTo+1)
	}
	if !rep.AnchorDisabled {
		t.Error("未啟用 syslog 轉發時 anchor_disabled 應為 true（降級橫幅的判據）")
	}
}

// TestChainReportCarriesSealThresholds 鏈報告須帶現行封章門檻。
//
// **這是誠實邊界 R5 的資料來源**：頁面上「未封窗口最長多久」的數字必須
// 是現行設定值。門檻自本能力起可由管理員在政策頁調整，前端若自行寫死，
// 管理員一調就成了對稽核的假陳述
func TestChainReportCarriesSealThresholds(t *testing.T) {
	f := setupVerifyFixture(t)
	f.stampedRows(t, 3, time.Now())
	if _, err := f.seal.SealNow(); err != nil {
		t.Fatalf("SealNow: %v", err)
	}

	rep, err := f.verifier.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	wantInterval := int64(f.seal.Interval() / time.Second)
	if rep.SealIntervalSeconds != wantInterval {
		t.Errorf("封章週期 = %d, want %d", rep.SealIntervalSeconds, wantInterval)
	}
	if rep.SealRowThreshold != f.seal.RowThreshold() {
		t.Errorf("筆數門檻 = %d, want %d", rep.SealRowThreshold, f.seal.RowThreshold())
	}

	// 調整政策後報告須跟著變（若在啟動期快取一份，此處會停在舊值）
	f.seal.SetPolicySource(fixedPolicySource{
		policy.PolicyAuditCheckpointIntervalSeconds: 900,
		policy.PolicyAuditCheckpointRowThreshold:    250,
	})
	rep, err = f.verifier.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain（調整後）: %v", err)
	}
	if rep.SealIntervalSeconds != 900 || rep.SealRowThreshold != 250 {
		t.Errorf("調整後 = %d 秒／%d 筆, want 900／250",
			rep.SealIntervalSeconds, rep.SealRowThreshold)
	}
}

// fixedPolicySource 固定值政策來源（測試用）
type fixedPolicySource map[string]int

func (f fixedPolicySource) GetInt(key string) int { return f[key] }

// TestCheckpointAnchorDisabledUsesLatest 降級判定取**鏈尾**而非全鏈聚合。
//
// 曾經啟用過 syslog、後來關掉的部署（dev 環境實際就是這個形狀：seq=5 為
// enqueued、其餘 disabled），若以「任一檢查點非 disabled」判定就不顯示降級
// 橫幅——而那正是最需要提醒的狀態：舊檢查點有外部證跡、新的全都沒有
func TestCheckpointAnchorDisabledUsesLatest(t *testing.T) {
	f := setupVerifyFixture(t)
	f.stampedRows(t, 1, time.Now())
	mid, _ := f.seal.SealNow()
	f.stampedRows(t, 1, time.Now())
	f.seal.SealNow()
	// 中段那一點曾成功錨定（走白名單 map 形式，與生產路徑同一入口）
	if err := f.db.Model(&model.AuditCheckpoint{}).Where("seq = ?", mid.Seq).
		Updates(map[string]any{"anchor_status": model.AnchorStatusEnqueued}).Error; err != nil {
		t.Fatalf("mark enqueued: %v", err)
	}

	rep, err := f.verifier.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !rep.AnchorDisabled {
		t.Fatal("鏈尾未錨定即應判降級，不得因鏈中有一點曾錨定而隱藏橫幅")
	}

	// 反向：鏈尾已錨定 → 不降級
	if err := f.db.Model(&model.AuditCheckpoint{}).Where("seq = ?", rep.LatestSeq).
		Updates(map[string]any{"anchor_status": model.AnchorStatusEnqueued}).Error; err != nil {
		t.Fatalf("mark latest enqueued: %v", err)
	}
	rep, err = f.verifier.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if rep.AnchorDisabled {
		t.Fatal("鏈尾已錨定時不得判降級（橫幅不是常駐裝飾）")
	}
}

// TestCheckpointChainReportTrimmedHeadPasses 修剪後的殘鏈仍通過結構層驗證
//
// 合法修剪與「鏈頭被挖」必須可區分：前者有簽章修剪記錄且錨得上，後者沒有
func TestCheckpointChainReportTrimmedHeadPasses(t *testing.T) {
	f := setupVerifyFixture(t)
	aged := time.Now().Add(-4000 * 24 * time.Hour)
	old := time.Now().Add(-400 * 24 * time.Hour)
	for i := 0; i < 3; i++ {
		f.stampedRows(t, 1, old)
		cp, err := f.seal.SealNow()
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		f.mustExec(t, "UPDATE audit_checkpoints SET sealed_at = ? WHERE seq = ?",
			aged.Add(time.Duration(i)*time.Minute), cp.Seq)
		if _, err := f.purger.PurgeInterval(cp, 365, time.Now().Add(-365*24*time.Hour)); err != nil {
			t.Fatalf("purge: %v", err)
		}
	}
	f.stampedRows(t, 1, time.Now())
	if _, err := f.seal.SealNow(); err != nil {
		t.Fatalf("seal newest: %v", err)
	}
	f.mustExec(t, "UPDATE audit_checkpoints SET sealed_at = ? WHERE seq = 1", aged.Add(-time.Hour))

	// **重簽被改過 sealed_at 的檢查點**：sealed_at 在簽章涵蓋內，直改會使簽章
	// 失效——不重簽的話本測會在驗自己製造的竄改，而非驗修剪後的殘鏈
	f.resignAll(t)

	trimmed, trim, err := f.purger.TrimChain(3650)
	if err != nil {
		t.Fatalf("TrimChain: %v", err)
	}
	if trimmed == 0 || trim == nil {
		t.Fatal("前提破了：未發生修剪")
	}
	rep, err := f.verifier.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if rep.Status != IntervalStatusPassed {
		t.Fatalf("殘鏈狀態 = %s, want passed（失敗點：%+v）", rep.Status, rep.Failures)
	}
	if rep.TrimmedThroughSeq == nil || *rep.TrimmedThroughSeq != trim.LastTrimmedSeq {
		t.Errorf("報告未帶出修剪錨 seq")
	}
}

// mustExec 原生 SQL（模擬 DB 直寫；ORM 守衛不適用於此路徑）
func (f *verifyFixture) mustExec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.db.Exec(sql, args...).Error; err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// resignAll 以現行鑰重算全鏈的鏈接與簽章（測試造資料用）。
//
// 只在「測試以 SQL 直改了進入簽章的欄位」之後使用——生產路徑無任何重簽入口
func (f *verifyFixture) resignAll(t *testing.T) {
	t.Helper()
	var chain []model.AuditCheckpoint
	if err := f.db.Order("seq ASC").Find(&chain).Error; err != nil {
		t.Fatalf("load chain: %v", err)
	}
	for i := range chain {
		cp := chain[i]
		if i > 0 {
			h, err := CheckpointLinkHash(&chain[i-1])
			if err != nil {
				t.Fatalf("link hash: %v", err)
			}
			cp.PrevCheckpointHash = h
		}
		payload, err := CheckpointSignBytes(&cp)
		if err != nil {
			t.Fatalf("payload: %v", err)
		}
		_, sig := f.signer.Sign(payload)
		cp.Signature = sig
		f.mustExec(t, "UPDATE audit_checkpoints SET prev_checkpoint_hash = ?, signature = ? WHERE seq = ?",
			cp.PrevCheckpointHash, cp.Signature, cp.Seq)
		chain[i] = cp
	}
}

// snapshot 兩張表的內容摘要（驗證唯讀性用）
func (f *verifyFixture) snapshot(t *testing.T) string {
	t.Helper()
	var out string
	if err := f.db.Raw(`SELECT COALESCE(group_concat(x), '') FROM (
		SELECT seq || ':' || agg_hash || ':' || signature || ':' || anchor_status ||
		       ':' || COALESCE(purge_signature, '-') AS x FROM audit_checkpoints ORDER BY seq)`).
		Scan(&out).Error; err != nil {
		t.Fatalf("snapshot checkpoints: %v", err)
	}
	var logs string
	if err := f.db.Raw(`SELECT COALESCE(group_concat(x), '') FROM (
		SELECT id || ':' || integrity_hmac AS x FROM audit_logs ORDER BY id)`).
		Scan(&logs).Error; err != nil {
		t.Fatalf("snapshot logs: %v", err)
	}
	return out + "|" + logs
}
