package audit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

const bulkBatchID = "0b6f6c1e-3d2a-4f5b-8c7d-9e0f1a2b3c4d"

// failOnNthTxSink 第 n 次寫入時回錯，其餘交給真實落地面（測試接縫：模擬中途的稽核寫入失敗）
type failOnNthTxSink struct {
	n, calls int
	inner    port.TxSink
}

func (s *failOnNthTxSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	s.calls++
	if s.calls == s.n {
		return errors.New("注入的稽核寫入失敗")
	}
	return s.inner.WriteInTx(tx, ev)
}

// setupBulkReview 批次審閱的 sqlite 環境：告警表、稽核表、真實交易內落地面。
// 單一連線：交易與其後的查詢落在同一個記憶體庫
func setupBulkReview(t *testing.T) (*CommandAlertService, *gorm.DB) {
	t.Helper()
	svc, db := setupAlertDB(t)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate audit_logs: %v", err)
	}
	svc.SetAuditTxSink(NewTxSink())
	return svc, db
}

// seedOwnedAlerts 建 n 筆未審閱告警，觸發者依 owners 循序指定
func seedOwnedAlerts(t *testing.T, db *gorm.DB, owners ...uint) []uint {
	t.Helper()
	ids := make([]uint, 0, len(owners))
	for i, owner := range owners {
		a := &model.CommandAlert{RuleName: "r", SessionID: 1, UserID: owner, Command: "cmd",
			Severity: "high", TriggeredAt: time.Now().Add(time.Duration(i) * time.Second),
			Disposition: model.AlertDispositionPending}
		if err := db.Create(a).Error; err != nil {
			t.Fatalf("seed alert: %v", err)
		}
		ids = append(ids, a.ID)
	}
	return ids
}

func bulkInput(ids []uint, ack int) AlertBatchReviewInput {
	return AlertBatchReviewInput{AlertIDs: ids, Disposition: model.AlertDispositionBenign, Note: "變更單 CHG-1123",
		BatchID: bulkBatchID, SelfTriggeredAck: ack, Reviewer: gatewayapi.Actor{UserID: 8, Username: "auditor-8"},
		Request: gatewayapi.RequestMeta{Method: "POST", Path: "/api/v1/command-alerts/batch-review", ClientIP: "10.1.1.1",
			StatusCode: 200, RequestID: "req-1"}}
}

func countAlertAudit(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	db.Model(&model.AuditLog{}).Where("resource = ? AND resource_id IS NOT NULL", model.ResourceCommandAlert).Count(&n)
	return n
}

func countSummaryAudit(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	db.Model(&model.AuditLog{}).Where("resource = ? AND resource_id IS NULL", model.ResourceCommandAlert).Count(&n)
	return n
}

func lastSummary(t *testing.T, db *gorm.DB) (model.AuditLog, map[string]any) {
	t.Helper()
	var row model.AuditLog
	if err := db.Where("resource = ? AND resource_id IS NULL", model.ResourceCommandAlert).Order("id DESC").First(&row).Error; err != nil {
		t.Fatalf("找不到摘要稽核列: %v", err)
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(row.Details), &d); err != nil {
		t.Fatalf("摘要 details 不是 JSON: %q", row.Details)
	}
	return row, d
}

func countReviewed(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	db.Model(&model.CommandAlert{}).Where("reviewed_at IS NOT NULL").Count(&n)
	return n
}

// tenWithFourSelf 十筆，其中第 2、4、6、8 筆由審閱者（8）觸發
func tenWithFourSelf(t *testing.T, db *gorm.DB) []uint {
	return seedOwnedAlerts(t, db, 1, 8, 2, 8, 3, 8, 4, 8, 5, 6)
}

// TestAlertBulkReviewSelfTriggeredWithAck (a) 確認筆數相符時，含本人觸發的十筆一次寫入。
//
// 擋的威脅：本人觸發的告警經確認後仍被擋下（放寬沒有生效），或寫入了但稽核列沒有標出
// 審閱者即觸發者、沒有同一個關聯碼與筆數，使稽核面查不出「自己審自己」的那幾筆。
func TestAlertBulkReviewSelfTriggeredWithAck(t *testing.T) {
	svc, db := setupBulkReview(t)
	ids := tenWithFourSelf(t, db)

	res, err := svc.ReviewBatch(bulkInput(ids, 4))
	if err != nil {
		t.Fatalf("ReviewBatch: %v", err)
	}
	if res.Summary != (AlertBatchReviewSummary{Reviewed: 10, SelfTriggered: 4}) || res.Limit != AlertBatchReviewLimit ||
		res.BatchID != bulkBatchID || len(res.Items) != 10 {
		t.Fatalf("結果不符: %+v", res)
	}
	selfSet := map[uint]bool{ids[1]: true, ids[3]: true, ids[5]: true, ids[7]: true}
	for i, it := range res.Items {
		if it.ID != ids[i] || it.Result != AlertBatchResultReviewed || it.SelfTriggered != selfSet[it.ID] || it.ReviewedByYou != nil {
			t.Fatalf("第 %d 筆結果不符: %+v", i, it)
		}
	}
	if n := countReviewed(t, db); n != 10 {
		t.Fatalf("已審閱 %d 筆, want 10", n)
	}
	var rows []model.AuditLog
	db.Where("resource = ? AND resource_id IS NOT NULL", model.ResourceCommandAlert).Order("id").Find(&rows)
	if len(rows) != 10 {
		t.Fatalf("處置稽核列 %d, want 10", len(rows))
	}
	selfCount := 0
	for _, r := range rows {
		var d map[string]any
		if err := json.Unmarshal([]byte(r.Details), &d); err != nil {
			t.Fatalf("details 不是 JSON: %q", r.Details)
		}
		if d["batch_id"] != bulkBatchID || d["batch_size"] != float64(10) || d["note"] != "變更單 CHG-1123" ||
			d["disposition"] != "benign" {
			t.Fatalf("details 不符: %v", d)
		}
		want := selfSet[*r.ResourceID]
		if d["self_review"] != want {
			t.Fatalf("告警 %d 的 self_review = %v, want %v", *r.ResourceID, d["self_review"], want)
		}
		if want {
			selfCount++
		}
		if r.Action != model.ActionUpdate || r.ErrorMsg != "alert_disposition_benign" || r.UserID != 8 ||
			r.Username != "auditor-8" || r.ClientIP != "10.1.1.1" || r.RequestID != "req-1" {
			t.Fatalf("稽核列欄位不符: %+v", r)
		}
	}
	if selfCount != 4 {
		t.Fatalf("self_review=true 的列 %d, want 4", selfCount)
	}
	// 摘要列：同交易一列，帶請求筆數、各結果筆數、本人觸發與確認值、請求識別
	sumRow, sum := lastSummary(t, db)
	if countSummaryAudit(t, db) != 1 || sum["event"] != "alert_batch_review" || sum["batch_id"] != bulkBatchID ||
		sum["batch_size"] != float64(10) || sum["reviewed"] != float64(10) || sum["already_reviewed"] != float64(0) ||
		sum["not_found"] != float64(0) || sum["self_triggered"] != float64(4) || sum["self_triggered_ack"] != float64(4) ||
		sum["request_id"] != "req-1" || sumRow.RequestID != "req-1" || sumRow.Action != model.ActionReview {
		t.Fatalf("摘要列不符: %+v %v", sumRow, sum)
	}
}

// TestAlertBulkReviewSelfAckMismatchRejectsAll (b) 確認筆數不符（含沒帶）時整批拒收。
//
// 擋的威脅：直接呼叫端點時不帶確認就把自己的告警混進批次結案；或拒收前已寫入前幾筆。
func TestAlertBulkReviewSelfAckMismatchRejectsAll(t *testing.T) {
	svc, db := setupBulkReview(t)
	ids := tenWithFourSelf(t, db)
	for _, ack := range []int{3, 0, 5, -4} {
		_, err := svc.ReviewBatch(bulkInput(ids, ack))
		var selfAck *AlertBatchSelfAckError
		if !errors.As(err, &selfAck) || selfAck.SelfTriggered != 4 {
			t.Fatalf("確認 %d：應回本人觸發筆數不符（4），得到 %v", ack, err)
		}
		if n := countReviewed(t, db); n != 0 {
			t.Fatalf("確認 %d：整批拒收後仍有 %d 筆被處置", ack, n)
		}
		if n := countAlertAudit(t, db); n != 0 {
			t.Fatalf("確認 %d：整批拒收後仍有 %d 列處置稽核", ack, n)
		}
	}
	// 沒有本人觸發時確認數必須為 0
	others := seedOwnedAlerts(t, db, 1, 2)
	_, err := svc.ReviewBatch(bulkInput(others, 1))
	var selfAck *AlertBatchSelfAckError
	if !errors.As(err, &selfAck) || selfAck.SelfTriggered != 0 {
		t.Fatalf("沒有本人觸發卻確認 1：應拒收並回 0，得到 %v", err)
	}
}

// TestAlertBulkReviewKeepsExistingReview (c) 事前已被他人審閱的一筆被拒、原處置不變，其餘寫入。
func TestAlertBulkReviewKeepsExistingReview(t *testing.T) {
	svc, db := setupBulkReview(t)
	ids := seedOwnedAlerts(t, db, 1, 2, 3)
	if err := svc.Review(ids[1], 7, model.AlertDispositionEscalated, "已通報主管"); err != nil {
		t.Fatal(err)
	}
	var before model.CommandAlert
	db.First(&before, ids[1])

	res, err := svc.ReviewBatch(bulkInput(ids, 0))
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.Reviewed != 2 || res.Summary.AlreadyReviewed != 1 {
		t.Fatalf("summary = %+v", res.Summary)
	}
	it := res.Items[1]
	if it.Result != AlertBatchResultAlreadyReviewed || it.ReviewedByYou == nil || *it.ReviewedByYou ||
		it.ExistingDisposition != model.AlertDispositionEscalated {
		t.Fatalf("他人已審閱的一筆結果 = %+v, want already_reviewed、reviewed_by_you=false、existing_disposition=escalated", it)
	}
	if res.Items[0].ExistingDisposition != "" {
		t.Fatalf("成立的一筆不應帶 existing_disposition: %+v", res.Items[0])
	}
	var after model.CommandAlert
	db.First(&after, ids[1])
	if after.Disposition != model.AlertDispositionEscalated || after.Note != "已通報主管" || *after.ReviewedBy != 7 ||
		!after.ReviewedAt.Equal(*before.ReviewedAt) {
		t.Fatalf("既有處置被覆蓋: %+v", after)
	}
	if n := countAlertAudit(t, db); n != 2 {
		t.Fatalf("處置稽核列 %d, want 2（被拒的不寫）", n)
	}
	if _, sum := lastSummary(t, db); sum["batch_size"] != float64(3) || sum["reviewed"] != float64(2) ||
		sum["already_reviewed"] != float64(1) {
		t.Fatalf("摘要列應說得清差額: %v", sum)
	}
}

// TestAlertBulkReviewResendIsIdempotent (d) 同一批成功後再送：全部回已由你處置，不改審閱時間、不多稽核列。
func TestAlertBulkReviewResendIsIdempotent(t *testing.T) {
	svc, db := setupBulkReview(t)
	ids := tenWithFourSelf(t, db)
	if _, err := svc.ReviewBatch(bulkInput(ids, 4)); err != nil {
		t.Fatal(err)
	}
	var first []model.CommandAlert
	db.Order("id").Find(&first)
	auditBefore := countAlertAudit(t, db)

	in := bulkInput(ids, 4)
	in.Note = "第二次送出的理由"
	in.Disposition = model.AlertDispositionEscalated
	res, err := svc.ReviewBatch(in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.AlreadyReviewed != 10 || res.Summary.Reviewed != 0 {
		t.Fatalf("重送 summary = %+v", res.Summary)
	}
	for _, it := range res.Items {
		if it.Result != AlertBatchResultAlreadyReviewed || it.ReviewedByYou == nil || !*it.ReviewedByYou ||
			it.ExistingDisposition != model.AlertDispositionBenign {
			t.Fatalf("重送結果 = %+v, want already_reviewed、reviewed_by_you=true、existing_disposition=benign", it)
		}
	}
	var second []model.CommandAlert
	db.Order("id").Find(&second)
	for i := range first {
		if !second[i].ReviewedAt.Equal(*first[i].ReviewedAt) || second[i].Note != first[i].Note ||
			second[i].Disposition != first[i].Disposition {
			t.Fatalf("重送改到了既有處置: %+v -> %+v", first[i], second[i])
		}
	}
	if n := countAlertAudit(t, db); n != auditBefore {
		t.Fatalf("重送後處置稽核列 %d, want %d", n, auditBefore)
	}
	if n := countSummaryAudit(t, db); n != 2 {
		t.Fatalf("重送後摘要列 %d, want 2（只多一列摘要）", n)
	}
}

// TestAlertBulkReviewLimit (e) 去重後超過上限整批拒收；重複編號去重後計數。
func TestAlertBulkReviewLimit(t *testing.T) {
	svc, db := setupBulkReview(t)
	over := make([]uint, 0, AlertBatchReviewLimit+1)
	for i := 1; i <= AlertBatchReviewLimit+1; i++ {
		over = append(over, uint(i))
	}
	seedOwnedAlerts(t, db, 1, 2)
	if _, err := svc.ReviewBatch(bulkInput(over, 0)); !errors.Is(err, ErrAlertBatchTooLarge) {
		t.Fatalf("%d 筆應回上限錯誤，得到 %v", len(over), err)
	}
	if countReviewed(t, db) != 0 || countAlertAudit(t, db) != 0 {
		t.Fatal("上限錯誤後不得有任何寫入")
	}
	// 恰為上限（含不存在的編號）通過整批檢查
	if _, err := svc.ReviewBatch(bulkInput(over[:AlertBatchReviewLimit], 0)); err != nil {
		t.Fatalf("恰為上限應通過，得到 %v", err)
	}
	// 去重：上限 +1 個編號但含一個重複 → 去重後恰為上限，通過
	dup := append(append([]uint{}, over[:AlertBatchReviewLimit]...), over[0])
	res, err := svc.ReviewBatch(bulkInput(dup, 0))
	if err != nil {
		t.Fatalf("去重後恰為上限應通過，得到 %v", err)
	}
	if len(res.Items) != AlertBatchReviewLimit {
		t.Fatalf("去重後 items %d, want %d", len(res.Items), AlertBatchReviewLimit)
	}
}

// TestAlertBulkReviewDedupesInOrder 重複編號去重並保留首次出現的順序；batch_size 以去重後計。
func TestAlertBulkReviewDedupesInOrder(t *testing.T) {
	svc, db := setupBulkReview(t)
	ids := seedOwnedAlerts(t, db, 1, 2, 3)
	res, err := svc.ReviewBatch(bulkInput([]uint{ids[2], ids[0], ids[2], ids[1], ids[0]}, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 3 || res.Items[0].ID != ids[2] || res.Items[1].ID != ids[0] || res.Items[2].ID != ids[1] {
		t.Fatalf("items 順序 = %+v", res.Items)
	}
	var r model.AuditLog
	db.Where("resource = ?", model.ResourceCommandAlert).First(&r)
	if !strings.Contains(r.Details, `"batch_size":3`) {
		t.Fatalf("batch_size 應以去重後計: %s", r.Details)
	}
}

// TestAlertBulkReviewBatchLevelValidation (f) 理由只有空白等整批檢查不成立時，一筆都不寫。
func TestAlertBulkReviewBatchLevelValidation(t *testing.T) {
	svc, db := setupBulkReview(t)
	ids := seedOwnedAlerts(t, db, 1, 2)
	cases := map[string]struct {
		mut  func(*AlertBatchReviewInput)
		want error
	}{
		"理由只有空白":     {func(in *AlertBatchReviewInput) { in.Note = " \t\n　" }, ErrAlertBatchNote},
		"理由超過上限":     {func(in *AlertBatchReviewInput) { in.Note = strings.Repeat("字", maxAlertBatchNoteRunes+1) }, ErrAlertBatchNote},
		"處置分類不合法":    {func(in *AlertBatchReviewInput) { in.Disposition = "pending" }, ErrInvalidDisposition},
		"編號為空":       {func(in *AlertBatchReviewInput) { in.AlertIDs = nil }, ErrAlertBatchEmpty},
		"編號含 0":      {func(in *AlertBatchReviewInput) { in.AlertIDs = []uint{ids[0], 0} }, ErrAlertBatchEmpty},
		"關聯碼不是 UUID": {func(in *AlertBatchReviewInput) { in.BatchID = "batch-1" }, ErrAlertBatchID},
		"關聯碼缺少":      {func(in *AlertBatchReviewInput) { in.BatchID = "" }, ErrAlertBatchID},
	}
	for name, tc := range cases {
		in := bulkInput(ids, 0)
		tc.mut(&in)
		if _, err := svc.ReviewBatch(in); !errors.Is(err, tc.want) {
			t.Fatalf("%s：應回 %v，得到 %v", name, tc.want, err)
		}
		if countReviewed(t, db) != 0 || countAlertAudit(t, db) != 0 {
			t.Fatalf("%s：整批拒收後不得有寫入", name)
		}
	}
	// 恰為上限的理由通過
	in := bulkInput(ids, 0)
	in.Note = strings.Repeat("字", maxAlertBatchNoteRunes)
	if _, err := svc.ReviewBatch(in); err != nil {
		t.Fatalf("恰為上限的理由應通過: %v", err)
	}
}

// TestAlertBulkReviewNotFound (g) 不存在的編號回 not_found、不計入本人觸發，不影響其他筆。
func TestAlertBulkReviewNotFound(t *testing.T) {
	svc, db := setupBulkReview(t)
	ids := seedOwnedAlerts(t, db, 8, 2)
	res, err := svc.ReviewBatch(bulkInput([]uint{ids[0], 99999, ids[1]}, 1))
	if err != nil {
		t.Fatalf("不存在的編號不應使整批失敗: %v", err)
	}
	if res.Summary != (AlertBatchReviewSummary{Reviewed: 2, NotFound: 1, SelfTriggered: 1}) {
		t.Fatalf("summary = %+v", res.Summary)
	}
	if it := res.Items[1]; it.ID != 99999 || it.Result != AlertBatchResultNotFound || it.SelfTriggered || it.ReviewedByYou != nil {
		t.Fatalf("不存在的一筆 = %+v", it)
	}
}

// TestAlertBulkReviewAuditFailureRollsBackAll (h) 第 k 筆稽核寫入失敗時整批回滾。
//
// 擋的威脅：處置寫了但稽核沒寫（全操作稽核的缺口），或前幾筆已提交而後面沒有，
// 使「沒有收到回應」時的狀態變成任意組合。
func TestAlertBulkReviewAuditFailureRollsBackAll(t *testing.T) {
	for _, k := range []int{1, 5, 10} {
		svc, db := setupBulkReview(t)
		ids := tenWithFourSelf(t, db)
		svc.SetAuditTxSink(&failOnNthTxSink{n: k, inner: NewTxSink()})
		if _, err := svc.ReviewBatch(bulkInput(ids, 4)); err == nil {
			t.Fatalf("第 %d 筆稽核失敗時應回錯", k)
		}
		if n := countReviewed(t, db); n != 0 {
			t.Fatalf("第 %d 筆稽核失敗：仍有 %d 筆處置", k, n)
		}
		if n := countAlertAudit(t, db); n != 0 {
			t.Fatalf("第 %d 筆稽核失敗：仍有 %d 列處置稽核", k, n)
		}
	}
	// 落地面未注入：同樣整批不生效（不得靜默略過稽核）
	svc, db := setupBulkReview(t)
	ids := seedOwnedAlerts(t, db, 1)
	svc.SetAuditTxSink(nil)
	if _, err := svc.ReviewBatch(bulkInput(ids, 0)); !errors.Is(err, port.ErrTxSinkMissing) {
		t.Fatalf("落地面未注入應回 ErrTxSinkMissing，得到 %v", err)
	}
	if countReviewed(t, db) != 0 {
		t.Fatal("落地面未注入時不得寫入處置")
	}
}

// TestAlertBulkReviewSelfCountIncludesReviewed 本人觸發的計數含已審閱的告警、不含不存在的。
//
// 擋的威脅：計數只算未審閱的，重送同一批（或部分已被處置）時確認數對不上而整批被拒（409），
// 與「重送逐筆回報已由你處置」互相矛盾。
func TestAlertBulkReviewSelfCountIncludesReviewed(t *testing.T) {
	svc, db := setupBulkReview(t)
	ids := seedOwnedAlerts(t, db, 8, 8, 1)
	if err := svc.Review(ids[0], 5, model.AlertDispositionBenign, "他人先審"); err != nil {
		t.Fatal(err)
	}
	res, err := svc.ReviewBatch(bulkInput([]uint{ids[0], ids[1], ids[2], 88888}, 2))
	if err != nil {
		t.Fatalf("已審閱的本人觸發仍應計入（確認 2）: %v", err)
	}
	if res.Summary.SelfTriggered != 2 || res.Summary.AlreadyReviewed != 1 || res.Summary.NotFound != 1 || res.Summary.Reviewed != 2 {
		t.Fatalf("summary = %+v", res.Summary)
	}
	if !res.Items[0].SelfTriggered || res.Items[0].Result != AlertBatchResultAlreadyReviewed {
		t.Fatalf("已審閱的本人觸發 = %+v", res.Items[0])
	}
}

// TestAlertBulkReviewTimeoutRollsBack 交易時限在提交前到期：整批回滾，回「確定沒有生效」的那一類錯誤。
//
// 擋的威脅：交易沒有上限、無限期持有連線與列鎖；或時限到期後仍留下部分寫入。
// 時限在提交前到期時從未送出提交，結果是確定的（回滾），不歸「無法確定」。
func TestAlertBulkReviewTimeoutRollsBack(t *testing.T) {
	svc, db := setupBulkReview(t)
	ids := seedOwnedAlerts(t, db, 1, 2, 3)
	svc.batchTxTimeout = 50 * time.Millisecond
	svc.SetAuditTxSink(slowTxSink{delay: 120 * time.Millisecond, inner: NewTxSink()})
	_, err := svc.ReviewBatch(bulkInput(ids, 0))
	if err == nil || errors.Is(err, ErrAlertBatchOutcomeUnknown) {
		t.Fatalf("提交前逾時應回確定回滾的錯誤，得到 %v", err)
	}
	if n := countReviewed(t, db); n != 0 {
		t.Fatalf("逾時後仍有 %d 筆處置", n)
	}
	if n := countAlertAudit(t, db) + countSummaryAudit(t, db); n != 0 {
		t.Fatalf("逾時後仍有 %d 列稽核", n)
	}
	// 提交前的一般錯誤不是「無法確定」
	svc2, db2 := setupBulkReview(t)
	ids2 := seedOwnedAlerts(t, db2, 1)
	svc2.SetAuditTxSink(&failOnNthTxSink{n: 1, inner: NewTxSink()})
	if _, err := svc2.ReviewBatch(bulkInput(ids2, 0)); err == nil || errors.Is(err, ErrAlertBatchOutcomeUnknown) {
		t.Fatalf("提交前的稽核失敗應為確定回滾，得到 %v", err)
	}
}

// TestAlertBulkReviewTxTimeoutBound 交易逾時上限為 30 秒，且不大於稽核檢查點的預設寬限。
//
// 擋的威脅：上限被調大到超過檢查點寬限，交易內寫入的稽核列在封章掃描後才提交；
// 或上限被拿掉，介面判斷「待確認」的時間界線失去依據。
func TestAlertBulkReviewTxTimeoutBound(t *testing.T) {
	if AlertBatchReviewTxTimeout != 30*time.Second {
		t.Fatalf("交易逾時上限 = %v, want 30s（介面的待確認時間界線依此訂定）", AlertBatchReviewTxTimeout)
	}
	if AlertBatchReviewTxTimeout > checkpointGraceDefault {
		t.Fatalf("交易逾時上限 %v 大於檢查點預設寬限 %v", AlertBatchReviewTxTimeout, checkpointGraceDefault)
	}
	if NewCommandAlertService(nil).batchTxTimeout != 0 {
		t.Fatal("正式組裝的交易逾時應取常數")
	}
}

// slowTxSink 每次寫入前等待（模擬交易內的慢寫入，用來觸發交易逾時）
type slowTxSink struct {
	delay time.Duration
	inner port.TxSink
}

func (s slowTxSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	time.Sleep(s.delay)
	return s.inner.WriteInTx(tx, ev)
}
