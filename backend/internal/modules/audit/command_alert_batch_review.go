package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AlertBatchReviewLimit 批次審閱端點一次請求可處置的告警筆數上限（去重後計）。
//
// 這是單次交易的大小，不是可處置筆數的限制：超過時請呼叫端分次送出。
// 每筆在同一交易內是一句條件更新與一列稽核，上限讓交易時間與列鎖的持有時間有界
const AlertBatchReviewLimit = 500

// AlertBatchReviewTxTimeout 批次審閱交易的逾時上限。
//
// 交易不綁請求的 context（用戶端斷線不中止處理），改由這個上限保證不無限期持有連線與列鎖；
// 逾時即回滾、整批不生效。介面據此判斷：送出後未滿這個時長、查回仍未審閱的告警只能說「待確認」。
//
// 與稽核檢查點的相依：檢查點封章先取編號上界、等待寬限後才掃描，交易內寫入的稽核列必須在寬限內
// 提交，否則該區間會出現封章後才提交的列。本上限不大於檢查點的預設寬限（測試斷言）；
// 部署方把寬限調得比本上限更短時，這個保證不成立
const AlertBatchReviewTxTimeout = 30 * time.Second

// 批次審閱的逐筆結果值（回應的 items[].result）
const (
	AlertBatchResultReviewed        = "reviewed"
	AlertBatchResultAlreadyReviewed = "already_reviewed"
	AlertBatchResultNotFound        = "not_found"
)

// alertBatchSummaryEvent 批次摘要稽核列的 details.event
const alertBatchSummaryEvent = "alert_batch_review"

var (
	// ErrAlertBatchEmpty 批次的告警編號為空或含不合法的編號（0）
	ErrAlertBatchEmpty = errors.New("批次審閱的告警編號不合法")
	// ErrAlertBatchTooLarge 批次的告警筆數（去重後）超過 AlertBatchReviewLimit
	ErrAlertBatchTooLarge = errors.New("批次審閱的告警筆數超過上限")
	// ErrAlertBatchID 批次關聯碼缺少或不是 UUID 格式
	ErrAlertBatchID = errors.New("批次關聯碼不合法")
	// ErrAlertBatchOutcomeUnknown 無法確定交易是否已提交（交易本體已完成、錯誤發生在提交階段）。
	// 與其他交易錯誤不同：其他錯誤（含時限在提交前到期）發生在提交之前，交易確定已回滾、整批沒有生效
	ErrAlertBatchOutcomeUnknown = errors.New("無法確定批次審閱是否已生效")
)

// AlertBatchSelfAckError 請求明示的本人觸發筆數與伺服端計得的筆數不符。
// SelfTriggered 是伺服端依告警的觸發者計得的筆數，回給呼叫端重新確認
type AlertBatchSelfAckError struct {
	SelfTriggered int
}

func (e *AlertBatchSelfAckError) Error() string {
	return fmt.Sprintf("本人觸發的告警筆數與確認筆數不符（伺服端計得 %d 筆）", e.SelfTriggered)
}

// AlertBatchReviewInput 批次審閱一次請求的內容與審閱者。
type AlertBatchReviewInput struct {
	AlertIDs    []uint
	Disposition string
	Note        string
	BatchID     string
	// SelfTriggeredAck 請求明示已確認看過的本人觸發筆數；沒帶視為 0
	SelfTriggeredAck int
	Reviewer         gatewayapi.Actor
	// Request 這次請求的識別與來源，逐筆稽核列與摘要列照抄。
	// 請求識別由伺服端產生，是「同一次請求」的依據；批次關聯碼是用戶端宣告
	Request gatewayapi.RequestMeta
}

// AlertBatchReviewItem 批次中一筆告警的結果。
// ReviewedByYou、ExistingDisposition 只在 already_reviewed 出現：既有的審閱結果是否由這次的
// 審閱者處置、既有的處置分類（不回既有處置者的名稱）
type AlertBatchReviewItem struct {
	ID                  uint   `json:"id"`
	Result              string `json:"result"`
	SelfTriggered       bool   `json:"self_triggered"`
	ReviewedByYou       *bool  `json:"reviewed_by_you,omitempty"`
	ExistingDisposition string `json:"existing_disposition,omitempty"`
}

// AlertBatchReviewSummary 各結果的筆數；SelfTriggered 是請求中本人觸發的筆數（伺服端計得）
type AlertBatchReviewSummary struct {
	Reviewed        int `json:"reviewed"`
	AlreadyReviewed int `json:"already_reviewed"`
	NotFound        int `json:"not_found"`
	SelfTriggered   int `json:"self_triggered"`
}

// AlertBatchReviewResult 批次審閱的回應本文。Items 依請求去重後的順序
type AlertBatchReviewResult struct {
	BatchID string                  `json:"batch_id"`
	Limit   int                     `json:"limit"`
	Summary AlertBatchReviewSummary `json:"summary"`
	Items   []AlertBatchReviewItem  `json:"items"`
}

// alertBatchAuditDetails 逐筆處置稽核列的 details。BatchSize 是這次請求去重後的筆數
// （同一關聯碼的處置列數可以少於它，差額是被拒的筆，見摘要列）
type alertBatchAuditDetails struct {
	BatchID     string `json:"batch_id"`
	BatchSize   int    `json:"batch_size"`
	Note        string `json:"note"`
	Disposition string `json:"disposition"`
	SelfReview  bool   `json:"self_review"`
}

// alertBatchSummaryDetails 一次批次請求的摘要稽核列：單看稽核紀錄就說得清這次做了什麼
type alertBatchSummaryDetails struct {
	Event            string `json:"event"`
	BatchID          string `json:"batch_id"`
	BatchSize        int    `json:"batch_size"`
	Reviewed         int    `json:"reviewed"`
	AlreadyReviewed  int    `json:"already_reviewed"`
	NotFound         int    `json:"not_found"`
	SelfTriggered    int    `json:"self_triggered"`
	SelfTriggeredAck int    `json:"self_triggered_ack"`
	Disposition      string `json:"disposition"`
	Note             string `json:"note"`
	RequestID        string `json:"request_id"`
}

// lockedAlert 交易內鎖住的一筆告警的現況
type lockedAlert struct {
	ID          uint
	UserID      uint
	ReviewedBy  *uint
	Disposition string
}

// SetAuditTxSink 注入交易內稽核落地面（組裝根）。批次審閱的逐筆稽核與處置同交易寫入
func (s *CommandAlertService) SetAuditTxSink(sink port.TxSink) {
	s.auditTx = sink
}

// dedupeAlertIDs 依首次出現的順序去重；含 0 時回 false
func dedupeAlertIDs(ids []uint) ([]uint, bool) {
	seen := make(map[uint]bool, len(ids))
	out := make([]uint, 0, len(ids))
	for _, id := range ids {
		if id == 0 {
			return nil, false
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out, true
}

// validateAlertBatch 整批檢查：任何一項不成立即整批拒收，在任何寫入之前判定
func validateAlertBatch(in *AlertBatchReviewInput) ([]uint, error) {
	if _, err := uuid.Parse(in.BatchID); err != nil || len(in.BatchID) != 36 {
		return nil, ErrAlertBatchID
	}
	ids, ok := dedupeAlertIDs(in.AlertIDs)
	if !ok || len(ids) == 0 {
		return nil, ErrAlertBatchEmpty
	}
	if len(ids) > AlertBatchReviewLimit {
		return nil, ErrAlertBatchTooLarge
	}
	if in.Disposition != model.AlertDispositionBenign && in.Disposition != model.AlertDispositionEscalated {
		return nil, ErrInvalidDisposition
	}
	if strings.TrimSpace(in.Note) == "" || utf8.RuneCountInString(in.Note) > maxAlertBatchNoteRunes {
		return nil, ErrAlertBatchNote
	}
	return ids, nil
}

// ReviewBatch 以一次請求審閱多筆告警（批次審閱端點）。
//
// 與逐筆送出的 ReviewInBatch 不同，本方法可以處置審閱者本人觸發的告警，條件是請求
// 明示的本人觸發筆數（SelfTriggeredAck）等於伺服端依觸發者計得的筆數；不符時整批拒收。
// 計數範圍是請求中存在的告警，不論是否已審閱（重送同一批時計得的數與第一次相同）；不存在的不計。
//
// 判定與寫入的範圍（全部在一個交易內）：
//   - 整批檢查（批次關聯碼、去重後 1..上限、處置分類、理由必填）在交易前；
//   - 以告警編號遞增的固定順序鎖住請求中存在的告警（不論請求順序），兩個重疊的批次不會互相等待成環；
//   - 核對本人觸發筆數；
//   - 依同一順序逐筆以 `reviewed_at IS NULL` 條件更新；更新不到的回 already_reviewed（附既有處置分類），
//     不存在的回 not_found，都不寫入；
//   - 全部更新做完後才集中寫稽核列（成立者每筆一列，加一列這次請求的摘要），
//     「寫了稽核列之後才回滾」只剩稽核寫入本身失敗一種成因；
//   - 任何資料庫或稽核寫入錯誤都讓整批回滾。
//
// 交易不綁請求的 context，另以 AlertBatchReviewTxTimeout 為上限。提交階段出錯回
// ErrAlertBatchOutcomeUnknown（無法確定是否已提交）；其餘錯誤（含時限在提交前到期）發生在提交前，
// 交易確定已回滾。
//
// 重送同一批時每一筆都回 already_reviewed（reviewed_by_you=true），既有處置與審閱時間不變。
func (s *CommandAlertService) ReviewBatch(in AlertBatchReviewInput) (*AlertBatchReviewResult, error) {
	ids, err := validateAlertBatch(&in)
	if err != nil {
		return nil, err
	}
	timeout := s.batchTxTimeout
	if timeout <= 0 {
		timeout = AlertBatchReviewTxTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var out *AlertBatchReviewResult
	bodyDone := false
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res, err := s.reviewBatchInTx(tx, &in, ids)
		if err != nil {
			return err
		}
		out = res
		bodyDone = true
		return nil
	})
	if err != nil {
		// 交易本體已完成、錯誤來自提交（含時限在提交中到期）：無法確定結果。
		// 本體未完成就出錯（含時限在提交前到期）：從未送出提交，交易確定已回滾
		if bodyDone {
			return nil, fmt.Errorf("%w: %v", ErrAlertBatchOutcomeUnknown, err)
		}
		return nil, err
	}
	return out, nil
}

// reviewBatchInTx 交易本體：鎖定、核對、逐筆更新，最後集中寫稽核
func (s *CommandAlertService) reviewBatchInTx(tx *gorm.DB, in *AlertBatchReviewInput, ids []uint) (*AlertBatchReviewResult, error) {
	reviewerID := in.Reviewer.UserID
	var locked []lockedAlert
	// 以表名而非型別標記指定告警表：本檔只做條件更新與讀取，不構造告警列（告警列只由告警落地面產生）
	if err := tx.Table("command_alerts").Select("id", "user_id", "reviewed_by", "disposition").
		Where("id IN ?", ids).Order("id ASC").
		Clauses(clause.Locking{Strength: "UPDATE"}).Scan(&locked).Error; err != nil {
		return nil, fmt.Errorf("鎖定告警失敗: %w", err)
	}
	byID := make(map[uint]lockedAlert, len(locked))
	selfCount := 0
	for _, a := range locked {
		byID[a.ID] = a
		if a.UserID == reviewerID {
			selfCount++
		}
	}
	if in.SelfTriggeredAck != selfCount {
		return nil, &AlertBatchSelfAckError{SelfTriggered: selfCount}
	}

	// 依編號遞增逐筆條件更新（與取鎖同一順序）
	sorted := append([]uint(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	now := time.Now()
	items := make(map[uint]AlertBatchReviewItem, len(ids))
	var reviewedIDs []uint
	for _, id := range sorted {
		cur, exists := byID[id]
		if !exists {
			items[id] = AlertBatchReviewItem{ID: id, Result: AlertBatchResultNotFound}
			continue
		}
		self := cur.UserID == reviewerID
		res := tx.Table("command_alerts").
			Where("id = ? AND reviewed_at IS NULL", id).
			Updates(map[string]interface{}{
				"reviewed_by": reviewerID,
				"reviewed_at": now,
				"disposition": in.Disposition,
				"note":        in.Note,
			})
		if res.Error != nil {
			return nil, fmt.Errorf("審閱告警失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			byYou := cur.ReviewedBy != nil && *cur.ReviewedBy == reviewerID
			items[id] = AlertBatchReviewItem{ID: id, Result: AlertBatchResultAlreadyReviewed, SelfTriggered: self,
				ReviewedByYou: &byYou, ExistingDisposition: cur.Disposition}
			continue
		}
		items[id] = AlertBatchReviewItem{ID: id, Result: AlertBatchResultReviewed, SelfTriggered: self}
		reviewedIDs = append(reviewedIDs, id)
	}

	out := &AlertBatchReviewResult{BatchID: in.BatchID, Limit: AlertBatchReviewLimit,
		Items: make([]AlertBatchReviewItem, 0, len(ids))}
	out.Summary.SelfTriggered = selfCount
	for _, id := range ids {
		it := items[id]
		switch it.Result {
		case AlertBatchResultReviewed:
			out.Summary.Reviewed++
		case AlertBatchResultAlreadyReviewed:
			out.Summary.AlreadyReviewed++
		default:
			out.Summary.NotFound++
		}
		out.Items = append(out.Items, it)
	}

	for _, id := range reviewedIDs {
		if err := s.writeBatchDispositionAudit(tx, in, id, items[id].SelfTriggered, len(ids)); err != nil {
			return nil, err
		}
	}
	if err := s.writeBatchSummaryAudit(tx, in, out, len(ids)); err != nil {
		return nil, err
	}
	return out, nil
}

// writeBatchDispositionAudit 一筆成立處置的稽核列（與單筆審閱同一口徑：update＋alert_disposition_*）
func (s *CommandAlertService) writeBatchDispositionAudit(tx *gorm.DB, in *AlertBatchReviewInput, id uint, self bool, batchSize int) error {
	raw, err := json.Marshal(alertBatchAuditDetails{BatchID: in.BatchID, BatchSize: batchSize,
		Note: in.Note, Disposition: in.Disposition, SelfReview: self})
	if err != nil {
		return fmt.Errorf("編碼批次審閱稽核詳情失敗: %w", err)
	}
	alertID := id
	if err := port.WriteInTx(s.auditTx, tx, port.AuditEvent{
		Actor:      in.Reviewer,
		Action:     string(model.ActionUpdate),
		Resource:   string(model.ResourceCommandAlert),
		ResourceID: &alertID,
		Status:     string(model.StatusSuccess),
		Request:    in.Request,
		ErrorMsg:   "alert_disposition_" + in.Disposition,
		Details:    string(raw),
	}); err != nil {
		return fmt.Errorf("批次審閱稽核留痕失敗: %w", err)
	}
	return nil
}

// writeBatchSummaryAudit 這次請求的摘要稽核列（不指向單一告警）：請求筆數與各結果筆數、
// 本人觸發筆數與確認值。被拒的筆沒有逐筆列，靠這一列說得清差額
func (s *CommandAlertService) writeBatchSummaryAudit(tx *gorm.DB, in *AlertBatchReviewInput, out *AlertBatchReviewResult, batchSize int) error {
	raw, err := json.Marshal(alertBatchSummaryDetails{Event: alertBatchSummaryEvent, BatchID: in.BatchID,
		BatchSize: batchSize, Reviewed: out.Summary.Reviewed, AlreadyReviewed: out.Summary.AlreadyReviewed,
		NotFound: out.Summary.NotFound, SelfTriggered: out.Summary.SelfTriggered,
		SelfTriggeredAck: in.SelfTriggeredAck, Disposition: in.Disposition, Note: in.Note,
		RequestID: in.Request.RequestID})
	if err != nil {
		return fmt.Errorf("編碼批次審閱摘要失敗: %w", err)
	}
	if err := port.WriteInTx(s.auditTx, tx, port.AuditEvent{
		Actor:    in.Reviewer,
		Action:   string(model.ActionReview),
		Resource: string(model.ResourceCommandAlert),
		Status:   string(model.StatusSuccess),
		Request:  in.Request,
		Details:  string(raw),
	}); err != nil {
		return fmt.Errorf("批次審閱摘要稽核留痕失敗: %w", err)
	}
	return nil
}
