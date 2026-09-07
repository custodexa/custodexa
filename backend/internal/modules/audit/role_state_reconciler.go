package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 角色指派對帳（role-assignment-integrity）。
//
// # 它回答的問題
//
// 「最近一個**可信**檢查點之後，`user_roles` 的每一筆變動，是不是都經過應用程式？」
//
// 可信＝封章當下對過帳且相符（`role_state_reconciled = true`），或是尚無不符
// 紀錄前的涵蓋起點；選法與其理由見 `baselineCheckpoint`。
//
// 預期集合 ＝ 該檢查點的快照 ⊕ 其 `id_to` 之後所有 `user_role` 審計列
//（assign 加入、revoke 移除）。與現況不符即為**繞過應用程式的角色變更**——
// 五條合法路徑全部同交易留痕（`model.AssignUserRole`／`RevokeUserRole`），
// 審計寫不進去角色就掛不上，故差集非空只有一種來源：直接寫資料庫。
//
// # 三個刻意
//
//   - **不更動任何角色指派**：偵測不自動回滾。自動回滾會在誤判時把合法的權限
//     拿掉，而本機制防的是「不知情」不是「不發生」。
//   - **尚無可信檢查點時回 not_covered，不判不符**：升級後首個封章之前
//     沒有基準，把「沒有基準」講成「不符」是假警報，而假警報會讓真警報失去意義。
//   - **事件冪等鍵是 (since_seq, actual_hash)**：同一筆未經留痕的變更會在每次
//     登入與每次驗證被比對到，逐次開單會在稽核面堆出一疊描述同一件事的事件，
//     反而蓋掉後來真正發生的第二件事。
//
// # 集合語義使封章當下的競態無害
//
// 只套用 id > `id_to` 的審計列。封章取上界與讀快照之間若有一筆角色變更 commit，
// 它會**同時**出現在快照與待套用的審計列中；但套用是集合語義（assign 加入已在
// 集合內的元素、revoke 移除不在集合內的元素皆為無變化），故重複套用不改變結果。

// 對帳狀態（出站字串，前端與驗證頁按此分支）
const (
	// RoleStateMatch 現況與預期相符
	RoleStateMatch = "match"
	// RoleStateMismatch 差集非空
	RoleStateMismatch = "mismatch"
	// RoleStateNotCovered 尚無含快照的檢查點（升級後首個封章之前）
	RoleStateNotCovered = "not_covered"
)

// RoleStateReport 一次對帳的結果。
//
// Missing／Extra 只帶識別（user_id、role_id），換算成帳號名與角色名是呈現層
// 的事——快照與事件一律不含個資
type RoleStateReport struct {
	// Covered 是否已有含快照的檢查點可作為基準
	Covered bool `json:"covered"`
	// State 見 RoleState* 常數
	State string `json:"state"`
	// SinceSeq 作為基準的檢查點序號（Covered 為 false 時為 0）
	SinceSeq uint `json:"since_seq,omitempty"`
	// ExpectedHash／ActualHash 預期與現況的快照雜湊（長度前綴 SHA-256）
	ExpectedHash string `json:"expected_hash,omitempty"`
	ActualHash   string `json:"actual_hash,omitempty"`
	// Missing 預期有而現況無；Extra 現況有而預期無
	Missing []RolePair `json:"missing,omitempty"`
	Extra   []RolePair `json:"extra,omitempty"`
}

// Matched 現況與預期相符（未涵蓋時為 false——未知不是相符）
func (r *RoleStateReport) Matched() bool { return r != nil && r.State == RoleStateMatch }

// 失效事件出口＝`AuditFailureAlerter`（chain_verify_service.go，實作為
// `*AuditFailureService`）。以介面收下而非直接吃型別：對帳器在測試裡要能斷言
// 「開了幾筆、什麼參數」。
//
// **刻意共用鏈驗證編排者的那一個宣告，不另立一份同形窄介面**：
// `Resolve` 與認證脈絡的 `Resolve` 同名，每多一個宣告位置就要在
// `TestAuthContextTouchpointsGuard` 的同名例外表多佔一個名額，而那張表的
// 條數上限正是「新增例外必須被質問」的付費閘。兩個消費者要的是同一個出口

// RoleStateReconciler 角色指派對帳器。三個比對時機（封章前、驗證、
// 特權登入）共用同一個實例，冪等鍵因此是跨時機的
type RoleStateReconciler struct {
	db      *gorm.DB
	failure AuditFailureAlerter

	// mu 保護冪等鍵；對帳頻率低（每次封章、每次驗證、每次特權登入），粗鎖足矣
	mu sync.Mutex
	// lastKey 最近一次已開單的 (since_seq, actual_hash)。空＝目前無未結案的不符
	lastKey string
}

// NewRoleStateReconciler 建立對帳器。failure 為 nil 時只回報不開事件
//（工具與測試路徑；產品組裝根必注入）
func NewRoleStateReconciler(db *gorm.DB, failure AuditFailureAlerter) *RoleStateReconciler {
	return &RoleStateReconciler{db: db, failure: failure}
}

// Reconcile 執行一次對帳並在不符時開立失效事件。
//
// 回傳的 error 只表示**對帳本身沒做成**（讀不到檢查點、快照解不開）——
// 那是「未知」而非「無異常」，呼叫端不得把它當成相符。
func (r *RoleStateReconciler) Reconcile(ctx context.Context) (*RoleStateReport, error) {
	report, err := r.compute(ctx)
	if err != nil {
		return nil, err
	}
	r.settle(report)
	return report, nil
}

// compute 純計算：不開事件、不寫任何東西
func (r *RoleStateReconciler) compute(ctx context.Context) (*RoleStateReport, error) {
	base, err := r.baselineCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	if base == nil {
		return &RoleStateReport{Covered: false, State: RoleStateNotCovered}, nil
	}
	tables, err := DecodeStateSnapshotColumn(*base.RoleStateSnapshot)
	if err != nil {
		return nil, err
	}
	body, ok := tables[StateTableUserRoles]
	if !ok {
		return nil, fmt.Errorf("檢查點 seq=%d 的快照欄缺 %s：基準不可用",
			base.Seq, StateTableUserRoles)
	}
	baseline, err := DecodeRolePairs(body)
	if err != nil {
		return nil, err
	}
	events, err := r.roleEventsAfter(ctx, base.IDTo)
	if err != nil {
		return nil, err
	}
	expected := applyRoleEvents(baseline, events)
	expectedBody, _ := EncodeRolePairs(expected)

	actualSnap, err := SnapshotUserRoles(ctx, r.db)
	if err != nil {
		return nil, err
	}
	actual, err := DecodeRolePairs(actualSnap.Body)
	if err != nil {
		return nil, err
	}
	missing, extra := DiffRolePairs(expected, actual)
	report := &RoleStateReport{
		Covered:      true,
		State:        RoleStateMatch,
		SinceSeq:     base.Seq,
		ExpectedHash: stateHash(expectedBody),
		ActualHash:   actualSnap.Hash,
		Missing:      missing,
		Extra:        extra,
	}
	if len(missing) > 0 || len(extra) > 0 {
		report.State = RoleStateMismatch
	}
	return report, nil
}

// settle 依對帳結果開立或結案失效事件（冪等鍵 = since_seq + actual_hash）
func (r *RoleStateReconciler) settle(report *RoleStateReport) {
	if r.failure == nil || !report.Covered {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if report.State == RoleStateMatch {
		if r.lastKey != "" {
			r.lastKey = ""
		}
		r.failure.Resolve(model.MechanismRoleStateIntegrity)
		return
	}
	key := strconv.FormatUint(uint64(report.SinceSeq), 10) + ":" + report.ActualHash
	if key == r.lastKey {
		return // 同一筆不符已開過單
	}
	r.lastKey = key
	// counts 傳 nil＝`Report` 的原語義（`Report` 本身即 `ReportWithCounts(…, nil)`）：
	// 角色指派的不符沒有受控整數計數可出站，差集只進事件詳情
	r.failure.ReportWithCounts(model.MechanismRoleStateIntegrity, model.CauseRoleStateMismatch,
		map[string]string{
			"since_seq":   strconv.FormatUint(uint64(report.SinceSeq), 10),
			"actual_hash": report.ActualHash,
			"missing":     formatRolePairs(report.Missing),
			"extra":       formatRolePairs(report.Extra),
		}, nil)
}

// baselineCheckpoint 選出對帳的基準檢查點；無可用基準時回 (nil, nil)。
//
// # 為什麼不能只取「最近一個含快照的檢查點」
//
// 快照記的是**封存當下的現況**，不是應然狀態。直寫提權之後攻擊者什麼都不必再做，
// 只要等下一次自動封章——那次封章會把含提權的現況寫進快照。若基準只看「有沒有
// 快照」，下一次對帳就拿這張含提權的快照當預期集合，驗證頁回「相符」，而那筆
// 從未經過應用程式的指派仍在表裡。封章當下的對帳結果正是用來分辨這件事的。
//
// # 取捨順序
//
//  1. 最近一個 `role_state_reconciled = true` 的含快照檢查點。封章當下對過帳且
//     相符，才是可信的起點。
//  2. 無此點時退到**涵蓋起點**：`reconciled IS NULL`（該次封章沒有做出判讀——
//     升級後的第一個含快照檢查點、還原後的新起點，或對帳當時沒做成）的檢查點，
//     且必須排在任何一個已知不符（false）的檢查點**之前**。已知不符之後的
//     「不知道」不是「通過」，拿它當基準與拿 false 當基準是同一件事。
//  3. 兩者皆無（升級後首個含快照的封章之前）＝ 無基準，由呼叫端判 not_covered。
//
// **只取載荷版本涵蓋狀態摘要的檢查點（agg_scheme v2）**：v1 檢查點的簽章不涵蓋
// 快照欄，能寫資料庫的人可以事後把快照欄與 reconciled=true 補到舊檢查點上，鏈驗證照過、
// 對帳卻拿它當基準——基準的可信度必須由簽章背書，而不是由欄位存在與否背書。
//
// 已知不符的檢查點永遠不作基準：基準因此停在最後一個可信點，不符會一路持續到
// 有人把它處理掉為止——處理掉之後的下一次封章會記 true，基準自動前進
func (r *RoleStateReconciler) baselineCheckpoint(ctx context.Context) (*model.AuditCheckpoint, error) {
	db := r.db.WithContext(ctx)

	var reconciled model.AuditCheckpoint
	switch err := db.Where("agg_scheme = ? AND role_state_snapshot IS NOT NULL AND role_state_reconciled = ?", model.AggSchemeV2, true).
		Order("seq DESC").First(&reconciled).Error; {
	case err == nil:
		return &reconciled, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		// 落到涵蓋起點
	default:
		return nil, fmt.Errorf("讀取最近一個對帳相符的檢查點失敗: %w", err)
	}

	// 第一個已知不符的檢查點；其後的一切都不可信
	var firstTainted model.AuditCheckpoint
	taintedSeq := uint(0)
	switch err := db.Where("agg_scheme = ? AND role_state_snapshot IS NOT NULL AND role_state_reconciled = ?", model.AggSchemeV2, false).
		Order("seq ASC").First(&firstTainted).Error; {
	case err == nil:
		taintedSeq = firstTainted.Seq
	case errors.Is(err, gorm.ErrRecordNotFound):
	default:
		return nil, fmt.Errorf("讀取最早一個對帳不符的檢查點失敗: %w", err)
	}

	q := db.Where("agg_scheme = ? AND role_state_snapshot IS NOT NULL AND role_state_reconciled IS NULL", model.AggSchemeV2)
	if taintedSeq > 0 {
		q = q.Where("seq < ?", taintedSeq)
	}
	var anchor model.AuditCheckpoint
	switch err := q.Order("seq DESC").First(&anchor).Error; {
	case err == nil:
		return &anchor, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	default:
		return nil, fmt.Errorf("讀取含快照的涵蓋起點失敗: %w", err)
	}
}

// roleEventsAfter 讀 id > idTo 的 `user_role` 審計列（含軟刪，與封章掃描同口徑）。
//
// **含軟刪**：軟刪一筆審計列不該讓對帳把一個合法變更當成竄改——那會讓
// 「刪審計列」成為製造假警報的手段，而假警報淹沒真警報
func (r *RoleStateReconciler) roleEventsAfter(ctx context.Context, idTo uint) ([]model.AuditLog, error) {
	var rows []model.AuditLog
	if err := r.db.WithContext(ctx).Unscoped().
		Where("resource = ? AND id > ?", model.ResourceUserRole, idTo).
		Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取角色指派審計列失敗: %w", err)
	}
	return rows, nil
}

// applyRoleEvents 把審計列依序套用到基準集合上。
//
// details 解不開或動作不在 {assign, revoke} 內的列**跳過並記 log**：
// 那是一筆壞掉的證據，而不是一個狀態變更；把它當成變更去猜語義，
// 猜錯的方向是靜默地讓真的竄改看起來合法
func applyRoleEvents(baseline []RolePair, rows []model.AuditLog) []RolePair {
	set := make(map[RolePair]bool, len(baseline))
	for _, p := range baseline {
		set[p] = true
	}
	for i := range rows {
		var d model.UserRoleAuditDetails
		if err := json.Unmarshal([]byte(rows[i].Details), &d); err != nil {
			log.Printf("[RoleState] 審計列 id=%d 的詳情解析失敗，本列不套用: %v", rows[i].ID, err)
			continue
		}
		pair := RolePair{UserID: uint64(d.UserID), RoleID: uint64(d.RoleID)}
		switch rows[i].Action {
		case model.ActionAssign:
			set[pair] = true
		case model.ActionRevoke:
			delete(set, pair)
		default:
			log.Printf("[RoleState] 審計列 id=%d 的動作 %q 不在角色指派的動作值域內，本列不套用",
				rows[i].ID, rows[i].Action)
		}
	}
	out := make([]RolePair, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sortRolePairs(out)
	return out
}

// formatRolePairs 差集的緊湊表述（落 cause_params，不出站）
func formatRolePairs(pairs []RolePair) string {
	if len(pairs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, strconv.FormatUint(p.UserID, 10)+"/"+strconv.FormatUint(p.RoleID, 10))
	}
	return strings.Join(parts, ",")
}

// ReconcileOnPrivilegedLogin 特權帳號（admin／auditor）通過身分驗證（密碼、目錄或外部身分）、即將簽發
// 權杖時的比對。
//
// **不阻斷、不改權杖、無回傳值**：型別本身就說死這件事——登入被擋掉的代價是
// 管理者進不來，而進不來的管理者無法處理正在發生的提權。比對的產物是事件與
// 通知，不是拒絕。對帳做不成只記日誌：登入路徑不因一個旁支判讀而失敗
func (r *RoleStateReconciler) ReconcileOnPrivilegedLogin(ctx context.Context) {
	if _, err := r.Reconcile(ctx); err != nil {
		log.Printf("[RoleState] 特權登入時對帳未能完成（登入不受影響）: %v", err)
	}
}
