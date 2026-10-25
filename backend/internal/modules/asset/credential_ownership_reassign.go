package asset

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// 共用憑證改歸（單筆經 PUT /credentials/:id 的 ownership，批次經 POST /credentials/ownership）。
//
// 能力為 credential:update：變更前與變更後的歸屬都要在操作者含該能力之指派的範圍內，涉及全域
// 限不限範圍的主體；專用憑證的歸屬恆隨資產，不可改歸。批次逐筆判定、整批原子：任一筆不可操作
// （無權、範圍外、不存在或為專用）即整批拒絕，只回筆數。每筆實際改變寫一列憑證 update 審計
// （fields=["ownership"]，details 帶前後歸屬）；權限版本由交易擁有者在全部寫入後、有任一筆
// 改變時推進一次。交易第一個動作取拓撲序列化鎖，其後 Begin，再依識別升冪取憑證列鎖。

// ReassignCredentialOwnershipRequest 批次改歸。
type ReassignCredentialOwnershipRequest struct {
	CredentialIDs []uint                    `json:"credential_ids"`
	Ownership     *CredentialOwnershipInput `json:"ownership"`
}

// ReassignCredentialOwnershipResult 實際改變歸屬的筆數（歸屬原本即為目的者不計）。
type ReassignCredentialOwnershipResult struct {
	Changed int `json:"changed"`
}

// CredentialBatchUnavailableError 整批中有 Count 筆不可操作；不帶識別與原因。
type CredentialBatchUnavailableError struct {
	Count int
}

// Error 固定字串，不含識別或名稱。
func (e *CredentialBatchUnavailableError) Error() string {
	return "asset: credential batch items unavailable"
}

// ErrCredentialReassignEmpty 批次改歸未帶任何憑證識別。
var ErrCredentialReassignEmpty = errors.New("改歸至少需要一筆憑證")

// ReassignOwnership 批次改歸。
func (s *CredentialService) ReassignOwnership(ctx context.Context,
	req *ReassignCredentialOwnershipRequest) (*ReassignCredentialOwnershipResult, error) {

	if req == nil {
		return nil, ErrCredentialReassignEmpty
	}
	ids := uniqueSortedIDs(req.CredentialIDs)
	if len(ids) == 0 {
		return nil, ErrCredentialReassignEmpty
	}
	if req.Ownership == nil {
		return nil, ErrCredentialOwnershipInvalid
	}
	if err := ValidateCredentialOwnershipInput(req.Ownership); err != nil {
		return nil, err
	}
	target := *req.Ownership

	userID, operator := model.UserFromContext(ctx)
	changed := 0
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := s.beginOwnershipTx(tx); err != nil {
			return err
		}
		creds, missing, err := lockReassignRowsTx(tx, ids)
		if err != nil {
			return err
		}
		n, err := s.reassignOwnershipTx(ctx, tx, userID, operator, creds, missing, target, true)
		if err != nil {
			return err
		}
		changed = n
		if n == 0 {
			return nil
		}
		return s.advanceOwnershipVersionTx(tx)
	})
	if err != nil {
		return nil, err
	}
	return &ReassignCredentialOwnershipResult{Changed: changed}, nil
}

// lockReassignRowsTx 依識別升冪逐筆取憑證列鎖；不存在或已刪者計入 missing（不中斷，整批再一起拒絕）。
func lockReassignRowsTx(tx *gorm.DB, ids []uint) ([]*model.Credential, int, error) {
	out := make([]*model.Credential, 0, len(ids))
	missing := 0
	for _, id := range ids {
		cred, err := lockCredentialRow(tx, id)
		if errors.Is(err, ErrCredentialNotFound) {
			missing++
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		out = append(out, cred)
	}
	return out, missing, nil
}

// reassignOwnershipTx 在呼叫端交易（已取拓撲序列化鎖並 Begin、憑證列已鎖）內判定並寫入改歸。
//
// missing 為呼叫端已知不存在的筆數。不推進權限版本、不呼叫 Begin／Settle：回傳實際改變的筆數，
// 由交易擁有者決定是否推進。單筆路徑（batch=false）的不可操作回 ErrCredentialNotFound（範圍外與
// 不存在同形）或 ErrCredentialOwnershipInvalid（專用）；批次回 *CredentialBatchUnavailableError。
func (s *CredentialService) reassignOwnershipTx(ctx context.Context, tx *gorm.DB, userID uint, operator string,
	creds []*model.Credential, missing int, target CredentialOwnershipInput, batch bool) (int, error) {

	if s.ownership == nil {
		return 0, ErrCredentialOwnershipScopeUnwired
	}
	shared := make([]*model.Credential, 0, len(creds))
	current := make([]CredentialOwnership, 0, len(creds))
	dedicated := 0
	gated := 0
	for _, c := range creds {
		if c.Scope != model.CredentialScopeShared {
			dedicated++
			continue
		}
		// 逐筆關卡：單筆與批次同一個函式，口徑只有一處
		if gerr := s.requireOwnershipChangeGate(ctx, tx, c); gerr != nil {
			if batch && isOwnershipGateRefusal(gerr) {
				gated++
				continue
			}
			return 0, gerr
		}
		shared = append(shared, c)
		current = append(current, currentOwnership(c))
	}
	allowed, err := s.ownership.AuthorizeOwnershipChange(ctx, tx, userID, CredCapUpdate, target, current)
	if err != nil {
		return 0, err
	}
	if len(allowed) != len(current) {
		return 0, fmt.Errorf("asset: ownership change decision length %d, want %d", len(allowed), len(current))
	}
	to := CredentialOwnership{Kind: target.Kind}
	if target.Kind == model.CredentialOwnerNode {
		id := *target.NodeID
		to.NodeID = &id
		if err := validateNodeIDsTx(tx, []uint{id}); err != nil {
			return 0, err
		}
	}
	denied := 0
	for _, ok := range allowed {
		if !ok {
			denied++
		}
	}
	if unavailable := missing + dedicated + gated + denied; unavailable > 0 {
		switch {
		case batch:
			return 0, &CredentialBatchUnavailableError{Count: unavailable}
		case dedicated > 0:
			return 0, ErrCredentialOwnershipInvalid
		default:
			return 0, ErrCredentialNotFound
		}
	}

	changed := 0
	for i, c := range shared {
		before := current[i]
		if sameOwnership(before, to) {
			continue
		}
		res := tx.Model(&model.Credential{}).Where("id = ?", c.ID).Updates(ownershipColumns(to))
		if res.Error != nil {
			return 0, fmt.Errorf("改歸憑證失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return 0, ErrCredentialNotFound
		}
		if err := writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID:    c.ID,
			Operation:       model.AccountOpUpdate,
			Scope:           c.Scope,
			Fields:          []string{"ownership"},
			Ownership:       ownershipAudit(to),
			OwnershipBefore: ownershipAudit(before),
		}, userID, operator); err != nil {
			return 0, err
		}
		changed++
	}
	return changed, nil
}

// requireOwnershipChangeGate 單筆改歸前的逐筆關卡（單筆與批次共用）：對該憑證的管理能力
// （credential:update；範圍化主體依憑證現行歸屬判定，不逐台驗掛載資產），以及輪替進行中拒絕。
// 這是「改歸前憑證本身是否可被操作」的唯一判定處；變更前後歸屬範圍的判定另在 AuthorizeOwnershipChange。
func (s *CredentialService) requireOwnershipChangeGate(ctx context.Context, tx *gorm.DB, cred *model.Credential) error {
	if err := s.requireBoundManagement(ctx, tx, CredOpUpdate, cred.ID, CredCapUpdate); err != nil {
		return err
	}
	return assertNoActiveRotation(cred)
}

// isOwnershipGateRefusal 關卡錯誤是否為判定拒絕（能力不足、憑證在範圍外、輪替中）；其餘（含判定器
// 缺席、資料庫錯誤）一律視為錯誤原樣回傳，fail-close：不認得的不當成「僅不可操作」。
// 憑證層的範圍拒絕必須計入批次筆數：原樣回傳會成為單筆的不存在回應，與批次中真正不存在的
// 識別（計入筆數）分得出來，範圍化主體即可據此探出範圍外憑證是否存在。
func isOwnershipGateRefusal(err error) bool {
	if errors.Is(err, ErrCredentialBindForbidden) || errors.Is(err, ErrCredentialRotationActive) {
		return true
	}
	var d scopeDeniedTarget
	return errors.As(err, &d) && d.ScopeDeniedTargetKind() == scopeTargetKindCredential
}

// scopeTargetKindCredential 與 authz 的憑證目標種類字串一致（由批次改歸的同形整合測試鎖定）。
const scopeTargetKindCredential = "credential"

// currentOwnership 憑證列的現行歸屬（欄位缺值時種類為空，判定器對條件範圍主體視為不可操作）。
func currentOwnership(c *model.Credential) CredentialOwnership {
	o := CredentialOwnership{}
	if c.OwnerKind != nil {
		o.Kind = *c.OwnerKind
	}
	if c.OwnerNodeID != nil {
		id := *c.OwnerNodeID
		o.NodeID = &id
	}
	return o
}

func sameOwnership(a, b CredentialOwnership) bool {
	if a.Kind != b.Kind {
		return false
	}
	if a.NodeID == nil || b.NodeID == nil {
		return a.NodeID == nil && b.NodeID == nil
	}
	return *a.NodeID == *b.NodeID
}

func uniqueSortedIDs(ids []uint) []uint {
	seen := make(map[uint]bool, len(ids))
	out := make([]uint, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// updateOwnershipTx PUT /credentials/:id 帶 ownership 時的單筆改歸（cred 已在本交易鎖定）。
func (s *CredentialService) updateOwnershipTx(ctx context.Context, tx *gorm.DB, userID uint, operator string,
	cred *model.Credential, target CredentialOwnershipInput) (bool, error) {

	if cred.Scope != model.CredentialScopeShared {
		return false, ErrCredentialOwnershipInvalid
	}
	n, err := s.reassignOwnershipTx(ctx, tx, userID, operator, []*model.Credential{cred}, 0, target, false)
	return n > 0, err
}
