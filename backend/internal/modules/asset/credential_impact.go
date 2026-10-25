package asset

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 共用憑證修改的範圍外影響確認。
//
// 範圍化主體修改共用憑證的秘密（宣告新秘密、遠端輪替）時，會連帶影響掛在其範圍外的主機。
// 伺服器在憑證列鎖內算出「不在操作者對該動作所需能力範圍內的掛載資產集合」並保存在確認列；提交時於同一把鎖內重算，
// 缺漏、已用、操作者／憑證／動作不符或集合擴大都退回，縮小與相等照過；確認單次使用。
// 確認列只留在伺服器：回應不含任何範圍外資產識別、名稱或節點，也不接受前端帶回集合。
// 範圍外集合為空（含全域主體）時不看確認欄。

// ErrCredentialImpactOperationInvalid 影響確認的動作值不在值域內。
var ErrCredentialImpactOperationInvalid = errors.New("影響確認的動作僅允許宣告新秘密或遠端輪替")

// CredentialImpactConfirmationRequiredError 提交需要（更新後的）影響確認；Count 為當下範圍外台數。
type CredentialImpactConfirmationRequiredError struct {
	Count int
}

// Error 固定字串，不含任何識別。
func (e *CredentialImpactConfirmationRequiredError) Error() string {
	return "asset: credential impact confirmation required"
}

// ConfirmCredentialImpactRequest 建立影響確認的請求。
type ConfirmCredentialImpactRequest struct {
	Operation string `json:"operation"`
}

// ConfirmCredentialImpactResult 建立影響確認的結果；OutOfScopeAssets 由接入層經揭露登錄轉出，不直接序列化。
// InScopeCount 只計能力範圍內且操作者可檢視者；其餘（能力範圍外，以及能力範圍內但不可檢視者）只計入 OutOfScopeAssets。
type ConfirmCredentialImpactResult struct {
	Required         bool   `json:"required"`
	ConfirmationID   string `json:"confirmation_id,omitempty"`
	InScopeCount     int    `json:"in_scope_count"`
	OutOfScopeAssets int    `json:"-"`
}

// impactOutcome 一次提交通過確認後留給審計的資訊；nil＝不涉範圍外。
type impactOutcome struct {
	OutOfScope     int
	ConfirmationID string
}

// auditDetails 審計 details 的附加鍵（值為字串；鍵名引用揭露登錄常數，不寫字面值）。
func (o *impactOutcome) auditDetails() map[string]string {
	if o == nil {
		return nil
	}
	return map[string]string{
		disclosure.AuditDetailOutOfScopeCount: strconv.Itoa(o.OutOfScope),
		"impact_confirmation_id":              o.ConfirmationID,
	}
}

// impactOperationOf 動作值對應的授權操作與能力。
func impactOperationOf(op string) (CredentialOperation, string, error) {
	switch op {
	case model.CredentialImpactOpSetSecret:
		return CredOpSetSecret, CredCapSetSecret, nil
	case model.CredentialImpactOpRotate:
		return CredOpRotate, CredCapRotate, nil
	}
	return "", "", ErrCredentialImpactOperationInvalid
}

// impactGuard 影響確認的共用判定（憑證服務與輪替服務各持一份；確認端點與提交重算都走 split）。
type impactGuard struct {
	scope CredentialScopeSource
}

// impactSplit 憑證當下掛載資產依操作者對該動作的能力範圍切分的結果。
//
//   - Out：不在操作者對該動作所需能力（宣告＝set-secret、輪替＝rotate）資產範圍內者；確認集合與提交重算皆以此為準。
//   - Listed：在能力範圍內且操作者也可檢視者；只有這些可列出（範圍內台數）。
//   - Unlisted：在能力範圍內但操作者不可檢視者；只計台數，不列出。
type impactSplit struct {
	Listed   []uint
	Unlisted int
	Out      []uint
}

// split 掛載集合在呼叫端的交易與憑證列鎖之內讀取。非範圍化主體或未注入來源：全部列為範圍內、範圍外為空。
func (g impactGuard) split(ctx context.Context, tx *gorm.DB, credentialID uint, operation string) (impactSplit, error) {
	_, capKey, err := impactOperationOf(operation)
	if err != nil {
		return impactSplit{}, err
	}
	mounted, err := credentialBoundAssetIDs(tx, credentialID)
	if err != nil {
		return impactSplit{}, err
	}
	if g.scope == nil {
		return impactSplit{Listed: mounted}, nil
	}
	inCap, inView, scoped, err := g.scope.CredentialImpactScopeIn(ctx, tx, capKey, mounted)
	if err != nil {
		return impactSplit{}, err
	}
	if !scoped {
		return impactSplit{Listed: mounted}, nil
	}
	var res impactSplit
	for _, id := range mounted {
		switch {
		case !inCap[id]:
			res.Out = append(res.Out, id)
		case inView[id]:
			res.Listed = append(res.Listed, id)
		default:
			res.Unlisted++
		}
	}
	return res, nil
}

// enforce 提交時的重算與消耗：範圍外集合為空 → (nil, nil)；否則須有符合且集合涵蓋當下範圍外集合的確認，
// 通過即刪除確認列（單次使用）。回 CredentialImpactConfirmationRequiredError 時呼叫端交易整筆回滾。
func (g impactGuard) enforce(ctx context.Context, tx *gorm.DB, credentialID uint, operation, confirmationID string) (*impactOutcome, error) {
	split, err := g.split(ctx, tx, credentialID, operation)
	if err != nil {
		return nil, err
	}
	out := split.Out
	if len(out) == 0 {
		return nil, nil
	}
	required := &CredentialImpactConfirmationRequiredError{Count: len(out)}
	if confirmationID == "" {
		return nil, required
	}
	userID, _ := model.UserFromContext(ctx)
	var row model.CredentialImpactConfirmation
	err = tx.Where("id = ? AND credential_id = ? AND user_id = ? AND operation = ?",
		confirmationID, credentialID, userID, operation).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, required
	}
	if err != nil {
		return nil, fmt.Errorf("查詢影響確認失敗: %w", err)
	}
	var confirmed []uint
	if err := json.Unmarshal([]byte(row.OutOfScopeAssetIDs), &confirmed); err != nil {
		return nil, required
	}
	known := make(map[uint]bool, len(confirmed))
	for _, id := range confirmed {
		known[id] = true
	}
	for _, id := range out {
		if !known[id] {
			return nil, required
		}
	}
	res := tx.Where("id = ?", row.ID).Delete(&model.CredentialImpactConfirmation{})
	if res.Error != nil {
		return nil, fmt.Errorf("消耗影響確認失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, required
	}
	return &impactOutcome{OutOfScope: len(out), ConfirmationID: confirmationID}, nil
}

// ConfirmImpact 建立影響確認（POST /credentials/:id/impact-confirmations）。
//
// 依動作要求宣告或輪替能力（含憑證歸屬的範圍判定，範圍外憑證與不存在同形）。範圍外集合為空回
// required=false 且不建紀錄；非空則寫一列確認（同一操作者、憑證、動作的舊列同交易刪除）。
// 只計算並寫確認列，不修改憑證；留一筆讀取審計。
func (s *CredentialService) ConfirmImpact(ctx context.Context, id uint, req *ConfirmCredentialImpactRequest) (*ConfirmCredentialImpactResult, error) {
	if req == nil {
		return nil, ErrCredentialImpactOperationInvalid
	}
	op, capKey, err := impactOperationOf(req.Operation)
	if err != nil {
		return nil, err
	}
	// 能力判定先於任何查表：路由層只要求宣告或輪替其一，缺本次動作能力者對任何識別（含不存在）
	// 同為能力拒絕；交易內以全部掛載再判一次照舊
	if err := s.requireManagement(ctx, nil, op, []string{capKey}, []uint{id}, nil); err != nil {
		return nil, err
	}
	userID, operator := model.UserFromContext(ctx)
	var result *ConfirmCredentialImpactResult
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		cred, err := lockCredentialRow(tx, id)
		if err != nil {
			return err
		}
		mounted, err := credentialBoundAssetIDs(tx, cred.ID)
		if err != nil {
			return err
		}
		decision, err := s.mgmt.require(ctx, tx, CredentialManagementRequest{
			Operation: op, Capabilities: []string{capKey}, CredentialIDs: []uint{cred.ID}, MountedAssetIDs: mounted,
		})
		if err != nil {
			return err
		}
		split, err := impactGuard{scope: s.scope}.split(ctx, tx, cred.ID, req.Operation)
		if err != nil {
			return err
		}
		out := split.Out
		result = &ConfirmCredentialImpactResult{InScopeCount: len(split.Listed), OutOfScopeAssets: len(out) + split.Unlisted}
		if len(out) > 0 {
			confirmID, err := newImpactConfirmationID()
			if err != nil {
				return err
			}
			ids, err := json.Marshal(out)
			if err != nil {
				return fmt.Errorf("序列化影響確認集合失敗: %w", err)
			}
			if err := tx.Where("credential_id = ? AND user_id = ? AND operation = ?", cred.ID, userID, req.Operation).
				Delete(&model.CredentialImpactConfirmation{}).Error; err != nil {
				return fmt.Errorf("清除舊影響確認失敗: %w", err)
			}
			if err := tx.Create(&model.CredentialImpactConfirmation{
				ID: confirmID, CredentialID: cred.ID, UserID: userID, Operation: req.Operation,
				AuthzVersion: decision.AuthzVersion, OutOfScopeAssetIDs: string(ids),
			}).Error; err != nil {
				return fmt.Errorf("寫入影響確認失敗: %w", err)
			}
			result.Required, result.ConfirmationID = true, confirmID
		}
		return writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: cred.ID,
			Operation:    "impact_confirmation",
			Scope:        cred.Scope,
			Action:       model.ActionRead,
		}, userID, operator)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// newImpactConfirmationID 128 位元隨機十六進位（32 字元），只回給操作者的不透明識別。
func newImpactConfirmationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("產生影響確認識別失敗: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
