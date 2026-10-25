package authz

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// 防自我授權的共用判定。
//
// 「本人範圍」＝操作者本人 ∪ 本人為成員的使用者群組（`user_group_members` 現有列，
// 手動與映射來源皆算直接所屬）∪ `kind=agent` 且 `owner_user_id` 為本人的帳號（含停用中，
// 因可再啟用）。四個入口（授權規則建立與帳號範圍調整、審核範圍建立、申請決定、
// agent 擁有者轉移）共用同一份判定，於寫入交易內現查、不快取。
//
// **只在當下判定**：事後群組成員異動、事後把 agent 加入群組、刪除規則後再轉移，都不追溯。
//
// **鎖序**：以 agent 為主體建規則與轉移擁有者都先鎖該 agent 的使用者列（postgres
// `FOR NO KEY UPDATE`，多列以單一 `ORDER BY id` 語句取得；sqlite 無列鎖，單連線序列化即等價），
// 再做判定，避免並發轉移造成判定過期。

var (
	// ErrSelfSubjectGrant 授權規則的主體落在操作者的本人範圍內
	ErrSelfSubjectGrant = errors.New("不得對自己、自己所屬的群組或自己擁有的 agent 建立或調整授權規則")
	// ErrApproverScopeSubjectOverlap 申請人型審核範圍的審核方集合與申請人集合相交
	ErrApproverScopeSubjectOverlap = errors.New("審核方與申請人不得重疊")
	// ErrAgentOwnerTransferSelfGrant 新擁有者曾替該 agent 建立仍有效的授權規則、申請人型審核範圍，
	// 或對該 agent 的申請投下仍有效的核准票
	ErrAgentOwnerTransferSelfGrant = errors.New("新擁有者曾替此 agent 建立仍有效的授權、審核範圍或核准票，不得轉移")
	// ErrAccountScopeWidenRestricted 非建立者、非超管擴大既有規則的帳號範圍
	ErrAccountScopeWidenRestricted = errors.New("非規則建立者只能縮小帳號範圍，擴大須由建立者或超級管理者執行")
)

// SelfSubjects 操作者的本人範圍（供守衛與自身範圍唯讀端點共用同一份資料）。
type SelfSubjects struct {
	UserID       uint   `json:"user_id"`
	UserGroupIDs []uint `json:"user_group_ids"`
	AgentIDs     []uint `json:"agent_ids"`
}

// SelfGrantGuard 無狀態守衛：全部方法以呼叫端的交易為準。
type SelfGrantGuard struct{}

// SelfSubjectsOf 現查操作者的本人範圍。
func SelfSubjectsOf(tx *gorm.DB, userID uint) (SelfSubjects, error) {
	return loadSelfSubjects(tx, userID, true, true)
}

// loadSelfSubjects 只查需要的部分（groups：所屬群組；agents：擁有的 agent），未查的欄位為空切片。
func loadSelfSubjects(tx *gorm.DB, userID uint, groups, agents bool) (SelfSubjects, error) {
	out := SelfSubjects{UserID: userID, UserGroupIDs: []uint{}, AgentIDs: []uint{}}
	if groups {
		if err := tx.Table("user_group_members").
			Where("user_id = ?", userID).Order("user_group_id").
			Pluck("user_group_id", &out.UserGroupIDs).Error; err != nil {
			return out, fmt.Errorf("查詢本人所屬群組失敗: %w", err)
		}
	}
	if agents {
		if err := tx.Model(&model.User{}).
			Where("kind = ? AND owner_user_id = ?", model.KindAgent, userID).Order("id").
			Pluck("id", &out.AgentIDs).Error; err != nil {
			return out, fmt.Errorf("查詢本人擁有的 agent 失敗: %w", err)
		}
	}
	return out, nil
}

// SelfSubjects 同 SelfSubjectsOf（方法形式，供介面注入）。
func (SelfGrantGuard) SelfSubjects(tx *gorm.DB, userID uint) (SelfSubjects, error) {
	return SelfSubjectsOf(tx, userID)
}

// lockUserRows 鎖住一批使用者列（agent 主體的擁有者現查與擁有者轉移同鎖序）。
// 單一語句帶 ORDER BY id 與 FOR NO KEY UPDATE：PostgreSQL 對帶排序的鎖定查詢先排序再上鎖，
// 所以不論呼叫端傳入的順序，一律依使用者編號升冪取得，與其他入口的使用者層鎖序一致；
// 只排序傳入的切片不算數（WHERE id IN 的取鎖順序取決於執行計畫）。
func lockUserRows(tx *gorm.DB, ids []uint) error {
	if len(ids) == 0 {
		return nil
	}
	// 鎖序守衛探針（測試期；生產恆為 nil）：取帳號列鎖之前
	if probe := LockOrderProbeHook(); probe != nil {
		probe(tx, LockLayerUserRow, ids...)
	}
	q := tx.Model(&model.User{})
	if tx.Dialector.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "NO KEY UPDATE"})
	}
	var locked []uint
	if err := q.Where("id IN ?", ids).Order("id").Pluck("id", &locked).Error; err != nil {
		return fmt.Errorf("鎖定主體帳號失敗: %w", err)
	}
	if h := loadLockOrderHook(); h != nil {
		h("user_rows_locked", tx, ids...)
	}
	return nil
}

// CheckRuleSubjects 非超管建立或調整授權規則時的主體判定：主體（批次為全部主體）
// 含本人範圍任一者即回 ErrSelfSubjectGrant。agent 主體以帳號列鎖讀取擁有者。
func (SelfGrantGuard) CheckRuleSubjects(tx *gorm.DB, operatorID uint, userIDs, groupIDs []uint) error {
	for _, id := range userIDs {
		if id == operatorID {
			return ErrSelfSubjectGrant
		}
	}
	if len(userIDs) > 0 {
		if err := lockUserRows(tx, userIDs); err != nil {
			return err
		}
	}
	if len(userIDs) == 0 && len(groupIDs) == 0 {
		return nil
	}
	self, err := loadSelfSubjects(tx, operatorID, len(groupIDs) > 0, len(userIDs) > 0)
	if err != nil {
		return err
	}
	if ruleSubjectsInSelfScope(self, userIDs, groupIDs) {
		return ErrSelfSubjectGrant
	}
	return nil
}

// ruleSubjectsInSelfScope 規則主體（使用者、群組）是否有任一落在操作者的本人範圍內。
// 守衛與授權列表的列級旗標共用這一個判定。
func ruleSubjectsInSelfScope(self SelfSubjects, userIDs, groupIDs []uint) bool {
	for _, id := range userIDs {
		if id == self.UserID {
			return true
		}
		for _, agent := range self.AgentIDs {
			if id == agent {
				return true
			}
		}
	}
	for _, id := range groupIDs {
		for _, g := range self.UserGroupIDs {
			if id == g {
				return true
			}
		}
	}
	return false
}

// CheckApproverScope 申請人型審核範圍的不相交檢查：審核方集合（個人本人或群組現有成員）
// 與申請人集合（個人本人或群組現有成員）交集非空即回 ErrApproverScopeSubjectOverlap。
// 資產型與節點型範圍沒有申請人集合，不判定；適用所有建立者。
func (SelfGrantGuard) CheckApproverScope(tx *gorm.DB, spec ApproverScopeSpec) error {
	if spec.SubjectUserID == nil && spec.SubjectGroupID == nil {
		return nil
	}
	var overlap int64
	var err error
	switch {
	case spec.ApproverID != nil && spec.SubjectUserID != nil:
		if *spec.ApproverID == *spec.SubjectUserID {
			overlap = 1
		}
	case spec.ApproverID != nil && spec.SubjectGroupID != nil:
		err = tx.Table("user_group_members").
			Where("user_group_id = ? AND user_id = ?", *spec.SubjectGroupID, *spec.ApproverID).
			Count(&overlap).Error
	case spec.ApproverGroupID != nil && spec.SubjectUserID != nil:
		err = tx.Table("user_group_members").
			Where("user_group_id = ? AND user_id = ?", *spec.ApproverGroupID, *spec.SubjectUserID).
			Count(&overlap).Error
	case spec.ApproverGroupID != nil && spec.SubjectGroupID != nil:
		err = tx.Table("user_group_members AS a").
			Joins("JOIN user_group_members AS s ON s.user_id = a.user_id").
			Where("a.user_group_id = ? AND s.user_group_id = ?", *spec.ApproverGroupID, *spec.SubjectGroupID).
			Count(&overlap).Error
	}
	if err != nil {
		return fmt.Errorf("查詢審核方與申請人重疊失敗: %w", err)
	}
	if overlap > 0 {
		return ErrApproverScopeSubjectOverlap
	}
	return nil
}

// IsOwnAgentRequest 申請人是否為操作者擁有的 agent（決定當下現查）。
func (SelfGrantGuard) IsOwnAgentRequest(tx *gorm.DB, actorID, requesterID uint) (bool, error) {
	if actorID == 0 || requesterID == 0 || actorID == requesterID {
		return false, nil
	}
	var n int64
	if err := tx.Model(&model.User{}).
		Where("id = ? AND kind = ? AND owner_user_id = ?", requesterID, model.KindAgent, actorID).
		Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢申請人擁有者失敗: %w", err)
	}
	return n > 0, nil
}

// ownAgentRequesterCondition 待審過濾的 SQL 片段：排除申請人為操作者所擁有 agent 的單。
// 與 IsOwnAgentRequest 同一判定（kind=agent 且 owner_user_id=操作者）。
const ownAgentRequesterCondition = "requester_id NOT IN (SELECT id FROM users WHERE kind = 'agent' AND owner_user_id = ? AND deleted_at IS NULL)"

// CheckOwnerTransfer 把 agent 的擁有者改為 newOwnerID 前的判定：新擁有者曾建立以該 agent
// 為主體、仍有效的授權規則（未刪除、未過期，含核准產生的臨時授權）、以該 agent 為申請人
// 的審核範圍，或對該 agent 的申請投下仍有效的核准票（項目待審中，或已核准且其票證未到期），
// 即回 ErrAgentOwnerTransferSelfGrant。新擁有者為超管時不判定。
// 呼叫端須已在同一交易內鎖住 agent 的使用者列（申請決定的交易同樣先鎖這一列再計票，
// 故「投票」與「轉移」以同一把鎖序列化）。
//
// 核准票納入的理由：多票核准時票證只記最後一票的 granted_by，先前投票者對票證的貢獻
// 只存在於票列；不查票列，新擁有者可以先投票、再接手 agent、由他人補足最後一票。
// 選擇「拒絕轉移」而不是「轉移時作廢票」：身分管理操作不該悄悄改變申請單的狀態，且與
// 規則、審核範圍兩項的處置一致；計票側另以獨立性重驗（independentVoteCount）作為第二道。
func (SelfGrantGuard) CheckOwnerTransfer(tx *gorm.DB, agentID, newOwnerID uint) error {
	now := time.Now()
	blocked, err := ownerTransferBlockers(tx, agentID, newOwnerID, now)
	if err != nil {
		return err
	}
	if !blocked {
		return nil
	}
	// 有阻擋項才查新擁有者是否超管（超管已有連線豁免，規則不增加其能力）
	p, err := NewResolver(tx).ResolveUser(newOwnerID, TokenFacts{})
	if err != nil {
		return fmt.Errorf("解析新擁有者主體失敗: %w", err)
	}
	if p.IsSuperAdmin() {
		return nil
	}
	return ErrAgentOwnerTransferSelfGrant
}

// ownerTransferBlockers 依序查三類阻擋項，任一命中即停。
func ownerTransferBlockers(tx *gorm.DB, agentID, newOwnerID uint, now time.Time) (bool, error) {
	var rules int64
	if err := tx.Model(&model.AssetAuthorization{}).
		Where("user_id = ? AND granted_by = ? AND (date_expired IS NULL OR date_expired > ?)", agentID, newOwnerID, now).
		Count(&rules).Error; err != nil {
		return false, fmt.Errorf("查詢新擁有者建立的授權規則失敗: %w", err)
	}
	if rules > 0 {
		return true, nil
	}
	var scopes int64
	if err := tx.Model(&model.ApproverScope{}).
		Where("subject_user_id = ? AND granted_by = ?", agentID, newOwnerID).
		Count(&scopes).Error; err != nil {
		return false, fmt.Errorf("查詢新擁有者建立的審核範圍失敗: %w", err)
	}
	if scopes > 0 {
		return true, nil
	}
	votes, err := activeVotesBy(tx, agentID, newOwnerID, now)
	if err != nil {
		return false, err
	}
	return votes > 0, nil
}

// activeVotesBy 新擁有者對該 agent 所提申請、仍有效的核准票數：
// 項目待審（單未逾期）或已核准且票證未刪除、未到期。項目層級缺席的舊票以單的狀態判定。
func activeVotesBy(tx *gorm.DB, agentID, approverID uint, now time.Time) (int64, error) {
	const validTicket = "EXISTS (SELECT 1 FROM asset_authorizations aa WHERE aa.id = %s AND aa.deleted_at IS NULL AND (aa.date_expired IS NULL OR aa.date_expired > ?))"
	var n int64
	err := tx.Table("access_request_approvals AS a").
		Joins("JOIN access_requests AS r ON r.id = a.request_id AND r.deleted_at IS NULL").
		Joins("LEFT JOIN access_request_items AS i ON i.id = a.item_id AND i.deleted_at IS NULL").
		Where("r.requester_id = ? AND a.approver_id = ?", agentID, approverID).
		Where("(a.item_id IS NOT NULL AND ((i.status = ? AND r.status = ? AND r.pending_expires_at > ?) OR (i.status = ? AND "+fmt.Sprintf(validTicket, "i.authorization_id")+")))"+
			" OR (a.item_id IS NULL AND ((r.status = ? AND r.pending_expires_at > ?) OR (r.status = ? AND "+fmt.Sprintf(validTicket, "r.authorization_id")+")))",
			model.AccessRequestPending, model.AccessRequestPending, now, model.AccessRequestApproved, now,
			model.AccessRequestPending, now, model.AccessRequestApproved, now).
		Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("查詢新擁有者投下的核准票失敗: %w", err)
	}
	return n, nil
}

// ErrOperatorUnknown 需要操作者主體的入口在請求脈絡找不到主體：fail-close，不猜操作者。
var ErrOperatorUnknown = errors.New("操作者主體缺失，無法判定本人範圍")

// ErrOperatorMismatch 呼叫端宣稱的授權者（GrantedBy）與請求脈絡主體不是同一人：
// 拒收，不以宣稱值判定本人範圍，也不讓 granted_by 記成別人。
var ErrOperatorMismatch = errors.New("宣稱的授權者與請求脈絡主體不一致")

// trustedOperator 取可信的操作者：只認請求脈絡帶入的主體（HTTP 入口恆經 AuthMiddleware
// 填入）。脈絡無主體即拒（程式內部呼叫也不例外，不猜操作者）；呼叫端另自報的
// grantedBy 只准與主體相同——它會寫進 granted_by，而擁有者轉移守衛（CheckOwnerTransfer）
// 以 granted_by 判定，記成別人等於替日後的轉移開洞。超管豁免也只以回傳的主體認定。
func trustedOperator(ctx context.Context, grantedBy uint) (*Principal, error) {
	p := PrincipalFromContext(ctx)
	if p == nil {
		return nil, ErrOperatorUnknown
	}
	if p.UserID != grantedBy {
		return nil, ErrOperatorMismatch
	}
	return p, nil
}

// guardRuleSubjects 單筆授權規則的本人範圍守衛（Grant 的交易內呼叫）。
// grantedBy 是呼叫端宣稱的授權者，只用來與脈絡主體核對，不作為判定依據。
func (s *AssetAuthorizationService) guardRuleSubjects(ctx context.Context, tx *gorm.DB, grantedBy uint, userID, groupID *uint) error {
	p, err := trustedOperator(ctx, grantedBy)
	if err != nil {
		return err
	}
	if p.IsSuperAdmin() {
		return nil
	}
	var users, groups []uint
	if userID != nil {
		users = []uint{*userID}
	}
	if groupID != nil {
		groups = []uint{*groupID}
	}
	return SelfGrantGuard{}.CheckRuleSubjects(tx, p.UserID, users, groups)
}

// guardBatchSubjects 批次授權規則的本人範圍守衛：主體集任一命中即整批拒絕。
// 操作者認定同 guardRuleSubjects。
func (s *AssetAuthorizationService) guardBatchSubjects(ctx context.Context, tx *gorm.DB, grantedBy uint, userIDs, groupIDs []uint) error {
	p, err := trustedOperator(ctx, grantedBy)
	if err != nil {
		return err
	}
	if p.IsSuperAdmin() {
		return nil
	}
	return SelfGrantGuard{}.CheckRuleSubjects(tx, p.UserID, userIDs, groupIDs)
}

// guardAccountScopeOperator 帳號範圍調整的本人範圍守衛：操作者取自請求脈絡主體。
func (s *AssetAuthorizationService) guardAccountScopeOperator(ctx context.Context, tx *gorm.DB, auth *model.AssetAuthorization) error {
	p := PrincipalFromContext(ctx)
	if p == nil {
		return ErrOperatorUnknown
	}
	if p.IsSuperAdmin() {
		return nil
	}
	var users, groups []uint
	if auth.UserID != nil {
		users = []uint{*auth.UserID}
	}
	if auth.UserGroupID != nil {
		groups = []uint{*auth.UserGroupID}
	}
	return SelfGrantGuard{}.CheckRuleSubjects(tx, p.UserID, users, groups)
}

// guardAccountScopeWiden 非超管且非規則建立者調整帳號範圍時，只准縮小：新範圍須落在
// 交易內現查的既有範圍之內（既有為 @ALL 時任何範圍都在內；新範圍為 @ALL 只有既有也是 @ALL 才算）。
//
// 不變式：每條有效規則的帳號範圍 ⊆ 其 granted_by 主張過的範圍。擁有者轉移守衛以 granted_by
// 判定「新擁有者曾替此 agent 授權」，只有在這個不變式之下才充分——否則先擴大他人建立的規則、
// 再接手 agent，就取得了 granted_by 以外的人主張的範圍。要擴大，由建立者或超管執行，
// 或刪除後以自己名義重建（此時 granted_by 即本人，轉移守衛照常命中）；縮小不取得主張權。
// 不改寫 granted_by：改寫會讓再一次修改洗掉先前的擴大者，且原建立者須留供稽核。
func (s *AssetAuthorizationService) guardAccountScopeWiden(ctx context.Context, tx *gorm.DB, authorizationID uint, next model.AccountScope) error {
	p := PrincipalFromContext(ctx)
	if p == nil {
		return ErrOperatorUnknown
	}
	if p.IsSuperAdmin() {
		return nil
	}
	var cur model.AssetAuthorization
	if err := tx.Select("id", "granted_by", "accounts").First(&cur, authorizationID).Error; err != nil {
		return fmt.Errorf("現查授權列失敗: %w", err)
	}
	if ruleCreatedBy(p, cur.GrantedBy) || scopeWithin(next, cur.Accounts) {
		return nil
	}
	return ErrAccountScopeWidenRestricted
}

// ruleCreatedBy 操作者是否為規則的建立者（granted_by）。窄化守衛與授權列表的列級旗標共用。
func ruleCreatedBy(p *Principal, grantedBy uint) bool { return p != nil && p.UserID == grantedBy }

// scopeWithin next 是否不超出 cur（@ALL 為上界）。
func scopeWithin(next, cur model.AccountScope) bool {
	if cur.IsAll() {
		return true
	}
	if next.IsAll() {
		return false
	}
	for _, name := range next {
		if !cur.Contains(name) {
			return false
		}
	}
	return true
}
