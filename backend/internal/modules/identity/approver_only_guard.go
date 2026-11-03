package identity

import (
	"fmt"
	"log"
	"sort"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"gorm.io/gorm"
)

// 指派寫入後、提交前的交易內斷言：寫入結果使帳號「只有審核者角色」（authz.ApproverOnly）時整筆拒絕。
// 斷言只讀指派相關表，發生在各路徑既有的取鎖與寫入之後，不新增鎖、不改取鎖順序；回錯誤即由呼叫端
// 回滾，權限版本、成功審計與告警事件都不留下。操作者權限與指派關卡先於本斷言。

// approverOnlyAffectedLimit 群組拒絕回應最多帶出的帳號筆數（人數照實）。
const approverOnlyAffectedLimit = 20

func errRoleSetApproverOnly() error {
	return &PrincipalError{Code: apierror.CodeValidationRoleSetApproverOnly, Status: 400}
}

// assertNotApproverOnly 直接指派入口（建立帳號帶角色、整組替換、冪等追加）：寫入結果使對象成為此狀態即拒，
// 不論寫入前是否已是。
func assertNotApproverOnly(tx *gorm.DB, userID uint) error {
	only, err := authz.IsApproverOnlyTx(tx, userID)
	if err != nil {
		return fmt.Errorf("判定指派結果失敗: %w", err)
	}
	if only {
		return errRoleSetApproverOnly()
	}
	return nil
}

// AffectedUser 群組拒絕回應中的一位受影響成員：只有識別碼與帳號名稱。
type AffectedUser struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
}

// ApproverOnlyMembersError 群組寫入使原本不是此狀態的成員成為此狀態。Count 為轉入的未刪除帳號總人數，
// Users 為依識別碼升冪的前 approverOnlyAffectedLimit 位。不帶角色、範圍或節點資訊。
type ApproverOnlyMembersError struct {
	Count int
	Users []AffectedUser
}

func (e *ApproverOnlyMembersError) Error() string {
	return fmt.Sprintf("%s (count=%d)", apierror.CodeValidationUserGroupApproverOnlyMembers, e.Count)
}

// approverOnlyBefore 群組路徑寫入前（已取鎖後）讀出成員的判定，供寫入後比對「轉入」。
// 群組目前沒有任何角色指派時，三條路徑都不可能讓成員失去經本群組的指派，不判定（回 nil）。
func approverOnlyBefore(tx *gorm.DB, groupID uint, memberIDs []uint) (map[uint]bool, error) {
	bindings, err := authz.UserGroupRoleIDs(tx, groupID)
	if err != nil {
		return nil, err
	}
	if len(bindings) == 0 {
		return nil, nil
	}
	m, err := authz.LoadApproverOnly(tx, memberIDs)
	if err != nil {
		return nil, fmt.Errorf("判定成員指派狀態失敗: %w", err)
	}
	return m, nil
}

// assertNoApproverOnlyTransitions 群組路徑寫入後：只拒「寫入前不是、寫入後是」的成員；寫入前已是者不阻擋。
func assertNoApproverOnlyTransitions(tx *gorm.DB, before map[uint]bool) error {
	if len(before) == 0 {
		return nil
	}
	ids := make([]uint, 0, len(before))
	for id := range before {
		ids = append(ids, id)
	}
	after, err := authz.LoadApproverOnly(tx, ids)
	if err != nil {
		return fmt.Errorf("判定成員指派結果失敗: %w", err)
	}
	var turned []uint
	for _, id := range ids {
		if after[id] && !before[id] {
			turned = append(turned, id)
		}
	}
	if len(turned) == 0 {
		return nil
	}
	// 已刪除（軟刪除）的帳號不能登入、也無法在使用者管理中修正，不列入人數與名單；
	// 轉入者全是已刪除帳號時不阻擋。人數與名單取自同一組存活帳號，兩者一致。
	var live []uint
	if err := tx.Model(&model.User{}).Where("id IN ?", turned).Order("id").Pluck("id", &live).Error; err != nil {
		return fmt.Errorf("讀取受影響成員帳號失敗: %w", err)
	}
	if len(live) == 0 {
		return nil
	}
	sort.Slice(live, func(i, j int) bool { return live[i] < live[j] })
	listed := live
	if len(listed) > approverOnlyAffectedLimit {
		listed = listed[:approverOnlyAffectedLimit]
	}
	var rows []AffectedUser
	if err := tx.Model(&model.User{}).Select("id, username").Where("id IN ?", listed).
		Order("id").Scan(&rows).Error; err != nil {
		return fmt.Errorf("讀取受影響成員帳號失敗: %w", err)
	}
	return &ApproverOnlyMembersError{Count: len(live), Users: rows}
}

// fillApproverOnly 為當頁使用者填入「只有審核者角色」標示（真假都填）。固定兩支批次查詢，與頁內筆數無關。
// 查詢失敗只記錄不中斷，欄位維持 nil（標示是輔助資訊）。
func (s *UserService) fillApproverOnly(users []model.User) {
	if len(users) == 0 {
		return
	}
	kinds := make(map[uint]string, len(users))
	for i := range users {
		kinds[users[i].ID] = users[i].Kind
	}
	m, err := authz.LoadApproverOnlyKnownKinds(s.db, kinds)
	if err != nil {
		log.Printf("[UserService] fillApproverOnly: %v", err)
		return
	}
	for i := range users {
		v := m[users[i].ID]
		users[i].ApproverOnly = &v
	}
}

// MarkApproverOnly 單筆讀取路徑填入同一標示（與列表同一個判定）。
func (s *UserService) MarkApproverOnly(user *model.User) error {
	if user == nil {
		return nil
	}
	m, err := authz.LoadApproverOnlyKnownKinds(s.db, map[uint]string{user.ID: user.Kind})
	if err != nil {
		return fmt.Errorf("判定帳號指派狀態失敗: %w", err)
	}
	v := m[user.ID]
	user.ApproverOnly = &v
	return nil
}
