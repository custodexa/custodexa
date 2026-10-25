package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 外部群組映射的寫入守衛。
//
// 兩類規則（外部群組到角色、外部群組到使用者群組）與釘住，全部經 AssignmentGuard 裁決與
// 直接指派同一套保護目標與指派能力規則。本檔只做兩件事：
//
//  1. 直接映射的目標 allowlist（以內建鍵判定，不看名稱）。
//  2. 把規則的舊值與新值轉成關卡的輸入，在來源鎖內以重讀的現值判定。

// 直接映射 allowlist：無範圍的內建範本。自訂角色與可範圍化角色改走使用者群組。
var mappingDirectKeys = map[string]struct{}{
	model.BuiltinSuperAdmin:    {},
	model.BuiltinAuditor:       {},
	model.BuiltinUser:          {},
	model.BuiltinApprover:      {},
	model.BuiltinIdentityAdmin: {},
	model.BuiltinSecurityAdmin: {},
}

var (
	// ErrMappingRoleNotDirectMappable 目標角色不在直接映射 allowlist。
	ErrMappingRoleNotDirectMappable = &PrincipalError{Code: apierror.CodeMappingRoleNotDirectMappable, Status: 400}
	// ErrMappingScopeFieldRejected 請求帶了範圍或節點欄位。
	ErrMappingScopeFieldRejected = &PrincipalError{Code: apierror.CodeMappingScopeFieldRejected, Status: 400}
)

// MappingScopeFields 映射請求不接受的範圍欄位。欄位只用來偵測：出現任何一個即整筆拒絕，
// 值不被使用（映射規則本身沒有範圍，範圍只在使用者群組的角色指派上設定）。
type MappingScopeFields struct {
	Nodes      json.RawMessage `json:"nodes,omitempty"`
	NodeIDs    json.RawMessage `json:"node_ids,omitempty"`
	Scope      json.RawMessage `json:"scope,omitempty"`
	ScopeKind  json.RawMessage `json:"scope_kind,omitempty"`
	ScopeNodes json.RawMessage `json:"scope_nodes,omitempty"`
}

func rawPresent(r json.RawMessage) bool { return len(r) > 0 && string(r) != "null" }

// Present 請求是否帶了任何範圍欄位。
func (f MappingScopeFields) Present() bool {
	return rawPresent(f.Nodes) || rawPresent(f.NodeIDs) || rawPresent(f.Scope) ||
		rawPresent(f.ScopeKind) || rawPresent(f.ScopeNodes)
}

// SetAssignmentGuard 注入共用指派關卡（與使用者服務共用同一個，含組裝時的目標集合）。
func (s *IdentitySourceService) SetAssignmentGuard(g *AssignmentGuard) { s.guard = g }

// SetGrantGrader 注入規則寫入的授權變更分級與留痕。
func (s *IdentitySourceService) SetGrantGrader(g *GrantGrader) { s.grader = g }

// GrantGraderReady 組裝根啟動自檢：授權變更分級與留痕已注入。
func (s *IdentitySourceService) GrantGraderReady() error {
	// 規則寫入還要餵危險組合預覽：缺注入時規則照常成立卻沒有預覽輸入，所以同樣在啟動時拒絕。
	if s.grader == nil || sinkMissing(s.grader.auditTx) || sinkMissing(s.grader.alerts) || sinkMissing(s.grader.preview) {
		return fmt.Errorf("身分來源管理服務: %w", ErrGrantGraderMissing)
	}
	return nil
}

// GrantGraderReady 組裝根啟動自檢：釘住的授權變更分級與留痕已注入。
func (s *UserService) GrantGraderReady() error {
	if s.grader == nil || sinkMissing(s.grader.auditTx) || sinkMissing(s.grader.alerts) {
		return fmt.Errorf("使用者服務: %w", ErrGrantGraderMissing)
	}
	return nil
}

// ErrGrantGraderMissing 授權變更分級與留痕缺注入。
var ErrGrantGraderMissing = errors.New("授權變更分級與留痕未注入")

func (s *IdentitySourceService) assignmentGuard() *AssignmentGuard {
	if s.guard == nil {
		return NewAssignmentGuard(nil)
	}
	return s.guard
}

func mappingOperator(a GroupRoleMappingActor) Operator {
	return Operator{UserID: a.ID, Username: a.Name, ClientIP: a.IP}
}

// mappingDirectRole 以名稱取直接映射的目標角色。
//
// 判定順序：查無 → 內建鍵不在 allowlist（含自訂角色）→ 不在組裝注入的目標集合。
// 前兩者的區別對操作者有意義（引導改用使用者群組）；目標集合外的角色對操作者等同不存在，
// 沿用既有的未知角色碼，不洩漏角色存在與否。
func (s *IdentitySourceService) mappingDirectRole(tx *gorm.DB, name string) (*model.Role, error) {
	rows := []model.Role{}
	v := strings.TrimSpace(name)
	if v == "" {
		return nil, ErrMappingRoleUnknown
	}
	if err := tx.Where("name = ?", v).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrMappingRoleUnknown
	}
	r := rows[0]
	if !roleDirectMappable(r) {
		return nil, ErrMappingRoleNotDirectMappable
	}
	if !s.assignmentGuard().Catalog().Allows(r) {
		return nil, ErrMappingRoleUnknown
	}
	return &r, nil
}

// guardMappingTargets 在來源鎖內對規則的舊值與新值各做一次關卡裁決。
//
// oldRoleIDs 是被取代或收回的舊目標（收回方向，不做目錄檢查，既有規則不因目錄收斂被擋）；
// newRoleIDs 是新目標（授予方向）。兩者任一為保護目標，非超級管理者即被關卡拒絕；
// 兩者都為空時仍會檢查指派能力（不持有者一律拒絕）。
func (s *IdentitySourceService) guardMappingTargets(tx *gorm.DB, actor GroupRoleMappingActor, oldRoleIDs, newRoleIDs []uint) error {
	g := s.assignmentGuard()
	op := mappingOperator(actor)
	checked := false
	if len(oldRoleIDs) > 0 {
		checked = true
		if err := g.Check(tx, op, AssignmentChange{Path: PathMapping, OldRoleIDs: oldRoleIDs}); err != nil {
			return err
		}
	}
	if len(newRoleIDs) > 0 {
		checked = true
		if err := g.Check(tx, op, AssignmentChange{Path: PathMapping, NewRoleIDs: newRoleIDs}); err != nil {
			return err
		}
	}
	if !checked {
		return g.Check(tx, op, AssignmentChange{Path: PathMapping})
	}
	return nil
}

// groupRoleIDs 使用者群組目前直接帶的角色。
func groupRoleIDs(tx *gorm.DB, groupID uint) ([]uint, error) {
	if groupID == 0 {
		return nil, nil
	}
	return authz.UserGroupRoleIDs(tx, groupID)
}
