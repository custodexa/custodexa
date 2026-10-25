package authz

import (
	"cmp"
	"errors"
	"slices"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 節點被角色指派引用的原始關係查詢：節點刪除的引用阻擋與「被搬移子樹含範圍節點只限超級管理者」共用。
//
// 引用＝role_binding_nodes 有一列指向該節點，且其指派紀錄（user_roles 或 user_group_roles）存在。
// 直接查這兩層原始關係，不經主體解析：不看主體是否停用、角色是否含範圍化權限點——停用的主體
// 重新啟用後指派會恢復，若此時節點已刪就成了失效範圍。

// bindingAssignmentExists role_binding_nodes（別名 rbn）的指派紀錄仍存在。
const bindingAssignmentExists = `((rbn.subject_kind = '` + model.BindingSubjectUser + `' AND EXISTS (
		SELECT 1 FROM user_roles ur WHERE ur.user_id = rbn.subject_id AND ur.role_id = rbn.role_id))
	OR (rbn.subject_kind = '` + model.BindingSubjectUserGroup + `' AND EXISTS (
		SELECT 1 FROM user_group_roles gr WHERE gr.user_group_id = rbn.subject_id AND gr.role_id = rbn.role_id)))`

var errNodeReferenceNilTx = errors.New("authz: node scope reference query without transaction")

// NodeScopeReferenceReader 節點刪除前的範圍引用查詢（實作 asset 的消費者側窄介面）。
type NodeScopeReferenceReader struct{}

// NewNodeScopeReferenceReader 建立無狀態的查詢器。
func NewNodeScopeReferenceReader() *NodeScopeReferenceReader { return &NodeScopeReferenceReader{} }

type bindingRef struct {
	SubjectKind string
	SubjectID   uint
	RoleID      uint
}

// NodeScopeReferences 引用該節點的指派（主體種類＋主體＋角色）：Count 為不同指派筆數，Items 依
// （主體種類, 主體, 角色）升冪、去重，附主體名稱、角色名稱與群組成員數。查詢錯誤原樣回傳，
// 呼叫方不得當成沒有引用。
func (r *NodeScopeReferenceReader) NodeScopeReferences(tx *gorm.DB, nodeID uint) (asset.NodeReferences, error) {
	if tx == nil {
		return asset.NodeReferences{}, errNodeReferenceNilTx
	}
	db := tx.Session(&gorm.Session{NewDB: true})
	var refs []bindingRef
	if err := db.Raw(`SELECT DISTINCT rbn.subject_kind, rbn.subject_id, rbn.role_id FROM role_binding_nodes rbn
		WHERE rbn.node_id = ? AND `+bindingAssignmentExists, nodeID).Scan(&refs).Error; err != nil {
		return asset.NodeReferences{}, err
	}
	slices.SortFunc(refs, func(a, b bindingRef) int {
		return cmp.Or(cmp.Compare(a.SubjectKind, b.SubjectKind), cmp.Compare(a.SubjectID, b.SubjectID), cmp.Compare(a.RoleID, b.RoleID))
	})
	refs = slices.Compact(refs)
	out := asset.NodeReferences{Count: len(refs), Items: make([]asset.NodeReference, 0, len(refs))}
	for _, ref := range refs {
		item, err := describeBindingRef(db, ref)
		if err != nil {
			return asset.NodeReferences{}, err
		}
		out.Items = append(out.Items, item)
	}
	return out, nil
}

// describeBindingRef 補主體名稱、角色名稱與群組成員數（只作超級管理者檢視的提示）。
func describeBindingRef(db *gorm.DB, ref bindingRef) (asset.NodeReference, error) {
	item := asset.NodeReference{SubjectKind: ref.SubjectKind, SubjectID: ref.SubjectID, RoleID: ref.RoleID}
	var names []string
	if err := db.Raw(`SELECT name FROM roles WHERE id = ?`, ref.RoleID).Scan(&names).Error; err != nil {
		return item, err
	}
	if len(names) > 0 {
		item.RoleName = names[0]
	}
	names = nil
	switch ref.SubjectKind {
	case model.BindingSubjectUser:
		if err := db.Raw(`SELECT username FROM users WHERE id = ?`, ref.SubjectID).Scan(&names).Error; err != nil {
			return item, err
		}
	case model.BindingSubjectUserGroup:
		if err := db.Raw(`SELECT name FROM user_groups WHERE id = ?`, ref.SubjectID).Scan(&names).Error; err != nil {
			return item, err
		}
		var n int64
		if err := db.Raw(`SELECT COUNT(*) FROM user_group_members WHERE user_group_id = ?`, ref.SubjectID).Scan(&n).Error; err != nil {
			return item, err
		}
		members := int(n)
		item.MemberCount = &members
	}
	if len(names) > 0 {
		item.SubjectName = names[0]
	}
	return item, nil
}

// subtreeHasScopeNodes 以 root 為根的子樹（含自身、只計未刪除節點）內是否有任何指派的範圍節點。
func subtreeHasScopeNodes(tx *gorm.DB, topo ScopeTopology, root uint) (bool, error) {
	db := tx.Session(&gorm.Session{NewDB: true})
	var n int64
	err := db.Raw(`SELECT COUNT(*) FROM role_binding_nodes rbn WHERE rbn.node_id IN (?) AND `+bindingAssignmentExists,
		topo.SubtreeNodeIDs(tx, []uint{root})).Scan(&n).Error
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
