package asset

import (
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"sync"

	"github.com/custodexa/backend/internal/kernel"
	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// treeStructMu 樹結構變更互斥：
// Move/Delete/Create 的「檢查→寫入」窗口與資產掛載的「節點存在驗證→寫入」
// 窗口皆無 DB 約束兜底（parent_id/asset_nodes 無 FK、環路/深度為跨列不變量），
// 並發交錯可造成環、超深、掛到已刪節點、刪掉非空節點。單體部署（單 backend
// 實例）以進程內互斥消除 TOCTOU——管理操作低頻，鎖成本可忽略
var treeStructMu sync.Mutex

// 節點樹錯誤：handler 以 errors.Is 映射 404/409/400
var (
	ErrGroupNotFound     = errors.New("節點不存在")
	ErrGroupNameExists   = errors.New("同層已有同名節點")
	ErrNodeDepthExceeded = errors.New("節點深度超過上限（10 層）")
	ErrNodeCycle         = errors.New("不可搬移到自身或其子孫節點")
	ErrNodeNotEmpty      = errors.New("僅可刪除無子節點且無直掛資產的空節點")
)

// maxNodeDepth 樹深上限（防失控巢狀）
const maxNodeDepth = 10

// AssetGroupRequest 節點建立/更新請求（分組升級為節點樹；
// 政策欄已移除——政策掛資產本身）。ParentID 僅建立時使用（更新不動位置，
// 搬移走獨立 Move 語義）
type AssetGroupRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	ParentID    *uint  `json:"parent_id"`
}

// AssetGroupService 資產節點樹 CRUD
type AssetGroupService struct {
	db *gorm.DB
	// auditTx 交易內審計落地面：節點結構變更與刪除的留痕與變更同交易，
	// 留痕失敗即回滾（授權涵蓋範圍變更不可無痕）。未注入時寫入回 error，
	// 語義與「審計寫失敗」同格——見 internal/modules/audit/port/txsink.go 的 port.WriteInTx
	auditTx port.TxSink
	// authzRevoker 節點刪除時的 authz 級聯撤銷（tx-taking 窄 port）
	authzRevoker assetGroupAuthorizationRevoker
}

// assetGroupAuthorizationRevoker 節點刪除時對 authz 表的級聯撤銷。
//
// **消費者側窄介面**：asset 不得 import authz（矩陣 asset→authz ✗），
// 故在此宣告意圖、由組裝根注入 authz 的實作。介面刻意**不匯出**——外部呼叫端
// 傳的是具體型別，不需要指名它。
//
// **誠實邊界**：本介面把整個 `*gorm.DB` 交出去，**編譯器管不到對方寫哪張表**
// （白名單見 `cmd/server/tx_taking_whitelist_test.go`）。
type assetGroupAuthorizationRevoker interface {
	RevokeByAssetGroup(tx *gorm.DB, groupID uint) (revokedAuthorizations, revokedApproverScopes int64, err error)
}

// NewAssetGroupService 建立節點樹服務
func NewAssetGroupService(db *gorm.DB, auditTx port.TxSink, authzRevoker assetGroupAuthorizationRevoker) *AssetGroupService {
	return &AssetGroupService{db: db, auditTx: auditTx, authzRevoker: authzRevoker}
}

// List 全部節點（平面列表；樹形導覽用 TreeNode 端點）
func (s *AssetGroupService) List() ([]model.AssetGroup, error) {
	var groups []model.AssetGroup
	if err := s.db.Order("id").Find(&groups).Error; err != nil {
		return nil, err
	}
	return groups, nil
}

// GroupWithAssets 平面節點＋直掛資產 DTO（GET /asset-groups 回應形狀；
// 消費端：授權精靈節點選擇、工作區分節）。Assets＝直掛成員（不含子樹）
type GroupWithAssets struct {
	ID          uint          `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	ParentID    *uint         `json:"parent_id,omitempty"`
	Path        string        `json:"path"`
	Assets      []model.Asset `json:"assets"`
}

// ListWithAssets 全節點＋直掛資產（成員經 asset_nodes M2M）
func (s *AssetGroupService) ListWithAssets() ([]GroupWithAssets, error) {
	groups, err := s.List()
	if err != nil {
		return nil, err
	}
	paths, err := NodePathMap(s.db)
	if err != nil {
		return nil, err
	}

	var members []model.AssetNode
	if err := s.db.Find(&members).Error; err != nil {
		return nil, err
	}
	assetIDs := make([]uint, 0, len(members))
	for _, m := range members {
		assetIDs = append(assetIDs, m.AssetID)
	}
	assetByID := make(map[uint]*model.Asset, len(assetIDs))
	if len(assetIDs) > 0 {
		var assets []model.Asset
		if err := s.db.Where("id IN ?", kernel.DedupeUint(assetIDs)).Find(&assets).Error; err != nil {
			return nil, err
		}
		for i := range assets {
			assetByID[assets[i].ID] = &assets[i]
		}
	}

	byNode := make(map[uint][]model.Asset)
	for _, m := range members {
		if a, ok := assetByID[m.AssetID]; ok {
			byNode[m.NodeID] = append(byNode[m.NodeID], *a)
		}
	}

	result := make([]GroupWithAssets, 0, len(groups))
	for _, g := range groups {
		assets := byNode[g.ID]
		if assets == nil {
			assets = []model.Asset{}
		}
		result = append(result, GroupWithAssets{
			ID:          g.ID,
			Name:        g.Name,
			Description: g.Description,
			ParentID:    g.ParentID,
			Path:        paths[g.ID],
			Assets:      assets,
		})
	}
	return result, nil
}

// TreeNode 樹導覽節點 DTO
type TreeNode struct {
	ID                uint   `json:"id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	ParentID          *uint  `json:"parent_id,omitempty"`
	Path              string `json:"path"`
	AssetCount        int64  `json:"asset_count"`         // 直掛資產數
	SubtreeAssetCount int64  `json:"subtree_asset_count"` // 含子樹資產數（去重）
	HasChildren       bool   `json:"has_children"`
}

// TreeVisibility 樹收斂範圍：nil＝全量（admin/auditor）。
// NodeIDs＝可視節點鏈；AssetIDs＝可視資產集——計數與 has_children 同受收斂
// （僅過濾節點不過濾計數，會經 subtree_asset_count 洩漏
// 隱藏子樹的未授權資產數量與結構存在性）
type TreeVisibility struct {
	NodeIDs  map[uint]bool
	AssetIDs map[uint]bool
}

// Tree 樹導覽：parentID nil＝根層，非 nil＝該節點子層
func (s *AssetGroupService) Tree(parentID *uint, vis *TreeVisibility) ([]TreeNode, error) {
	q := s.db.Model(&model.AssetGroup{}).Order("name")
	if parentID == nil {
		q = q.Where("parent_id IS NULL")
	} else {
		q = q.Where("parent_id = ?", *parentID)
	}
	var nodes []model.AssetGroup
	if err := q.Find(&nodes).Error; err != nil {
		return nil, err
	}

	paths, err := NodePathMap(s.db)
	if err != nil {
		return nil, err
	}

	visibleAssetIDs := []uint{}
	if vis != nil {
		for id := range vis.AssetIDs {
			visibleAssetIDs = append(visibleAssetIDs, id)
		}
	}

	result := make([]TreeNode, 0, len(nodes))
	for _, n := range nodes {
		if vis != nil && !vis.NodeIDs[n.ID] {
			continue
		}
		tn := TreeNode{
			ID:          n.ID,
			Name:        n.Name,
			Description: n.Description,
			ParentID:    n.ParentID,
			Path:        paths[n.ID],
		}

		directQ := s.db.Model(&model.AssetNode{}).
			Joins("JOIN assets ON assets.id = asset_nodes.asset_id AND assets.deleted_at IS NULL").
			Where("asset_nodes.node_id = ?", n.ID)
		if vis != nil {
			directQ = directQ.Where("asset_nodes.asset_id IN ?", emptySafeIDs(visibleAssetIDs))
		}
		if err := directQ.Count(&tn.AssetCount).Error; err != nil {
			return nil, err
		}

		subtreeSQL := `SELECT COUNT(DISTINCT an.asset_id) FROM asset_nodes an
			JOIN assets a ON a.id = an.asset_id AND a.deleted_at IS NULL
			WHERE an.node_id IN (
				WITH RECURSIVE sub(id) AS (
					SELECT id FROM asset_groups WHERE id = ? AND deleted_at IS NULL
					UNION
					SELECT g.id FROM asset_groups g JOIN sub ON g.parent_id = sub.id
					WHERE g.deleted_at IS NULL
				) SELECT id FROM sub
			)`
		var subtreeErr error
		if vis != nil {
			subtreeErr = s.db.Raw(subtreeSQL+" AND an.asset_id IN ?", n.ID, emptySafeIDs(visibleAssetIDs)).
				Scan(&tn.SubtreeAssetCount).Error
		} else {
			subtreeErr = s.db.Raw(subtreeSQL, n.ID).Scan(&tn.SubtreeAssetCount).Error
		}
		if subtreeErr != nil {
			return nil, subtreeErr
		}

		childQ := s.db.Model(&model.AssetGroup{}).Where("parent_id = ?", n.ID)
		if vis != nil {
			visibleNodeIDList := make([]uint, 0, len(vis.NodeIDs))
			for id := range vis.NodeIDs {
				visibleNodeIDList = append(visibleNodeIDList, id)
			}
			childQ = childQ.Where("id IN ?", emptySafeIDs(visibleNodeIDList))
		}
		var childCount int64
		if err := childQ.Count(&childCount).Error; err != nil {
			return nil, err
		}
		tn.HasChildren = childCount > 0
		result = append(result, tn)
	}
	return result, nil
}

// emptySafeIDs GORM `IN ?` 對空 slice 產生恆假條件需要非空集——以不可能的
// id 0 佔位（資產/節點 id 自 1 起）
func emptySafeIDs(ids []uint) []uint {
	if len(ids) == 0 {
		return []uint{0}
	}
	return ids
}

// nodeDepthTx 節點深度（根＝1）；環防禦：走訪逾上限即以超限計。
// 吃 tx——結構檢查與寫入同交易（treeStructMu 互斥下讀到即最新）
func nodeDepthTx(tx *gorm.DB, id uint) (int, error) {
	depth := 0
	cur := &id
	for cur != nil {
		depth++
		if depth > maxNodeDepth {
			return depth, nil
		}
		var node model.AssetGroup
		if err := tx.Select("parent_id").First(&node, *cur).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return 0, ErrGroupNotFound
			}
			return 0, err
		}
		cur = node.ParentID
	}
	return depth, nil
}

// subtreeHeightTx 子樹高度（自身＝1）：搬移深度重驗用
func subtreeHeightTx(tx *gorm.DB, id uint) (int, error) {
	var height int
	err := tx.Raw(`WITH RECURSIVE sub(id, lvl) AS (
		SELECT id, 1 FROM asset_groups WHERE id = ? AND deleted_at IS NULL
		UNION ALL
		SELECT g.id, sub.lvl + 1 FROM asset_groups g JOIN sub ON g.parent_id = sub.id
		WHERE g.deleted_at IS NULL AND sub.lvl < ?
	) SELECT COALESCE(MAX(lvl), 1) FROM sub`, id, maxNodeDepth+1).Scan(&height).Error
	if err != nil {
		return 0, err
	}
	return height, nil
}

// isDescendantTx 判 candidate 是否為 root 的子孫（含自身）——環路檢查
func isDescendantTx(tx *gorm.DB, root, candidate uint) (bool, error) {
	if root == candidate {
		return true, nil
	}
	var count int64
	err := tx.Raw(`WITH RECURSIVE sub(id) AS (
		SELECT id FROM asset_groups WHERE id = ? AND deleted_at IS NULL
		UNION
		SELECT g.id FROM asset_groups g JOIN sub ON g.parent_id = sub.id
		WHERE g.deleted_at IS NULL
	) SELECT COUNT(*) FROM sub WHERE id = ?`, root, candidate).Scan(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// siblingNameExistsTx 同層同名預檢（唯一索引兜底並發窗）
func siblingNameExistsTx(tx *gorm.DB, parentID *uint, name string, excludeID uint) (bool, error) {
	q := tx.Model(&model.AssetGroup{}).Where("name = ?", name)
	if parentID == nil {
		q = q.Where("parent_id IS NULL")
	} else {
		q = q.Where("parent_id = ?", *parentID)
	}
	if excludeID != 0 {
		q = q.Where("id <> ?", excludeID)
	}
	var count int64
	if err := q.Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// nodeAudit 節點結構變更審計（搬移/建立/改名即授權
// 涵蓋範圍變更，須留痕可追溯）；與變更同交易——審計失敗即回滾。
//
// **收口**：原為自由函式直寫 `tx.Create(&model.AuditLog{...})`，改為經
// audit 模組的 TxSink（AP-36）。改掛型別方法只為取得 s.auditTx，三個呼叫點
// （Create／Update／Move）都已在 *AssetGroupService 的方法內，呼叫形態不變、
// 錯誤包裝詞不變、回滾語義不變。
func (s *AssetGroupService) nodeAudit(tx *gorm.DB, action model.AuditAction, nodeID uint, actorID uint, actorName, clientIP, details string) error {
	// **AssetID 刻意留空**（auditor-workbench）：ResourceID 是**節點 id**，不是資產 id。
	// 節點建立／改名／搬移一次影響其下全部資產，沒有單一主體可釘；把 nodeID 填進
	// asset_id 等於宣稱「這件事發生在編號相同的那台資產上」——那正是資產樞紐要消滅的假事件。
	if err := port.WriteInTx(s.auditTx, tx, port.AuditEvent{
		Action:     string(action),
		Resource:   string(model.ResourceAsset),
		ResourceID: &nodeID,
		Status:     string(model.StatusSuccess),
		Actor:      gatewayapi.Actor{UserID: actorID, Username: actorName},
		Request:    gatewayapi.RequestMeta{ClientIP: clientIP},
		Details:    details,
	}); err != nil {
		return fmt.Errorf("審計留痕失敗: %w", err)
	}
	return nil
}

// Create 建立節點（任意層，深度上限 10、同層同名 409）；審計留痕
func (s *AssetGroupService) Create(req *AssetGroupRequest, actorID uint, actorName, clientIP string) (*model.AssetGroup, error) {
	treeStructMu.Lock()
	defer treeStructMu.Unlock()

	group := &model.AssetGroup{Name: req.Name, Description: req.Description, ParentID: req.ParentID}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if req.ParentID != nil {
			parentDepth, err := nodeDepthTx(tx, *req.ParentID)
			if err != nil {
				return err
			}
			if parentDepth+1 > maxNodeDepth {
				return ErrNodeDepthExceeded
			}
		}
		if exists, err := siblingNameExistsTx(tx, req.ParentID, req.Name, 0); err != nil {
			return err
		} else if exists {
			return ErrGroupNameExists
		}
		if err := tx.Create(group).Error; err != nil {
			if dberr.IsUniqueViolation(err) {
				return ErrGroupNameExists
			}
			return err
		}
		return s.nodeAudit(tx, model.ActionCreate, group.ID, actorID, actorName, clientIP,
			fmt.Sprintf(`{"asset_node_name":%q,"parent_id":%v}`, group.Name, ptrOrNull(req.ParentID)))
	})
	if err != nil {
		return nil, err
	}
	return group, nil
}

// Update 更新節點名稱/描述（位置不動——搬移走 Move）；改名入審計
func (s *AssetGroupService) Update(id uint, req *AssetGroupRequest, actorID uint, actorName, clientIP string) (*model.AssetGroup, error) {
	treeStructMu.Lock()
	defer treeStructMu.Unlock()

	var group model.AssetGroup
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&group, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrGroupNotFound
			}
			return err
		}
		if exists, err := siblingNameExistsTx(tx, group.ParentID, req.Name, id); err != nil {
			return err
		} else if exists {
			return ErrGroupNameExists
		}
		oldName := group.Name
		group.Name = req.Name
		group.Description = req.Description
		if err := tx.Save(&group).Error; err != nil {
			if dberr.IsUniqueViolation(err) {
				return ErrGroupNameExists
			}
			return err
		}
		if oldName == req.Name {
			return nil // 僅描述變更不留痕（不影響授權涵蓋與路徑）
		}
		return s.nodeAudit(tx, model.ActionUpdate, group.ID, actorID, actorName, clientIP,
			fmt.Sprintf(`{"asset_node_rename":{"old":%q,"new":%q}}`, oldName, req.Name))
	})
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// Move 搬移節點：環路檢查（目標不得在自身子樹內）、
// 深度重驗（搬移後整棵子樹不得超限）、同層同名 409；treeStructMu 消除
// 並發互搬建環/超深窗口。搬移即子樹授權涵蓋變更，入審計。
// newParentID nil＝搬到根層
func (s *AssetGroupService) Move(id uint, newParentID *uint, actorID uint, actorName, clientIP string) (*model.AssetGroup, error) {
	treeStructMu.Lock()
	defer treeStructMu.Unlock()

	var group model.AssetGroup
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&group, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrGroupNotFound
			}
			return err
		}
		oldParent := group.ParentID

		targetDepth := 0
		if newParentID != nil {
			descendant, err := isDescendantTx(tx, id, *newParentID)
			if err != nil {
				return err
			}
			if descendant {
				return ErrNodeCycle
			}
			parentDepth, err := nodeDepthTx(tx, *newParentID)
			if err != nil {
				return err
			}
			targetDepth = parentDepth
		}
		height, err := subtreeHeightTx(tx, id)
		if err != nil {
			return err
		}
		if targetDepth+height > maxNodeDepth {
			return ErrNodeDepthExceeded
		}
		if exists, err := siblingNameExistsTx(tx, newParentID, group.Name, id); err != nil {
			return err
		} else if exists {
			return ErrGroupNameExists
		}

		// parent_id 單欄更新（CTE 表示法紅利：無 materialized key 需重寫後代）
		if err := tx.Model(&group).Update("parent_id", newParentID).Error; err != nil {
			if dberr.IsUniqueViolation(err) {
				return ErrGroupNameExists
			}
			return err
		}
		return s.nodeAudit(tx, model.ActionUpdate, group.ID, actorID, actorName, clientIP,
			fmt.Sprintf(`{"asset_node_move":{"name":%q,"old_parent_id":%v,"new_parent_id":%v}}`,
				group.Name, ptrOrNull(oldParent), ptrOrNull(newParentID)))
	})
	if err != nil {
		return nil, err
	}
	group.ParentID = newParentID
	return &group, nil
}

// ptrOrNull 審計 JSON 的 *uint 呈現（nil＝null）
func ptrOrNull(v *uint) interface{} {
	if v == nil {
		return "null"
	}
	return *v
}

// Delete 刪除節點：僅「無子節點且無直掛資產」可刪
// （防誤刪大子樹）；掛該節點的授權與 approver 審核範圍
// 連動軟刪＋審計留痕同交易。回傳連動撤銷的授權筆數。
// treeStructMu 消除「空節點判定後並發掛載/建子」窗口
func (s *AssetGroupService) Delete(id uint, actorID uint, actorName, clientIP string) (int64, error) {
	treeStructMu.Lock()
	defer treeStructMu.Unlock()

	var revoked int64
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var group model.AssetGroup
		if err := tx.First(&group, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrGroupNotFound
			}
			return err
		}

		var childCount int64
		if err := tx.Model(&model.AssetGroup{}).Where("parent_id = ?", id).Count(&childCount).Error; err != nil {
			return err
		}
		var memberCount int64
		if err := tx.Model(&model.AssetNode{}).Where("node_id = ?", id).Count(&memberCount).Error; err != nil {
			return err
		}
		if childCount > 0 || memberCount > 0 {
			return ErrNodeNotEmpty
		}

		// 連動軟刪節點授權與 approver 審核範圍（tx-taking 窄 port）：兩張表皆屬 authz，
		// 故經 tx-taking 窄 port 交由擁有者寫入，asset 不直接碰他模組的表。
		// 未注入即 fail-close——靜默略過會留下幽靈授權與懸掛審核範圍
		if s.authzRevoker == nil {
			return fmt.Errorf("authz 級聯撤銷面未注入：節點刪除不得在不撤銷授權的情況下完成")
		}
		var revokedScopes int64
		var rerr error
		revoked, revokedScopes, rerr = s.authzRevoker.RevokeByAssetGroup(tx, id)
		if rerr != nil {
			return rerr
		}

		if err := tx.Delete(&group).Error; err != nil {
			return err
		}

		groupID := id
		// 收口（AP-37）：留痕與級聯撤銷同交易，寫不進去即整筆回滾
		//（授權撤銷不可無痕）。錯誤包裝詞與收口前逐字相同。
		// **AssetID 刻意留空**（同 nodeAudit）：一次刪節點連動撤掉其下多台資產的授權，
		// 主體是節點而非某一台機器；被撤授權的逐資產事實在 authz 側各自留痕。
		if err := port.WriteInTx(s.auditTx, tx, port.AuditEvent{
			Action:     string(model.ActionDelete),
			Resource:   string(model.ResourceAsset),
			ResourceID: &groupID,
			Status:     string(model.StatusSuccess),
			Actor:      gatewayapi.Actor{UserID: actorID, Username: actorName},
			Request:    gatewayapi.RequestMeta{ClientIP: clientIP},
			Details: fmt.Sprintf(`{"asset_node_name":%q,"revoked_authorizations":%d,"revoked_approver_scopes":%d}`,
				group.Name, revoked, revokedScopes),
		}); err != nil {
			return fmt.Errorf("審計留痕失敗: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return revoked, nil
}
