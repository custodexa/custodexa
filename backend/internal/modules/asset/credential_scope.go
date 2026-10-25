package asset

import (
	"context"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 憑證庫的範圍化讀取投影（消費者側窄介面；asset 不匯入 authz）。
//
// 範圍化檢視者的列表、計數、搜尋與篩選在服務查詢內先套範圍條件，其後才切頁與做輪替狀態篩選；
// 掛載數、掛載清單與刪除名單只計、只列範圍內的資產，範圍外只給台數；列與掛載列附伺服器逐項判定的
// 動作旗標與不含名稱的原因碼。旗標只決定畫面，每個寫入端點仍由伺服器自行裁決。

// 列級旗標的原因碼。
const (
	CredentialActionNoCapability = "no_capability"
	CredentialActionOutOfScope   = "out_of_scope"
)

// CredentialAction 一個動作的可操作結果。
type CredentialAction struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// CredentialScopeView 範圍化檢視者的投影來源（以請求主體建立）。
type CredentialScopeView interface {
	// ApplyVisible 把檢視集合加到以 credentials 為主表的查詢上。
	ApplyVisible(q *gorm.DB) (*gorm.DB, error)
	// AssetsInView ids 中落在檢視集合內的資產。
	AssetsInView(ids []uint) (map[uint]bool, error)
	// AssetsInCapability ids 中落在該動作能力有效範圍內的資產。
	AssetsInCapability(capability string, ids []uint) (map[uint]bool, error)
	// Allows 動作能力對一組涵蓋節點是否可操作；原因為受控碼。
	Allows(capability string, nodeIDs []uint) (bool, string)
	// MaskNodes 依檢視範圍遮蔽資產歸屬：回範圍內節點（原順序）與範圍外筆數（與資產頁同一判定）。
	MaskNodes(nodeIDs []uint) ([]uint, int)
}

// CredentialScopeSource 建立投影；非範圍化檢視者回 (nil, nil)。
type CredentialScopeSource interface {
	CredentialScopeView(ctx context.Context) (CredentialScopeView, error)
	// CredentialImpactScopeIn 在呼叫端的交易內（持有憑證列鎖時用，不另開連線）判定 ids 中落在該動作能力範圍內、
	// 與落在檢視集合內的資產；不留存交易句柄。非範圍化檢視者回 scoped 為假。
	CredentialImpactScopeIn(ctx context.Context, tx *gorm.DB, capability string, ids []uint) (inCapability, inView map[uint]bool, scoped bool, err error)
}

// WithScopeSource 注入憑證庫範圍化投影來源（組裝根）。未注入＝不帶範圍化欄位。
func (s *CredentialService) WithScopeSource(src CredentialScopeSource) *CredentialService {
	s.scope = src
	return s
}

func (s *CredentialService) scopeView(ctx context.Context) (CredentialScopeView, error) {
	if s.scope == nil {
		return nil, nil
	}
	return s.scope.CredentialScopeView(ctx)
}

// CredentialOwnershipDTO 回應中的管理歸屬。
type CredentialOwnershipDTO struct {
	Kind   string `json:"kind"`
	NodeID *uint  `json:"node_id,omitempty"`
}

func ownershipDTOOf(c *model.Credential) *CredentialOwnershipDTO {
	if c.OwnerKind == nil {
		return nil
	}
	out := &CredentialOwnershipDTO{Kind: *c.OwnerKind}
	if c.OwnerNodeID != nil {
		id := *c.OwnerNodeID
		out.NodeID = &id
	}
	return out
}

// 憑證列動作鍵與其能力。
var credentialActionCaps = []struct{ key, cap string }{
	{"edit", CredCapUpdate},
	{"set_secret", CredCapSetSecret},
	{"rotate", CredCapRotate},
	{"bind", CredCapBind},
	{"convert_scope", CredCapConvertScope},
	{"reassign", CredCapUpdate},
	{"delete", CredCapDelete},
}

// decorateScoped 範圍化檢視者的列投影：掛載數只計範圍內、範圍外台數、列級旗標。
// dtos 與 creds 等長同序；所有查詢批次進行，不逐列查。
func (s *CredentialService) decorateScoped(db *gorm.DB, view CredentialScopeView,
	creds []model.Credential, dtos []*CredentialDTO) error {

	if len(creds) == 0 {
		return nil
	}
	ids := make([]uint, 0, len(creds))
	for i := range creds {
		ids = append(ids, creds[i].ID)
	}
	var mounts []model.AssetAccount
	// 依掛載 id 排序：每筆憑證的第一個元素即最早一筆掛載（專用憑證的歸屬判定口徑）
	if err := db.Select("id", "credential_id", "asset_id").Where("credential_id IN ?", ids).
		Order("id ASC").Find(&mounts).Error; err != nil {
		return err
	}
	mountAssets := map[uint][]uint{}
	var assetIDs []uint
	for _, m := range mounts {
		mountAssets[m.CredentialID] = append(mountAssets[m.CredentialID], m.AssetID)
		assetIDs = append(assetIDs, m.AssetID)
	}
	inView, err := view.AssetsInView(uniqueSortedIDs(assetIDs))
	if err != nil {
		return err
	}
	nodes, err := NodeIDsOfAssets(db, uniqueSortedIDs(assetIDs))
	if err != nil {
		return err
	}
	for i := range creds {
		c, dto := &creds[i], dtos[i]
		in, out := 0, 0
		for _, a := range mountAssets[c.ID] {
			if inView[a] {
				in++
			} else {
				out++
			}
		}
		dto.BindingCount = in
		n := out
		dto.OutOfScopeAssets = &n
		dto.Actions = scopedRowActions(view, c, mountAssets[c.ID], nodes)
	}
	return nil
}

// credentialOwnerNodes 憑證歸屬的涵蓋節點：節點歸屬為歸屬節點，專用為最早一筆掛載資產的節點
// （與單筆解析同一口徑；mountAssets 依掛載 id 升冪），全域為空。
func credentialOwnerNodes(c *model.Credential, mountAssets []uint, nodes map[uint][]uint) []uint {
	if c.OwnerKind == nil {
		return nil
	}
	switch *c.OwnerKind {
	case model.CredentialOwnerNode:
		if c.OwnerNodeID != nil {
			return []uint{*c.OwnerNodeID}
		}
	case model.CredentialOwnerAsset:
		if len(mountAssets) == 0 {
			return nil
		}
		return append([]uint(nil), nodes[mountAssets[0]]...)
	}
	return nil
}

func scopedRowActions(view CredentialScopeView, c *model.Credential, mountAssets []uint,
	nodes map[uint][]uint) map[string]CredentialAction {

	owner := credentialOwnerNodes(c, mountAssets, nodes)
	out := make(map[string]CredentialAction, len(credentialActionCaps))
	for _, a := range credentialActionCaps {
		ok, reason := view.Allows(a.cap, owner)
		out[a.key] = CredentialAction{Allowed: ok, Reason: reason}
	}
	return out
}

// filterBindingsInView 詳情掛載清單只留範圍內資產，並附 unbind／detach 旗標；回範圍外台數。
func filterBindingsInView(db *gorm.DB, view CredentialScopeView, in []*CredentialBindingDTO) ([]*CredentialBindingDTO, int, error) {
	assetIDs := make([]uint, 0, len(in))
	for _, b := range in {
		assetIDs = append(assetIDs, b.AssetID)
	}
	assetIDs = uniqueSortedIDs(assetIDs)
	inView, err := view.AssetsInView(assetIDs)
	if err != nil {
		return nil, 0, err
	}
	nodes, err := NodeIDsOfAssets(db, assetIDs)
	if err != nil {
		return nil, 0, err
	}
	out := make([]*CredentialBindingDTO, 0, len(in))
	outside := 0
	for _, b := range in {
		if !inView[b.AssetID] {
			outside++
			continue
		}
		unbind, ur := view.Allows(CredCapBind, nodes[b.AssetID])
		detach, dr := view.Allows(CredCapDetach, nodes[b.AssetID])
		b.Actions = map[string]CredentialAction{
			"unbind": {Allowed: unbind, Reason: ur},
			"detach": {Allowed: detach, Reason: dr},
		}
		out = append(out, b)
	}
	return out, outside, nil
}

// projectBindingNodes 掛載列的所屬節點路徑（與資產列表同一路徑投影）。範圍化檢視者只帶檢視範圍內的
// 歸屬並記下範圍外筆數；view 為 nil 時帶全部歸屬。
func projectBindingNodes(db *gorm.DB, view CredentialScopeView, bindings []*CredentialBindingDTO) error {
	if len(bindings) == 0 {
		return nil
	}
	assetIDs := make([]uint, 0, len(bindings))
	for _, b := range bindings {
		assetIDs = append(assetIDs, b.AssetID)
	}
	nodes, err := NodeIDsOfAssets(db, uniqueSortedIDs(assetIDs))
	if err != nil {
		return err
	}
	paths, err := NodePathMap(db)
	if err != nil {
		return err
	}
	for _, b := range bindings {
		owned := nodes[b.AssetID]
		if view != nil {
			in, out := view.MaskNodes(owned)
			owned = in
			b.OutOfScopeNodes = &out
		}
		ps := make([]string, 0, len(owned))
		for _, id := range owned {
			ps = append(ps, paths[id])
		}
		b.NodePaths = ps
	}
	return nil
}
