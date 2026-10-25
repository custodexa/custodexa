package asset

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 單台存取政策覆寫清單（唯讀）：依存取政策權限點的範圍投影列出已覆寫資產，或以搜尋列出可加入覆寫的資產。
//
// 範圍只依存取政策權限點的有效指派：集合在覆寫條件、搜尋、計數與分頁之前套到查詢上，
// 歸屬節點以同一份物化範圍遮蔽並計範圍外筆數。資產管理可視與連線授權不擴大結果。
// asset 不 import authz：投影經消費者側窄介面取得，由組裝根注入 authz 的實作。

// AccessPolicyProjection 一次請求內存取政策權限點的範圍投影。
type AccessPolicyProjection interface {
	// Scoped 檢視者的範圍不是不限（只經節點範圍指派持有）。
	Scoped() bool
	// ApplyAssets 把集合加到以 assets 為主表的查詢上（分頁與計數之前呼叫）。
	ApplyAssets(q *gorm.DB) (*gorm.DB, error)
	// SplitNodes 資產歸屬分成範圍內（原順序）與範圍外筆數。
	SplitNodes(nodeIDs []uint) ([]uint, int)
}

// AccessPolicyOverrideScopePort 覆寫清單的範圍投影來源；主體由呼叫方放在 ctx（本模組不讀取）。
type AccessPolicyOverrideScopePort interface {
	AccessPolicyProjection(ctx context.Context, db *gorm.DB) (AccessPolicyProjection, error)
}

// ErrAccessPolicyOverrideScopeMissing 覆寫清單的範圍投影未注入：寧可拒絕，也不在沒有投影的情況下列出資產。
var ErrAccessPolicyOverrideScopeMissing = errors.New("asset: access policy override scope port not injected")

// SetAccessPolicyOverrideScopePort 注入覆寫清單的範圍投影（組裝時）。
func (s *AssetService) SetAccessPolicyOverrideScopePort(p AccessPolicyOverrideScopePort) {
	s.overrideScope = p
}

// AccessPolicyOverrideMaxPageSize 覆寫清單單頁上限。
const AccessPolicyOverrideMaxPageSize = 1000

const accessPolicyOverrideDefaultPageSize = 20

// AccessPolicyOverrideQuery 覆寫清單查詢條件。
type AccessPolicyOverrideQuery struct {
	// Overridden 為真列已覆寫資產；為假列可加入覆寫的未覆寫資產（須帶 Search，空搜尋回空集合）。
	Overridden bool
	Search     string
	Page       int
	PageSize   int
}

// AccessPolicyOverrideRow 一筆資產；NodeIDs 與 NodePaths 只含範圍內歸屬（同序）。
type AccessPolicyOverrideRow struct {
	ID           uint
	Name         string
	Protocol     model.ProtocolType
	AccessPolicy *string
	NodeIDs      []uint
	NodePaths    []string
	// OutOfScopeNodes 範圍外歸屬筆數（只在 Scoped 為真時有意義）
	OutOfScopeNodes int
}

// AccessPolicyOverridePage 一頁結果。
type AccessPolicyOverridePage struct {
	Rows     []AccessPolicyOverrideRow
	Total    int64
	Page     int
	PageSize int
	// GlobalDefault 目前已儲存的全系統預設段位（只讀值）
	GlobalDefault string
	// Scoped 檢視者只經節點範圍指派持有存取政策權限點
	Scoped bool
}

func normalizeOverridePaging(q *AccessPolicyOverrideQuery) {
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize < 1 {
		q.PageSize = accessPolicyOverrideDefaultPageSize
	}
	if q.PageSize > AccessPolicyOverrideMaxPageSize {
		q.PageSize = AccessPolicyOverrideMaxPageSize
	}
}

// ListAccessPolicyOverrides 依存取政策權限點的範圍投影列出覆寫清單。
func (s *AssetService) ListAccessPolicyOverrides(ctx context.Context, q AccessPolicyOverrideQuery) (*AccessPolicyOverridePage, error) {
	if s.overrideScope == nil {
		return nil, ErrAccessPolicyOverrideScopeMissing
	}
	if s.accessDefaults == nil {
		return nil, ErrAccessPolicyDefaultMissing
	}
	normalizeOverridePaging(&q)
	q.Search = strings.TrimSpace(q.Search)
	db := database.DB.WithContext(ctx)
	proj, err := s.overrideScope.AccessPolicyProjection(ctx, db)
	if err != nil {
		return nil, err
	}
	page := &AccessPolicyOverridePage{Rows: []AccessPolicyOverrideRow{}, Page: q.Page, PageSize: q.PageSize,
		GlobalDefault: s.accessDefaults.Get(policy.PolicyAccessPolicyDefault), Scoped: proj.Scoped()}
	if !q.Overridden && q.Search == "" {
		return page, nil
	}
	query, err := proj.ApplyAssets(db.Model(&model.Asset{}))
	if err != nil {
		return nil, err
	}
	if q.Overridden {
		query = query.Where("assets.access_policy IS NOT NULL AND assets.access_policy <> ''")
	} else {
		query = query.Where("(assets.access_policy IS NULL OR assets.access_policy = '')")
	}
	if q.Search != "" {
		pattern := "%" + strings.ToLower(q.Search) + "%"
		query = query.Where("(LOWER(assets.name) LIKE ? OR LOWER(assets.host) LIKE ?)", pattern, pattern)
	}
	if err := query.Count(&page.Total).Error; err != nil {
		return nil, fmt.Errorf("查詢覆寫清單總數失敗: %w", err)
	}
	var assets []model.Asset
	if err := query.Select("assets.id", "assets.name", "assets.protocol", "assets.access_policy").
		Order("assets.name ASC, assets.id ASC").Offset((q.Page - 1) * q.PageSize).Limit(q.PageSize).
		Find(&assets).Error; err != nil {
		return nil, fmt.Errorf("查詢覆寫清單失敗: %w", err)
	}
	if len(assets) == 0 {
		return page, nil
	}
	rows, err := overrideRows(db, proj, assets)
	if err != nil {
		return nil, err
	}
	page.Rows = rows
	return page, nil
}

// AccessPolicyOverrideRowOf 一台資產在請求主體存取政策權限點投影下的清單列（與覆寫清單同一投影與遮蔽）。
// scoped 為假表示主體不受該權限點的範圍限縮，此時不回列、呼叫方沿用原回應形狀。
// 供只含存取政策的更新回應使用：歸屬只出範圍內節點與範圍外筆數。
func (s *AssetService) AccessPolicyOverrideRowOf(ctx context.Context, id uint) (*AccessPolicyOverrideRow, bool, error) {
	if s.overrideScope == nil {
		return nil, false, ErrAccessPolicyOverrideScopeMissing
	}
	db := database.DB.WithContext(ctx)
	proj, err := s.overrideScope.AccessPolicyProjection(ctx, db)
	if err != nil {
		return nil, false, err
	}
	if !proj.Scoped() {
		return nil, false, nil
	}
	var assets []model.Asset
	if err := db.Model(&model.Asset{}).Select("id", "name", "protocol", "access_policy").
		Where("id = ?", id).Limit(1).Find(&assets).Error; err != nil {
		return nil, false, fmt.Errorf("查詢資產失敗: %w", err)
	}
	if len(assets) == 0 {
		return nil, false, ErrAssetNotFound
	}
	rows, err := overrideRows(db, proj, assets)
	if err != nil {
		return nil, false, err
	}
	return &rows[0], true, nil
}

// overrideRows 以投影遮蔽每台資產的歸屬：只留範圍內節點（原順序）與其路徑，另計範圍外筆數。
func overrideRows(db *gorm.DB, proj AccessPolicyProjection, assets []model.Asset) ([]AccessPolicyOverrideRow, error) {
	ids := make([]uint, 0, len(assets))
	for _, a := range assets {
		ids = append(ids, a.ID)
	}
	mounts, err := assetNodeIDsFor(db, ids)
	if err != nil {
		return nil, err
	}
	paths, err := NodePathMap(db)
	if err != nil {
		return nil, err
	}
	rows := make([]AccessPolicyOverrideRow, 0, len(assets))
	for _, a := range assets {
		in, out := proj.SplitNodes(mounts[a.ID])
		row := AccessPolicyOverrideRow{ID: a.ID, Name: a.Name, Protocol: a.Protocol, AccessPolicy: a.AccessPolicy,
			NodeIDs: in, NodePaths: make([]string, 0, len(in)), OutOfScopeNodes: out}
		for _, id := range in {
			row.NodePaths = append(row.NodePaths, paths[id])
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// assetNodeIDsFor 多台資產的歸屬節點（依節點 ID 遞增）。
func assetNodeIDsFor(db *gorm.DB, assetIDs []uint) (map[uint][]uint, error) {
	var rows []model.AssetNode
	if err := db.Where("asset_id IN ?", assetIDs).Order("asset_id ASC, node_id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢資產歸屬失敗: %w", err)
	}
	out := make(map[uint][]uint, len(assetIDs))
	for _, r := range rows {
		out[r.AssetID] = append(out[r.AssetID], r.NodeID)
	}
	return out, nil
}
