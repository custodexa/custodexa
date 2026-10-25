package authz

import (
	"context"
	"errors"
	"sort"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 授權畫面的有限選擇器：主體目錄與客體候選。
//
//   - 主體目錄：不依節點範圍過濾，但要求檢視者至少有一筆含授權規則管理權限點的有效指派
//     （空範圍或節點全刪的指派不算）；欄位固定，不含信箱、身分來源、多因素與登入紀錄。
//   - 客體候選：一律用授權規則管理能力的集合述詞投影。資產取範圍內資產，節點取範圍子樹
//     （祖先只作定位、不可授權），標籤只取範圍內候選資產上出現過的標籤。
//
// 範圍外的 node_id 篩選與不存在同形（空頁）。本檔不取鎖、不寫表；檢視者一律在讀取連線上重解。

// 選擇器的失敗類別。
var (
	// ErrSelectorCapabilityMissing 檢視者沒有生效的授權規則管理指派。
	ErrSelectorCapabilityMissing = errors.New("authz: authorization selector without effective capability")
	// ErrSelectorUnwired 選擇器缺判定器、拓撲或連線。
	ErrSelectorUnwired = errors.New("authz: authorization selector without evaluator or topology")
)

// 選擇器的種類值。
const (
	SubjectKindUser      = "user"
	SubjectKindUserGroup = "user_group"
	TargetKindAsset      = "asset"
	TargetKindNode       = "node"
	TargetKindTag        = "tag"
)

// SelectorMaxPageSize 單頁筆數上限。
const SelectorMaxPageSize = 1000

// AuthorizationSelectors 授權畫面的選擇器服務。
type AuthorizationSelectors struct {
	db *gorm.DB
	e  *ScopeEvaluator
}

// NewAuthorizationSelectors 建立選擇器；e 為授權規則管理範圍的判定器。
func NewAuthorizationSelectors(db *gorm.DB, e *ScopeEvaluator) *AuthorizationSelectors {
	return &AuthorizationSelectors{db: db, e: e}
}

// SubjectOptionsQuery 主體目錄查詢。
type SubjectOptionsQuery struct {
	Kind     string
	Search   string
	Page     int
	PageSize int
}

// SubjectUserOption 使用者候選（欄位固定）。
type SubjectUserOption struct {
	ID          uint     `json:"id"`
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Kind        string   `json:"kind"`
	Active      bool     `json:"active"`
	Roles       []string `json:"roles"`
}

// SubjectGroupOption 群組候選（欄位固定）。
type SubjectGroupOption struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MemberCount int    `json:"member_count"`
}

// SubjectOptionsPage 主體目錄的一頁；Data 依 Kind 為使用者或群組候選清單。
type SubjectOptionsPage struct {
	Kind     string `json:"kind"`
	Data     any    `json:"data"`
	Total    int64  `json:"total"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

// TargetOptionsQuery 客體候選查詢。
type TargetOptionsQuery struct {
	Kind     string
	Search   string
	NodeID   *uint
	Tags     []string
	Page     int
	PageSize int
}

// TargetNodeRef 資產在範圍內的歸屬節點。
type TargetNodeRef struct {
	ID   uint   `json:"id"`
	Path string `json:"path"`
}

// TargetAssetOption 資產候選；範圍外歸屬節點只給計數，不給名稱與路徑。
type TargetAssetOption struct {
	ID       uint            `json:"id"`
	Name     string          `json:"name"`
	Protocol string          `json:"protocol"`
	Host     string          `json:"host"`
	Nodes    []TargetNodeRef `json:"nodes"`
	*disclosure.NodeCountField
}

// TargetNodeOption 節點候選；Selectable 為假的節點只是定位祖先，不可授權。
type TargetNodeOption struct {
	ID         uint   `json:"id"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	Selectable bool   `json:"selectable"`
}

// TargetTagOption 標籤候選與範圍內使用數。
type TargetTagOption struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// TargetOptionsPage 客體候選的一頁；Data 依 Kind 為資產、節點或標籤候選清單。
type TargetOptionsPage struct {
	Kind     string `json:"kind"`
	Data     any    `json:"data"`
	Total    int64  `json:"total"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

// viewer 在讀取連線上重解檢視者並取授權規則管理能力的集合；沒有生效指派回 ErrSelectorCapabilityMissing。
func (s *AuthorizationSelectors) viewer(ctx context.Context) (*Principal, ScopeSet, error) {
	if s == nil || s.e == nil || s.db == nil {
		return nil, ScopeSet{}, ErrSelectorUnwired
	}
	p, err := s.e.resolveInTx(s.db, PrincipalFromContext(ctx))
	if err != nil {
		return nil, ScopeSet{}, err
	}
	set := scopeSetOn(p, PermAuthorizationManage, sourcesAll)
	switch set.state {
	case ScopeSetUnlimited:
	case ScopeSetConditional:
		if s.e.topo == nil {
			return nil, ScopeSet{}, ErrSelectorUnwired
		}
	default:
		return nil, ScopeSet{}, ErrSelectorCapabilityMissing
	}
	return p, set, nil
}

func clampPage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > SelectorMaxPageSize {
		size = SelectorMaxPageSize
	}
	return page, size
}

func selectorLikePattern(search string) string {
	escaper := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + escaper.Replace(strings.ToLower(strings.TrimSpace(search))) + "%"
}

// SubjectOptions 主體目錄：使用者或群組，搜尋與分頁在資料庫端完成。
func (s *AuthorizationSelectors) SubjectOptions(ctx context.Context, q SubjectOptionsQuery) (*SubjectOptionsPage, error) {
	if _, _, err := s.viewer(ctx); err != nil {
		return nil, err
	}
	page, size := clampPage(q.Page, q.PageSize)
	out := &SubjectOptionsPage{Kind: q.Kind, Page: page, PageSize: size}
	switch q.Kind {
	case SubjectKindUser:
		return s.userOptions(out, q.Search)
	case SubjectKindUserGroup:
		return s.groupOptions(out, q.Search)
	}
	return nil, errors.New("authz: unknown subject option kind")
}

func (s *AuthorizationSelectors) userOptions(out *SubjectOptionsPage, search string) (*SubjectOptionsPage, error) {
	query := s.db.Model(&model.User{})
	if strings.TrimSpace(search) != "" {
		p := selectorLikePattern(search)
		query = query.Where(`(LOWER(users.username) LIKE ? ESCAPE '\' OR LOWER(users.full_name) LIKE ? ESCAPE '\' OR LOWER(users.local_display_name) LIKE ? ESCAPE '\')`, p, p, p)
	}
	if err := query.Count(&out.Total).Error; err != nil {
		return nil, err
	}
	var users []model.User
	if err := query.Select("users.id", "users.username", "users.full_name", "users.local_display_name", "users.kind", "users.active").
		Order("users.id ASC").Offset((out.Page - 1) * out.PageSize).Limit(out.PageSize).Find(&users).Error; err != nil {
		return nil, err
	}
	ids := make([]uint, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	roles := map[uint][]string{}
	if len(ids) > 0 {
		var rows []struct {
			UserID uint
			Name   string
		}
		if err := s.db.Table("user_roles").
			Select("user_roles.user_id AS user_id, roles.name AS name").
			Joins("JOIN roles ON roles.id = user_roles.role_id AND roles.deleted_at IS NULL").
			Where("user_roles.user_id IN ?", ids).Order("roles.name ASC").Scan(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			roles[r.UserID] = append(roles[r.UserID], r.Name)
		}
	}
	data := make([]SubjectUserOption, 0, len(users))
	for i := range users {
		u := &users[i]
		r := roles[u.ID]
		if r == nil {
			r = []string{}
		}
		data = append(data, SubjectUserOption{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName(), Kind: u.Kind, Active: u.Active, Roles: r})
	}
	out.Data = data
	return out, nil
}

func (s *AuthorizationSelectors) groupOptions(out *SubjectOptionsPage, search string) (*SubjectOptionsPage, error) {
	query := s.db.Model(&model.UserGroup{})
	if strings.TrimSpace(search) != "" {
		p := selectorLikePattern(search)
		query = query.Where(`(LOWER(user_groups.name) LIKE ? ESCAPE '\' OR LOWER(user_groups.description) LIKE ? ESCAPE '\')`, p, p)
	}
	if err := query.Count(&out.Total).Error; err != nil {
		return nil, err
	}
	var groups []model.UserGroup
	if err := query.Select("user_groups.id", "user_groups.name", "user_groups.description").
		Order("user_groups.id ASC").Offset((out.Page - 1) * out.PageSize).Limit(out.PageSize).Find(&groups).Error; err != nil {
		return nil, err
	}
	ids := make([]uint, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	counts := map[uint]int{}
	if len(ids) > 0 {
		var rows []struct {
			GroupID uint
			N       int
		}
		if err := s.db.Table("user_group_members AS m").
			Select("m.user_group_id AS group_id, COUNT(*) AS n").
			Joins("JOIN users u ON u.id = m.user_id AND u.deleted_at IS NULL").
			Where("m.user_group_id IN ?", ids).Group("m.user_group_id").Scan(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			counts[r.GroupID] = r.N
		}
	}
	data := make([]SubjectGroupOption, 0, len(groups))
	for _, g := range groups {
		data = append(data, SubjectGroupOption{ID: g.ID, Name: g.Name, Description: g.Description, MemberCount: counts[g.ID]})
	}
	out.Data = data
	return out, nil
}

// TargetOptions 客體候選：資產、節點或標籤，皆依授權規則管理能力的集合述詞投影。
func (s *AuthorizationSelectors) TargetOptions(ctx context.Context, q TargetOptionsQuery) (*TargetOptionsPage, error) {
	p, set, err := s.viewer(ctx)
	if err != nil {
		return nil, err
	}
	page, size := clampPage(q.Page, q.PageSize)
	out := &TargetOptionsPage{Kind: q.Kind, Page: page, PageSize: size}
	if q.NodeID != nil && s.e.topo == nil {
		return nil, ErrSelectorUnwired
	}
	// 範圍外的節點篩選與不存在同形：空頁
	if q.NodeID != nil {
		ok, err := (AuthorizationListScope{e: s.e, p: p, set: set}).nodeAllowed(s.db, *q.NodeID)
		if err != nil {
			return nil, err
		}
		if !ok {
			out.Data = emptyTargetData(q.Kind)
			return out, nil
		}
	}
	switch q.Kind {
	case TargetKindAsset:
		return s.assetOptions(out, set, q)
	case TargetKindNode:
		return s.nodeOptions(out, set, q)
	case TargetKindTag:
		return s.tagOptions(out, set, q)
	}
	return nil, errors.New("authz: unknown target option kind")
}

func emptyTargetData(kind string) any {
	switch kind {
	case TargetKindAsset:
		return []TargetAssetOption{}
	case TargetKindNode:
		return []TargetNodeOption{}
	}
	return []TargetTagOption{}
}

// candidateAssets 範圍內的候選資產查詢（尚未排序與分頁）：node_id 取該節點子樹掛載的資產，tags 為 AND。
func (s *AuthorizationSelectors) candidateAssets(set ScopeSet, q TargetOptionsQuery, withSearch bool) (*gorm.DB, error) {
	query, err := s.e.ApplyScopeSet(s.db, s.db.Model(&model.Asset{}), set, ScopeQueryAsset)
	if err != nil {
		return nil, err
	}
	if q.NodeID != nil {
		if s.e.topo == nil {
			return nil, ErrSelectorUnwired
		}
		query = query.Where("assets.id IN (?)", s.e.topo.SubtreeAssetIDs(s.db, []uint{*q.NodeID}))
	}
	for _, tag := range q.Tags {
		query = query.Where(asset.TagMatchCondition, asset.TagMatchPattern(tag))
	}
	if withSearch && strings.TrimSpace(q.Search) != "" {
		p := selectorLikePattern(q.Search)
		query = query.Where(`(LOWER(assets.name) LIKE ? ESCAPE '\' OR LOWER(assets.host) LIKE ? ESCAPE '\')`, p, p)
	}
	return query, nil
}

func (s *AuthorizationSelectors) assetOptions(out *TargetOptionsPage, set ScopeSet, q TargetOptionsQuery) (*TargetOptionsPage, error) {
	query, err := s.candidateAssets(set, q, true)
	if err != nil {
		return nil, err
	}
	if err := query.Count(&out.Total).Error; err != nil {
		return nil, err
	}
	var assets []model.Asset
	if err := query.Select("assets.id", "assets.name", "assets.protocol", "assets.host").
		Order("assets.name ASC, assets.id ASC").Offset((out.Page - 1) * out.PageSize).Limit(out.PageSize).Find(&assets).Error; err != nil {
		return nil, err
	}
	ids := make([]uint, 0, len(assets))
	for _, a := range assets {
		ids = append(ids, a.ID)
	}
	mounts := map[uint][]uint{}
	if len(ids) > 0 {
		var rows []struct {
			AssetID uint
			NodeID  uint
		}
		if err := s.db.Table("asset_nodes AS an").
			Select("DISTINCT an.asset_id AS asset_id, an.node_id AS node_id").
			Joins("JOIN asset_groups g ON g.id = an.node_id AND g.deleted_at IS NULL").
			Where("an.asset_id IN ?", ids).Order("an.asset_id, an.node_id").Scan(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			mounts[r.AssetID] = append(mounts[r.AssetID], r.NodeID)
		}
	}
	proj, err := s.e.projectionOn(s.db, set)
	if err != nil {
		return nil, err
	}
	paths, err := asset.NodePathMap(s.db)
	if err != nil {
		return nil, err
	}
	data := make([]TargetAssetOption, 0, len(assets))
	for _, a := range assets {
		opt := TargetAssetOption{ID: a.ID, Name: a.Name, Protocol: string(a.Protocol), Host: a.Host, Nodes: []TargetNodeRef{}}
		hidden := 0
		for _, nid := range mounts[a.ID] {
			if set.state == ScopeSetUnlimited || proj.Selectable[nid] {
				opt.Nodes = append(opt.Nodes, TargetNodeRef{ID: nid, Path: paths[nid]})
			} else {
				hidden++
			}
		}
		if hidden > 0 {
			opt.NodeCountField = nodeCountField(hidden)
		}
		data = append(data, opt)
	}
	out.Data = data
	return out, nil
}

func (s *AuthorizationSelectors) nodeOptions(out *TargetOptionsPage, set ScopeSet, q TargetOptionsQuery) (*TargetOptionsPage, error) {
	proj, err := s.projectNodes(set)
	if err != nil {
		return nil, err
	}
	paths, err := asset.NodePathMap(s.db)
	if err != nil {
		return nil, err
	}
	var within map[uint]bool
	if q.NodeID != nil {
		var ids []uint
		if err := s.e.topo.SubtreeNodeIDs(s.db, []uint{*q.NodeID}).Scan(&ids).Error; err != nil {
			return nil, err
		}
		within = make(map[uint]bool, len(ids))
		for _, id := range ids {
			within[id] = true
		}
	}
	needle := strings.ToLower(strings.TrimSpace(q.Search))
	var all []TargetNodeOption
	appendNode := func(id uint, selectable bool) {
		path, ok := paths[id]
		if !ok || (within != nil && !within[id]) {
			return
		}
		if needle != "" && !strings.Contains(strings.ToLower(path), needle) {
			return
		}
		name := path
		if i := strings.LastIndex(path, " / "); i >= 0 {
			name = path[i+3:]
		}
		all = append(all, TargetNodeOption{ID: id, Name: name, Path: path, Selectable: selectable})
	}
	if set.state == ScopeSetUnlimited {
		for id := range paths {
			appendNode(id, true)
		}
	} else {
		for id := range proj.Selectable {
			appendNode(id, true)
		}
		for id := range proj.Locators {
			appendNode(id, false)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Path != all[j].Path {
			return all[i].Path < all[j].Path
		}
		return all[i].ID < all[j].ID
	})
	out.Total = int64(len(all))
	from, to := pageBounds(len(all), out.Page, out.PageSize)
	out.Data = append([]TargetNodeOption{}, all[from:to]...)
	return out, nil
}

func (s *AuthorizationSelectors) projectNodes(set ScopeSet) (NodeProjection, error) {
	return s.e.projectionOn(s.db, set)
}

func (s *AuthorizationSelectors) tagOptions(out *TargetOptionsPage, set ScopeSet, q TargetOptionsQuery) (*TargetOptionsPage, error) {
	query, err := s.candidateAssets(set, q, false)
	if err != nil {
		return nil, err
	}
	var raws []string
	if err := query.Where("assets.tags IS NOT NULL AND assets.tags <> ''").Order("assets.id ASC").Pluck("assets.tags", &raws).Error; err != nil {
		return nil, err
	}
	spelling := map[string]string{}
	counts := map[string]int{}
	for _, raw := range raws {
		for _, tag := range asset.NormalizeTagList(raw) {
			key := asset.CanonicalTagKey(tag)
			if _, ok := spelling[key]; !ok {
				spelling[key] = tag
			}
			counts[key]++
		}
	}
	needle := strings.ToLower(strings.TrimSpace(q.Search))
	var all []TargetTagOption
	for key, name := range spelling {
		if needle != "" && !strings.Contains(key, needle) {
			continue
		}
		all = append(all, TargetTagOption{Name: name, Count: counts[key]})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	out.Total = int64(len(all))
	from, to := pageBounds(len(all), out.Page, out.PageSize)
	out.Data = append([]TargetTagOption{}, all[from:to]...)
	return out, nil
}

func pageBounds(n, page, size int) (int, int) {
	from := (page - 1) * size
	if from > n {
		from = n
	}
	to := from + size
	if to > n {
		to = n
	}
	return from, to
}
