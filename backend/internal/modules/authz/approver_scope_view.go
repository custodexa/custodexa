package authz

import (
	"context"
	"sort"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

// 審核範圍的讀取面：列表投影、可審人數、審核方目錄與客體候選。

// ApproverNodeCoverage 一個可視節點的可審人數。
type ApproverNodeCoverage struct {
	NodeID        uint `json:"node_id"`
	ApproverCount int  `json:"approver_count"`
}

// ApproverScopeListView 列表的服務層結果。Full 為真（超級管理者或未注入判定）時只有 Rows，回應維持現行形狀。
type ApproverScopeListView struct {
	Full                bool
	Rows                []*model.ApproverScope
	Coverage            []ApproverNodeCoverage
	MinApprovals        int
	ApplicantManageable bool
	NodeScoped          bool
}

func (s *ApproverScopeService) preloaded(q *gorm.DB) *gorm.DB {
	return q.Preload("Approver").Preload("ApproverGroup").Preload("Asset").Preload("AssetGroup").
		Preload("SubjectUser").Preload("SubjectGroup").Order("created_at DESC")
}

// ListFor 依檢視者投影：資產型與節點型列以審核範圍管理鍵的集合述詞在資料庫內過濾；
// 申請人型列只給同時為全域持有兩鍵者。
func (s *ApproverScopeService) ListFor(ctx context.Context) (*ApproverScopeListView, error) {
	p := PrincipalFromContext(ctx)
	if s.writeScope == nil || s.e == nil {
		rows, err := s.List()
		return &ApproverScopeListView{Full: true, Rows: rows}, err
	}
	if p == nil {
		return nil, ErrOperatorUnknown
	}
	db := s.db.WithContext(ctx)
	kSet, err := s.e.ScopeSetFor(db, p, PermApproverScopeManage)
	if err != nil {
		return nil, err
	}
	if kSet.State() == ScopeSetUnlimited && p.IsSuperAdmin() {
		rows, err := s.List()
		return &ApproverScopeListView{Full: true, Rows: rows}, err
	}
	kaSet, err := s.e.ScopeSetFor(db, p, PermApproverScopeApplicantManage)
	if err != nil {
		return nil, err
	}
	view := &ApproverScopeListView{NodeScoped: kSet.State() == ScopeSetConditional,
		ApplicantManageable: kSet.State() == ScopeSetUnlimited && kaSet.State() == ScopeSetUnlimited}
	q := db.Model(&model.ApproverScope{})
	if kSet.State() == ScopeSetUnlimited {
		if !view.ApplicantManageable {
			q = q.Where("approver_scopes.asset_id IS NOT NULL OR approver_scopes.asset_group_id IS NOT NULL")
		}
	} else {
		as, err := s.e.ApplyScopeSet(db, db.Model(&model.Asset{}).Select("assets.id"), kSet, ScopeQueryAsset)
		if err != nil {
			return nil, err
		}
		ns, err := s.e.ApplyScopeSet(db, db.Model(&model.AssetGroup{}).Select("asset_groups.id"), kSet, ScopeQueryNode)
		if err != nil {
			return nil, err
		}
		q = q.Where("approver_scopes.asset_id IN (?) OR approver_scopes.asset_group_id IN (?)", as, ns)
	}
	if err := s.preloaded(q).Find(&view.Rows).Error; err != nil {
		return nil, err
	}
	view.MinApprovals = 1
	if s.minApprovals != nil {
		if n := s.minApprovals.GetInt(policy.PolicyAccessRequestMinApprovals); n > 1 {
			view.MinApprovals = n
		}
	}
	view.Coverage, err = s.coverage(db, p, view.Rows)
	return view, err
}

// coverage 可視節點上的可審人數：該節點及祖先上、檢視者可視的節點型列的審核方展開去重
// （個人計本人；群組展開為目前成員）。範圍外祖先上的列不計。
func (s *ApproverScopeService) coverage(db *gorm.DB, p *Principal, rows []*model.ApproverScope) ([]ApproverNodeCoverage, error) {
	proj, err := s.e.NodeScopeProjection(db, p, PermApproverScopeManage)
	if err != nil {
		return nil, err
	}
	var nodes []model.AssetGroup
	if err := db.Select("id", "parent_id").Find(&nodes).Error; err != nil {
		return nil, err
	}
	parent := map[uint]uint{}
	for _, n := range nodes {
		if n.ParentID != nil {
			parent[n.ID] = *n.ParentID
		}
	}
	byNode := map[uint]map[uint]bool{}
	for _, r := range rows {
		if r.AssetGroupID == nil {
			continue
		}
		set := byNode[*r.AssetGroupID]
		if set == nil {
			set = map[uint]bool{}
			byNode[*r.AssetGroupID] = set
		}
		if r.ApproverID != nil {
			set[*r.ApproverID] = true
		}
		if r.ApproverGroupID != nil {
			var ids []uint
			if err := db.Table("user_group_members").Where("user_group_id = ?", *r.ApproverGroupID).Pluck("user_id", &ids).Error; err != nil {
				return nil, err
			}
			for _, id := range ids {
				set[id] = true
			}
		}
	}
	out := []ApproverNodeCoverage{}
	for _, n := range nodes {
		if proj.State == ScopeSetConditional && !proj.Selectable[n.ID] || proj.State == ScopeSetEmpty {
			continue
		}
		pool := map[uint]bool{}
		for cur, depth := n.ID, 0; cur != 0 && depth < 64; depth++ {
			for id := range byNode[cur] {
				pool[id] = true
			}
			cur = parent[cur]
		}
		out = append(out, ApproverNodeCoverage{NodeID: n.ID, ApproverCount: len(pool)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out, nil
}

// ApproverUserOption 審核方使用者候選（欄位固定，無 email）。
type ApproverUserOption struct {
	ID          uint   `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Active      bool   `json:"active"`
	IsApprover  bool   `json:"is_approver"`
	Selectable  bool   `json:"selectable"`
}

// ApproverGroupOption 審核方群組候選。
type ApproverGroupOption struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

// ApproverOptionsResult 審核方目錄。
type ApproverOptionsResult struct {
	Users  []ApproverUserOption  `json:"users"`
	Groups []ApproverGroupOption `json:"groups"`
}

// ApproverOptions 審核方目錄：非 agent、未刪除；不依節點範圍過濾。selectable 依保留身分
// （超級管理者、稽核員）排除，不依角色顯示名稱、不加啟用條件。
func (s *ApproverScopeService) ApproverOptions(ctx context.Context) (*ApproverOptionsResult, error) {
	db := s.db.WithContext(ctx)
	var users []model.User
	if err := db.Select("id", "username", "active", "local_display_name").Where("kind <> ?", model.KindAgent).Order("id").Find(&users).Error; err != nil {
		return nil, err
	}
	type roleRow struct {
		UserID     uint
		BuiltinKey string
	}
	var rr []roleRow
	if err := db.Table("user_roles").Select("user_roles.user_id AS user_id, roles.builtin_key AS builtin_key").
		Joins("JOIN roles ON roles.id = user_roles.role_id AND roles.deleted_at IS NULL").
		Where("user_roles.scope_kind = ? AND roles.builtin_key IS NOT NULL", model.ScopeKindGlobal).Scan(&rr).Error; err != nil {
		return nil, err
	}
	builtin := map[uint]map[string]bool{}
	for _, r := range rr {
		if builtin[r.UserID] == nil {
			builtin[r.UserID] = map[string]bool{}
		}
		builtin[r.UserID][r.BuiltinKey] = true
	}
	out := &ApproverOptionsResult{Users: []ApproverUserOption{}, Groups: []ApproverGroupOption{}}
	for _, u := range users {
		b := builtin[u.ID]
		name := u.Username
		if u.LocalDisplayName != nil && *u.LocalDisplayName != "" {
			name = *u.LocalDisplayName
		}
		out.Users = append(out.Users, ApproverUserOption{ID: u.ID, Username: u.Username, DisplayName: name, Active: u.Active,
			IsApprover: b[model.BuiltinApprover], Selectable: !b[model.BuiltinSuperAdmin] && !b[model.BuiltinAuditor]})
	}
	var groups []model.UserGroup
	if err := db.Select("id", "name").Order("id").Find(&groups).Error; err != nil {
		return nil, err
	}
	for _, g := range groups {
		out.Groups = append(out.Groups, ApproverGroupOption{ID: g.ID, Name: g.Name})
	}
	return out, nil
}

// ApproverTargetQuery 客體候選查詢。
type ApproverTargetQuery struct {
	Kind     string
	Search   string
	NodeID   *uint
	Page     int
	PageSize int
}

// ApproverTargetOption 客體候選；資產只有 id 與 name，節點另帶路徑與可選旗標（假者只作定位祖先）。
type ApproverTargetOption struct {
	ID         uint   `json:"id"`
	Name       string `json:"name"`
	Path       string `json:"path,omitempty"`
	Selectable *bool  `json:"selectable,omitempty"`
}

// ApproverTargetPage 客體候選的一頁。
type ApproverTargetPage struct {
	Kind     string                 `json:"kind"`
	Data     []ApproverTargetOption `json:"data"`
	Total    int64                  `json:"total"`
	Page     int                    `json:"page"`
	PageSize int                    `json:"page_size"`
}

// TargetOptions 依審核範圍管理鍵的集合述詞投影；node_id 範圍外與不存在同形為空。
func (s *ApproverScopeService) TargetOptions(ctx context.Context, q ApproverTargetQuery) (*ApproverTargetPage, error) {
	p := PrincipalFromContext(ctx)
	if s.e == nil {
		return nil, ErrApproverScopeWriteScopeMissing
	}
	if p == nil {
		return nil, ErrOperatorUnknown
	}
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize < 1 {
		q.PageSize = 50
	}
	if q.PageSize > SelectorMaxPageSize {
		q.PageSize = SelectorMaxPageSize
	}
	db := s.db.WithContext(ctx)
	page := &ApproverTargetPage{Kind: q.Kind, Data: []ApproverTargetOption{}, Page: q.Page, PageSize: q.PageSize}
	set, err := s.e.ScopeSetFor(db, p, PermApproverScopeManage)
	if err != nil {
		return nil, err
	}
	if q.Kind == "asset" {
		aq := db.Model(&model.Asset{})
		if aq, err = s.e.ApplyScopeSet(db, aq, set, ScopeQueryAsset); err != nil {
			return nil, err
		}
		if q.NodeID != nil {
			ok, err := s.nodeInScope(db, p, *q.NodeID)
			if err != nil || !ok {
				return page, err
			}
			aq = aq.Where("assets.id IN (?)", s.e.topo.SubtreeAssetIDs(db, []uint{*q.NodeID}))
		}
		if q.Search != "" {
			aq = aq.Where("LOWER(assets.name) LIKE ?", "%"+strings.ToLower(q.Search)+"%")
		}
		if err := aq.Count(&page.Total).Error; err != nil {
			return nil, err
		}
		var rows []model.Asset
		if err := aq.Select("assets.id", "assets.name").Order("assets.name, assets.id").
			Offset((q.Page - 1) * q.PageSize).Limit(q.PageSize).Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			page.Data = append(page.Data, ApproverTargetOption{ID: r.ID, Name: r.Name})
		}
		return page, nil
	}
	proj, err := s.e.NodeScopeProjection(db, p, PermApproverScopeManage)
	if err != nil {
		return nil, err
	}
	var nodes []model.AssetGroup
	if err := db.Select("id", "name", "parent_id").Find(&nodes).Error; err != nil {
		return nil, err
	}
	byID := map[uint]model.AssetGroup{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	pathOf := func(id uint) string {
		var parts []string
		for cur, d := id, 0; cur != 0 && d < 64; d++ {
			n, ok := byID[cur]
			if !ok {
				break
			}
			parts = append([]string{n.Name}, parts...)
			if n.ParentID == nil {
				break
			}
			cur = *n.ParentID
		}
		return strings.Join(parts, " / ")
	}
	under := func(id, root uint) bool {
		for cur, d := id, 0; cur != 0 && d < 64; d++ {
			if cur == root {
				return true
			}
			n, ok := byID[cur]
			if !ok || n.ParentID == nil {
				return false
			}
			cur = *n.ParentID
		}
		return false
	}
	selectable := func(id uint) bool {
		return proj.State == ScopeSetUnlimited || proj.State == ScopeSetConditional && proj.Selectable[id]
	}
	if q.NodeID != nil && (byID[*q.NodeID].ID == 0 || !selectable(*q.NodeID)) {
		return page, nil
	}
	var all []ApproverTargetOption
	for _, n := range nodes {
		sel := selectable(n.ID)
		if !sel && !(proj.State == ScopeSetConditional && proj.Locators[n.ID] && q.NodeID == nil && q.Search == "") {
			continue
		}
		if q.NodeID != nil && !under(n.ID, *q.NodeID) {
			continue
		}
		path := pathOf(n.ID)
		if q.Search != "" && !strings.Contains(strings.ToLower(path), strings.ToLower(q.Search)) {
			continue
		}
		v := sel
		all = append(all, ApproverTargetOption{ID: n.ID, Name: n.Name, Path: path, Selectable: &v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Path < all[j].Path })
	page.Total = int64(len(all))
	lo := (q.Page - 1) * q.PageSize
	if lo < len(all) {
		hi := lo + q.PageSize
		if hi > len(all) {
			hi = len(all)
		}
		page.Data = all[lo:hi]
	}
	return page, nil
}

func (s *ApproverScopeService) nodeInScope(db *gorm.DB, p *Principal, id uint) (bool, error) {
	proj, err := s.e.NodeScopeProjection(db, p, PermApproverScopeManage)
	if err != nil {
		return false, err
	}
	switch proj.State {
	case ScopeSetUnlimited:
		var n int64
		err := db.Model(&model.AssetGroup{}).Where("id = ?", id).Count(&n).Error
		return n > 0, err
	case ScopeSetConditional:
		return proj.Selectable[id], nil
	}
	return false, nil
}
