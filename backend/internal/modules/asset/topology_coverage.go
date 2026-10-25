package asset

import (
	"cmp"
	"encoding/json"
	"slices"

	"gorm.io/gorm"
)

// 拓撲變更的涵蓋差異：快照型別與差集產生器。
//
// 快照由 authz 讀（連線授權、審核範圍、管理範圍三種來源各自涵蓋了哪些資產），本檔只負責
// 前後兩份快照的差集。結果附在拓撲變更實體既有的成功審計列 details（同交易、同一次寫入），
// 只含識別碼與等級／角色識別碼，不含名稱、憑證或其他欄位，也不出現在對操作者的回應中。

// CoverageListLimit 每個清單最多列出的識別碼數；總數不受限。
const CoverageListLimit = 100

// CoverageSubject 涵蓋來源的主體（kind 為 user／user_group 等，與來源表的主體種類相同）。
type CoverageSubject struct {
	Kind string `json:"kind"`
	ID   uint   `json:"id"`
}

// CoverageGrant 節點型連線授權的主體與等級。
type CoverageGrant struct {
	Kind  string `json:"kind"`
	ID    uint   `json:"id"`
	Level string `json:"level"`
}

// CoverageManager 節點範圍指派的主體與角色。
type CoverageManager struct {
	Kind   string `json:"kind"`
	ID     uint   `json:"id"`
	RoleID uint   `json:"role_id"`
}

// AssetCoverage 一個資產在三種來源的涵蓋（各自去重；順序不拘）。
type AssetCoverage struct {
	Grants    []CoverageGrant
	Approvers []CoverageSubject
	Managers  []CoverageManager
}

// CoverageSnapshot 一組資產在某一時點的涵蓋；查無涵蓋的資產可省略或為零值。
type CoverageSnapshot struct {
	Assets map[uint]AssetCoverage
}

// CoverageList 排序、去重後的清單：Total 為去重後總數，Items 只列前 CoverageListLimit 個。
type CoverageList[T any] struct {
	Total     int  `json:"total"`
	Items     []T  `json:"items"`
	Truncated bool `json:"truncated"`
}

// CoverageDelta 得到與失去兩個方向。
type CoverageDelta[T any] struct {
	Gained CoverageList[T] `json:"gained"`
	Lost   CoverageList[T] `json:"lost"`
}

// TopologyCoverage 一次拓撲變更的涵蓋差異（審計 details 的 topology_coverage 值）。
type TopologyCoverage struct {
	Assets    CoverageDelta[uint]            `json:"assets"`
	Grants    CoverageDelta[CoverageGrant]   `json:"grants"`
	Approvers CoverageDelta[CoverageSubject] `json:"approvers"`
	Managers  CoverageDelta[CoverageManager] `json:"managers"`
}

func cmpGrant(a, b CoverageGrant) int {
	return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.ID, b.ID), cmp.Compare(a.Level, b.Level))
}

func cmpSubject(a, b CoverageSubject) int {
	return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.ID, b.ID))
}

func cmpManager(a, b CoverageManager) int {
	return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.ID, b.ID), cmp.Compare(a.RoleID, b.RoleID))
}

// toList 去重、排序並截斷。
func toList[T comparable](set map[T]struct{}, less func(a, b T) int) CoverageList[T] {
	items := make([]T, 0, len(set))
	for v := range set {
		items = append(items, v)
	}
	slices.SortFunc(items, less)
	out := CoverageList[T]{Total: len(items), Items: items}
	if len(items) > CoverageListLimit {
		out.Items = items[:CoverageListLimit]
		out.Truncated = true
	}
	return out
}

func setOf[T comparable](xs []T) map[T]struct{} {
	m := make(map[T]struct{}, len(xs))
	for _, x := range xs {
		m[x] = struct{}{}
	}
	return m
}

// diffInto 把 after−before 加進 gained、before−after 加進 lost；回傳該資產是否有得／失。
func diffInto[T comparable](before, after []T, gained, lost map[T]struct{}) (hasGain, hasLoss bool) {
	b, a := setOf(before), setOf(after)
	for v := range a {
		if _, ok := b[v]; !ok {
			gained[v] = struct{}{}
			hasGain = true
		}
	}
	for v := range b {
		if _, ok := a[v]; !ok {
			lost[v] = struct{}{}
			hasLoss = true
		}
	}
	return hasGain, hasLoss
}

// BuildTopologyCoverage 前後快照的差集。資產列為「得到」表示在任一來源多了涵蓋它的主體，
// 「失去」表示任一來源少了；多歸屬資產因另一歸屬仍受同一主體涵蓋者不計為失去（快照已以資產為單位聯集）。
// 結果與輸入的迭代順序無關。
func BuildTopologyCoverage(before, after CoverageSnapshot) TopologyCoverage {
	assetIDs := map[uint]struct{}{}
	for id := range before.Assets {
		assetIDs[id] = struct{}{}
	}
	for id := range after.Assets {
		assetIDs[id] = struct{}{}
	}
	gainedAssets, lostAssets := map[uint]struct{}{}, map[uint]struct{}{}
	gGrants, lGrants := map[CoverageGrant]struct{}{}, map[CoverageGrant]struct{}{}
	gApprovers, lApprovers := map[CoverageSubject]struct{}{}, map[CoverageSubject]struct{}{}
	gManagers, lManagers := map[CoverageManager]struct{}{}, map[CoverageManager]struct{}{}
	for id := range assetIDs {
		b, a := before.Assets[id], after.Assets[id]
		g1, l1 := diffInto(b.Grants, a.Grants, gGrants, lGrants)
		g2, l2 := diffInto(b.Approvers, a.Approvers, gApprovers, lApprovers)
		g3, l3 := diffInto(b.Managers, a.Managers, gManagers, lManagers)
		if g1 || g2 || g3 {
			gainedAssets[id] = struct{}{}
		}
		if l1 || l2 || l3 {
			lostAssets[id] = struct{}{}
		}
	}
	return TopologyCoverage{
		Assets:    CoverageDelta[uint]{Gained: toList(gainedAssets, cmp.Compare[uint]), Lost: toList(lostAssets, cmp.Compare[uint])},
		Grants:    CoverageDelta[CoverageGrant]{Gained: toList(gGrants, cmpGrant), Lost: toList(lGrants, cmpGrant)},
		Approvers: CoverageDelta[CoverageSubject]{Gained: toList(gApprovers, cmpSubject), Lost: toList(lApprovers, cmpSubject)},
		Managers:  CoverageDelta[CoverageManager]{Gained: toList(gManagers, cmpManager), Lost: toList(lManagers, cmpManager)},
	}
}

// MarshalTopologyCoverage 審計 details 用的序列化（欄位順序固定）。
func MarshalTopologyCoverage(c TopologyCoverage) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// subtreeAssetIDsTx 節點子樹（含自身）內掛載的未刪除資產，升冪。
func subtreeAssetIDsTx(tx *gorm.DB, nodeID uint) ([]uint, error) {
	var ids []uint
	if err := NewScopeTopologyReader().SubtreeAssetIDs(tx, []uint{nodeID}).Scan(&ids).Error; err != nil {
		return nil, err
	}
	slices.Sort(ids)
	return ids, nil
}

// coverageSnapshotTx 取快照；未注入回 ErrCoverageSnapshotPortMissing。
func (s *AssetGroupService) coverageSnapshotTx(tx *gorm.DB, assetIDs []uint) (CoverageSnapshot, error) {
	if s.coverage == nil {
		return CoverageSnapshot{}, ErrCoverageSnapshotPortMissing
	}
	return s.coverage.CoverageSnapshot(tx, assetIDs)
}
