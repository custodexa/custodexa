package asset

import (
	"fmt"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// countQueries 掛上查詢計數回呼，回傳讀取當前累計值的函式。
func countQueries(t *testing.T, db *gorm.DB) func() int {
	t.Helper()
	n := 0
	inc := func(*gorm.DB) { n++ }
	if err := db.Callback().Query().Before("gorm:query").Register("test:count_query", inc); err != nil {
		t.Fatalf("register query callback: %v", err)
	}
	if err := db.Callback().Row().Before("gorm:row").Register("test:count_row", inc); err != nil {
		t.Fatalf("register row callback: %v", err)
	}
	return func() int { return n }
}

func mkNode(t *testing.T, db *gorm.DB, name string, parent *uint) uint {
	t.Helper()
	g := model.AssetGroup{Name: name, ParentID: parent}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("node: %v", err)
	}
	return g.ID
}

func mkMountedAsset(t *testing.T, db *gorm.DB, name string, nodes ...uint) uint {
	t.Helper()
	a := model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: name + ".example", Port: 22}
	if err := db.Create(&a).Error; err != nil {
		t.Fatalf("asset: %v", err)
	}
	for _, n := range nodes {
		if err := db.Create(&model.AssetNode{AssetID: a.ID, NodeID: n}).Error; err != nil {
			t.Fatalf("mount: %v", err)
		}
	}
	return a.ID
}

func TestAssignmentNodesSubtreeCounts(t *testing.T) {
	db := setupGroupOnlyDB(t)
	root := mkNode(t, db, "root", nil)
	mid := mkNode(t, db, "mid", &root)
	leaf := mkNode(t, db, "leaf", &mid)
	other := mkNode(t, db, "other", nil)
	gone := mkNode(t, db, "gone", &root)

	mkMountedAsset(t, db, "both", root, leaf) // 父與子孫同掛：父節點只計一次
	mkMountedAsset(t, db, "leaf-only", leaf)
	mkMountedAsset(t, db, "elsewhere", other)
	mkMountedAsset(t, db, "under-gone", gone)
	dead := mkMountedAsset(t, db, "dead-asset", leaf)
	if err := db.Delete(&model.Asset{}, dead).Error; err != nil {
		t.Fatalf("delete asset: %v", err)
	}
	if err := db.Delete(&model.AssetGroup{}, gone).Error; err != nil {
		t.Fatalf("delete node: %v", err)
	}

	got, err := AssignmentNodes(db)
	if err != nil {
		t.Fatalf("AssignmentNodes: %v", err)
	}
	byID := map[uint]AssignmentNode{}
	for _, n := range got {
		byID[n.ID] = n
	}
	if _, ok := byID[gone]; ok || len(got) != 4 {
		t.Fatalf("已刪除節點不得出現，got %d 筆: %+v", len(got), got)
	}
	want := map[uint]struct {
		depth, count int
		path         string
	}{
		root:  {1, 2, "root"},
		mid:   {2, 2, "root / mid"},
		leaf:  {3, 2, "root / mid / leaf"},
		other: {1, 1, "other"},
	}
	for id, w := range want {
		n := byID[id]
		if n.Depth != w.depth || n.SubtreeAssetCount != w.count || n.Path != w.path {
			t.Errorf("節點 %d: got depth=%d count=%d path=%q，want %+v", id, n.Depth, n.SubtreeAssetCount, n.Path, w)
		}
	}
	if byID[root].ParentID != nil || byID[mid].ParentID == nil || *byID[mid].ParentID != root {
		t.Errorf("parent_id 不符: root=%v mid=%v", byID[root].ParentID, byID[mid].ParentID)
	}
}

func TestAssignmentNodesQueryCountFlat(t *testing.T) {
	measure := func(nodes int) int {
		db := setupGroupOnlyDB(t)
		var parent *uint
		for i := 0; i < nodes; i++ {
			// 每十個節點接成一條鏈，其餘掛在根下，兼顧深度與寬度
			id := mkNode(t, db, fmt.Sprintf("n%d", i), parent)
			if i%10 != 9 {
				parent = &id
			} else {
				parent = nil
			}
			mkMountedAsset(t, db, fmt.Sprintf("a%d", i), id)
		}
		read := countQueries(t, db)
		before := read()
		got, err := AssignmentNodes(db)
		if err != nil {
			t.Fatalf("AssignmentNodes(%d): %v", nodes, err)
		}
		if len(got) != nodes {
			t.Fatalf("節點數 %d != %d", len(got), nodes)
		}
		return read() - before
	}
	q50, q200 := measure(50), measure(200)
	t.Logf("queries: 50 nodes=%d, 200 nodes=%d", q50, q200)
	if q50 == 0 || q50 != q200 {
		t.Fatalf("查詢次數不得隨節點數成長: 50=%d 200=%d", q50, q200)
	}
}
