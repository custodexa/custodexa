package asset

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupGroupDB(t *testing.T) (*AssetGroupService, *gorm.DB) {
	db := setupGroupOnlyDB(t)
	return NewAssetGroupService(db, audit.NewTxSink(), &cascadingGroupRevoker{}), db
}

// cascadingGroupRevoker 會**真的執行級聯刪除**的 port 替身。
//
// **為何需要它**：`audit_failclose_backstop_test.go` 的 AP-37 對照組斷言
// 「無故障時級聯撤銷確實發生」，實驗組再斷言「注入審計失敗後那些列隨交易回滾」。
// 若替身什麼都不刪，對照組必然失敗（實測到這一點：換成純記錄式 stub 後
// 該格立刻紅在對照組，證明那條對照不是裝飾）。
//
// **它不是第二份規則**：這裡只複製「刪哪兩張表、用哪個外鍵」這個**效果**，
// 目的是讓交易回滾的觀察對象存在。撤銷規則本身（含 RowsAffected 語義、
// 錯誤包裝、審核範圍的兩類條件）由 authz 的 `TestCascadeRevokeByAssetGroup`
// 對真實作驗證；asset 側不宣稱驗證了那個規則。
type cascadingGroupRevoker struct{}

func (c *cascadingGroupRevoker) RevokeByAssetGroup(tx *gorm.DB, groupID uint) (int64, int64, error) {
	res := tx.Where("asset_group_id = ?", groupID).Delete(&model.AssetAuthorization{})
	if res.Error != nil {
		return 0, 0, res.Error
	}
	scopeRes := tx.Where("asset_group_id = ?", groupID).Delete(&model.ApproverScope{})
	if scopeRes.Error != nil {
		return 0, 0, scopeRes.Error
	}
	return res.RowsAffected, scopeRes.RowsAffected, nil
}

func setupGroupOnlyDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// AssetAuthorization/ApproverScope：Delete 連動撤銷
	if err := db.AutoMigrate(&model.AssetGroup{}, &model.AssetNode{}, &model.Asset{}, &model.AuditLog{},
		&model.AssetAuthorization{}, &model.ApproverScope{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// stubAssetGroupRevoker tx-taking 窄 port 的測試替身。
//
// **為何不是真 authz**：authz import asset（`FillNodeInfo`／`ValidateAccountUsername`），
// 故 asset 的測試 import authz 會構成 `import cycle not allowed in test`；
// 而 asset→authz 本就是禁止邊（`forbiddenModuleEdges`）。
// **DB 級聯的本體斷言**（授權軟刪留痕、審核範圍失效）改由 authz 側
// `TestCascadeRevokeByAssetGroup` 承擔；此處負責 asset 的契約：
// 在交易內恰好委派一次、把回傳的兩個筆數放進審計 Details、且**自己不碰 authz 的表**。
type stubAssetGroupRevoker struct {
	calls   []stubRevokeCall
	authzN  int64
	scopeN  int64
	failErr error
}

type stubRevokeCall struct {
	TxIsNil bool
	GroupID uint
}

func newStubGroupRevoker(authzN, scopeN int64) *stubAssetGroupRevoker {
	return &stubAssetGroupRevoker{authzN: authzN, scopeN: scopeN}
}

func (s *stubAssetGroupRevoker) RevokeByAssetGroup(tx *gorm.DB, groupID uint) (int64, int64, error) {
	s.calls = append(s.calls, stubRevokeCall{TxIsNil: tx == nil, GroupID: groupID})
	if s.failErr != nil {
		return 0, 0, s.failErr
	}
	return s.authzN, s.scopeN, nil
}

func TestAssetGroupCRUD(t *testing.T) {
	svc, _ := setupGroupDB(t)

	g, err := svc.Create(&AssetGroupRequest{Name: "生產", Description: "prod"}, 1, "admin", "127.0.0.1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Create(&AssetGroupRequest{Name: "生產"}, 1, "admin", "127.0.0.1"); !errors.Is(err, ErrGroupNameExists) {
		t.Errorf("同層（根）同名應 409: %v", err)
	}

	// 同名不同層合法（同層唯一取代全域唯一）
	child, err := svc.Create(&AssetGroupRequest{Name: "生產", ParentID: &g.ID}, 1, "admin", "127.0.0.1")
	if err != nil {
		t.Fatalf("不同層同名應合法: %v", err)
	}
	if child.ParentID == nil || *child.ParentID != g.ID {
		t.Fatalf("child parent = %v", child.ParentID)
	}

	updated, err := svc.Update(g.ID, &AssetGroupRequest{Name: "正式", Description: "renamed"}, 1, "admin", "127.0.0.1")
	if err != nil || updated.Name != "正式" {
		t.Fatalf("Update = %+v, %v", updated, err)
	}

	groups, _ := svc.List()
	if len(groups) != 2 {
		t.Fatalf("List = %d", len(groups))
	}
}

// TestAssetNodeTreeDepthAndCycle 樹深上限與環路檢查
func TestAssetNodeTreeDepthAndCycle(t *testing.T) {
	svc, _ := setupGroupDB(t)

	// 建 10 層鏈（深度上限）
	var parent *uint
	nodes := make([]*model.AssetGroup, 0, 10)
	for i := 0; i < 10; i++ {
		g, err := svc.Create(&AssetGroupRequest{Name: "n", ParentID: parent}, 1, "admin", "127.0.0.1")
		if err != nil {
			t.Fatalf("depth %d create: %v", i+1, err)
		}
		nodes = append(nodes, g)
		parent = &g.ID
	}

	// 第 11 層應拒
	if _, err := svc.Create(&AssetGroupRequest{Name: "n11", ParentID: parent}, 1, "admin", "127.0.0.1"); !errors.Is(err, ErrNodeDepthExceeded) {
		t.Fatalf("超深應拒: %v", err)
	}

	// 環路：把根搬到自己的子孫下應拒
	if _, err := svc.Move(nodes[0].ID, &nodes[9].ID, 1, "admin", "127.0.0.1"); !errors.Is(err, ErrNodeCycle) {
		t.Fatalf("環路應拒: %v", err)
	}
	// 搬到自身應拒
	if _, err := svc.Move(nodes[0].ID, &nodes[0].ID, 1, "admin", "127.0.0.1"); !errors.Is(err, ErrNodeCycle) {
		t.Fatalf("搬到自身應拒: %v", err)
	}

	// 搬移後子樹深度超限應拒：另建 3 層鏈，其根搬到 nodes[8]（深 9）下
	//（9+3 > 10；非子孫關係，不觸發環路檢查）
	var mParent *uint
	var mRoot *model.AssetGroup
	for i := 0; i < 3; i++ {
		m, err := svc.Create(&AssetGroupRequest{Name: "m", ParentID: mParent}, 1, "admin", "127.0.0.1")
		if err != nil {
			t.Fatalf("chain2 depth %d: %v", i+1, err)
		}
		if i == 0 {
			mRoot = m
		}
		mParent = &m.ID
	}
	if _, err := svc.Move(mRoot.ID, &nodes[8].ID, 1, "admin", "127.0.0.1"); !errors.Is(err, ErrNodeDepthExceeded) {
		t.Fatalf("搬移超深應拒: %v", err)
	}

	// 合法搬移：nodes[9]（葉）改名後搬到根層（避開與 nodes[0] 同層同名）
	if _, err := svc.Update(nodes[9].ID, &AssetGroupRequest{Name: "leaf"}, 1, "admin", "127.0.0.1"); err != nil {
		t.Fatalf("rename leaf: %v", err)
	}
	moved, err := svc.Move(nodes[9].ID, nil, 1, "admin", "127.0.0.1")
	if err != nil || moved.ParentID != nil {
		t.Fatalf("葉搬根層應成功: %+v, %v", moved, err)
	}
}

// TestAssetNodeMoveSiblingName 搬移目標層同名 409
func TestAssetNodeMoveSiblingName(t *testing.T) {
	svc, _ := setupGroupDB(t)
	a, _ := svc.Create(&AssetGroupRequest{Name: "A"}, 1, "admin", "127.0.0.1")
	b, _ := svc.Create(&AssetGroupRequest{Name: "B"}, 1, "admin", "127.0.0.1")
	if _, err := svc.Create(&AssetGroupRequest{Name: "B", ParentID: &a.ID}, 1, "admin", "127.0.0.1"); err != nil {
		t.Fatalf("A 下建 B: %v", err)
	}
	// 根層 B 搬進 A 會撞 A/B
	if _, err := svc.Move(b.ID, &a.ID, 1, "admin", "127.0.0.1"); !errors.Is(err, ErrGroupNameExists) {
		t.Fatalf("目標層同名應 409: %v", err)
	}
}

// TestAssetNodeDeleteOnlyEmpty 僅空節點可刪
func TestAssetNodeDeleteOnlyEmpty(t *testing.T) {
	svc, db := setupGroupDB(t)
	parent, _ := svc.Create(&AssetGroupRequest{Name: "P"}, 1, "admin", "127.0.0.1")
	child, _ := svc.Create(&AssetGroupRequest{Name: "C", ParentID: &parent.ID}, 1, "admin", "127.0.0.1")

	// 有子節點不可刪
	if _, err := svc.Delete(parent.ID, 1, "admin", "127.0.0.1"); !errors.Is(err, ErrNodeNotEmpty) {
		t.Fatalf("有子節點應拒刪: %v", err)
	}

	// 有直掛資產不可刪
	asset := model.Asset{Name: "a1", Protocol: model.ProtocolSSH, Host: "h", Port: 22}
	if err := db.Create(&asset).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := db.Create(&model.AssetNode{AssetID: asset.ID, NodeID: child.ID}).Error; err != nil {
		t.Fatalf("attach: %v", err)
	}
	if _, err := svc.Delete(child.ID, 1, "admin", "127.0.0.1"); !errors.Is(err, ErrNodeNotEmpty) {
		t.Fatalf("有直掛資產應拒刪: %v", err)
	}

	// 摘掉資產後 child 可刪；之後 parent 也可刪
	if err := db.Where("asset_id = ?", asset.ID).Delete(&model.AssetNode{}).Error; err != nil {
		t.Fatalf("detach: %v", err)
	}
	if _, err := svc.Delete(child.ID, 1, "admin", "127.0.0.1"); err != nil {
		t.Fatalf("空節點應可刪: %v", err)
	}
	if _, err := svc.Delete(parent.ID, 1, "admin", "127.0.0.1"); err != nil {
		t.Fatalf("子節點刪後父應可刪: %v", err)
	}
	if _, err := svc.Delete(parent.ID, 1, "admin", "127.0.0.1"); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("second delete = %v", err)
	}
}

// TestAssetGroupDeleteRevokesGrants 刪節點連動軟刪授權＋approver 範圍＋審計留痕
// （沿使用者群組授權的既有慣例）
func TestAssetGroupDeleteRevokesGrants(t *testing.T) {
	db := setupGroupOnlyDB(t)
	revoker := newStubGroupRevoker(1, 1)
	svc := NewAssetGroupService(db, audit.NewTxSink(), revoker)
	g, _ := svc.Create(&AssetGroupRequest{Name: "G"}, 1, "admin", "127.0.0.1")

	uid := uint(7)
	if err := db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetGroupID: &g.ID, Permission: model.PermissionConnect, GrantedBy: 1,
	}).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	if err := db.Create(&model.ApproverScope{
		ApproverID: uptrAsset(9), AssetGroupID: &g.ID, GrantedBy: 1,
	}).Error; err != nil {
		t.Fatalf("seed scope: %v", err)
	}

	revoked, err := svc.Delete(g.ID, 1, "admin", "127.0.0.1")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if revoked != 1 {
		t.Fatalf("連動撤銷筆數 = %d, want 1", revoked)
	}

	// 委派恰一次、在交易句柄上、帶正確 groupID（tx-taking 窄 port）
	if len(revoker.calls) != 1 {
		t.Fatalf("應恰好委派一次 authz 級聯撤銷, got %d 次: %+v", len(revoker.calls), revoker.calls)
	}
	if revoker.calls[0].TxIsNil || revoker.calls[0].GroupID != g.ID {
		t.Fatalf("委派引數錯誤: %+v（tx 不得為 nil、groupID 應為 %d）", revoker.calls[0], g.ID)
	}

	// **asset 自己不得再寫 authz 的表**（資料邊界閘門的方向）：
	// 兩列由 stub（不執行任何刪除）承接後應原封不動——若 asset 私下又刪一次，此處會紅
	var active int64
	db.Model(&model.AssetAuthorization{}).Where("asset_group_id = ?", g.ID).Count(&active)
	if active != 1 {
		t.Errorf("asset 不得直接寫 authz 的 asset_authorizations（stub 未刪，應仍為 1）, got %d", active)
	}
	var activeScopes int64
	db.Model(&model.ApproverScope{}).Where("asset_group_id = ?", g.ID).Count(&activeScopes)
	if activeScopes != 1 {
		t.Errorf("asset 不得直接寫 authz 的 approver_scopes（stub 未刪，應仍為 1）, got %d", activeScopes)
	}

	// 審計留痕含連動筆數：兩個筆數都必須來自窄 port 的回傳值
	var entry model.AuditLog
	if err := db.Where("resource = ? AND action = ?", model.ResourceAsset, model.ActionDelete).
		First(&entry).Error; err != nil {
		t.Fatalf("審計記錄應存在: %v", err)
	}
	if entry.Username != "admin" || !strings.Contains(entry.Details, `"revoked_authorizations":1`) ||
		!strings.Contains(entry.Details, `"revoked_approver_scopes":1`) {
		t.Errorf("審計內容不完整: %+v", entry)
	}
}

// TestAssetNodeTreeListing Tree 端點：路徑組裝、資產計數（直掛/含子樹）、
// has_children 與可視集合收斂
func TestAssetNodeTreeListing(t *testing.T) {
	svc, db := setupGroupDB(t)
	prod, _ := svc.Create(&AssetGroupRequest{Name: "prod"}, 1, "admin", "127.0.0.1")
	kafka, _ := svc.Create(&AssetGroupRequest{Name: "kafka", ParentID: &prod.ID}, 1, "admin", "127.0.0.1")
	_, _ = svc.Create(&AssetGroupRequest{Name: "sit"}, 1, "admin", "127.0.0.1")

	a1 := model.Asset{Name: "a1", Protocol: model.ProtocolSSH, Host: "h", Port: 22}
	a2 := model.Asset{Name: "a2", Protocol: model.ProtocolSSH, Host: "h", Port: 22}
	db.Create(&a1)
	db.Create(&a2)
	db.Create(&model.AssetNode{AssetID: a1.ID, NodeID: prod.ID})
	db.Create(&model.AssetNode{AssetID: a2.ID, NodeID: kafka.ID})

	roots, err := svc.Tree(nil, nil)
	if err != nil {
		t.Fatalf("Tree root: %v", err)
	}
	if len(roots) != 2 {
		t.Fatalf("根層應 2 節點, got %d", len(roots))
	}
	var prodNode *TreeNode
	for i := range roots {
		if roots[i].ID == prod.ID {
			prodNode = &roots[i]
		}
	}
	if prodNode == nil || !prodNode.HasChildren {
		t.Fatalf("prod 應有子節點: %+v", prodNode)
	}
	if prodNode.AssetCount != 1 || prodNode.SubtreeAssetCount != 2 {
		t.Fatalf("prod 計數 direct=%d subtree=%d, want 1/2", prodNode.AssetCount, prodNode.SubtreeAssetCount)
	}

	children, err := svc.Tree(&prod.ID, nil)
	if err != nil || len(children) != 1 {
		t.Fatalf("prod 子層應 1 節點: %d, %v", len(children), err)
	}
	if children[0].Path != "prod / kafka" {
		t.Fatalf("路徑組裝 = %q", children[0].Path)
	}

	// 可視集合收斂：僅 kafka 可視時根層 prod 被濾除（handler 端會把祖先補進
	// 可視集合；此處驗證 service 嚴格按集合過濾）
	filtered, err := svc.Tree(nil, &TreeVisibility{NodeIDs: map[uint]bool{kafka.ID: true}, AssetIDs: map[uint]bool{}})
	if err != nil || len(filtered) != 0 {
		t.Fatalf("不可視根層應為空: %d, %v", len(filtered), err)
	}

	// 計數收斂：prod 可視但僅 a2（kafka 掛載）在授權集——
	// 直掛 a1 不可視故 asset_count=0、subtree 僅計 a2、has_children 依可視節點集
	vis := &TreeVisibility{
		NodeIDs:  map[uint]bool{prod.ID: true, kafka.ID: true},
		AssetIDs: map[uint]bool{a2.ID: true},
	}
	scoped, err := svc.Tree(nil, vis)
	if err != nil || len(scoped) != 1 {
		t.Fatalf("收斂樹根層應僅 prod: %d, %v", len(scoped), err)
	}
	if scoped[0].AssetCount != 0 || scoped[0].SubtreeAssetCount != 1 {
		t.Fatalf("收斂計數 direct=%d subtree=%d, want 0/1（未授權資產不得入計數）",
			scoped[0].AssetCount, scoped[0].SubtreeAssetCount)
	}
	if !scoped[0].HasChildren {
		t.Fatalf("kafka 可視，prod 應 has_children")
	}
}

// TestAssetMultiMembershipNodeInfo 多歸屬：同資產掛兩節點，NodeIDs/NodePaths 齊全
func TestAssetMultiMembershipNodeInfo(t *testing.T) {
	svc, db := setupGroupDB(t)
	prod, _ := svc.Create(&AssetGroupRequest{Name: "prod"}, 1, "admin", "127.0.0.1")
	sit, _ := svc.Create(&AssetGroupRequest{Name: "sit"}, 1, "admin", "127.0.0.1")

	a := model.Asset{Name: "multi", Protocol: model.ProtocolSSH, Host: "h", Port: 22}
	db.Create(&a)
	db.Create(&model.AssetNode{AssetID: a.ID, NodeID: prod.ID})
	db.Create(&model.AssetNode{AssetID: a.ID, NodeID: sit.ID})

	assets := []model.Asset{a}
	if err := FillNodeInfo(db, assets); err != nil {
		t.Fatalf("fill: %v", err)
	}
	if len(assets[0].NodeIDs) != 2 || len(assets[0].NodePaths) != 2 {
		t.Fatalf("多歸屬應 2 節點: ids=%v paths=%v", assets[0].NodeIDs, assets[0].NodePaths)
	}
	_ = svc
}

// uptrAsset 取位址的測試小工具（原 uptrScope 住在 authz 側的
// access_request_service_test.go，搬檔後跨包取不到；逐字複製一份，
// 不為此在生產碼開匯出面）。
func uptrAsset(v uint) *uint { return &v }

// TestAssetGroupDeleteFailsClosedWhenRevokeFails 級聯撤銷 fail-close：
// 級聯撤銷失敗或撤銷面未注入時，節點刪除**必須整筆失敗**。
//
// **為何非有不可**：載重性驗證實測到，把
// `revoked, _, rerr = ...; if rerr != nil { return rerr }` 改成
// 「撤銷失敗就記個 log 繼續刪」之後，`TestAssetGroupDeleteRevokesGrants` 與
// AP-37 的 audit backstop **兩格都照樣綠**——backstop 注入的是**審計**失敗，
// 不是**撤銷**失敗，那條路徑當時無人看守。節點刪掉而授權留著＝幽靈授權，
// 正是這條級聯存在的理由。
func TestAssetGroupDeleteFailsClosedWhenRevokeFails(t *testing.T) {
	t.Run("撤銷回錯誤即整筆回滾", func(t *testing.T) {
		db := setupGroupOnlyDB(t)
		boom := errors.New("撤銷面故障")
		rv := newStubGroupRevoker(0, 0)
		rv.failErr = boom
		svc := NewAssetGroupService(db, audit.NewTxSink(), rv)
		g, err := svc.Create(&AssetGroupRequest{Name: "G"}, 1, "admin", "127.0.0.1")
		if err != nil {
			t.Fatalf("前置建立: %v", err)
		}
		if _, err := svc.Delete(g.ID, 1, "admin", "127.0.0.1"); !errors.Is(err, boom) {
			t.Fatalf("撤銷失敗時刪除應回該錯誤, got %v", err)
		}
		var groups int64
		db.Model(&model.AssetGroup{}).Where("id = ?", g.ID).Count(&groups)
		if groups != 1 {
			t.Fatalf("撤銷失敗時節點竟被刪除（剩 %d 筆，應為 1）——幽靈授權即將產生", groups)
		}
	})

	t.Run("撤銷面未注入即拒絕刪除", func(t *testing.T) {
		db := setupGroupOnlyDB(t)
		svc := NewAssetGroupService(db, audit.NewTxSink(), nil)
		g, err := svc.Create(&AssetGroupRequest{Name: "G"}, 1, "admin", "127.0.0.1")
		if err != nil {
			t.Fatalf("前置建立: %v", err)
		}
		if _, err := svc.Delete(g.ID, 1, "admin", "127.0.0.1"); err == nil {
			t.Fatal("未注入撤銷面時刪除竟然成功——nil 被當成 no-op，授權將靜默殘留")
		}
		var groups int64
		db.Model(&model.AssetGroup{}).Where("id = ?", g.ID).Count(&groups)
		if groups != 1 {
			t.Fatalf("未注入撤銷面時節點竟被刪除（剩 %d 筆，應為 1）", groups)
		}
	})
}
