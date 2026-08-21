package authz

import (
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// assetAuthorizationRepository 資產授權資料存取層
type assetAuthorizationRepository struct {
	db *gorm.DB
}

// newAssetAuthorizationRepository 創建資產授權 Repository
func newAssetAuthorizationRepository(db *gorm.DB) *assetAuthorizationRepository {
	return &assetAuthorizationRepository{
		db: db,
	}
}

// Create 創建授權
func (r *assetAuthorizationRepository) Create(auth *model.AssetAuthorization) error {
	if err := r.db.Create(auth).Error; err != nil {
		return fmt.Errorf("創建授權失敗: %w", err)
	}
	return nil
}

// FindByID 根據 ID 查詢授權
func (r *assetAuthorizationRepository) FindByID(id uint) (*model.AssetAuthorization, error) {
	var auth model.AssetAuthorization
	if err := r.db.Preload("User").Preload("UserGroup").Preload("Asset").Preload("AssetGroup").First(&auth, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("授權不存在")
		}
		return nil, fmt.Errorf("查詢授權失敗: %w", err)
	}
	return &auth, nil
}

// FindByUserAndAsset 查詢特定用戶和資產的授權
func (r *assetAuthorizationRepository) FindByUserAndAsset(
	userID uint,
	assetID uint,
	permission model.PermissionType,
) (*model.AssetAuthorization, error) {
	var auth model.AssetAuthorization
	err := r.db.Where("user_id = ? AND asset_id = ? AND permission = ?", userID, assetID, permission).
		First(&auth).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // 不存在時返回 nil，不報錯
		}
		return nil, fmt.Errorf("查詢授權失敗: %w", err)
	}
	return &auth, nil
}

// Delete 軟刪除授權
func (r *assetAuthorizationRepository) Delete(id uint) error {
	if err := r.db.Delete(&model.AssetAuthorization{}, id).Error; err != nil {
		return fmt.Errorf("刪除授權失敗: %w", err)
	}
	return nil
}

// ValidityFilter 有效性篩選（authorization-page-redesign D7）：三態於 COUNT 與
// 分頁前生效（當頁過濾＝稽核漏報，設計裁決否決）。Now 由呼叫端一次捕捉注入，
// 與 validityCondition 同語義（跨 PostgreSQL/SQLite 可攜、測試可固定時間）
type ValidityFilter struct {
	State string // model.ValidityScheduled / ValidityActive / ValidityExpired
	Now   time.Time
}

// nodeStructuralNodesSubquery 目標節點的祖先鏈∪自身∪後代集合（authz-tag-node-filters
// D7 分支 1）：掛祖先的授權因子樹涵蓋本節點、掛後代的落在本節點範圍內。
// 仿 3b CTE 模式的 node 錨定版（既有常數以 asset_id/approver_id 為錨不可復用）。
// 佔位符：nodeID, nodeID
const nodeStructuralNodesSubquery = `(WITH RECURSIVE node_up(id) AS (
	SELECT id FROM asset_groups WHERE id = ? AND deleted_at IS NULL
	UNION
	SELECT g.parent_id FROM asset_groups g JOIN node_up ON g.id = node_up.id
	WHERE g.parent_id IS NOT NULL AND g.deleted_at IS NULL
), node_down(id) AS (
	SELECT id FROM asset_groups WHERE id = ? AND deleted_at IS NULL
	UNION
	SELECT g.id FROM asset_groups g JOIN node_down ON g.parent_id = node_down.id
	WHERE g.deleted_at IS NULL
) SELECT id FROM node_up UNION SELECT id FROM node_down)`

// nodeCoveringNodesSubquery「涵蓋目標子樹內任一資產」的節點集合（D7 分支 2
// 多歸屬橋接）：子樹內資產的掛載節點＋其全部祖先——資產 X 同時掛 A 與 C 子樹、
// 授權掛 C 時，以 A 盤點須命中該授權（其有效範圍涵蓋 A 子樹內的 X；缺此分支
// 即稽核漏報，對抗驗證兩軌交叉確認）。佔位符：nodeID
const nodeCoveringNodesSubquery = `(WITH RECURSIVE bridge_sub(id) AS (
	SELECT id FROM asset_groups WHERE id = ? AND deleted_at IS NULL
	UNION
	SELECT g.id FROM asset_groups g JOIN bridge_sub ON g.parent_id = bridge_sub.id
	WHERE g.deleted_at IS NULL
), covering(id) AS (
	SELECT an.node_id FROM asset_nodes an WHERE an.asset_id IN (
		SELECT an2.asset_id FROM asset_nodes an2 WHERE an2.node_id IN (SELECT id FROM bridge_sub)
	)
	UNION
	SELECT g.parent_id FROM asset_groups g JOIN covering ON g.id = covering.id
	WHERE g.parent_id IS NOT NULL AND g.deleted_at IS NULL
) SELECT id FROM covering)`

// nodeSubtreeAssetsSubquery 目標子樹內資產集合（D7 分支 3：資產客體掛於子樹內）。
// 佔位符：nodeID
const nodeSubtreeAssetsSubquery = `(SELECT an.asset_id FROM asset_nodes an WHERE an.node_id IN (
	WITH RECURSIVE asset_sub(id) AS (
		SELECT id FROM asset_groups WHERE id = ? AND deleted_at IS NULL
		UNION
		SELECT g.id FROM asset_groups g JOIN asset_sub ON g.parent_id = asset_sub.id
		WHERE g.deleted_at IS NULL
	) SELECT id FROM asset_sub
))`

// nodeCoverageCondition D7 涵蓋盤點三分支聯集：均為 IN 子查詢無 JOIN，
// 每筆授權記錄僅出現一次。佔位符：nodeID ×4
const nodeCoverageCondition = "(asset_group_id IN " + nodeStructuralNodesSubquery +
	" OR asset_group_id IN " + nodeCoveringNodesSubquery +
	" OR asset_id IN " + nodeSubtreeAssetsSubquery + ")"

// List 查詢授權列表（支援過濾和分頁）
// filters 支援的鍵: "user_id", "user_group_id", "asset_id", "node_id"（涵蓋盤點，
// authz-tag-node-filters D7）, "permission", "source", "validity"（ValidityFilter）；
// 空 map＝全量（authorization-page-redesign D1）
func (r *assetAuthorizationRepository) List(
	filters map[string]interface{},
	page, pageSize int,
) ([]*model.AssetAuthorization, int64, error) {
	query := r.db.Model(&model.AssetAuthorization{})

	// 應用過濾條件
	for key, value := range filters {
		switch key {
		case "user_id":
			query = query.Where("user_id = ?", value)
		case "user_group_id":
			query = query.Where("user_group_id = ?", value)
		case "asset_id":
			query = query.Where("asset_id = ?", value)
		case "node_id":
			query = query.Where(nodeCoverageCondition, value, value, value, value)
		case "permission":
			query = query.Where("permission = ?", value)
		case "source":
			query = query.Where("source = ?", value)
		case "validity":
			vf, ok := value.(ValidityFilter)
			if !ok {
				continue
			}
			switch vf.State {
			case model.ValidityActive:
				query = query.Where(validityCondition, vf.Now, vf.Now)
			case model.ValidityScheduled:
				query = query.Where("date_start IS NOT NULL AND date_start > ?", vf.Now)
			case model.ValidityExpired:
				query = query.Where("date_expired IS NOT NULL AND date_expired <= ?", vf.Now)
			}
		}
	}

	// 計算總數
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("查詢授權總數失敗: %w", err)
	}

	// 分頁
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	// 查詢數據
	var authorizations []*model.AssetAuthorization
	if err := query.
		Preload("User").
		Preload("UserGroup").
		Preload("Asset").
		Preload("AssetGroup").
		Preload("GrantedByUser").
		Order("created_at DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&authorizations).Error; err != nil {
		return nil, 0, fmt.Errorf("查詢授權列表失敗: %w", err)
	}

	return authorizations, total, nil
}

// subjectCondition 授權主體條件（user-group-authorization）：個人直屬 OR
// 所屬使用者群組。四路徑聯集語義的主體側，與客體側（直授 OR 節點含子樹）正交
const subjectCondition = "(user_id = ? OR user_group_id IN (SELECT user_group_id FROM user_group_members WHERE user_id = ?))"

// assetAncestorNodesSubquery 資產的「掛載節點＋全部祖先」集合（asset-node-tree D3）：
// 授權掛節點 N 含子樹涵蓋資產 A ⟺ N ∈ A 的掛載節點或其任一祖先。
// 佔位符：asset_id 一個。軟刪節點防禦性排除（正常流程僅空節點可刪不會在鏈上）
const assetAncestorNodesSubquery = `(WITH RECURSIVE asset_node_ancestors(id) AS (
	SELECT node_id FROM asset_nodes WHERE asset_id = ?
	UNION
	SELECT g.parent_id FROM asset_groups g
	JOIN asset_node_ancestors ana ON g.id = ana.id
	WHERE g.parent_id IS NOT NULL AND g.deleted_at IS NULL
) SELECT id FROM asset_node_ancestors)`

// nodeObjectCondition 授權客體條件（直授 OR 節點含子樹）；佔位符：assetID, assetID
const nodeObjectCondition = "(asset_id = ? OR asset_group_id IN " + assetAncestorNodesSubquery + ")"

// validityCondition 時效窗條件（D4）：空值＝永久；未達 date_start 或已過
// date_expired 的授權不生效（到期＝判定不命中，記錄留存供審計）。
// 時刻以參數注入（非 DB NOW()）：跨 PostgreSQL/SQLite 可攜，測試可用固定時間
const validityCondition = "(date_start IS NULL OR date_start <= ?) AND (date_expired IS NULL OR date_expired > ?)"

// CheckPermission 檢查權限（核心查詢）
// 查詢用戶（個人或經所屬群組）是否對指定資產擁有任一時效窗內的指定權限。
// 語義鐵則：四路徑（個人∪群組）×（直授∪節點含子樹）聯集、純加法無 deny、
// 無「個人優先」；節點授權隨掛隨涵蓋（asset-node-tree D3 即時查詢無快取）
func (r *assetAuthorizationRepository) CheckPermission(
	userID uint,
	assetID uint,
	permissions []model.PermissionType,
) (bool, error) {
	now := time.Now()
	var count int64
	err := r.db.Model(&model.AssetAuthorization{}).
		Where(subjectCondition+" AND permission IN ? AND "+nodeObjectCondition+" AND "+validityCondition,
			userID, userID, permissions, assetID, assetID, now, now).
		Count(&count).Error

	if err != nil {
		return false, fmt.Errorf("檢查權限失敗: %w", err)
	}

	return count > 0, nil
}

// ConnectSources 來源感知的 connect 授權命中（access-policy-approval D4）：
// 政策閘需要區分「常設授權」與「核准流臨時授權」——非 open 段位僅 ticket 來源放行
type ConnectSources struct {
	Standing bool // 時窗內常設 connect（source=manual 等非核准流來源）
	Ticket   bool // 時窗內核准流臨時 connect（source=ticket）
}

// ResolveConnectSources 一次查詢回傳使用者對資產的 connect 授權來源分組命中。
// 主體/客體/時效條件與 CheckPermission 完全同語義（四路徑聯集、時窗過濾）；
// 僅計 connect——政策閘只關心「可連」的來源，view 不參與判定
func (r *assetAuthorizationRepository) ResolveConnectSources(
	userID uint,
	assetID uint,
	now time.Time,
) (ConnectSources, error) {
	return r.ResolveConnectSourcesWithDB(r.db, userID, assetID, now)
}

// ResolveConnectSourcesWithDB 同 ResolveConnectSources，但以指定 db/tx 執行——
// 破窗於鎖定申請人列後於同一交易重判資格用（break-glass-revocation codex #2：
// 收緊「交易外查資格、交易內建票證」窗口內授權被撤的 TOCTOU）
func (r *assetAuthorizationRepository) ResolveConnectSourcesWithDB(
	db *gorm.DB,
	userID uint,
	assetID uint,
	now time.Time,
) (ConnectSources, error) {
	var sources []string
	err := db.Model(&model.AssetAuthorization{}).
		Distinct("source").
		Where(subjectCondition+" AND permission = ? AND "+nodeObjectCondition+" AND "+validityCondition,
			userID, userID, model.PermissionConnect, assetID, assetID, now, now).
		Pluck("source", &sources).Error
	if err != nil {
		return ConnectSources{}, fmt.Errorf("查詢連線授權來源失敗: %w", err)
	}

	var result ConnectSources
	for _, s := range sources {
		if s == model.AuthorizationSourceTicket {
			result.Ticket = true
		} else {
			result.Standing = true
		}
	}
	return result, nil
}

// AccountScopesFor 使用者對某資產「命中授權列的帳號範圍」原始清單
// （asset-multi-account D5）。
//
// 條件與 CheckPermission／ResolveConnectSources 就**授權列查詢**而言同構（四路徑
// 主體×（直授 OR 節點含子樹）×時效窗×軟刪×權限階梯）——這是刻意的：帳號維度是
// 既有授權判定的一個屬性，不是另一套平行判定。任何一邊的主體/客體/時效語義變動
// 而另一邊沒跟上，就會出現「有連線權但無任何可用帳號」或反之的裂縫。
//
// **一項刻意的不同構**（opus 階段 4 F2，據實記載勿當成待補的漏）：
// `CheckPermission(view)` 有第三來源「審核範圍隱含 view」（`ApproverScopeCoversAsset`），
// 本函式**沒有**。這不是遺漏而是裁決：該來源存在的目的是讓 approver 看得見待審
// 申請所指的資產以便判斷，而帳號清單是**憑證身分的盤點**（含 privileged 標記），
// 正是本階段從一般 asset:view 使用者手上收回的偵察面。approver 身分若能換來
// 全資產的帳號清單，等於用一個管理角色把剛關上的門重新打開。
// 故 approver 僅憑審核範圍時，帳號範圍恆為空（fail-close，資產仍可見、帳號不可見）。
// 其真正需要用某帳號連線時，走正常授權即可命中本查詢。
// 測試 `TestAccountScope_ApproverScopeDoesNotGrantAccounts` 釘住此差異。
//
// permissions 傳權限階梯（連線判定用 [connect]、可視判定用 [view, connect]）。
// 回傳每筆命中列的 accounts 原值（未展開、未聯集）——聯集與 @ALL 展開屬
// service 層語義，repository 只負責「哪些列命中」。
// 空清單＝零命中列（無權限），與「命中但範圍為 @ALL」語義不同，不可混淆
func (r *assetAuthorizationRepository) AccountScopesFor(
	userID uint,
	assetID uint,
	permissions []model.PermissionType,
	now time.Time,
) ([]model.AccountScope, error) {
	var rows []model.AssetAuthorization
	err := r.db.Model(&model.AssetAuthorization{}).
		Select("accounts").
		Where(subjectCondition+" AND permission IN ? AND "+nodeObjectCondition+" AND "+validityCondition,
			userID, userID, permissions, assetID, assetID, now, now).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("查詢授權帳號範圍失敗: %w", err)
	}
	scopes := make([]model.AccountScope, 0, len(rows))
	for _, row := range rows {
		scopes = append(scopes, row.Accounts)
	}
	return scopes, nil
}

// StandingConnectAssetIDs 給定資產集合中，使用者持「時窗內常設 connect」
// （source<>'ticket'）的資產 ID 集（break-glass-revocation D3：破窗資格 bulk 判定，
// 資產列表標註用——單資產裁決仍走 ResolveConnectSources）。
// 條件與 ResolveConnectSources 同構：四路徑主體×（直授 OR 經資產組）×時效窗
func (r *assetAuthorizationRepository) StandingConnectAssetIDs(userID uint, assetIDs []uint, now time.Time) (map[uint]bool, error) {
	if len(assetIDs) == 0 {
		return map[uint]bool{}, nil
	}
	var ids []uint
	err := r.db.Model(&model.Asset{}).
		Where("id IN ?", assetIDs).
		Where(`EXISTS (
			SELECT 1 FROM asset_authorizations aa
			WHERE aa.deleted_at IS NULL
			  AND aa.source <> 'ticket'
			  AND aa.permission = ?
			  AND (aa.user_id = ? OR aa.user_group_id IN (SELECT user_group_id FROM user_group_members WHERE user_id = ?))
			  AND (aa.asset_id = assets.id OR aa.asset_group_id IN (WITH RECURSIVE ana(id) AS (
				SELECT node_id FROM asset_nodes WHERE asset_id = assets.id
				UNION
				SELECT g.parent_id FROM asset_groups g JOIN ana ON g.id = ana.id
				WHERE g.parent_id IS NOT NULL AND g.deleted_at IS NULL
			  ) SELECT id FROM ana))
			  AND (aa.date_start IS NULL OR aa.date_start <= ?) AND (aa.date_expired IS NULL OR aa.date_expired > ?)
		)`, model.PermissionConnect, userID, userID, now, now).
		Pluck("id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("查詢常設連線授權失敗: %w", err)
	}
	result := make(map[uint]bool, len(ids))
	for _, id := range ids {
		result[id] = true
	}
	return result, nil
}

// approverScopeActorCondition 審核方命中條件（approval-routing-quorum D-7）：
// 個人直配 OR 屬於審核方群組（群組即資格，成員異動即時反映）。
// 佔位符：user_id, user_id
const approverScopeActorCondition = `(approver_id = ? OR approver_group_id IN (SELECT user_group_id FROM user_group_members WHERE user_id = ?))`

// approverScopeAssetCondition 審核範圍命中條件（access-policy-approval D5，
// asset-node-tree 升級）：直配資產 OR 經節點含子樹——審核範圍與授權客體
// 同構原則（範圍配節點者涵蓋子樹資產）
const approverScopeAssetCondition = `(asset_id = ? OR asset_group_id IN ` + assetAncestorNodesSubquery + `)`

// ApproverScopeCoversAsset 使用者的審核範圍是否涵蓋資產（決定資格＋可視第三來源；
// 審核方個人與群組成員同語義）
func (r *assetAuthorizationRepository) ApproverScopeCoversAsset(userID, assetID uint) (bool, error) {
	var count int64
	err := r.db.Model(&model.ApproverScope{}).
		Where(approverScopeActorCondition+" AND "+approverScopeAssetCondition,
			userID, userID, assetID, assetID).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("查詢審核範圍失敗: %w", err)
	}
	return count > 0, nil
}

// scopeDescendantAssetsSubquery 審核範圍節點的「後代含自身」掛載資產集
// （asset-node-tree：範圍配節點涵蓋子樹）。後代方向展開：自範圍節點起向下
// 收全部子孫節點，再經 asset_nodes 收資產。佔位符：user_id ×2（審核方條件）
const scopeDescendantAssetsSubquery = `(SELECT an.asset_id FROM asset_nodes an WHERE an.node_id IN (
	WITH RECURSIVE scope_desc(id) AS (
		SELECT asset_group_id FROM approver_scopes
		WHERE ` + approverScopeActorCondition + ` AND asset_group_id IS NOT NULL AND deleted_at IS NULL
		UNION
		SELECT g.id FROM asset_groups g JOIN scope_desc sd ON g.parent_id = sd.id
		WHERE g.deleted_at IS NULL
	) SELECT id FROM scope_desc
))`

// ApproverScopedAssets 使用者審核範圍內的全部資產（可視解析第三來源，D5）：
// 僅 view 語義——approver 對範圍內資產可見以便審核，不隱含連線權；
// 不進存取複審矩陣（範圍是職能可視，不是授權記錄）。
// 刻意僅資產側：申請人側範圍不隱含任何資產可視（approval-routing-quorum D-2）；
// 審核方群組成員與個人同享資產側可視（D-7）
func (r *assetAuthorizationRepository) ApproverScopedAssets(userID uint) ([]*model.Asset, error) {
	var assets []*model.Asset
	err := r.db.
		Where(`id IN (SELECT asset_id FROM approver_scopes WHERE `+approverScopeActorCondition+` AND asset_id IS NOT NULL AND deleted_at IS NULL)
			OR id IN `+scopeDescendantAssetsSubquery,
			userID, userID, userID, userID).
		Find(&assets).Error
	if err != nil {
		return nil, fmt.Errorf("查詢審核範圍資產失敗: %w", err)
	}
	return assets, nil
}

// ── 審核範圍命中家族（approval-routing-quorum D-1/D-2 收斂）─────────────
// 「範圍涵蓋」語義的全部 SQL 集中於本檔此區——禁止在 service 或他處另寫等價
// SQL（歷史漂移：scopedAssetSubquery 曾在 service 手寫後代方向拷貝，致單筆
// 判定與列表過濾兩套實作）。兩種查詢形狀、同一語義：
//   單筆（祖先方向，給定資產問「誰的範圍蓋到」）→ ApproverScopeCoversRequest
//   列表（後代方向，給定 approver 展開「蓋到哪些單」）→ approverScopeRouteCondition
// 等價性由 repository 測試釘住（同一棵樹上兩方向結論必一致）；修改任一側
// 涵蓋規則，本區全部常數與兩個入口同步改。

// approverScopeSubjectCondition 申請人側命中（scope 表內條件）：申請人本人
// （subject_user）或其所屬使用者群組（subject_group）。成員異動即時反映
// （判定時 join，無快取）。佔位符：requester_id, requester_id
const approverScopeSubjectCondition = `(subject_user_id = ? OR subject_group_id IN (SELECT user_group_id FROM user_group_members WHERE user_id = ?))`

// ApproverScopeCoversRequest 核准資格命中（單筆判定唯一入口）：操作者為審核方
// （個人本人 OR 群組成員）且〔資產側（直配 OR 祖先節點含子樹）OR 申請人側
// （本人 OR 所屬群組）〕。核准/拒絕/撤銷/補審的範圍資格一律走此函式；
// admin 兜底與自核禁止在 service 層
func (r *assetAuthorizationRepository) ApproverScopeCoversRequest(approverID, assetID, requesterID uint) (bool, error) {
	return r.coversRequest(r.db, approverID, assetID, requesterID)
}

// ApproverScopeCoversRequestTx 交易內資格重查（approval-routing-quorum，codex #3）：
// quorum 投票的鎖單交易內重跑資格判定，消除「eligibleToDecide 判定 → 鎖單投票」
// 之間成員被移出群組/範圍被刪的 TOCTOU 窗口（否則已撤資格的票仍可能成為達門檻的最後一票）
func (r *assetAuthorizationRepository) ApproverScopeCoversRequestTx(tx *gorm.DB, approverID, assetID, requesterID uint) (bool, error) {
	return r.coversRequest(tx, approverID, assetID, requesterID)
}

func (r *assetAuthorizationRepository) coversRequest(db *gorm.DB, approverID, assetID, requesterID uint) (bool, error) {
	var count int64
	err := db.Model(&model.ApproverScope{}).
		Where(approverScopeActorCondition+" AND ("+approverScopeAssetCondition+" OR "+approverScopeSubjectCondition+")",
			approverID, approverID, assetID, assetID, requesterID, requesterID).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("查詢審核資格失敗: %w", err)
	}
	return count > 0, nil
}

// evaluateEffectiveApprover 審核資格的**唯一述詞**（D-12 收斂，W7b 8.1）：
// 具 approver 角色 OR 屬於任一審核方群組。**`admin` 角色本身不構成審核資格。**
// 即時查——入組/離組、配摘角色即刻生效，無快取。
//
// 收斂前存在兩份真相（守衛入口放行 admin、入口/badge 判定不放行），D-12 拍板
// 以「不含 admin」為準，故審核端點守衛（`EvaluateApproverRouteEligibility`）與
// 入口/badge（`IsEffectiveApprover`）自本函式取得同一份判定。
//
// roleQueryFailed 供呼叫端維持既有的兩種內部錯誤碼分流
// （角色查詢失敗＝CodeInternalRoleQuery、群組查詢失敗＝CodeInternalApproverQuery）。
func evaluateEffectiveApprover(db *gorm.DB, userID uint) (allowed bool, roleQueryFailed bool, err error) {
	var count int64
	if qErr := db.Table("user_roles").
		Joins("JOIN roles ON user_roles.role_id = roles.id").
		Where("user_roles.user_id = ? AND roles.name = ? AND roles.deleted_at IS NULL",
			userID, model.RoleApprover).
		Count(&count).Error; qErr != nil {
		return false, true, fmt.Errorf("查詢審核角色失敗: %w", qErr)
	}
	if count > 0 {
		return true, false, nil
	}
	if qErr := db.Model(&model.ApproverScope{}).
		Where("approver_group_id IN (SELECT user_group_id FROM user_group_members WHERE user_id = ?)", userID).
		Count(&count).Error; qErr != nil {
		return false, false, fmt.Errorf("查詢審核方群組資格失敗: %w", qErr)
	}
	return count > 0, false, nil
}

// IsEffectiveApprover 審核資格判定（D-7 群組即資格）：具 approver 角色 OR
// 屬於任一審核方群組。**D-12 收斂後**守衛（`RequireApproverRole`）與入口/badge
// 判定確實共用同一述詞（`evaluateEffectiveApprover`）——收斂前守衛另有一份含
// admin 放行的 SQL，並未呼叫本函式，原註解「守衛與入口共用」在當時不成立（W7b 8.4 訂正）
func (r *assetAuthorizationRepository) IsEffectiveApprover(userID uint) (bool, error) {
	allowed, _, err := evaluateEffectiveApprover(r.db, userID)
	return allowed, err
}

// scopeRouteAssetSubquery 資產側列表過濾（後代方向；自 service 遷入，D-1 整改）：
// 直配資產 OR 範圍節點後代掛載資產。佔位符：user_id ×4（審核方條件 ×2 處）
const scopeRouteAssetSubquery = `asset_id IN (
	SELECT id FROM assets WHERE deleted_at IS NULL AND (
		id IN (SELECT asset_id FROM approver_scopes WHERE ` + approverScopeActorCondition + ` AND asset_id IS NOT NULL AND deleted_at IS NULL)
		OR id IN ` + scopeDescendantAssetsSubquery + `
	))`

// scopeRouteSubjectSubquery 申請人側列表過濾：範圍直配使用者 ∪ 範圍群組成員
// 展開。佔位符：user_id ×4（審核方條件 ×2 處）
const scopeRouteSubjectSubquery = `(
	SELECT s.subject_user_id FROM approver_scopes s
	WHERE (s.approver_id = ? OR s.approver_group_id IN (SELECT user_group_id FROM user_group_members WHERE user_id = ?))
	  AND s.subject_user_id IS NOT NULL AND s.deleted_at IS NULL
	UNION
	SELECT gm.user_id FROM user_group_members gm
	JOIN approver_scopes s ON s.subject_group_id = gm.user_group_id
	WHERE (s.approver_id = ? OR s.approver_group_id IN (SELECT user_group_id FROM user_group_members WHERE user_id = ?))
	  AND s.deleted_at IS NULL)`

// approverScopeRouteCondition 列表過濾條件（雙側聯集）：requesterCol 為該表的
// 申請人欄名（access_requests→requester_id、asset_authorizations→user_id），
// 呼叫端傳編譯期常數字串、非使用者輸入。佔位符：user_id ×8（操作者 id 重複八次）
func approverScopeRouteCondition(requesterCol string) string {
	return "(" + scopeRouteAssetSubquery + " OR " + requesterCol + " IN " + scopeRouteSubjectSubquery + ")"
}

// permissionWeight 權限權重（connect > view，J 兩階收斂），用於聚合每資產最高授權等級。
// 歷史軟刪列可能殘留 manage 值（審計不可變），不在此表內＝權重 0，
// 但軟刪列本就不進任何解析路徑，無實際影響
func permissionWeight(p model.PermissionType) int {
	switch p {
	case model.PermissionConnect:
		return 2
	case model.PermissionView:
		return 1
	default:
		return 0
	}
}

// GetAuthorizedAssets 獲取用戶有權限的資產列表與每資產最高授權等級。
// 四路徑聯集（與 CheckPermission 同語義）：主體＝個人 OR 所屬群組、
// 客體＝直授 OR 節點含子樹（asset-node-tree D3）；僅計入時效窗內授權。
func (r *assetAuthorizationRepository) GetAuthorizedAssets(
	userID uint,
	permissions []model.PermissionType,
) ([]*model.Asset, map[uint]model.PermissionType, error) {
	now := time.Now()
	assets, err := r.AccessibleAssetsWithin(userID, permissions, now)
	if err != nil {
		return nil, nil, err
	}

	// 聚合最高等級：撈命中該 user（個人或群組主體）的時效內授權記錄
	//（軟刪除由 GORM 預設 scope 排除），建 asset_id / node_id → 最高權重
	// 映射；節點授權的等級沿「資產→祖先節點」映射傳播（任一祖先命中即貢獻）。
	// 主體維度不進映射鍵：任一主體路徑命中的授權都對等貢獻等級（聯集取最高）
	var grants []model.AssetAuthorization
	if err := r.db.Where(subjectCondition+" AND permission IN ? AND "+validityCondition, userID, userID, permissions, now, now).
		Find(&grants).Error; err != nil {
		return nil, nil, fmt.Errorf("查詢授權記錄失敗: %w", err)
	}

	byAsset := make(map[uint]model.PermissionType, len(grants))
	byNode := make(map[uint]model.PermissionType, len(grants))
	upgrade := func(m map[uint]model.PermissionType, key uint, p model.PermissionType) {
		if permissionWeight(p) > permissionWeight(m[key]) {
			m[key] = p
		}
	}
	for _, g := range grants {
		if g.AssetID != nil {
			upgrade(byAsset, *g.AssetID, g.Permission)
		}
		if g.AssetGroupID != nil {
			upgrade(byNode, *g.AssetGroupID, g.Permission)
		}
	}

	assetIDs := make([]uint, 0, len(assets))
	for _, a := range assets {
		assetIDs = append(assetIDs, a.ID)
	}
	ancestors, err := r.AssetAncestorNodes(assetIDs)
	if err != nil {
		return nil, nil, err
	}

	levels := make(map[uint]model.PermissionType, len(assets))
	for _, a := range assets {
		best := byAsset[a.ID]
		for _, nodeID := range ancestors[a.ID] {
			if permissionWeight(byNode[nodeID]) > permissionWeight(best) {
				best = byNode[nodeID]
			}
		}
		if best != "" {
			levels[a.ID] = best
		}
	}

	return assets, levels, nil
}

// fourPathAccessibleAssetsCondition 四路徑可及資產相關子查詢（自 GetAuthorizedAssets
// 抽出共用，authorization-page-redesign D3 防漂移：resolver 禁另寫等價 SQL）。
// 佔位符：userID, userID, permissions, now, now
const fourPathAccessibleAssetsCondition = `EXISTS (
	SELECT 1 FROM asset_authorizations aa
	WHERE aa.deleted_at IS NULL
	  AND (aa.user_id = ? OR aa.user_group_id IN (SELECT user_group_id FROM user_group_members WHERE user_id = ?))
	  AND aa.permission IN ?
	  AND (aa.asset_id = assets.id OR aa.asset_group_id IN (WITH RECURSIVE ana(id) AS (
		SELECT node_id FROM asset_nodes WHERE asset_id = assets.id
		UNION
		SELECT g.parent_id FROM asset_groups g JOIN ana ON g.id = ana.id
		WHERE g.parent_id IS NOT NULL AND g.deleted_at IS NULL
	  ) SELECT id FROM ana))
	  AND (aa.date_start IS NULL OR aa.date_start <= ?) AND (aa.date_expired IS NULL OR aa.date_expired > ?)
)`

// AccessibleAssetsWithin 指定時刻四路徑聯集可及的資產集合（授權記錄路徑，
// 不含角色短路與 approver 範圍）。GetAuthorizedAssets 與 EffectiveAccessResolver
// 共用此查詢（同一 SQL 消語義漂移）
func (r *assetAuthorizationRepository) AccessibleAssetsWithin(
	userID uint,
	permissions []model.PermissionType,
	now time.Time,
) ([]*model.Asset, error) {
	var assets []*model.Asset
	err := r.db.
		Where(fourPathAccessibleAssetsCondition, userID, userID, permissions, now, now).
		Find(&assets).Error
	if err != nil {
		return nil, fmt.Errorf("查詢授權資產失敗: %w", err)
	}
	return assets, nil
}

// SubjectGrantsWithin 主體（個人＋所屬群組）於時窗內的全部授權記錄，
// 帶群組關聯供溯因呈現（authorization-page-redesign D3）
func (r *assetAuthorizationRepository) SubjectGrantsWithin(
	userID uint,
	now time.Time,
) ([]model.AssetAuthorization, error) {
	var grants []model.AssetAuthorization
	if err := r.db.
		Preload("UserGroup").
		Where(subjectCondition+" AND "+validityCondition, userID, userID, now, now).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("查詢主體授權記錄失敗: %w", err)
	}
	return grants, nil
}

// AssetGrantsWithin 命中指定資產（直授 OR 祖先節點含子樹）於時窗內的全部
// 授權記錄，帶主體關聯供溯因呈現（authorization-page-redesign D3 客體視角）
func (r *assetAuthorizationRepository) AssetGrantsWithin(
	assetID uint,
	now time.Time,
) ([]model.AssetAuthorization, error) {
	var grants []model.AssetAuthorization
	if err := r.db.
		Preload("User").
		Preload("UserGroup").
		Where(nodeObjectCondition+" AND "+validityCondition, assetID, assetID, now, now).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("查詢資產授權記錄失敗: %w", err)
	}
	return grants, nil
}

// ApproversCoveringAsset 審核範圍涵蓋指定資產的 approver 集合
// （authorization-page-redesign D3 客體視角的 approver_scope 來源）
func (r *assetAuthorizationRepository) ApproversCoveringAsset(assetID uint) ([]uint, error) {
	var ids []uint
	if err := r.db.Model(&model.ApproverScope{}).
		Distinct("approver_id").
		Where(approverScopeAssetCondition, assetID, assetID).
		Pluck("approver_id", &ids).Error; err != nil {
		return nil, fmt.Errorf("查詢資產審核範圍失敗: %w", err)
	}
	return ids, nil
}

// GroupMembersByGroupIDs 批次撈群組成員（排除軟刪使用者），供客體視角
// 展開群組主體至成員（authorization-page-redesign D3）
func (r *assetAuthorizationRepository) GroupMembersByGroupIDs(groupIDs []uint) (map[uint][]model.User, error) {
	result := make(map[uint][]model.User, len(groupIDs))
	if len(groupIDs) == 0 {
		return result, nil
	}
	var rows []struct {
		UserGroupID uint
		model.User
	}
	if err := r.db.Table("user_group_members m").
		Select("m.user_group_id, u.id, u.username").
		Joins("JOIN users u ON u.id = m.user_id AND u.deleted_at IS NULL").
		Where("m.user_group_id IN ?", groupIDs).
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢群組成員失敗: %w", err)
	}
	for _, row := range rows {
		result[row.UserGroupID] = append(result[row.UserGroupID], row.User)
	}
	return result, nil
}

// AssetAncestorNodes 批次撈「資產→掛載節點＋全部祖先」映射（asset-node-tree）：
// 單次遞迴 CTE 取代逐資產展開，供等級聚合與可視鏈組裝
func (r *assetAuthorizationRepository) AssetAncestorNodes(assetIDs []uint) (map[uint][]uint, error) {
	result := make(map[uint][]uint, len(assetIDs))
	if len(assetIDs) == 0 {
		return result, nil
	}
	type pair struct {
		AssetID uint
		NodeID  uint
	}
	var pairs []pair
	err := r.db.Raw(`WITH RECURSIVE anc(asset_id, node_id) AS (
		SELECT asset_id, node_id FROM asset_nodes WHERE asset_id IN ?
		UNION
		SELECT anc.asset_id, g.parent_id FROM asset_groups g
		JOIN anc ON g.id = anc.node_id
		WHERE g.parent_id IS NOT NULL AND g.deleted_at IS NULL
	) SELECT asset_id, node_id FROM anc`, assetIDs).Scan(&pairs).Error
	if err != nil {
		return nil, fmt.Errorf("查詢資產節點祖先失敗: %w", err)
	}
	for _, p := range pairs {
		result[p.AssetID] = append(result[p.AssetID], p.NodeID)
	}
	return result, nil
}

// AuthorizationTargetAssetID 授權列的資產客體 id（審計主體鍵用）。
//
// **為何是本模組的匯出函式而不是接入層自查**（SD-2）：`asset_authorizations`
// 由 authz 擁有，handler 一旦自己查它，「這列指向哪台資產」就出現第二份真相
// （SD-3／SD-4 的成因）。形態沿 `asset.NodePathMap(db)` 的既有作法——接入層傳
// 句柄、查詢留在擁有者這一側。
//
// 三種情況一律回 (nil, nil)：查不到、客體是節點（一次涵蓋多台資產，沒有單一主體）、
// 該列的 asset_id 為 NULL。nil 即中介層不填 asset_id，而非填 0。
func AuthorizationTargetAssetID(db *gorm.DB, authorizationID uint) (*uint, error) {
	if db == nil {
		return nil, nil
	}
	var row model.AssetAuthorization
	if err := db.Select("asset_id").First(&row, authorizationID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("查詢授權客體失敗: %w", err)
	}
	return row.AssetID, nil
}
