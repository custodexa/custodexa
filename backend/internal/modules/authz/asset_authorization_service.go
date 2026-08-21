package authz

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/custodexa/backend/internal/kernel"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	// ErrAuthorizationNotFound 授權不存在
	ErrAuthorizationNotFound = errors.New("授權不存在")
	// ErrAuthorizationExists 授權已存在
	ErrAuthorizationExists = errors.New("授權已存在")
	// ErrPermissionDenied 權限不足
	ErrPermissionDenied = errors.New("權限不足")
	// ErrTicketRevocationRequired 臨時授權裸刪守門（authorization-page-redesign D4）：
	// 有關聯申請單的 ticket 授權必須走申請單撤銷流（資格判定、票證附註、
	// 斷線聯動），不得直接 DELETE。handler 以 errors.Is 映射 409
	ErrTicketRevocationRequired = errors.New("臨時授權須經申請單撤銷流處理，不可直接刪除")
)

// AssetAuthorizationService 資產授權服務
type AssetAuthorizationService struct {
	repo *assetAuthorizationRepository
	db   *gorm.DB
}

// NewAssetAuthorizationService 創建資產授權服務
func NewAssetAuthorizationService(db *gorm.DB) *AssetAuthorizationService {
	return &AssetAuthorizationService{
		repo: newAssetAuthorizationRepository(db),
		db:   db,
	}
}

// IsEffectiveApprover 審核資格判定（D-7 群組即資格）：具 approver 角色 OR
// 屬於任一審核方群組。即時查——入組/離組、配摘角色即刻生效。
//
// **W7 §3.3 匯出面**：資料存取層自 `internal/repository` 內化為 authz 的未匯出
// `assetAuthorizationRepository` 後，identity 的登入回應（`is_approver` 顯示欄，
// `auth_service.go:855,1058`）需要一個模組級入口。本方法是該入口的**唯一**形式，
// 不另開包級函式——避免同一判定出現第二條可呼叫路徑。
//
// **注意（D-12 未收斂前的事實）**：本判定**不含 admin**，而
// `EvaluateApproverRouteEligibility`（守衛入口）含 admin，兩者對「僅具 admin」
// 者不等價。差異的機器化證據見 `approver_eligibility_parity_test.go`；
// 收斂是 W7b 的行為變更，不在本波範圍。
func (s *AssetAuthorizationService) IsEffectiveApprover(userID uint) (bool, error) {
	return s.repo.IsEffectiveApprover(userID)
}

// AssetActive 查資產啟用態（asset-list-info-layering D8 停用連線硬擋；
// SFTP 檔案面收口用——與 connect-token 簽發點同語義）。
//
// 回傳契約（asset-syslog-debt-cleanup D3）：資產不存在（含軟刪）時回
// gorm.ErrRecordNotFound，呼叫端須以 errors.Is 分流為「不存在」而非「已停用」。
// 原以 Scan 取值的寫法對空結果集不報錯、active 保持零值 false，使兩者不可分，
// 讓 admin（權限短路）與持軟刪資產殘留授權的使用者收到誤導的 403 asset_disabled。
func (s *AssetAuthorizationService) AssetActive(assetID uint) (bool, error) {
	var asset model.Asset
	if err := s.db.Select("active").First(&asset, assetID).Error; err != nil {
		return false, err
	}
	return asset.Active, nil
}

// GetPermissionHierarchy 獲取權限層級列表（包含隱含的上級權限）
// 權限層級: connect > view（access-policy-approval J：manage 已移除，兩階收斂）
// 例如: 需要 view 權限時，擁有 connect 權限的用戶也可以存取
func GetPermissionHierarchy(perm model.PermissionType) []model.PermissionType {
	switch perm {
	case model.PermissionView:
		return []model.PermissionType{model.PermissionView, model.PermissionConnect}
	case model.PermissionConnect:
		return []model.PermissionType{model.PermissionConnect}
	default:
		return []model.PermissionType{perm}
	}
}

// CheckPermission 檢查用戶是否有資產的指定權限
// 權限層級: connect > view（J 兩階收斂）
// Admin 角色自動擁有所有權限；Auditor 為稽核唯讀角色，僅自動擁有非連線（view）
// 權限，connect 須經正常授權查詢（CPG-002 職責分離：稽核者只檢視不連線）
func (s *AssetAuthorizationService) CheckPermission(
	ctx context.Context,
	userID uint,
	assetID uint,
	requiredPerm model.PermissionType,
) (bool, error) {
	// 1. 從 context 獲取用戶角色（如果有）
	role, ok := ctx.Value("role").(string)
	if ok {
		// 2. Admin 自動擁有所有權限
		if role == model.RoleAdmin {
			log.Printf("[CheckPermission] 用戶 %d 擁有 admin 角色，自動授予權限", userID)
			return true, nil
		}
		// Auditor 稽核唯讀：僅非連線權限（view）自動放行；connect 不短路，
		// 落正常授權查詢——顯式授予某資產 connect 者仍可連（CPG-002）
		if role == model.RoleAuditor && requiredPerm != model.PermissionConnect {
			log.Printf("[CheckPermission] 用戶 %d 擁有 auditor 角色，自動授予 %s（非連線）權限", userID, requiredPerm)
			return true, nil
		}
	}

	// 3. 獲取權限層級列表（包含隱含的上級權限）
	permissions := GetPermissionHierarchy(requiredPerm)

	// 4. 查詢數據庫
	hasPermission, err := s.repo.CheckPermission(userID, assetID, permissions)
	if err != nil {
		log.Printf("[CheckPermission] 查詢權限失敗: userID=%d, assetID=%d, error=%v", userID, assetID, err)
		return false, err
	}

	// 5. 可視第三來源（access-policy-approval D5）：審核範圍隱含 view——
	// approver 對範圍內資產可見以便審核。僅 view 路徑；connect 判定不經此來源
	if !hasPermission && requiredPerm == model.PermissionView {
		covered, err := s.repo.ApproverScopeCoversAsset(userID, assetID)
		if err != nil {
			log.Printf("[CheckPermission] 查詢審核範圍失敗: userID=%d, assetID=%d, error=%v", userID, assetID, err)
			return false, err
		}
		hasPermission = covered
	}

	log.Printf("[CheckPermission] 用戶 %d 對資產 %d 的 %s 權限檢查結果: %v", userID, assetID, requiredPerm, hasPermission)
	return hasPermission, nil
}

// GrantSpec 授權建立規格（user-group-authorization D6）：
// 主體恰一（UserID XOR UserGroupID）×客體恰一（AssetID XOR AssetGroupID）。
// 不含時效欄位——時效唯一來源是核准流（Change 2），管理 API 不接受手填
type GrantSpec struct {
	UserID       *uint
	UserGroupID  *uint
	AssetID      *uint
	AssetGroupID *uint
	Permission   model.PermissionType
	GrantedBy    uint
	// Accounts 帳號範圍（asset-multi-account D5）：**nil＝欄位省略＝`@ALL`**
	// （行為與多帳號維度引入前一致）；非 nil 空清單拒收，見 NormalizeGrantAccounts。
	// 呼叫端傳原始輸入即可，正規化與驗證在此層完成
	Accounts *[]string
}

// ErrInvalidGrantSubject 主體或客體不滿足恰一非空
var ErrInvalidGrantSubject = errors.New("授權主體與客體必須各恰一（user_id/user_group_id 二擇一、asset_id/asset_group_id 二擇一）")

// 授權引用實體不存在的哨兵（V2 對抗驗收 H2）。
//
// 單筆（validateGrantRefs）與批次（validateBatchRefs）共用同一組四個哨兵，
// 差異只在包裹的補充訊息。handler 一律以 errors.Is 分流並帶出 entity 參數，
// 不再對中文訊息做子字串比對——那使 service 的文案成為 API 契約的隱形一部分，
// 改一個字（「用戶」→「使用者」）就會讓 404 悄悄變成 500 且無測試會紅。
var (
	ErrGrantUserNotFound       = errors.New("引用的使用者不存在")
	ErrGrantUserGroupNotFound  = errors.New("引用的使用者群組不存在")
	ErrGrantAssetNotFound      = errors.New("引用的資產不存在")
	ErrGrantAssetGroupNotFound = errors.New("引用的資產分組不存在")
)

// ErrAccountScopeInvalid 帳號範圍不合法（asset-multi-account D5）：顯式空清單、
// 整份皆為空白項、超過 MaxAccountScopeEntries，或含控制字元／冒號
// （同 validateAccountUsername 的威脅面——username 會進 chpasswd stdin 與審計快照）。
//
// 關鍵分別：「**欄位省略**」（nil）才是合法的「未指定＝@ALL」；「**顯式空清單**」
// （`[]`）一律拒收。兩者在 `[]string` 下不可區分，故簽名收 `*[]string`——
// 把它們混為一談會讓「我要限縮」被靜默放大成「全放行」（F1）
var ErrAccountScopeInvalid = errors.New("帳號範圍不合法（不得為空清單、全空白項或含控制字元、冒號）")

// ErrAccountScopeRequired 端點語義要求顯式帳號範圍，但請求未提供該欄
// （`PUT /authorizations/:id/accounts` 用）
var ErrAccountScopeRequired = errors.New("必須顯式提供帳號範圍")

// MaxAccountScopeEntries 帳號範圍單筆授權的元素數上限（opus 階段 4 F7）。
//
// 非美觀限制：本欄是 TEXT，admin-only 端點可寫入任意長 JSON，而**每次連線判定
// 都要載入並展開解析**——無上限等於在最熱的授權路徑上留一個可放大的成本點。
// 200 遠超任何真實資產的帳號數（單台主機的可登入帳號實務上為個位到數十）
const MaxAccountScopeEntries = 200

// NormalizeGrantAccounts 驗證並正規化授權帳號範圍。
//
// **指標型別是安全語義的一部分**（opus F1／codex high，兩軌共同指認）：
// `[]string` 使「欄位省略」與「顯式空陣列」在伺服端不可區分，兩者皆為 nil。
// 舊版把兩者都正規化成 `@ALL`，於是管理員（或階段 5 UI 把 chip 全部清空的操作）
// 送出「我要收到零個帳號」時，實際落庫的是**全部帳號**——本 change 唯一
// 「操作失誤即溢授」的路徑，方向與使用者意圖完全相反。
//
// 語義（D5）：
//   - `nil`（欄位省略）＝未指定＝`@ALL`，維持舊前端與既有腳本的相容行為。
//   - 非 nil 空清單＝**拒收**。刻意不支援「空範圍授權列」：那會在每個判定點
//     多出一個「有授權列但零帳號可用」的邊緣狀態要處理。要撤銷就刪授權列，
//     兩者語義不重疊；要全部帳號就顯式送 `["@ALL"]`。
//   - 含 `@ALL` 即塌縮為 `["@ALL"]`（@ALL 恆為上界，見 model.NormalizeAccountScope）。
//
// 已知限制（據實記載）：帳號範圍綁 username 字串，故 username 為空的帳號
// （VNC/Redis 等無 username 協議）無法個別指定，只能由 @ALL 涵蓋——這是綁字串
// 而非 FK 的固有代價（授權客體可為資產群組，帳號卻是 per-asset 物件）
func NormalizeGrantAccounts(in *[]string) (model.AccountScope, error) {
	if in == nil {
		return nil, nil
	}
	raw := *in
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: 空清單（要全部帳號請顯式送 [\"%s\"]，要撤銷請刪除授權列）",
			ErrAccountScopeInvalid, model.AccountScopeAll)
	}
	if len(raw) > MaxAccountScopeEntries {
		return nil, fmt.Errorf("%w: 元素數超過上限 %d", ErrAccountScopeInvalid, MaxAccountScopeEntries)
	}
	scope := model.NormalizeAccountScope(raw)
	if len(scope) == 0 {
		return nil, fmt.Errorf("%w: 全部項目皆為空白", ErrAccountScopeInvalid)
	}
	for _, name := range scope {
		if name == model.AccountScopeAll {
			continue
		}
		if err := asset.ValidateAccountUsername(name); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrAccountScopeInvalid, err)
		}
	}
	return scope, nil
}

// validateGrantRefs 驗證 spec 形狀與被引用實體存在；引用缺失回上列哨兵的包裹
func (s *AssetAuthorizationService) validateGrantRefs(spec GrantSpec) error {
	if (spec.UserID == nil) == (spec.UserGroupID == nil) || (spec.AssetID == nil) == (spec.AssetGroupID == nil) {
		return ErrInvalidGrantSubject
	}
	if spec.UserID != nil {
		if err := s.db.First(&model.User{}, *spec.UserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: ID=%d", ErrGrantUserNotFound, *spec.UserID)
			}
			return fmt.Errorf("查詢用戶失敗: %w", err)
		}
	}
	if spec.UserGroupID != nil {
		if err := s.db.First(&model.UserGroup{}, *spec.UserGroupID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: ID=%d", ErrGrantUserGroupNotFound, *spec.UserGroupID)
			}
			return fmt.Errorf("查詢使用者群組失敗: %w", err)
		}
	}
	if spec.AssetID != nil {
		if err := s.db.First(&model.Asset{}, *spec.AssetID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: ID=%d", ErrGrantAssetNotFound, *spec.AssetID)
			}
			return fmt.Errorf("查詢資產失敗: %w", err)
		}
	}
	if spec.AssetGroupID != nil {
		if err := s.db.First(&model.AssetGroup{}, *spec.AssetGroupID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: ID=%d", ErrGrantAssetGroupNotFound, *spec.AssetGroupID)
			}
			return fmt.Errorf("查詢資產分組失敗: %w", err)
		}
	}
	return nil
}

// grantExists 活躍同組合是否已存在（軟刪不計，與 partial 唯一索引同語義）。
// 排除核准流來源：臨時授權不佔用手動授權的去重空間——使用者持有效臨時授權時
// admin 仍可授予同組合常設授權（D3 補充）
func (s *AssetAuthorizationService) grantExists(db *gorm.DB, spec GrantSpec) (bool, error) {
	var count int64
	q := db.Model(&model.AssetAuthorization{}).
		Where("permission = ?", spec.Permission).
		Where("source <> ?", model.AuthorizationSourceTicket)
	if spec.UserID != nil {
		q = q.Where("user_id = ?", *spec.UserID)
	} else {
		q = q.Where("user_group_id = ?", *spec.UserGroupID)
	}
	if spec.AssetID != nil {
		q = q.Where("asset_id = ?", *spec.AssetID)
	} else {
		q = q.Where("asset_group_id = ?", *spec.AssetGroupID)
	}
	if err := q.Count(&count).Error; err != nil {
		return false, fmt.Errorf("查詢既有授權失敗: %w", err)
	}
	return count > 0, nil
}

// Grant 統一授權建立入口：四種主體×客體組合共用驗證/去重/建立
func (s *AssetAuthorizationService) Grant(ctx context.Context, spec GrantSpec) (*model.AssetAuthorization, error) {
	if err := s.validateGrantRefs(spec); err != nil {
		return nil, err
	}
	exists, err := s.grantExists(s.db, spec)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrAuthorizationExists
	}

	accounts, err := NormalizeGrantAccounts(spec.Accounts)
	if err != nil {
		return nil, err
	}

	auth := &model.AssetAuthorization{
		UserID:       spec.UserID,
		UserGroupID:  spec.UserGroupID,
		AssetID:      spec.AssetID,
		AssetGroupID: spec.AssetGroupID,
		Permission:   spec.Permission,
		GrantedBy:    spec.GrantedBy,
		Accounts:     accounts,
	}
	if err := s.db.Create(auth).Error; err != nil {
		return nil, fmt.Errorf("建立授權失敗: %w", err)
	}

	var result model.AssetAuthorization
	if err := s.db.Preload("User").Preload("UserGroup").Preload("Asset").Preload("AssetGroup").
		First(&result, auth.ID).Error; err != nil {
		return auth, nil // 回原始 auth（無關聯資料）
	}
	return &result, nil
}

// MaxBatchExpansion 批次授權單次展開上限（成本紅線：長迴圈須設上限）
const MaxBatchExpansion = 10000

// ErrBatchTooLarge 批次展開超上限
var ErrBatchTooLarge = fmt.Errorf("批次授權展開筆數超過上限 %d，請縮小範圍", MaxBatchExpansion)

// ErrBatchEmpty 主體集或客體集為空
var ErrBatchEmpty = errors.New("批次授權須至少各含一個主體（使用者或群組）與客體（資產或資產組）")

// BatchGrantResult 批次授權結果
type BatchGrantResult struct {
	Created int `json:"created"`
	Skipped int `json:"skipped"`
}

// GrantBatch 多主體批次授權（user-group-authorization D6）：
// 主體集（users∪user_groups）×客體集（assets∪asset_groups）於單一交易展開為
// 多筆 XOR 單主體記錄；已存在的活躍組合跳過不報錯。審計事件由審計中介層
// 對 POST /authorizations/batch 記錄（與單筆授權同機制）
func (s *AssetAuthorizationService) GrantBatch(
	ctx context.Context,
	userIDs, userGroupIDs, assetIDs, assetGroupIDs []uint,
	permission model.PermissionType,
	grantedBy uint,
	accounts *[]string,
) (*BatchGrantResult, error) {
	accountScope, err := NormalizeGrantAccounts(accounts)
	if err != nil {
		return nil, err
	}
	userIDs = kernel.DedupeUint(userIDs)
	userGroupIDs = kernel.DedupeUint(userGroupIDs)
	assetIDs = kernel.DedupeUint(assetIDs)
	assetGroupIDs = kernel.DedupeUint(assetGroupIDs)

	subjects := len(userIDs) + len(userGroupIDs)
	objects := len(assetIDs) + len(assetGroupIDs)
	if subjects == 0 || objects == 0 {
		return nil, ErrBatchEmpty
	}
	if subjects*objects > MaxBatchExpansion {
		return nil, ErrBatchTooLarge
	}

	// 引用完整性：任一 id 不存在即整批拒絕（不部分寫入）
	if err := s.validateBatchRefs(userIDs, userGroupIDs, assetIDs, assetGroupIDs); err != nil {
		return nil, err
	}

	// 展開全部組合為單主體單客體記錄
	var toCreate []model.AssetAuthorization
	appendCombo := func(userID, userGroupID, assetID, assetGroupID *uint) {
		toCreate = append(toCreate, model.AssetAuthorization{
			UserID: userID, UserGroupID: userGroupID,
			AssetID: assetID, AssetGroupID: assetGroupID,
			Permission: permission, GrantedBy: grantedBy,
			Accounts: accountScope,
		})
	}
	for i := range userIDs {
		for j := range assetIDs {
			appendCombo(&userIDs[i], nil, &assetIDs[j], nil)
		}
		for j := range assetGroupIDs {
			appendCombo(&userIDs[i], nil, nil, &assetGroupIDs[j])
		}
	}
	for i := range userGroupIDs {
		for j := range assetIDs {
			appendCombo(nil, &userGroupIDs[i], &assetIDs[j], nil)
		}
		for j := range assetGroupIDs {
			appendCombo(nil, &userGroupIDs[i], nil, &assetGroupIDs[j])
		}
	}

	result := &BatchGrantResult{}
	if len(toCreate) > 0 {
		// ON CONFLICT DO NOTHING：既有組合（partial 唯一索引命中）原子跳過。
		// 先查後寫在並發下無法序列化（codex P2：兩交易先讀不存在、之一撞索引整批回滾回 500），
		// 交由 DB 唯一索引兜底才是並發安全的去重。created=實插筆數、skipped=展開數−created
		res := s.db.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(toCreate, 200)
		if res.Error != nil {
			return nil, fmt.Errorf("批次建立授權失敗: %w", res.Error)
		}
		result.Created = int(res.RowsAffected)
		result.Skipped = len(toCreate) - result.Created
	}
	log.Printf("[GrantBatch] 批次授權完成: created=%d, skipped=%d, permission=%s, grantedBy=%d",
		result.Created, result.Skipped, permission, grantedBy)
	return result, nil
}

// validateBatchRefs 批次驗證引用實體存在（各一次 IN 查詢）
func (s *AssetAuthorizationService) validateBatchRefs(userIDs, userGroupIDs, assetIDs, assetGroupIDs []uint) error {
	// notFound 為該實體種類的哨兵（H2）：handler 以 errors.Is 判種類，
	// label 只服務伺服端 log 的可讀性
	checkAll := func(modelPtr interface{}, ids []uint, label string, notFound error) error {
		if len(ids) == 0 {
			return nil
		}
		var count int64
		if err := s.db.Model(modelPtr).Where("id IN ?", ids).Count(&count).Error; err != nil {
			return fmt.Errorf("查詢%s失敗: %w", label, err)
		}
		if count != int64(len(ids)) {
			return fmt.Errorf("%w: %s名單含不存在的 ID", notFound, label)
		}
		return nil
	}
	if err := checkAll(&model.User{}, userIDs, "使用者", ErrGrantUserNotFound); err != nil {
		return err
	}
	if err := checkAll(&model.UserGroup{}, userGroupIDs, "使用者群組", ErrGrantUserGroupNotFound); err != nil {
		return err
	}
	if err := checkAll(&model.Asset{}, assetIDs, "資產", ErrGrantAssetNotFound); err != nil {
		return err
	}
	return checkAll(&model.AssetGroup{}, assetGroupIDs, "資產分組", ErrGrantAssetGroupNotFound)
}

// GrantGroupPermission 授予用戶資產分組權限（asset-group-completion）：
// 組授權對組內全資產生效（CheckPermission OR 查詢）。統一走 Grant
func (s *AssetAuthorizationService) GrantGroupPermission(
	ctx context.Context,
	userID uint,
	groupID uint,
	permission model.PermissionType,
	grantedBy uint,
) (*model.AssetAuthorization, error) {
	return s.Grant(ctx, GrantSpec{
		UserID: &userID, AssetGroupID: &groupID,
		Permission: permission, GrantedBy: grantedBy,
	})
}

// GrantPermission 授予用戶資產權限。統一走 Grant
func (s *AssetAuthorizationService) GrantPermission(
	ctx context.Context,
	userID uint,
	assetID uint,
	permission model.PermissionType,
	grantedBy uint,
) (*model.AssetAuthorization, error) {
	return s.Grant(ctx, GrantSpec{
		UserID: &userID, AssetID: &assetID,
		Permission: permission, GrantedBy: grantedBy,
	})
}

// UpdateAccountScope 調整既有授權列的帳號範圍（asset-multi-account D5）。
//
// 為何是「改列」而非「刪了重授」：帳號範圍不入唯一索引（見 model 欄位註解），
// 同組合恆為單列——收緊範圍若走刪除重建會斷開 created_at／granted_by 的沿革，
// 且 ticket 列根本不允許裸刪。
//
// ticket 列不得由本入口調整：臨時授權的範圍來自申請單內容（核准人不得上調，
// 見 AccessRequest.Accounts），事後從授權頁改等於繞過申請與核准的一致性
func (s *AssetAuthorizationService) UpdateAccountScope(
	ctx context.Context,
	authorizationID uint,
	accounts *[]string,
) (*model.AssetAuthorization, error) {
	// 本端點的唯一職責就是設定帳號範圍，省略該欄不是「維持原狀」也不是「@ALL」，
	// 而是請求沒說清楚要什麼——擋下要求明確，不替管理員猜（F1 同源：猜錯的方向是溢授）
	if accounts == nil {
		return nil, ErrAccountScopeRequired
	}
	scope, err := NormalizeGrantAccounts(accounts)
	if err != nil {
		return nil, err
	}
	auth, err := s.repo.FindByID(authorizationID)
	if err != nil {
		return nil, ErrAuthorizationNotFound
	}
	if auth.Source == model.AuthorizationSourceTicket {
		return nil, ErrTicketAccountScopeImmutable
	}
	if err := s.db.Model(&model.AssetAuthorization{}).
		Where("id = ?", authorizationID).
		Update("accounts", scope).Error; err != nil {
		return nil, fmt.Errorf("更新授權帳號範圍失敗: %w", err)
	}
	log.Printf("[UpdateAccountScope] 授權帳號範圍已更新: authID=%d subject=%s scope=%v",
		authorizationID, describeAuthSubject(auth), scope)

	var result model.AssetAuthorization
	if err := s.db.Preload("User").Preload("UserGroup").Preload("Asset").Preload("AssetGroup").
		First(&result, authorizationID).Error; err != nil {
		return nil, fmt.Errorf("查詢更新後授權失敗: %w", err)
	}
	return &result, nil
}

// ErrTicketAccountScopeImmutable 臨時授權的帳號範圍不可由授權管理入口調整
var ErrTicketAccountScopeImmutable = errors.New("臨時授權的帳號範圍由申請單決定，不可直接調整")

// RevokePermission 撤銷用戶資產權限（軟刪除）
func (s *AssetAuthorizationService) RevokePermission(
	ctx context.Context,
	authorizationID uint,
) error {
	// 1. 檢查授權是否存在
	auth, err := s.repo.FindByID(authorizationID)
	if err != nil {
		return ErrAuthorizationNotFound
	}

	// 2. ticket 裸刪守門（authorization-page-redesign D4）：有關聯申請單者必須
	// 走申請單撤銷流；反查無單的孤兒放行（操作審計由 audit middleware 記錄，
	// 此處補 log 標示孤兒清理）
	if auth.Source == model.AuthorizationSourceTicket {
		var linked int64
		if err := s.db.Model(&model.AccessRequest{}).
			Where("authorization_id = ?", authorizationID).
			Count(&linked).Error; err != nil {
			return fmt.Errorf("查詢票證所屬申請單失敗: %w", err)
		}
		if linked > 0 {
			return ErrTicketRevocationRequired
		}
		log.Printf("[RevokePermission] 孤兒 ticket 授權放行刪除: authID=%d（反查無申請單）", authorizationID)
	}

	// 3. 軟刪除授權記錄
	if err := s.repo.Delete(authorizationID); err != nil {
		log.Printf("[RevokePermission] 撤銷授權失敗: authID=%d, error=%v", authorizationID, err)
		return err
	}

	// 主體可能是群組（UserID 為 nil），日誌以可讀形式描述主體
	log.Printf("[RevokePermission] 授權撤銷成功: authID=%d, subject=%s, assetID=%v",
		authorizationID, describeAuthSubject(auth), auth.AssetID)

	return nil
}

// describeAuthSubject 授權主體的日誌可讀描述（user XOR user_group）
func describeAuthSubject(auth *model.AssetAuthorization) string {
	if auth.UserID != nil {
		return fmt.Sprintf("user=%d", *auth.UserID)
	}
	if auth.UserGroupID != nil {
		return fmt.Sprintf("user_group=%d", *auth.UserGroupID)
	}
	return "unknown"
}

// ListAuthorizations 通用授權列表（authorization-page-redesign D1）：filters 直通
// repository（user_id/user_group_id/asset_id/source/validity），空 map＝全量分頁。
// ticket 記錄批次回填 request_id（撤銷入口回鏈，一次 IN 查詢禁 N+1）
func (s *AssetAuthorizationService) ListAuthorizations(
	filters map[string]interface{},
	page, pageSize int,
) ([]*model.AssetAuthorization, int64, error) {
	authorizations, total, err := s.repo.List(filters, page, pageSize)
	if err != nil {
		log.Printf("[ListAuthorizations] 查詢授權列表失敗: filters=%v, error=%v", filters, err)
		return nil, 0, err
	}
	if err := s.attachTicketRequestIDs(authorizations); err != nil {
		return nil, 0, err
	}
	return authorizations, total, nil
}

// attachTicketRequestIDs 為 ticket 來源授權回填所屬申請單 id（同
// AccessRequestService.attachRequestIDs 模式；此處按 source 過濾後單次 IN 查詢）
func (s *AssetAuthorizationService) attachTicketRequestIDs(auths []*model.AssetAuthorization) error {
	ticketIDs := make([]uint, 0)
	for _, a := range auths {
		if a.Source == model.AuthorizationSourceTicket {
			ticketIDs = append(ticketIDs, a.ID)
		}
	}
	if len(ticketIDs) == 0 {
		return nil
	}
	var rows []struct {
		ID              uint
		AuthorizationID uint
	}
	if err := s.db.Model(&model.AccessRequest{}).
		Select("id", "authorization_id").
		Where("authorization_id IN ?", ticketIDs).
		Scan(&rows).Error; err != nil {
		return fmt.Errorf("查詢票證所屬申請單失敗: %w", err)
	}
	reqByAuth := make(map[uint]uint, len(rows))
	for _, r := range rows {
		reqByAuth[r.AuthorizationID] = r.ID
	}
	for _, a := range auths {
		if rid, ok := reqByAuth[a.ID]; ok {
			id := rid
			a.RequestID = &id
		}
	}
	return nil
}

// ListUserAuthorizations 查詢用戶的所有授權
func (s *AssetAuthorizationService) ListUserAuthorizations(
	userID uint,
	page int,
	pageSize int,
) ([]*model.AssetAuthorization, int64, error) {
	filters := map[string]interface{}{
		"user_id": userID,
	}

	authorizations, total, err := s.repo.List(filters, page, pageSize)
	if err != nil {
		log.Printf("[ListUserAuthorizations] 查詢用戶授權失敗: userID=%d, error=%v", userID, err)
		return nil, 0, err
	}

	log.Printf("[ListUserAuthorizations] 查詢成功: userID=%d, total=%d, page=%d, pageSize=%d",
		userID, total, page, pageSize)

	return authorizations, total, nil
}

// ListUserGroupAuthorizations 查詢群組主體的所有授權
func (s *AssetAuthorizationService) ListUserGroupAuthorizations(
	userGroupID uint,
	page int,
	pageSize int,
) ([]*model.AssetAuthorization, int64, error) {
	filters := map[string]interface{}{
		"user_group_id": userGroupID,
	}
	authorizations, total, err := s.repo.List(filters, page, pageSize)
	if err != nil {
		log.Printf("[ListUserGroupAuthorizations] 查詢群組授權失敗: userGroupID=%d, error=%v", userGroupID, err)
		return nil, 0, err
	}
	return authorizations, total, nil
}

// ListAssetAuthorizations 查詢資產的所有授權用戶
func (s *AssetAuthorizationService) ListAssetAuthorizations(
	assetID uint,
	page int,
	pageSize int,
) ([]*model.AssetAuthorization, int64, error) {
	filters := map[string]interface{}{
		"asset_id": assetID,
	}

	authorizations, total, err := s.repo.List(filters, page, pageSize)
	if err != nil {
		log.Printf("[ListAssetAuthorizations] 查詢資產授權失敗: assetID=%d, error=%v", assetID, err)
		return nil, 0, err
	}

	log.Printf("[ListAssetAuthorizations] 查詢成功: assetID=%d, total=%d, page=%d, pageSize=%d",
		assetID, total, page, pageSize)

	return authorizations, total, nil
}

// AuthorizedAssetDTO 授權資產回應：Asset 欄位攤平＋該使用者的最高授權等級
// （直授與組授聚合，connect > view）。admin/auditor 全量分支不帶
// Permission——管理視圖恆全權限，該欄無意義（asset-management spec）。
type AuthorizedAssetDTO struct {
	model.Asset
	Permission model.PermissionType `json:"permission,omitempty"`

	// 連線入口三態（access-policy-approval D7 補充二）：伺服端單一事實源，
	// 前端零推導。connectable/reason_required/approval_required/pending；
	// 空＝沿既有 permission 欄渲染（open 段位 view-only 等）。
	// 按鈕行為不看此欄——點擊一律走簽發路徑，以政策閘回應為準（過時自癒）
	AccessState       string     `json:"access_state,omitempty"`
	PendingRequestID  *uint      `json:"pending_request_id,omitempty"`
	TicketDateExpired *time.Time `json:"ticket_date_expired,omitempty"`

	// BreakGlassAvailable 破窗可用（break-glass-revocation 六題 6）：開關開啟＋
	// 時窗內常設 connect＋非 open 段位＋無有效票證才 true；開關關閉恆 false
	//（藏入口的伺服端事實源）。同樣僅供顯示，行為以破窗 API 裁決為準
	BreakGlassAvailable bool `json:"break_glass_available,omitempty"`
}

// GetAuthorizedAssets 獲取用戶有權限的資產列表
func (s *AssetAuthorizationService) GetAuthorizedAssets(
	ctx context.Context,
	userID uint,
	permission model.PermissionType,
) ([]*AuthorizedAssetDTO, error) {
	// 1. 檢查是否為 admin/auditor 角色
	role, ok := ctx.Value("role").(string)
	if ok && (role == model.RoleAdmin || role == model.RoleAuditor) {
		// Admin/Auditor 返回所有資產
		var assets []*model.Asset
		if err := s.db.Find(&assets).Error; err != nil {
			log.Printf("[GetAuthorizedAssets] 查詢所有資產失敗: error=%v", err)
			return nil, fmt.Errorf("查詢資產失敗: %w", err)
		}

		log.Printf("[GetAuthorizedAssets] Admin/Auditor 用戶 %d 獲取所有資產: total=%d", userID, len(assets))
		result := make([]*AuthorizedAssetDTO, len(assets))
		for i, a := range assets {
			result[i] = &AuthorizedAssetDTO{Asset: *a}
		}
		return result, nil
	}

	// 2. 一般用戶：查詢有權限的資產與最高授權等級
	permissions := GetPermissionHierarchy(permission)
	assets, levels, err := s.repo.GetAuthorizedAssets(userID, permissions)
	if err != nil {
		log.Printf("[GetAuthorizedAssets] 查詢授權資產失敗: userID=%d, error=%v", userID, err)
		return nil, err
	}

	result := make([]*AuthorizedAssetDTO, len(assets))
	for i, a := range assets {
		result[i] = &AuthorizedAssetDTO{Asset: *a, Permission: levels[a.ID]}
	}

	// 3. 可視第三來源（access-policy-approval D5）：審核範圍內資產以 view 等級
	// 併入清單（僅 view 語義查詢；授權來源已含者不重複、等級不被降低）
	if permission == model.PermissionView {
		scoped, err := s.repo.ApproverScopedAssets(userID)
		if err != nil {
			log.Printf("[GetAuthorizedAssets] 查詢審核範圍資產失敗: userID=%d, error=%v", userID, err)
			return nil, err
		}
		seen := make(map[uint]bool, len(result))
		for _, dto := range result {
			seen[dto.ID] = true
		}
		for _, a := range scoped {
			if !seen[a.ID] {
				result = append(result, &AuthorizedAssetDTO{Asset: *a, Permission: model.PermissionView})
			}
		}
	}

	log.Printf("[GetAuthorizedAssets] 用戶 %d 的可視資產: total=%d, permission=%s",
		userID, len(result), permission)
	return result, nil
}

// ExplicitAuthorizedAssetIDs 回 userID 以顯式授權（個人/群組主體、時效內、
// 含節點授權傳播與權限階梯聚合）達到 permission 等級的資產 ID 集合。
// repo 直查、不經角色短路——auditor 列表入口判定需其顯式 grant 集合
// （auditor-connect-entry-honesty D1），GetAuthorizedAssets 的管理角色短路
// 回全量無法區分
func (s *AssetAuthorizationService) ExplicitAuthorizedAssetIDs(
	userID uint,
	permission model.PermissionType,
) (map[uint]bool, error) {
	assets, _, err := s.repo.GetAuthorizedAssets(userID, GetPermissionHierarchy(permission))
	if err != nil {
		return nil, err
	}
	ids := make(map[uint]bool, len(assets))
	for _, a := range assets {
		ids[a.ID] = true
	}
	return ids, nil
}

// VisibleTreeScope 非特權角色的樹收斂範圍（asset-node-tree D6）：可視資產集
// （授權聯集＋approver 第三來源）＋其掛載節點與全部祖先。樹端點的節點過濾、
// 資產計數、has_children 皆據此收斂——無關子樹的結構與數量都不洩漏（codex P1）
func (s *AssetAuthorizationService) VisibleTreeScope(ctx context.Context, userID uint) (*asset.TreeVisibility, error) {
	dtos, err := s.GetAuthorizedAssets(ctx, userID, model.PermissionView)
	if err != nil {
		return nil, err
	}
	assetIDs := make([]uint, 0, len(dtos))
	assetSet := make(map[uint]bool, len(dtos))
	for _, dto := range dtos {
		assetIDs = append(assetIDs, dto.ID)
		assetSet[dto.ID] = true
	}
	ancestors, err := s.repo.AssetAncestorNodes(assetIDs)
	if err != nil {
		return nil, err
	}
	nodeSet := make(map[uint]bool)
	for _, nodeIDs := range ancestors {
		for _, id := range nodeIDs {
			nodeSet[id] = true
		}
	}
	return &asset.TreeVisibility{NodeIDs: nodeSet, AssetIDs: assetSet}, nil
}
