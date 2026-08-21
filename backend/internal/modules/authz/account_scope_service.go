package authz

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 授權帳號維度的解析器（asset-multi-account D5，階段 4）。
//
// 定位：帳號範圍是既有授權判定的**一個屬性**，不是平行的第二套判定。所以本檔
// 的主體／客體／時效語義一律沿用 repository 的 subjectCondition／
// nodeObjectCondition／validityCondition（見 AccountScopesFor 註解），角色語義
// 一律沿用 CheckPermission（admin 全量短路、auditor 不對 connect 短路）。
//
// 強制點三處（D5）：connect token 簽發、兌換複查、帳號列表／選擇器過濾；
// 系統路徑（改密 runner、k8s、SFTP 側車）走預設帳號不經本判定。

// EffectiveAccountScope 使用者對某資產的有效帳號範圍（聯集結果）。
//
// All 與 Usernames 不是互斥表示：All=true 時 Usernames 無意義（上界已達）。
// **聯集取寬**（D5 Scenario「聯集語義」）：個人授權 `["app"]` ＋ 群組授權 `@ALL`
// ＝全部帳號。授權模型是純加法無 deny 的（CheckPermission 語義鐵則），
// 帳號維度若採交集會憑空造出一個 deny 語義，與整套授權哲學相衝。
type EffectiveAccountScope struct {
	// All 全帳號（任一命中授權列為 @ALL，或角色為 admin）
	All bool
	// Usernames 具名帳號聯集（All=false 時有效）
	Usernames map[string]bool
	// Matched 是否有任何命中的授權列。false＝無權限，與「命中但範圍為空」不同——
	// 後者不存在（空範圍正規化後即 @ALL，見 AccountScope 型別註解）
	Matched bool
}

// Allows 判定某 username 是否在有效範圍內。無命中授權列一律否（fail-close）
func (e EffectiveAccountScope) Allows(username string) bool {
	if !e.Matched {
		return false
	}
	if e.All {
		return true
	}
	return e.Usernames[username]
}

// resolveAccountScope 帳號範圍解析核心：以指定權限階梯查命中授權列並聯集。
// 角色短路與 CheckPermission 同語義——admin 全量；auditor 僅在非 connect
// 判定時短路（CPG-002 職責分離：稽核者只檢視不連線）
func (s *AssetAuthorizationService) resolveAccountScope(
	ctx context.Context,
	userID, assetID uint,
	requiredPerm model.PermissionType,
	now time.Time,
) (EffectiveAccountScope, error) {
	if role, ok := ctx.Value("role").(string); ok {
		if role == model.RoleAdmin {
			return EffectiveAccountScope{All: true, Matched: true}, nil
		}
		if role == model.RoleAuditor && requiredPerm != model.PermissionConnect {
			return EffectiveAccountScope{All: true, Matched: true}, nil
		}
	}

	scopes, err := s.repo.AccountScopesFor(userID, assetID, GetPermissionHierarchy(requiredPerm), now)
	if err != nil {
		return EffectiveAccountScope{}, err
	}
	result := EffectiveAccountScope{Usernames: make(map[string]bool)}
	for _, scope := range scopes {
		result.Matched = true
		if scope.IsAll() {
			result.All = true
			continue
		}
		for _, name := range scope {
			result.Usernames[name] = true
		}
	}
	return result, nil
}

// EffectiveConnectAccountScope 使用者對資產的有效**連線**帳號範圍（強制點用）
func (s *AssetAuthorizationService) EffectiveConnectAccountScope(
	ctx context.Context,
	userID, assetID uint,
) (EffectiveAccountScope, error) {
	return s.resolveAccountScope(ctx, userID, assetID, model.PermissionConnect, time.Now())
}

// EffectiveViewAccountScope 使用者對資產的有效**可視**帳號範圍（帳號列表過濾用）。
// 權限階梯含 connect——持連線權者當然看得到自己能用的帳號
func (s *AssetAuthorizationService) EffectiveViewAccountScope(
	ctx context.Context,
	userID, assetID uint,
) (EffectiveAccountScope, error) {
	return s.resolveAccountScope(ctx, userID, assetID, model.PermissionView, time.Now())
}

// ErrAccountNotAuthorized 帳號不在使用者的有效授權範圍內（asset-multi-account D5）。
//
// 呼叫端一律映射為與「帳號不存在」**同一支對外碼**（NOTFOUND_ASSET_ACCOUNT）：
// 分開回應等於告訴請求方「這個帳號存在，只是你沒被授權」，讓連線端點成為
// 帳號枚舉器。伺服端日誌才記真正成因
var ErrAccountNotAuthorized = fmt.Errorf("帳號不在有效授權範圍內")

// AuthorizeConnectAccount 連線帳號授權判定（三強制點共用的單一入口）。
//
// username 為**已解析出的實際連線帳號名**（非請求參數）——強制點必須判定
// 「這條線實際會用哪個帳號」，而不是「請求說了哪個帳號」：省略 account_id 時
// 走預設帳號，若預設帳號不在授權範圍內卻放行，整個帳號維度只要不填參數即可繞過。
//
// k8s 資產豁免（D5）：固定單一預設帳號的系統語義，不經 per-account 判定。
// admin 於 resolveAccountScope 短路全量
func (s *AssetAuthorizationService) AuthorizeConnectAccount(
	ctx context.Context,
	userID, assetID uint,
	protocol model.ProtocolType,
	username string,
) error {
	if protocol == model.ProtocolK8s {
		return nil
	}
	scope, err := s.EffectiveConnectAccountScope(ctx, userID, assetID)
	if err != nil {
		return err
	}
	if !scope.Allows(username) {
		log.Printf("[AccountScope] 帳號不在有效授權範圍: userID=%d assetID=%d username=%q all=%v matched=%v",
			userID, assetID, username, scope.All, scope.Matched)
		return ErrAccountNotAuthorized
	}
	return nil
}

// **W6 6.5（R3.1 §5.4 拆檔）**：`AccountIdentity` 與 `(*AssetService).ResolveAccountIdentity`
// 已遷入 `asset_account_identity.go`——它們是 asset 的型別與方法（「型別的方法必須與
// 型別同包」，design.md:35），留在本檔會讓 authz 的檔案在搬包時把 asset 的方法一起帶走。
