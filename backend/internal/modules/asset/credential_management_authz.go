package asset

import (
	"context"
	"fmt"
	"log"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 憑證管理授權。
//
// # 為什麼不再用資產 connect 判管理
//
// 憑證管理（改秘密、換範圍、刪除、遠端輪替、脫離）與「能不能連上那台機器」是兩件事：
// 管理者可以決定一組秘密怎麼登入，卻不因此多一張連線票；反過來能連線也不代表能管理。
// 舊檢核以資產 connect 判管理，且未注入判定器時放行，兩者都在開放自訂角色前必須換掉。
//
// # 這個 port 的形狀
//
// 服務只描述「這次操作需要哪些語義能力、影響到哪些憑證／資產／帳號」，由組裝根注入的
// 實作回答「這個伺服器端主體現在有沒有」。asset 不匯入 authz（出向邊會讓遷入順序反轉），
// 能力以權限點鍵字串傳遞，由 authz 側目錄驗證。
//
// - 主體只來自伺服器端 context（ctx 內的使用者識別），不接受請求 body 的 actor、版本或
//   「已授權」旗標；空主體一律拒絕。
// - 判定器缺席是配置錯誤，回 ErrCredentialAuthzUnavailable（fail closed），不是放行。
// - 無權回 ErrCredentialBindForbidden，沿既有端點的收斂拒絕形狀（與「憑證不存在」同回應）。
// - 影響集合（憑證、資產、帳號 ID）隨請求傳入：本段全域 binding 只驗能力，P3 節點範圍
//   落地後由同一個 port 做交集，服務不必再改簽章。
// - Decision 帶判定當下的權限版本，供持久授權脈絡保存；不持久化 allow 布林當票。

// 憑證管理的語義能力鍵。與 authz 目錄一對一，不新增同義鍵。
const (
	CredCapView          = "credential:view"
	CredCapCreate        = "credential:create"
	CredCapUpdate        = "credential:update"
	CredCapSetSecret     = "credential:set-secret"
	CredCapRotate        = "credential:rotate"
	CredCapConvertScope  = "credential:convert-scope"
	CredCapDetach        = "credential:detach"
	CredCapDelete        = "credential:delete"
	CredCapBind          = "credential:bind"
	CredCapAccountRotate = "account:rotate"
	// 帳號編輯能力：專用憑證改登入帳號名時，同時驗唯一掛載的帳號編輯能力。
	CredCapAccountEdit = "asset:update"
)

// CredentialOperation 管理操作的名稱（審計與日誌用，非授權依據）。
type CredentialOperation string

const (
	CredOpView         CredentialOperation = "view"
	CredOpCreate       CredentialOperation = "create"
	CredOpUpdate       CredentialOperation = "update"
	CredOpSetSecret    CredentialOperation = "set_secret"
	CredOpRotate       CredentialOperation = "rotate"
	CredOpConvertScope CredentialOperation = "convert_scope"
	CredOpDetach       CredentialOperation = "detach"
	CredOpDelete       CredentialOperation = "delete"
	CredOpBind         CredentialOperation = "bind"
	CredOpSplit        CredentialOperation = "split"
	// CredOpRun 背景工作（排程、批次、補跑、重試）執行前的重驗
	CredOpRun CredentialOperation = "run"
)

// CredentialManagementActor 伺服器端主體。SubjectKind 空值由實作從 context 內的
// 已解析主體取得（缺省視為 human）。
type CredentialManagementActor struct {
	UserID      uint
	Username    string
	SubjectKind string
}

// CredentialManagementRequest 一次管理操作的授權請求：Capabilities 必須全部具備。
type CredentialManagementRequest struct {
	Operation     CredentialOperation
	Capabilities  []string
	CredentialIDs []uint
	// AssetIDs 明確指定的目標資產（掛載目標、脫離與卸載選定的那一台等）；範圍化主體須在其能力範圍內
	AssetIDs []uint
	// MountedAssetIDs 憑證當下全部掛載的影響集合；範圍化主體改以憑證歸屬判定，不逐台驗範圍
	MountedAssetIDs []uint
	AccountIDs      []uint
	// NodeTarget 以 NodeIDs 為目標（新增資產時資產尚未存在，目標是送出的節點）：每個節點都須在該能力的
	// 範圍內，任一不涵蓋即整筆拒絕；NodeIDs 為空時只認全域來源。是否走節點目標只看這個旗標，不看 NodeIDs 長度
	NodeTarget bool
	NodeIDs    []uint
}

// CredentialManagementDecision 判定結果。Missing 為第一個缺少的能力鍵（供日誌，不外露）；
// AuthzVersion 是判定時的權限世代版本。
type CredentialManagementDecision struct {
	Allowed      bool
	Missing      string
	AuthzVersion int64
	// Sources 主體權限的來源種類（direct／group／mapped／both），隨授權脈絡保存供稽核
	Sources []string
	// ScopeDenial 範圍拒絕值（憑證或目標資產在範圍化主體的範圍外或不存在）；非 nil 時 Allowed 為 false，
	// 關卡原樣回傳此值，由接入層共用出口寫出與不存在同形的回應
	ScopeDenial error
	// ScopeNarrowingRequired 不帶目標的請求只因節點範圍來源而放行（列表、建立）：呼叫端必須其後自行收斂範圍，
	// 收斂所需的投影或判定未注入、或主體不構成範圍化檢視者時一律拒絕（fail closed），不得退回全域口徑
	ScopeNarrowingRequired bool
	// ScopedCapabilityDenial 範圍化檢視者的帶目標請求被範圍判定器判為能力拒絕（含交易內重判時
	// 指派已被撤銷）：關卡回單一 forbidden 的能力拒絕，不收斂成與不存在同形的回應。判定器在解析
	// 目標之前先驗能力，此拒絕與目標存在與否無關，不構成存在性探測；其他主體維持收斂回應
	ScopedCapabilityDenial bool
}

// CredentialManagementAuthorizer 管理授權 port（消費者側窄介面）。
// db 為 nil 時由實作使用自己的連線；非 nil 時在該交易內解析，使判定與呼叫端的鎖序一致。
type CredentialManagementAuthorizer interface {
	AuthorizeCredentialManagement(ctx context.Context, db *gorm.DB,
		actor CredentialManagementActor, req CredentialManagementRequest) (CredentialManagementDecision, error)
}

// RestoreGenerationReader 持久還原世代的讀取（消費者側窄介面）。
// 由組裝根的授權轉接頭一併實作；授權判定器若沒有實作（單元測試夾具），還原世代比對不啟用，
// 授權脈絡記空世代。生產組裝必須實作（見組裝自檢）。
type RestoreGenerationReader interface {
	RestoreGeneration(db *gorm.DB) (string, error)
}

// currentRestoreGeneration 讀目前還原世代；讀取器缺席回 ("", false, nil)。讀取失敗原樣回傳（呼叫端 fail-close）。
func (g credentialManagementGate) currentRestoreGeneration(db *gorm.DB) (string, bool, error) {
	reader, ok := g.authorizer.(RestoreGenerationReader)
	if !ok || reader == nil {
		return "", false, nil
	}
	gen, err := reader.RestoreGeneration(db)
	return gen, true, err
}

// restoreMismatch 授權脈絡記錄的還原世代是否與目前世代不同。
// 讀取器缺席＝不比對（回 false）；讀取失敗回錯誤，呼叫端依 fail closed 停止。
func (g credentialManagementGate) restoreMismatch(db *gorm.DB, recorded string) (bool, error) {
	cur, enabled, err := g.currentRestoreGeneration(db)
	if err != nil {
		return false, err
	}
	return enabled && cur != recorded, nil
}

// restoreGenerationWired 判定器是否同時可讀還原世代（組裝自檢用）。
func (g credentialManagementGate) restoreGenerationWired() bool {
	reader, ok := g.authorizer.(RestoreGenerationReader)
	return ok && reader != nil
}

// credentialManagementGate 兩個服務共用的關卡：把 port 的三種結果收斂成服務層錯誤。
type credentialManagementGate struct {
	authorizer CredentialManagementAuthorizer
}

// require 驗當前伺服器端主體具備 req 的全部能力。
func (g credentialManagementGate) require(ctx context.Context, db *gorm.DB,
	req CredentialManagementRequest) (CredentialManagementDecision, error) {

	if g.authorizer == nil {
		log.Printf("[Credential] 管理授權判定器未注入，拒絕操作: op=%s", req.Operation)
		return CredentialManagementDecision{}, ErrCredentialAuthzUnavailable
	}
	if len(req.Capabilities) == 0 {
		// 沒有宣告任何能力的請求是程式錯誤，不能因此當作「不需要授權」
		return CredentialManagementDecision{}, fmt.Errorf("%w: 管理操作 %s 未宣告能力", ErrCredentialAuthzUnavailable, req.Operation)
	}
	userID, username := model.UserFromContext(ctx)
	if userID == 0 {
		log.Printf("[Credential] 空主體，拒絕操作: op=%s", req.Operation)
		// 無從得知缺哪一項：依據記本操作要求的全部能力
		return CredentialManagementDecision{}, capabilityDenied(ErrCredentialBindForbidden, req.Capabilities...)
	}
	decision, err := g.authorizer.AuthorizeCredentialManagement(ctx, db,
		CredentialManagementActor{UserID: userID, Username: username}, req)
	if err != nil {
		return CredentialManagementDecision{}, fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	if !decision.Allowed && decision.ScopeDenial != nil {
		return decision, decision.ScopeDenial
	}
	if !decision.Allowed {
		log.Printf("[Credential] 管理能力不足，拒絕操作: operator=%d op=%s missing=%s", userID, req.Operation, decision.Missing)
		denied := capabilityDenied(ErrCredentialBindForbidden, deniedCapabilityKeys(req.Capabilities, decision.Missing)...)
		if decision.ScopedCapabilityDenial {
			denied.(*CapabilityDeniedError).Forbidden = true
		}
		return decision, denied
	}
	return decision, nil
}

// deniedCapabilityKeys 拒絕依據的權限點鍵：判定器回報的缺漏是本次要求的能力之一即記該項；
// 缺漏不是能力（主體不存在或停用等）時無從得知缺哪一項，記本操作要求的全部能力。
func deniedCapabilityKeys(required []string, missing string) []string {
	for _, c := range required {
		if c == missing {
			return []string{missing}
		}
	}
	return required
}

// contextWithInitiator 以工作的發起者建立授權脈絡（沿既有審計 context 慣例的鍵）。
// 發起者為零值時原樣回傳 ctx：管理關卡會把空主體當作拒絕，不會變成放行。
func contextWithInitiator(ctx context.Context, userID uint, username string) context.Context {
	if userID == 0 {
		return ctx
	}
	ctx = context.WithValue(ctx, "userID", userID)      //nolint:staticcheck // 沿用既有審計 context 慣例
	return context.WithValue(ctx, "username", username) //nolint:staticcheck
}

// requireDeclaredSecretOn 內嵌宣告秘密（資產表單或帳號表單帶密碼／私鑰）的共用關卡。
// 寫入面（appendDeclaredSecret）對共用憑證一律拒絕，故影響集合只有這一台資產。
func requireDeclaredSecretOn(g credentialManagementGate, ctx context.Context, tx *gorm.DB, assetID uint) error {
	_, err := g.require(ctx, tx, CredentialManagementRequest{
		Operation:    CredOpSetSecret,
		Capabilities: []string{CredCapSetSecret},
		AssetIDs:     []uint{assetID},
	})
	return err
}

// requireCredentialFieldOn 經語義能力寫入帳號名稱或 SFTP 側車欄位的關卡：以這台資產為目標判定該能力，
// 與 requireDeclaredSecretOn 同形（範圍外回與資產不存在同形，缺能力回單一能力拒絕）。
func requireCredentialFieldOn(g credentialManagementGate, ctx context.Context, tx *gorm.DB,
	op CredentialOperation, capability string, assetID uint) error {

	_, err := g.require(ctx, tx, CredentialManagementRequest{
		Operation:    op,
		Capabilities: []string{capability},
		AssetIDs:     []uint{assetID},
	})
	return err
}

// requireCreateCredentialOnNodes 新增資產建立專用憑證的交易內關卡：以送出的節點為目標判定建立憑證能力，
// 每個節點都須涵蓋；未掛節點只限全域持有者。系統作業（WithSystemCaller）豁免，與欄位級能力同一口徑。
func requireCreateCredentialOnNodes(g credentialManagementGate, ctx context.Context, tx *gorm.DB, nodeIDs []uint) error {
	if isSystemCaller(ctx) {
		return nil
	}
	_, err := g.require(ctx, tx, CredentialManagementRequest{
		Operation:    CredOpCreate,
		Capabilities: []string{CredCapCreate},
		NodeTarget:   true,
		NodeIDs:      nodeIDs,
	})
	return err
}

// requireCreateCredentialCaps 建立路徑（資產建立、帳號建立、批次匯入）的憑證語義能力：
// 掛既有共用憑證＝掛載（credential:bind，影響集合＝所指憑證與目標資產），與憑證端點的掛載同一能力；
// 內嵌秘密＝新建一份專用憑證（credential:create），與憑證庫直接建立同一能力。改既有憑證的秘密
// 才是 credential:set-secret（更新路徑）。只持資產寫入能力者不得把共用憑證掛到自己可連線的
// 資產上——那等於取得以該秘密登入的能力。
//
// 呼叫端在任何載入與寫入之前判一次（db 為 nil），交易內以實際組裝出的資料再判一次（db 為 tx）。
// 資產建立時目標資產尚不存在，assetID 傳 0。系統作業（WithSystemCaller）沒有操作者主體，
// 與欄位級能力同一豁免；該標記只能由服務端設定（靜態守衛鎖定呼叫位置）。
//
// newDedicatedSecret 為帶登入密碼或私鑰（不論欄位經哪一種能力通過）；namedViaSemantic 為帳號名稱等
// 欄位經建立憑證能力（而非相容能力）通過。兩者任一為真即判建立能力。
//
// 不帶目標的內嵌秘密（資產建立）只因節點範圍來源放行時（決定的 ScopeNarrowingRequired），範圍收斂由
// 呼叫端的寫入範圍判定承擔；scopeWired 為假（該判定未注入）即回 ErrAssetWriteScopePortMissing，
// 不以未收斂的口徑放行。
func requireCreateCredentialCaps(g credentialManagementGate, ctx context.Context, db *gorm.DB,
	credentialIDs []uint, assetID uint, newDedicatedSecret, namedViaSemantic, scopeWired bool) error {

	if isSystemCaller(ctx) {
		return nil
	}
	var assetIDs []uint
	if assetID != 0 {
		assetIDs = []uint{assetID}
	}
	if len(credentialIDs) > 0 {
		if _, err := g.require(ctx, db, CredentialManagementRequest{
			Operation:     CredOpBind,
			Capabilities:  []string{CredCapBind},
			CredentialIDs: credentialIDs,
			AssetIDs:      assetIDs,
		}); err != nil {
			return err
		}
	}
	if newDedicatedSecret || namedViaSemantic {
		d, err := g.require(ctx, db, CredentialManagementRequest{
			Operation:    CredOpCreate,
			Capabilities: []string{CredCapCreate},
			AssetIDs:     assetIDs,
		})
		if err != nil {
			return err
		}
		if d.ScopeNarrowingRequired && !scopeWired {
			return ErrAssetWriteScopePortMissing
		}
	}
	return nil
}

// nonZeroIDs 去掉零值並去重（序穩定）。
func nonZeroIDs(ids ...uint) []uint {
	var out []uint
	seen := map[uint]bool{}
	for _, id := range ids {
		if id != 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
