package asset

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

// 計劃驗證錯誤：handler 以 errors.Is 區分 400/404/409 與 500
var (
	ErrPlanNotFound       = errors.New("改密計劃不存在")
	ErrPlanNameExists     = errors.New("計劃名稱已存在")
	ErrPlanNoAssets       = errors.New("計劃必須包含至少一個資產")
	ErrPlanBadCron        = errors.New("排程格式錯誤（標準 5 欄 cron）")
	ErrPlanBadSecretType  = errors.New("秘密型別僅支援 password 或 ssh_key")
	ErrPlanBadKeyStrategy = errors.New("金鑰策略僅支援 append_replace 或 exclusive")
	// ErrPlanBadMaxAgeDays 憑證最長使用天數覆蓋越界（0＝沿用全域，否則 1–3650）
	ErrPlanBadMaxAgeDays = errors.New("憑證最長使用天數覆蓋須為 0（沿用全域）或 1 至 3650")
	// ErrPlanBadTargetKind 目標種類不在值域內
	ErrPlanBadTargetKind = errors.New("目標種類僅支援 account 或 credential")
	// ErrPlanTargetCredentialRequired 以憑證為目標卻沒指定憑證
	ErrPlanTargetCredentialRequired = errors.New("以憑證為目標的計劃必須指定憑證")
	// ErrPlanTargetCredentialNotFound 指定的目標憑證不存在
	ErrPlanTargetCredentialNotFound = errors.New("指定的目標憑證不存在")
	// ErrPlanSharedCredentialTarget 以帳號為目標的計劃選到了共用憑證的成員。
	//
	// 兩害相權都不可接受：只改其中一員會讓其餘成員失去可用秘密；自動擴張到
	// 其餘掛載則是去改操作者沒有選取的機器。兩條都不走，改要求以憑證為目標
	ErrPlanSharedCredentialTarget = errors.New("計劃選到了共用憑證的成員，請改以憑證為目標")
)

// planMaxAgeDaysUpper 計劃層天數覆蓋的上界，與全域安全政策鍵同值（10 年）。
//
// **本地常數而非引用政策模組**：改密計劃屬 asset 模組，向 policy 取一個純數字
// 會為此建立一條新的模組相依邊。兩處值必須相同，由 spec 條文與雙方的測試各自釘住。
const planMaxAgeDaysUpper = 3650

// ChangeSecretPlanRequest 計劃建立/更新請求
type ChangeSecretPlanRequest struct {
	Name     string `json:"name" binding:"required"`
	AssetIDs []uint `json:"asset_ids" binding:"required"`
	// Accounts 帳號範圍：空／含 @ALL ＝ 該資產全部帳號（回歸安全的既有慣例）
	Accounts []string `json:"accounts"`
	Cron     string   `json:"cron"`
	Enabled  *bool    `json:"enabled"`

	SecretType  string `json:"secret_type"`
	KeyStrategy string `json:"key_strategy"`

	PasswordLength           int   `json:"password_length"`
	PasswordIncludeSymbol    *bool `json:"password_include_symbol"`
	PasswordExcludeAmbiguous *bool `json:"password_exclude_ambiguous"`

	// MaxAgeDays 憑證最長使用天數覆蓋：0＝沿用全域安全政策鍵。
	// 只影響輪替證據報告的適用天數計算，不改變本計劃的執行時機
	MaxAgeDays int `json:"max_age_days"`

	// TargetKind 目標種類，見 model.PlanTarget* 常數；空值＝account（既有計劃）
	TargetKind string `json:"target_kind"`
	// TargetCredentialID TargetKind=credential 時的目標憑證
	TargetCredentialID uint `json:"target_credential_id"`
	// ImpactConfirmationID 範圍化發起者以憑證為目標時的影響確認識別（範圍外掛載須先確認）；其餘情形忽略
	ImpactConfirmationID string `json:"impact_confirmation_id"`
}

// ChangeSecretPlanService 改密計劃 CRUD（change-secret 階段 1）
type ChangeSecretPlanService struct {
	db *gorm.DB
	// versions 取發起者當下的權限世代版本（記進授權脈絡，不阻擋建立）；重新授權承接時也用它重驗點擊者，nil＝一律不承接
	versions CredentialManagementAuthorizer
	// auditTx 重新授權的審計落地面
	auditTx port.TxSink
	// alert 承接未完成的推送（組裝根注入）；nil＝只寫日誌
	alert func(rule, message string)
	// scope 讀取投影、建立與修改的範圍收斂（組裝根注入）；nil＝全系統口徑
	scope ChangeSecretScopePort
	// impactScope 範圍化發起者以憑證為目標儲存時的影響確認切分（與憑證端點同一來源）
	impactScope CredentialScopeSource
	// preTxHook 測試掛點：修改與一鍵重新授權在鎖前讀取之後、承接或儲存交易開始之前呼叫
	preTxHook func()
}

// WithAuthorizer 接上管理授權判定器，僅用來在授權脈絡內記錄建立當下的權限世代版本與確實通過的能力鍵。
// 計畫的儲存不因此多一道阻擋：撤權由執行時的重驗負責。
func (s *ChangeSecretPlanService) WithAuthorizer(a CredentialManagementAuthorizer) *ChangeSecretPlanService {
	s.versions = a
	return s
}

// planRunCapabilities 計畫執行所需的語義能力（供授權脈絡記錄與執行重驗共用）。
func planRunCapabilities(targetKind string) []string {
	if targetKind == model.PlanTargetCredential {
		return []string{CredCapRotate}
	}
	return []string{CredCapAccountRotate}
}

// recordPlanAuthorization 為計畫新增一列授權脈絡（修訂號遞增）並指向它。
// ctx 沒有伺服器端主體時不動既有脈絡（回 false）：不以空主體或系統身分替代。
func (s *ChangeSecretPlanService) recordPlanAuthorization(ctx context.Context, tx *gorm.DB,
	plan *model.ChangeSecretPlan, via, mountBound string) (bool, error) {

	userID, username := model.UserFromContext(ctx)
	if userID == 0 {
		return false, nil
	}
	var version int64
	var sources []string
	// confirmed 只放判定器確實放行的能力鍵：建立或修改不因缺能力被擋，但證據列不寫沒有發生的確認。
	// 留空不放寬執行：執行與重試一律以計畫目標種類所需的能力重驗（planRunCapabilities）
	confirmed := []string{}
	caps := planRunCapabilities(plan.TargetKind)
	if s.versions != nil {
		if d, err := s.versions.AuthorizeCredentialManagement(ctx, tx,
			CredentialManagementActor{UserID: userID, Username: username},
			CredentialManagementRequest{Operation: CredOpRun, Capabilities: caps}); err == nil {
			version, sources = d.AuthzVersion, d.Sources
			if d.Allowed {
				confirmed = caps
			}
		}
	}
	revision := plan.Revision + 1
	if plan.AuthorizationID == nil {
		revision = 1
	}
	row, err := insertJobAuthorization(credentialManagementGate{authorizer: s.versions}, tx, jobAuthInput{
		kind: model.JobAuthSourcePlan, sourceID: plan.ID, revision: revision,
		actorID: userID, actorName: username, via: via, authzVersion: version, sources: sources,
		capabilities: confirmed, targetBound: AssetIDList(plan), targetMountBound: mountBound,
	})
	if err != nil {
		return false, err
	}
	plan.AuthorizationID = &row.ID
	plan.AuthorizationState = ""
	plan.Revision = revision
	return true, nil
}

// ReauthorizePending 一鍵重新授權：把升級時查不到可歸屬者而暫停的計畫，重新授權給目前的操作者
// （之後照常以其當下權限重驗）。承接前先以點擊者**當下**的能力對每個計畫的目標做一次重驗
// （與執行前重驗同一函式）；能力不足的計畫不被承接、維持暫停，列在 skipped，不整批失敗。
// 承接與它的審計同一交易：審計寫不進去即不承接、計畫維持暫停並列在 skipped，每個計畫告警一次。
// 略過的審計另以獨立交易嘗試（略過本身沒有本地變更要綁），失敗只留日誌。
func (s *ChangeSecretPlanService) ReauthorizePending(ctx context.Context) (done, skipped []uint, err error) {
	uid, uname := model.UserFromContext(ctx)
	if uid == 0 {
		return nil, nil, ErrJobAuthorizationMissing
	}
	var plans []model.ChangeSecretPlan
	if err := s.db.Where("authorization_state IN ?",
		[]string{model.PlanAuthNeedsReauthorization, model.PlanAuthNeedsReconfirmation}).
		Order("id").Find(&plans).Error; err != nil {
		return nil, nil, err
	}
	// 範圍化點擊者只查、只承接可見的計畫；不可見者不出現在 done 與 skipped
	if plans, err = s.visibleOnly(ctx, plans); err != nil {
		return nil, nil, err
	}
	if s.preTxHook != nil {
		s.preTxHook()
	}
	gate := credentialManagementGate{authorizer: s.versions}
	for i := range plans {
		var plan model.ChangeSecretPlan
		skipReason := ""
		if err := s.db.Transaction(func(tx *gorm.DB) error {
			if err := s.lockTopology(tx); err != nil {
				return err
			}
			// 鎖後重讀最新列：已不在待承接狀態、已刪或已不可見者不承接，也不列入 done 或 skipped
			latest, err := latestPlanTx(tx, plans[i].ID)
			if errors.Is(err, ErrPlanNotFound) {
				return errReauthorizeGone
			}
			if err != nil {
				return err
			}
			if latest.AuthorizationState != model.PlanAuthNeedsReauthorization &&
				latest.AuthorizationState != model.PlanAuthNeedsReconfirmation {
				return errReauthorizeGone
			}
			if err := s.requireVisibleTx(ctx, tx, latest); err != nil {
				if errors.Is(err, ErrPlanNotFound) {
					return errReauthorizeGone
				}
				return err
			}
			plan = *latest
			// 待重新確認：只有經全系統來源持有憑證改密者可承接（不帶目標的判定只認全系統來源），
			// 範圍化點擊者須重新確認並儲存新版，不能以承接略過確認
			if plan.AuthorizationState == model.PlanAuthNeedsReconfirmation {
				if _, err := gate.require(ctx, tx, CredentialManagementRequest{
					Operation: CredOpRotate, Capabilities: []string{CredCapRotate},
				}); err != nil {
					skipReason = model.ChangeSecretReasonScopeBoundExceeded
					return errReauthorizeSkip
				}
			}
			// 目標重驗在承接交易內、以交易內視圖與最新列的目標判定
			credentialIDs, assetIDs := planRunTargets(&plan)
			if _, reason := requirePlanRun(gate, ctx, tx, plan.TargetKind, credentialIDs, assetIDs, nil); reason != "" {
				skipReason = reason
				return errReauthorizeSkip
			}
			if _, err := s.recordPlanAuthorization(ctx, tx, &plan, model.JobAuthViaReauthorized, ""); err != nil {
				return err
			}
			if err := tx.Model(&model.ChangeSecretPlan{}).Where("id = ?", plan.ID).
				Updates(map[string]any{
					"authorization_id": plan.AuthorizationID, "authorization_state": "", "revision": plan.Revision,
				}).Error; err != nil {
				return err
			}
			if err := s.writeReauthorizeAudit(tx, plan.ID, uid, uname, "reauthorized", ""); err != nil {
				return fmt.Errorf("%w: %v", errReauthorizeAuditFailed, err)
			}
			return nil
		}); err != nil {
			if errors.Is(err, errReauthorizeGone) {
				continue
			}
			if errors.Is(err, errReauthorizeSkip) {
				skipped = append(skipped, plan.ID)
				s.auditReauthorizeSkipped(plan.ID, uid, uname, skipReason)
				continue
			}
			if !errors.Is(err, errReauthorizeAuditFailed) {
				return done, skipped, err
			}
			// 承接已整筆回滾：計畫維持暫停，列入略過，告警一次
			log.Printf("[ChangeSecretPlan] 重新授權審計寫入失敗，不承接 plan=%d: %v", plan.ID, err)
			skipped = append(skipped, plan.ID)
			s.auditReauthorizeSkipped(plan.ID, uid, uname, model.ChangeSecretReasonAuthzUnavailable)
			if s.alert != nil {
				s.alert("改密計畫重新授權未完成",
					fmt.Sprintf("plan_id=%d 承接的審計寫不進去，計畫維持暫停（未承接、未執行），請確認審計儲存後再承接", plan.ID))
			}
			continue
		}
		done = append(done, plan.ID)
	}
	return done, skipped, nil
}

// errReauthorizeAuditFailed 承接的審計寫入失敗（承接隨之回滾）。
var errReauthorizeAuditFailed = errors.New("重新授權審計寫入失敗")

// errReauthorizeSkip 承接交易內的目標重驗未通過（不承接、列在 skipped）。
var errReauthorizeSkip = errors.New("重新授權略過")

// errReauthorizeGone 鎖後重讀時計畫已刪、已不在待承接狀態或已不可見（不承接、不列入回應）。
var errReauthorizeGone = errors.New("重新授權對象已不適用")

// planRunTargets 計畫執行與承接時重驗的目標：憑證目標帶目標憑證，帳號目標帶資產集合。
func planRunTargets(plan *model.ChangeSecretPlan) (credentialIDs, assetIDs []uint) {
	if plan.TargetKind == model.PlanTargetCredential {
		if plan.TargetCredentialID != nil {
			return []uint{*plan.TargetCredentialID}, nil
		}
		return nil, nil
	}
	return nil, AssetIDList(plan)
}

// WithAuditSink 接上重新授權的審計落地面；nil＝承接一律不成立（審計寫不進去）。
func (s *ChangeSecretPlanService) WithAuditSink(sink port.TxSink) *ChangeSecretPlanService {
	s.auditTx = sink
	return s
}

// WithAlertNotifier 接上承接未完成的推送（組裝根，與其他改密停止告警同一通道）。
func (s *ChangeSecretPlanService) WithAlertNotifier(fn func(rule, message string)) *ChangeSecretPlanService {
	s.alert = fn
	return s
}

// auditReauthorizeSkipped 被略過的計畫一則審計（獨立交易）；失敗只留日誌。
func (s *ChangeSecretPlanService) auditReauthorizeSkipped(planID, uid uint, uname, reason string) {
	err := s.db.Transaction(func(tx *gorm.DB) error {
		return s.writeReauthorizeAudit(tx, planID, uid, uname, "skipped", reason)
	})
	if err != nil {
		log.Printf("[ChangeSecretPlan] 重新授權略過的審計寫入失敗 plan=%d reason=%s: %v", planID, reason, err)
	}
}

// writeReauthorizeAudit 每個被處理的計畫一則審計（含被略過者），寫在呼叫端給的交易內；
// 落地面缺席或寫入失敗回錯誤。
func (s *ChangeSecretPlanService) writeReauthorizeAudit(tx *gorm.DB, planID, uid uint, uname, outcome, reason string) error {
	details, _ := json.Marshal(map[string]any{
		"resource": string(model.ResourceChangeSecretPlan), "operation": "reauthorize",
		"plan_id": planID, "outcome": outcome, "reason": reason,
	})
	status := model.StatusSuccess
	if outcome != "reauthorized" {
		status = model.StatusDenied
	}
	id := planID
	return port.WriteInTx(s.auditTx, tx, port.AuditEvent{
		OccurredAt: time.Now(),
		Actor:      gatewayapi.Actor{UserID: uid, Username: uname},
		Action:     string(model.ActionUpdate),
		Resource:   string(model.ResourceChangeSecretPlan),
		ResourceID: &id,
		Status:     string(status),
		Details:    string(details),
	})
}

// PendingReauthorization 目前因無從歸屬發起者而暫停的計畫（供啟動時告警與管理畫面）。
func (s *ChangeSecretPlanService) PendingReauthorization() ([]model.ChangeSecretPlan, error) {
	var plans []model.ChangeSecretPlan
	if err := s.db.Where("authorization_state = ?", model.PlanAuthNeedsReauthorization).
		Order("id").Find(&plans).Error; err != nil {
		return nil, err
	}
	return plans, nil
}

// NewChangeSecretPlanService 建立服務
func NewChangeSecretPlanService(db *gorm.DB) *ChangeSecretPlanService {
	return &ChangeSecretPlanService{db: db}
}

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// planFields 計劃的正規化欄位（驗證通過後套用到 model）
type planFields struct {
	assetIDs string
	accounts string
}

func validatePlan(req *ChangeSecretPlanRequest) (planFields, error) {
	var out planFields
	if req.TargetKind != "" && !model.IsPlanTargetKind(req.TargetKind) {
		return out, ErrPlanBadTargetKind
	}
	if req.TargetKind == model.PlanTargetCredential && req.TargetCredentialID == 0 {
		return out, ErrPlanTargetCredentialRequired
	}
	if len(req.AssetIDs) == 0 {
		return out, ErrPlanNoAssets
	}
	if req.Cron != "" {
		if _, err := cronParser.Parse(req.Cron); err != nil {
			return out, ErrPlanBadCron
		}
	}
	switch req.SecretType {
	case "", model.ChangeSecretTypePassword, model.ChangeSecretTypeSSHKey:
	default:
		return out, ErrPlanBadSecretType
	}
	switch req.KeyStrategy {
	case "", model.KeyStrategyAppendReplace, model.KeyStrategyExclusive:
	default:
		return out, ErrPlanBadKeyStrategy
	}
	if err := ValidatePasswordLength(req.PasswordLength); err != nil {
		return out, err
	}
	// 0＝沿用全域，其餘須落在值域內。**負值與超界都要擋**：覆蓋值直接進報告的
	// 適用天數計算，一個負數會讓每個被涵蓋的帳號都算出逾期
	if req.MaxAgeDays < 0 || req.MaxAgeDays > planMaxAgeDaysUpper {
		return out, ErrPlanBadMaxAgeDays
	}
	ids, err := json.Marshal(req.AssetIDs)
	if err != nil {
		return out, err
	}
	out.assetIDs = string(ids)

	scope := model.NormalizeAccountScope(req.Accounts)
	if len(scope) == 0 {
		scope = model.AccountScope{model.AccountScopeAll}
	}
	accounts, err := json.Marshal(scope)
	if err != nil {
		return out, err
	}
	out.accounts = string(accounts)
	return out, nil
}

// applyPlanFields 把請求套進 model（建立與更新共用，避免兩處漂移）
func applyPlanFields(plan *model.ChangeSecretPlan, req *ChangeSecretPlanRequest, f planFields) {
	plan.Name = req.Name
	plan.AssetIDs = f.assetIDs
	plan.Accounts = f.accounts
	plan.Cron = req.Cron
	plan.SecretType = req.SecretType
	if plan.SecretType == "" {
		plan.SecretType = model.ChangeSecretTypePassword
	}
	plan.KeyStrategy = req.KeyStrategy
	if plan.KeyStrategy == "" {
		plan.KeyStrategy = model.KeyStrategyAppendReplace
	}
	plan.PasswordLength = req.PasswordLength
	if plan.PasswordLength == 0 {
		plan.PasswordLength = model.PasswordLengthDefault
	}
	// 兩個布林以指標接收：未帶欄位時取出廠預設（含符號、排除易混淆），
	// 而非 Go 零值 false——後者會讓「沒填」靜默變成「關閉」
	plan.PasswordIncludeSymbol = true
	if req.PasswordIncludeSymbol != nil {
		plan.PasswordIncludeSymbol = *req.PasswordIncludeSymbol
	}
	plan.PasswordExcludeAmbiguous = true
	if req.PasswordExcludeAmbiguous != nil {
		plan.PasswordExcludeAmbiguous = *req.PasswordExcludeAmbiguous
	}
	plan.MaxAgeDays = req.MaxAgeDays
	plan.TargetKind = req.TargetKind
	if plan.TargetKind == "" {
		plan.TargetKind = model.PlanTargetAccount
	}
	plan.TargetCredentialID = nil
	if plan.TargetKind == model.PlanTargetCredential && req.TargetCredentialID != 0 {
		id := req.TargetCredentialID
		plan.TargetCredentialID = &id
	}
}

// PlanAccountScope 解析計劃的帳號範圍。空值一律讀成 @ALL（回歸安全方向：
// 漏設此欄若被讀成「零帳號」，計劃會靜默什麼都不做而看起來一切正常）
func PlanAccountScope(plan *model.ChangeSecretPlan) model.AccountScope {
	var scope model.AccountScope
	if plan.Accounts != "" {
		_ = json.Unmarshal([]byte(plan.Accounts), &scope)
	}
	if len(scope) == 0 {
		return model.AccountScope{model.AccountScopeAll}
	}
	return scope
}

// List 全部計劃
func (s *ChangeSecretPlanService) List() ([]model.ChangeSecretPlan, error) {
	var plans []model.ChangeSecretPlan
	if err := s.db.Order("id").Find(&plans).Error; err != nil {
		return nil, err
	}
	return plans, nil
}

// Get 單一計劃
func (s *ChangeSecretPlanService) Get(id uint) (*model.ChangeSecretPlan, error) {
	var plan model.ChangeSecretPlan
	if err := s.db.First(&plan, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPlanNotFound
		}
		return nil, err
	}
	return &plan, nil
}

// assertTargetResolvable 目標的儲存時前置驗證。
//
// 以憑證為目標者只需確認該憑證存在；以帳號為目標者要擋下共用憑證的成員——
// **這是兩層擋的第一層**，第二層在執行時（掛載會在計劃存檔之後改變，
// 只有儲存時擋會漏掉「存檔後才被改綁到共用憑證」的那些）。
func (s *ChangeSecretPlanService) assertTargetResolvable(db *gorm.DB, req *ChangeSecretPlanRequest) error {
	if req.TargetKind == model.PlanTargetCredential {
		var cred model.Credential
		if err := db.Where("id = ?", req.TargetCredentialID).First(&cred).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrPlanTargetCredentialNotFound
			}
			return fmt.Errorf("查詢目標憑證失敗: %w", err)
		}
		return nil
	}
	return s.assertNoSharedCredentialTarget(db, req)
}

// assertNoSharedCredentialTarget 以帳號為目標的計劃不得命中共用憑證的成員。
//
// 只改其中一員會讓同組其餘主機失去可用秘密；自動擴張到其餘掛載則是去改操作者
// 沒有選取的機器。兩條都不可接受，故在儲存時就要求改以憑證為目標。
//
// **命中一個就拒絕整筆**：靜默跳過那幾台會讓管理員以為它們也被涵蓋了。
func (s *ChangeSecretPlanService) assertNoSharedCredentialTarget(db *gorm.DB, req *ChangeSecretPlanRequest) error {
	if db.Migrator() != nil && !db.Migrator().HasTable(&model.Credential{}) {
		return nil
	}
	scope := model.NormalizeAccountScope(req.Accounts)
	if len(scope) == 0 {
		scope = model.AccountScope{model.AccountScopeAll}
	}
	q := db.Model(&model.AssetAccount{}).
		Joins("JOIN credentials ON credentials.id = asset_accounts.credential_id"+
			" AND credentials.deleted_at IS NULL").
		Where("asset_accounts.asset_id IN ?", req.AssetIDs).
		Where("credentials.scope = ?", model.CredentialScopeShared)
	if names := explicitAccountNames(scope); names != nil {
		if len(names) == 0 {
			return nil
		}
		q = q.Where("asset_accounts.username IN ?", names)
	}
	var count int64
	if err := q.Count(&count).Error; err != nil {
		return fmt.Errorf("查詢計劃涵蓋的共用憑證成員失敗: %w", err)
	}
	if count > 0 {
		return ErrPlanSharedCredentialTarget
	}
	return nil
}

// Create 建立計劃
func (s *ChangeSecretPlanService) Create(ctx context.Context, req *ChangeSecretPlanRequest) (*model.ChangeSecretPlan, error) {
	fields, err := validatePlan(req)
	if err != nil {
		return nil, err
	}
	if s.scope == nil {
		if err := s.assertTargetResolvable(s.db, req); err != nil {
			return nil, err
		}
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	plan := &model.ChangeSecretPlan{Enabled: enabled}
	applyPlanFields(plan, req, fields)
	// Enabled 與兩個密碼策略布林都帶 default:true：gorm 會把零值排除在 INSERT 外並
	// 回填 DB 預設值，故請求為 false 的欄位要在同一交易內以明確欄位補寫——否則
	// 建立即停用的計劃會以啟用狀態進排程，「不含符號」的計劃會產生含符號的密碼
	wanted := map[string]bool{
		"enabled":                    enabled,
		"password_include_symbol":    plan.PasswordIncludeSymbol,
		"password_exclude_ambiguous": plan.PasswordExcludeAmbiguous,
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		mountBound, err := s.scopePlanTargetsTx(ctx, tx, req)
		if err != nil {
			return err
		}
		if err := tx.Create(plan).Error; err != nil {
			return err
		}
		if err := restoreFalseDefaults(tx, &model.ChangeSecretPlan{}, plan.ID, wanted); err != nil {
			return err
		}
		// 發起者取自伺服器端主體；沒有主體（程式內部呼叫）的計畫沒有脈絡，排程不會替它執行
		plan.AuthorizationID, plan.Revision = nil, 0
		if _, err := s.recordPlanAuthorization(ctx, tx, plan, model.JobAuthViaRequest, mountBound); err != nil {
			return err
		}
		if plan.AuthorizationID == nil {
			plan.Revision = 1
			return nil
		}
		return tx.Model(&model.ChangeSecretPlan{}).Where("id = ?", plan.ID).
			Updates(map[string]any{"authorization_id": plan.AuthorizationID, "revision": plan.Revision}).Error
	}); err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || dberr.IsUniqueViolation(err) {
			return nil, ErrPlanNameExists
		}
		return nil, err
	}
	plan.Enabled = enabled
	plan.PasswordIncludeSymbol = wanted["password_include_symbol"]
	plan.PasswordExcludeAmbiguous = wanted["password_exclude_ambiguous"]
	return plan, nil
}

// restoreFalseDefaults 建立後補寫請求為 false、但因欄位帶 default:true 而被
// DB 預設值蓋掉的布林欄。只寫值為 false 的欄位；全為 true 時不發任何語句。
// 必須在建立的同一交易內呼叫：中間失敗不得留下一列與請求不符的資料
func restoreFalseDefaults(tx *gorm.DB, table any, id uint, wanted map[string]bool) error {
	updates := map[string]any{}
	for column, value := range wanted {
		if !value {
			updates[column] = false
		}
	}
	if len(updates) == 0 {
		return nil
	}
	return tx.Model(table).Where("id = ?", id).UpdateColumns(updates).Error
}

// Update 更新計劃
func (s *ChangeSecretPlanService) Update(ctx context.Context, id uint, req *ChangeSecretPlanRequest) (*model.ChangeSecretPlan, error) {
	plan, err := s.GetFor(ctx, id)
	if err != nil {
		return nil, err
	}
	fields, err := validatePlan(req)
	if err != nil {
		return nil, err
	}
	if s.scope == nil {
		if err := s.assertTargetResolvable(s.db, req); err != nil {
			return nil, err
		}
	}
	if s.preTxHook != nil {
		s.preTxHook()
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := s.lockTopology(tx); err != nil {
			return err
		}
		// 拓撲鎖之後以交易內視圖重讀最新列並重判可見：鎖前讀到的快照可能已被另一請求改成不可見的目標
		latest, err := latestPlanTx(tx, id)
		if err != nil {
			return err
		}
		if err := s.requireVisibleTx(ctx, tx, latest); err != nil {
			return err
		}
		mountBound, err := s.scopePlanTargetsLockedTx(ctx, tx, req)
		if err != nil {
			return err
		}
		applyPlanFields(latest, req, fields)
		if req.Enabled != nil {
			latest.Enabled = *req.Enabled
		}
		// 保存新版計畫採修改者為發起者：新增一列脈絡，舊列不被覆寫；修訂由最新列遞增
		if _, err := s.recordPlanAuthorization(ctx, tx, latest, model.JobAuthViaRequest, mountBound); err != nil {
			return err
		}
		if err := tx.Save(latest).Error; err != nil {
			return err
		}
		plan = latest
		return nil
	}); err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || dberr.IsUniqueViolation(err) {
			return nil, ErrPlanNameExists
		}
		return nil, err
	}
	return plan, nil
}

// Delete 刪除計劃（保留歷史 record）
func (s *ChangeSecretPlanService) Delete(id uint) error {
	result := s.db.Delete(&model.ChangeSecretPlan{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrPlanNotFound
	}
	return nil
}

// Records 計劃的執行記錄（新到舊）
func (s *ChangeSecretPlanService) Records(planID uint, limit int) ([]model.ChangeSecretRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var records []model.ChangeSecretRecord
	if err := s.db.Where("plan_id = ?", planID).Order("id desc").Limit(limit).Find(&records).Error; err != nil {
		return nil, err
	}
	return records, nil
}

// AssetIDList 解析計劃的資產 ID 集合
func AssetIDList(plan *model.ChangeSecretPlan) []uint {
	var ids []uint
	_ = json.Unmarshal([]byte(plan.AssetIDs), &ids)
	return ids
}

// recordAccountBatchSize 帳號 id 的分批大小。
//
// `IN (…)` 的參數數量在資料庫端有上限（postgres 的綁定參數上限為 65535），
// 而報告的範圍可以是全系統——帳號數沒有結構性上界。分批把上限問題變成迴圈次數
// 問題；1,000 遠低於任何驅動的上限，且單批的計畫仍走 account_id 索引。
const recordAccountBatchSize = 1000

// RecordsByAccounts 依帳號查改密記錄（新到舊）。
//
// **以 account_id 比對，不用帳號名快照**：帳號改名後，以名字比對會漏掉改名前的
// 記錄，而報告據此推導的「最後改密時刻」會憑空變舊或消失。名字快照仍留在記錄上
// 供顯示（帳號已刪時那是唯一還讀得出來的東西），但不作為比對鍵。
//
// from／to 為 nil 即該側不設限；有值時區間為 [from, to)——右開使連續兩期的
// 區間首尾相接而不重複計入同一筆。status 為空即不限狀態（區間明細要含
// failed 與 skipped，那正是稽核要看的東西）。
//
// 回傳不含任何秘密材料：記錄表本身就不存秘密，Error 欄只有機器碼。
func (s *ChangeSecretPlanService) RecordsByAccounts(accountIDs []uint, from, to *time.Time,
	status string) ([]model.ChangeSecretRecord, error) {

	if len(accountIDs) == 0 {
		return nil, nil
	}
	var out []model.ChangeSecretRecord
	for start := 0; start < len(accountIDs); start += recordAccountBatchSize {
		end := start + recordAccountBatchSize
		if end > len(accountIDs) {
			end = len(accountIDs)
		}
		q := s.db.Where("account_id IN ?", accountIDs[start:end])
		if from != nil {
			q = q.Where("executed_at >= ?", *from)
		}
		if to != nil {
			q = q.Where("executed_at < ?", *to)
		}
		if status != "" {
			q = q.Where("status = ?", status)
		}
		var batch []model.ChangeSecretRecord
		if err := q.Order("id desc").Find(&batch).Error; err != nil {
			return nil, err
		}
		out = append(out, batch...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// RecordsByCredential 依憑證識別查改密記錄（新到舊，有界）。
//
// **與依帳號查詢並存而非取代**：掛載可被改綁到另一筆憑證，兩個軸回答的是不同的問題
// ——「這台機器被改過幾次」問掛載，「這一組秘密被換過幾次」問憑證。記錄上的憑證
// 快照是執行當下的值，故本查詢不受事後改綁影響。
func (s *ChangeSecretPlanService) RecordsByCredential(credentialID uint, limit int) ([]model.ChangeSecretRecord, error) {
	if credentialID == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var records []model.ChangeSecretRecord
	if err := s.db.Where("credential_id = ?", credentialID).
		Order("id desc").Limit(limit).Find(&records).Error; err != nil {
		return nil, err
	}
	return records, nil
}

// LastSuccessByAccount 每個帳號在 asOf（含）之前最後一次改密成功的執行時刻。
//
// asOf 為零值時不設上界。**帶上界是為了讓截止時點真的是截止**：報告把時點往回
// 移時，晚於該時點才發生的改密不得計入，否則算出來的「距今天數」會描述一個當時
// 還沒發生的事實。
//
// 查無成功記錄的帳號**不出現在回傳的 map 內**——那是「本系統無成功改密記錄」，
// 與「很久以前改過」是兩件事，用零值時間表示會讓兩者在下游無法分辨。
//
// 單一 GROUP BY 而非逐帳號查詢：報告的範圍可達全系統，逐筆查會把一次報告產出
// 變成上萬次往返。
func (s *ChangeSecretPlanService) LastSuccessByAccount(accountIDs []uint,
	asOf time.Time) (map[uint]time.Time, error) {
	out := make(map[uint]time.Time, len(accountIDs))
	if len(accountIDs) == 0 {
		return out, nil
	}
	for start := 0; start < len(accountIDs); start += recordAccountBatchSize {
		end := start + recordAccountBatchSize
		if end > len(accountIDs) {
			end = len(accountIDs)
		}
		// **走原生 Rows 而非 Scan 進結構**：聚合結果失去欄位的宣告型別，各驅動
		// 因而回傳不同的 Go 型別（時間值或其字串表示）。以 any 逐列接收後在
		// coerceTime 收斂一次，勝過讓每個驅動各有一套隱性假設。
		q := s.db.Model(&model.ChangeSecretRecord{}).
			Select("account_id, MAX(executed_at) AS executed_at").
			Where("account_id IN ?", accountIDs[start:end]).
			Where("status = ?", model.ChangeSecretSuccess)
		if !asOf.IsZero() {
			q = q.Where("executed_at <= ?", asOf)
		}
		rows, err := q.Group("account_id").Rows()
		if err != nil {
			return nil, err
		}
		if err := scanLastSuccessRows(rows, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// scanLastSuccessRows 逐列讀出「帳號 → 最後成功時刻」，並確保結果集被關閉。
func scanLastSuccessRows(rows *sql.Rows, out map[uint]time.Time) error {
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var accountID uint
		var raw any
		if err := rows.Scan(&accountID, &raw); err != nil {
			return err
		}
		ts, ok := coerceTime(raw)
		if !ok {
			return fmt.Errorf("最後成功改密時刻無法解讀（帳號 %d）", accountID)
		}
		out[accountID] = ts
	}
	return rows.Err()
}

// coerceTime 把驅動回傳的聚合值轉成時間。
//
// **不靜默吞掉無法解讀的值**：回傳 false 讓呼叫端明確失敗，而不是塞一個零值時間
// ——零值會讓「無成功記錄」與「有記錄但讀不出來」在報告上長得一模一樣。
func coerceTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t, true
	case *time.Time:
		if t == nil {
			return time.Time{}, false
		}
		return *t, true
	case string:
		return parseTimeText(t)
	case []byte:
		return parseTimeText(string(t))
	}
	return time.Time{}, false
}

// parseTimeText 依序試幾種常見的時間文字表示（含驅動慣用的空白分隔形式）
func parseTimeText(s string) (time.Time, bool) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05.999999-07:00",
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05",
	} {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}
