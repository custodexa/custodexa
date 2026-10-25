package asset

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 批次驗證錯誤：handler 以 errors.Is 區分 400／404 與 500
var (
	ErrBatchUsernameRequired = errors.New("批次改密須指定帳號名")
	ErrBatchBadPasswordMode  = errors.New("密碼模式僅支援 per_target 或 shared")
	ErrBatchNoTargets        = errors.New("批次改密沒有可執行的目標")
	ErrBatchTargetMismatch   = errors.New("選定的帳號不屬於指定的帳號名")
	ErrBatchNotFound         = errors.New("批次改密不存在")
	// ErrBatchCredentialNameRequired 整批同一組模式沒給共用憑證名稱。
	//
	// 名稱必填而非自動產生：這一批改完之後，那組密碼會以一筆具名共用憑證的形式
	// 長期留在憑證庫裡，沒有名字的共用憑證在清單上無從辨認是哪一次批次留下的
	ErrBatchCredentialNameRequired = errors.New("整批同一組模式須指定共用憑證名稱")
)

// batchListLimit 最近批次列表的上界
const batchListLimit = 50

// ChangeSecretBatchRequest 建立批次的請求。
//
// 目標選擇二擇一：All 為真即全部符合者，否則以 AccountIDs 明列；明列的帳號必須
// 是該帳號名的目標，任一不符即整筆拒絕——靜默丟掉不符的那幾個，會讓管理員以為
// 它們也改了。
type ChangeSecretBatchRequest struct {
	Username     string `json:"username"`
	AccountIDs   []uint `json:"account_ids"`
	All          bool   `json:"all"`
	PasswordMode string `json:"password_mode"`
	// CredentialName 整批同一組模式下要建立的共用憑證名稱（必填，依共用唯一性檢核）；
	// 每台各自隨機時忽略
	CredentialName string `json:"credential_name"`
	// SharedCredentialOwnership 整批同一組模式新建共用憑證的管理歸屬（形狀與驗證同憑證庫建立）；
	// 未帶時全域主體為全域、只經節點範圍持有建立能力者為不合法。每台各自隨機時忽略
	SharedCredentialOwnership *CredentialOwnershipInput `json:"shared_credential_ownership"`

	PasswordLength           int   `json:"password_length"`
	PasswordIncludeSymbol    *bool `json:"password_include_symbol"`
	PasswordExcludeAmbiguous *bool `json:"password_exclude_ambiguous"`
}

// BatchUsername 帳號名清單的一列：登記於系統的帳號名與持有它的資產數
type BatchUsername struct {
	Username   string `json:"username"`
	AssetCount int    `json:"asset_count"`
}

// BatchTarget 批次的一個候選目標：報告資料集的同一列，外加執行前可判定的可改密性。
//
// 不可改密的目標仍列出——管理員要看得到「這台為什麼不在名單上」，
// 而不是名單裡少一台卻不知道少在哪。
type BatchTarget struct {
	AccountRow
	// RotationChannel 推導後的有效改密通道
	RotationChannel string `json:"rotation_channel"`
	// IneligibleReason 執行前即可判定的不可改密原因（機器碼）；空＝可改密
	IneligibleReason string `json:"ineligible_reason"`
}

// ChangeSecretBatchService 以帳號名為軸的批次改密：目標解析、建立與查詢。
//
// 執行本身在 ChangeSecretRunner（狀態機的唯一擁有者）；本服務只負責
// 「哪些目標、什麼設定」與批次列的生命週期。
type ChangeSecretBatchService struct {
	db      *gorm.DB
	reports *RotationReportBuilder
	// mgmt 建立批次時的管理授權關卡；未注入 fail closed
	mgmt credentialManagementGate
	// scope 建立交易內的拓撲鎖、能力來源與資產範圍；未注入＝全系統口徑（見 WithScope）
	scope ChangeSecretScopePort
	// ownership 整批同一組模式新共用憑證的歸屬判定；未注入時該模式建立 fail-close
	ownership CredentialOwnershipScopePort
}

// WithOwnershipScope 注入整批同一組模式新共用憑證的歸屬判定（組裝根）。
func (s *ChangeSecretBatchService) WithOwnershipScope(p CredentialOwnershipScopePort) *ChangeSecretBatchService {
	s.ownership = p
	return s
}

// WithManagementAuthorizer 注入憑證管理授權判定器（見 credential_management_authz.go）。
func (s *ChangeSecretBatchService) WithManagementAuthorizer(a CredentialManagementAuthorizer) *ChangeSecretBatchService {
	s.mgmt = credentialManagementGate{authorizer: a}
	return s
}

// NewChangeSecretBatchService 建立服務
func NewChangeSecretBatchService(db *gorm.DB, reports *RotationReportBuilder) *ChangeSecretBatchService {
	return &ChangeSecretBatchService{db: db, reports: reports}
}

// liveAccounts 掛在未刪除資產上的未刪除帳號（母體定義與輪替證據報告相同）
func (s *ChangeSecretBatchService) liveAccounts() *gorm.DB {
	return s.db.Model(&model.AssetAccount{}).
		Joins("JOIN assets ON assets.id = asset_accounts.asset_id AND assets.deleted_at IS NULL")
}

// Usernames 登記於系統的帳號名清單（附資產數，依帳號名排序）；不經檢視者投影，見 UsernamesFor
func (s *ChangeSecretBatchService) Usernames() ([]BatchUsername, error) {
	return usernamesOn(s.liveAccounts())
}

// usernamesOn 在給定的帳號母體上彙總帳號名與資產數
func usernamesOn(q *gorm.DB) ([]BatchUsername, error) {
	var out []BatchUsername
	if err := q.
		Select("asset_accounts.username AS username, COUNT(*) AS asset_count").
		Group("asset_accounts.username").
		Order("asset_accounts.username").
		Scan(&out).Error; err != nil {
		return nil, err
	}
	if out == nil {
		out = []BatchUsername{}
	}
	return out, nil
}

// Targets 持有該帳號名的全部目標（報告列 ＋ 可改密性）；不經檢視者投影，見 TargetsFor
func (s *ChangeSecretBatchService) Targets(username string, asOf time.Time) ([]BatchTarget, error) {
	return s.targetsIn(username, nil, nil, asOf)
}

// normalizedUsername 去頭尾空白；空值為必填錯誤
func normalizedUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", ErrBatchUsernameRequired
	}
	return username, nil
}

// targetsIn 該帳號名的目標；assetFilter 為 nil＝不限資產，空切片＝沒有任何資產；
// plans 為彙總涵蓋計畫前的可見性投影（nil＝全部計畫）
func (s *ChangeSecretBatchService) targetsIn(username string, assetFilter []uint, plans PlanFilter,
	asOf time.Time) ([]BatchTarget, error) {
	username, err := normalizedUsername(username)
	if err != nil {
		return nil, err
	}
	rows, err := s.reports.AccountRowsIn(model.AccountScope{username}, assetFilter, plans, asOf)
	if err != nil {
		return nil, err
	}
	assets, err := s.assetsFor(rows)
	if err != nil {
		return nil, err
	}
	out := make([]BatchTarget, 0, len(rows))
	for i := range rows {
		asset := assets[rows[i].AssetID]
		t := BatchTarget{AccountRow: rows[i]}
		if asset != nil {
			t.RotationChannel = asset.EffectiveRotationChannel()
		}
		t.IneligibleReason = ineligibleReason(asset, &rows[i])
		out = append(out, t)
	}
	return out, nil
}

func (s *ChangeSecretBatchService) assetsFor(rows []AccountRow) (map[uint]*model.Asset, error) {
	ids := make([]uint, 0, len(rows))
	seen := map[uint]bool{}
	for i := range rows {
		if !seen[rows[i].AssetID] {
			seen[rows[i].AssetID] = true
			ids = append(ids, rows[i].AssetID)
		}
	}
	out := map[uint]*model.Asset{}
	if len(ids) == 0 {
		return out, nil
	}
	var assets []model.Asset
	if err := s.db.Where("id IN ?", ids).Find(&assets).Error; err != nil {
		return nil, err
	}
	for i := range assets {
		out[assets[i].ID] = &assets[i]
	}
	return out, nil
}

// ineligibleReason 執行前即可判定的跳過原因，與 runner 的判定同源同碼。
//
// 只列「執行時必然跳過」的情形；遠端會不會拒絕，要真的連了才知道。
func ineligibleReason(asset *model.Asset, row *AccountRow) string {
	if asset == nil {
		return model.ChangeSecretReasonAssetLookupFailed
	}
	if asset.EffectiveRotationChannel() == model.RotationChannelNone {
		if asset.Protocol == model.ProtocolSSH || asset.Protocol == model.ProtocolRDP {
			return model.ChangeSecretReasonChannelNotConfigured
		}
		return model.ChangeSecretReasonProtocolUnsupported
	}
	if row.CandidateState != "" && row.CandidateState != CandidateNone {
		return model.ChangeSecretReasonCandidatePending
	}
	switch row.CredentialType {
	case CredentialTypeNone:
		return model.ChangeSecretReasonNoCredential
	case CredentialTypeSSHKey:
		// 批次只做密碼型別：只有私鑰的帳號沒有可換的密碼
		return model.ChangeSecretReasonNoPasswordCredential
	}
	return ""
}

// matchingAccountsOn 在給定的帳號母體查詢上取該帳號名的全部目標帳號（依資產 id 排序）
func matchingAccountsOn(q *gorm.DB, username string) ([]model.AssetAccount, error) {
	var accounts []model.AssetAccount
	if err := q.Select("asset_accounts.*").
		Where("asset_accounts.username = ?", username).
		Order("asset_accounts.asset_id asc, asset_accounts.id asc").
		Find(&accounts).Error; err != nil {
		return nil, err
	}
	return accounts, nil
}

// Create 以背景脈絡建立批次（見 CreateFor）；供沒有請求脈絡的呼叫端使用。
func (s *ChangeSecretBatchService) Create(req *ChangeSecretBatchRequest, requesterID uint,
	requesterName string) (*model.ChangeSecretBatch, []uint, error) {
	return s.CreateFor(context.Background(), req, requesterID, requesterName)
}

// CreateFor 驗證請求、解析目標並建立批次列（狀態為執行中）。
//
// 回傳目標資產 id 清單供執行器使用：批次的帳號範圍就是那一個帳號名，
// runner 對每台資產以此範圍解析帳號，通道與跳過語義與計劃完全相同。
//
// 順序固定，對所有主體一致：輸入形狀 → 模式決定的能力 → 交易內取拓撲鎖並重判能力 →
// 範圍與存在 → 帳號名相符 → 零目標 → 依目標的追加能力 → 新共用憑證歸屬 → 名稱查重 → 寫入。
// 缺能力者在讀任何目標資料之前即被拒，回應不隨目標資料而不同。
func (s *ChangeSecretBatchService) CreateFor(ctx context.Context, req *ChangeSecretBatchRequest, requesterID uint,
	requesterName string) (*model.ChangeSecretBatch, []uint, error) {

	username := strings.TrimSpace(req.Username)
	if username == "" {
		return nil, nil, ErrBatchUsernameRequired
	}
	if !model.IsBatchPasswordMode(req.PasswordMode) {
		return nil, nil, ErrBatchBadPasswordMode
	}
	if err := ValidatePasswordLength(req.PasswordLength); err != nil {
		return nil, nil, err
	}
	credentialName, err := sharedCredentialNameShape(req)
	if err != nil {
		return nil, nil, err
	}
	ctx = contextWithInitiator(ctx, requesterID, requesterName)
	modeCaps := batchModeCapabilities(req)
	if err := s.requireModeCapabilities(ctx, s.db, requesterID, modeCaps); err != nil {
		return nil, nil, err
	}

	batch := &model.ChangeSecretBatch{
		Username:     username,
		PasswordMode: req.PasswordMode,
		Status:       model.ChangeSecretBatchRunning,
		RequestedBy:  requesterID, RequestedByName: requesterName,
		StartedAt: time.Now(),
	}
	batch.SharedCredentialName = credentialName
	applyBatchPasswordPolicy(batch, req)
	// 兩個密碼策略布林帶 default:true：gorm 對零值改用 DB 預設值並回填到 batch，
	// 而執行器讀的正是這個結構——不補寫，「不含符號」的一批會產生含符號的密碼。
	// 意圖先記下，同一交易內補寫落庫，再還原到回傳的結構上
	wanted := map[string]bool{
		"password_include_symbol":    batch.PasswordIncludeSymbol,
		"password_exclude_ambiguous": batch.PasswordExcludeAmbiguous,
	}
	var targets []model.AssetAccount
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if s.scope != nil {
			// 拓撲序列化鎖是第一個動作：之後的能力重判與範圍交集看到的是同一份節點樹
			if err := s.scope.LockTopology(tx); err != nil {
				return err
			}
			if err := s.requireModeCapabilities(ctx, tx, requesterID, modeCaps); err != nil {
				return err
			}
		}
		var err error
		targets, err = s.resolveTargets(ctx, tx, requesterID, username, req)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return ErrBatchNoTargets
		}
		// 管理授權：複合請求逐項驗所需能力，任一缺少整批不建立（零寫入）
		batchCaps, batchDecision, err := s.authorizeBatch(ctx, tx, req, targets)
		if err != nil {
			return err
		}
		if credentialName != "" {
			// 歸屬在名稱查重之前：同一交易、拓撲鎖之後判定並持久化，runner 建立憑證時以持久值重驗
			owner, err := resolveSharedOwnershipTx(ctx, tx, s.ownership, requesterID, CredCapCreate,
				req.SharedCredentialOwnership)
			if err != nil {
				return err
			}
			batch.SharedCredentialOwnerKind = owner.Kind
			batch.SharedCredentialOwnerNodeID = owner.NodeID
			if err := assertSharedNameFree(tx, credentialName, 0); err != nil {
				return err
			}
		}
		batch.TargetCount = len(targets)
		if err := tx.Create(batch).Error; err != nil {
			return err
		}
		if err := restoreFalseDefaults(tx, &model.ChangeSecretBatch{}, batch.ID, wanted); err != nil {
			return err
		}
		// 發起者與當次確認的上界（選定的資產）存成不可變授權脈絡，之後的背景執行與補跑沿用
		auth, err := insertJobAuthorization(s.mgmt, tx, jobAuthInput{
			kind: model.JobAuthSourceBatch, sourceID: batch.ID, revision: 1,
			actorID: requesterID, actorName: requesterName, via: model.JobAuthViaRequest,
			authzVersion: batchDecision.AuthzVersion, sources: batchDecision.Sources, capabilities: batchCaps, targetBound: batchAssetIDs(targets),
		})
		if err != nil {
			return err
		}
		batch.AuthorizationID = &auth.ID
		return tx.Model(&model.ChangeSecretBatch{}).Where("id = ?", batch.ID).
			Update("authorization_id", auth.ID).Error
	}); err != nil {
		return nil, nil, err
	}
	batch.PasswordIncludeSymbol = wanted["password_include_symbol"]
	batch.PasswordExcludeAmbiguous = wanted["password_exclude_ambiguous"]

	assetIDs := make([]uint, 0, len(targets))
	for i := range targets {
		assetIDs = append(assetIDs, targets[i].AssetID)
	}
	return batch, assetIDs, nil
}

// batchModeCapabilities 由模式決定、與目標資料無關的能力：所有批次都改選定帳號的秘密；
// 整批同一組另會新建共用憑證並逐台掛入。
func batchModeCapabilities(req *ChangeSecretBatchRequest) []string {
	caps := []string{CredCapAccountRotate}
	if req.PasswordMode == model.BatchPasswordShared {
		caps = append(caps, CredCapCreate, CredCapBind)
	}
	return caps
}

// requireModeCapabilities 不帶目標的能力判定。不帶目標的關卡只認全系統來源：放行即全系統持有；
// 被拒時若已注入範圍判定，再以任一有效來源（含節點範圍）檢核，持有者往下由範圍收斂目標。
// 其餘一律回關卡原本的拒絕，不依目標資料分流。
func (s *ChangeSecretBatchService) requireModeCapabilities(ctx context.Context, db *gorm.DB, requesterID uint,
	caps []string) error {

	_, err := s.mgmt.require(ctx, db, CredentialManagementRequest{Operation: CredOpRotate, Capabilities: caps})
	if err == nil || s.scope == nil || requesterID == 0 || errors.Is(err, ErrCredentialAuthzUnavailable) {
		return err
	}
	missing, cerr := s.scope.CapabilityMissing(ctx, db, requesterID, caps)
	if cerr != nil {
		return fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, cerr)
	}
	if missing != "" {
		return err
	}
	return nil
}

// resolveTargets 交易內解析目標。範圍化主體（帳號改密只經節點範圍持有）：全部符合者只取範圍內，
// 明列者先計「不存在或資產在範圍外」的筆數，有就整批拒絕，之後才判帳號名相符；
// 不限範圍者（含未注入範圍判定）沿明列即比對帳號名的現行規則。
func (s *ChangeSecretBatchService) resolveTargets(ctx context.Context, tx *gorm.DB, requesterID uint,
	username string, req *ChangeSecretBatchRequest) ([]model.AssetAccount, error) {

	var scope ChangeSecretAssetScope
	if s.scope != nil {
		var err error
		scope, err = s.scope.AssetScope(ctx, tx, requesterID, CredCapAccountRotate)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
		}
	}
	live := func() *gorm.DB {
		q := tx.Model(&model.AssetAccount{}).
			Joins("JOIN assets ON assets.id = asset_accounts.asset_id AND assets.deleted_at IS NULL")
		if scope.Limited {
			q = q.Where("asset_accounts.asset_id IN (?)", scope.AssetIDs)
		}
		return q
	}
	if !scope.Limited {
		accounts, err := matchingAccountsOn(live(), username)
		if err != nil {
			return nil, err
		}
		return selectTargets(accounts, req)
	}
	if !req.All {
		ids := uniqueIDs(req.AccountIDs)
		if len(ids) > 0 {
			var available int64
			if err := live().Where("asset_accounts.id IN ?", ids).Count(&available).Error; err != nil {
				return nil, err
			}
			if missing := len(ids) - int(available); missing > 0 {
				return nil, &BatchItemsUnavailableError{Count: missing}
			}
		}
	}
	accounts, err := matchingAccountsOn(live(), username)
	if err != nil {
		return nil, err
	}
	return selectTargets(accounts, req)
}

// uniqueIDs 去重保序
func uniqueIDs(ids []uint) []uint {
	seen := make(map[uint]bool, len(ids))
	out := make([]uint, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// sharedCredentialNameShape 整批同一組模式的憑證名稱形狀檢核（必填與格式）；撞名在建立交易內、
// 能力與目標判定之後才查，缺能力者得不到「名稱已被使用」這個資料相依的回應。
// 回傳正規化後的名稱；其他模式回空字串。
func sharedCredentialNameShape(req *ChangeSecretBatchRequest) (string, error) {
	if req.PasswordMode != model.BatchPasswordShared {
		return "", nil
	}
	name := strings.TrimSpace(req.CredentialName)
	if name == "" {
		return "", ErrBatchCredentialNameRequired
	}
	if err := ValidateCredentialName(name); err != nil {
		return "", err
	}
	if err := ValidateCredentialOwnershipInput(req.SharedCredentialOwnership); err != nil {
		return "", err
	}
	return name, nil
}

// selectTargets 依請求挑出目標；明列的帳號必須全部屬於該帳號名
func selectTargets(accounts []model.AssetAccount, req *ChangeSecretBatchRequest) ([]model.AssetAccount, error) {
	if req.All {
		return accounts, nil
	}
	byID := make(map[uint]model.AssetAccount, len(accounts))
	for i := range accounts {
		byID[accounts[i].ID] = accounts[i]
	}
	seen := map[uint]bool{}
	out := make([]model.AssetAccount, 0, len(req.AccountIDs))
	for _, id := range req.AccountIDs {
		acc, ok := byID[id]
		if !ok {
			return nil, ErrBatchTargetMismatch
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, acc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AssetID < out[j].AssetID })
	return out, nil
}

// applyBatchPasswordPolicy 缺省值與計劃相同：16、含符號、排除易混淆
func applyBatchPasswordPolicy(batch *model.ChangeSecretBatch, req *ChangeSecretBatchRequest) {
	batch.PasswordLength = req.PasswordLength
	if batch.PasswordLength == 0 {
		batch.PasswordLength = model.PasswordLengthDefault
	}
	batch.PasswordIncludeSymbol = true
	if req.PasswordIncludeSymbol != nil {
		batch.PasswordIncludeSymbol = *req.PasswordIncludeSymbol
	}
	batch.PasswordExcludeAmbiguous = true
	if req.PasswordExcludeAmbiguous != nil {
		batch.PasswordExcludeAmbiguous = *req.PasswordExcludeAmbiguous
	}
}

// Get 單一批次
func (s *ChangeSecretBatchService) Get(id uint) (*model.ChangeSecretBatch, error) {
	var batch model.ChangeSecretBatch
	if err := s.db.First(&batch, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrBatchNotFound
		}
		return nil, err
	}
	return &batch, nil
}

// List 最近批次（新到舊，有界）
func (s *ChangeSecretBatchService) List() ([]model.ChangeSecretBatch, error) {
	var out []model.ChangeSecretBatch
	if err := s.db.Order("id desc").Limit(batchListLimit).Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// Records 批次的逐目標記錄（依資產、記錄順序）
func (s *ChangeSecretBatchService) Records(batchID uint) ([]model.ChangeSecretRecord, error) {
	var out []model.ChangeSecretRecord
	if err := s.db.Where("batch_id = ?", batchID).
		Order("asset_id asc, id asc").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// completeBatch 全部目標處理完後一次寫入四種計數與完成狀態；失敗只留 log
// （計數寫不進去不改變每個目標已各自落庫的結果）
func completeBatch(db *gorm.DB, batchID uint, records []model.ChangeSecretRecord) {
	var success, failed, unverified, skipped int
	for i := range records {
		switch records[i].Status {
		case model.ChangeSecretSuccess:
			success++
		case model.ChangeSecretFailed:
			failed++
		case model.ChangeSecretUnverified:
			unverified++
		case model.ChangeSecretSkipped:
			skipped++
		}
	}
	now := time.Now()
	err := db.Model(&model.ChangeSecretBatch{}).Where("id = ?", batchID).Updates(map[string]any{
		"success_count":    success,
		"failed_count":     failed,
		"unverified_count": unverified,
		"skipped_count":    skipped,
		"status":           model.ChangeSecretBatchCompleted,
		"finished_at":      now,
	}).Error
	if err != nil {
		log.Printf("[ChangeSecret] 批次完成狀態入庫失敗 batch=%d err=%v", batchID, err)
	}
}

// batchSource 告警內容裡的批次識別
func batchSource(batch *model.ChangeSecretBatch) string {
	return fmt.Sprintf("batch=%d username=%s", batch.ID, batch.Username)
}

// authorizeBatch 批次的管理授權（建立交易內，目標已經範圍收斂之後）。
//
// 所需能力依模式組合：所有批次都改選定帳號的秘密（account:rotate）；整批同一組會新建
// 共用憑證並逐台掛入（credential:create、credential:bind）；每台各自隨機遇到共用憑證的
// 成員時走單台脫離再改（credential:detach、credential:rotate）。影響集合是全部選定的
// 資產與帳號；不帶來源憑證——拆分只改所選掛載、不改來源共用憑證的秘密，判定依所選資產。
// 發起者取自 ctx（伺服器端已認證的請求者），不接受 body。
//
// 依目標追加的能力判為範圍外時（目標本身已在帳號改密範圍內）收斂為單一 forbidden，
// 不回範圍拒絕值，回應不揭露哪一台、哪一項。
func (s *ChangeSecretBatchService) authorizeBatch(ctx context.Context, tx *gorm.DB,
	req *ChangeSecretBatchRequest, targets []model.AssetAccount) ([]string, CredentialManagementDecision, error) {

	caps := batchModeCapabilities(req)
	var assetIDs, accountIDs []uint
	var credIDs []uint
	for i := range targets {
		assetIDs = append(assetIDs, targets[i].AssetID)
		accountIDs = append(accountIDs, targets[i].ID)
		if targets[i].CredentialID != 0 {
			credIDs = append(credIDs, targets[i].CredentialID)
		}
	}
	if req.PasswordMode != model.BatchPasswordShared && len(credIDs) > 0 {
		var shared int64
		if err := tx.Model(&model.Credential{}).
			Where("id IN ? AND scope = ?", credIDs, model.CredentialScopeShared).
			Count(&shared).Error; err != nil {
			return nil, CredentialManagementDecision{}, fmt.Errorf("%w: 讀取憑證範圍失敗", ErrCredentialAuthzUnavailable)
		}
		if shared > 0 {
			caps = append(caps, CredCapDetach, CredCapRotate)
		}
	}
	decision, err := s.mgmt.require(ctx, tx, CredentialManagementRequest{
		Operation:    CredOpRotate,
		Capabilities: caps,
		AssetIDs:     assetIDs,
		AccountIDs:   accountIDs,
	})
	if err != nil && decision.ScopeDenial != nil {
		denied := capabilityDenied(ErrCredentialBindForbidden, caps...)
		denied.(*CapabilityDeniedError).Forbidden = true
		return caps, decision, denied
	}
	return caps, decision, err
}

// batchAssetIDs 批次確認當下的目標上界（選定的資產，去重保序）。
func batchAssetIDs(targets []model.AssetAccount) []uint {
	seen := map[uint]bool{}
	out := make([]uint, 0, len(targets))
	for i := range targets {
		if !seen[targets[i].AssetID] {
			seen[targets[i].AssetID] = true
			out = append(out, targets[i].AssetID)
		}
	}
	return out
}
