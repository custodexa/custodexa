package asset

import (
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

// Usernames 登記於系統的帳號名清單（附資產數，依帳號名排序）
func (s *ChangeSecretBatchService) Usernames() ([]BatchUsername, error) {
	var out []BatchUsername
	if err := s.liveAccounts().
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

// Targets 持有該帳號名的全部目標（報告列 ＋ 可改密性）
func (s *ChangeSecretBatchService) Targets(username string, asOf time.Time) ([]BatchTarget, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, ErrBatchUsernameRequired
	}
	rows, err := s.reports.AccountRows(model.AccountScope{username}, asOf)
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

// matchingAccounts 該帳號名的全部目標帳號（依資產 id 排序）
func (s *ChangeSecretBatchService) matchingAccounts(username string) ([]model.AssetAccount, error) {
	var accounts []model.AssetAccount
	if err := s.liveAccounts().
		Select("asset_accounts.*").
		Where("asset_accounts.username = ?", username).
		Order("asset_accounts.asset_id asc, asset_accounts.id asc").
		Find(&accounts).Error; err != nil {
		return nil, err
	}
	return accounts, nil
}

// Create 驗證請求、解析目標並建立批次列（狀態為執行中）。
//
// 回傳目標資產 id 清單供執行器使用：批次的帳號範圍就是那一個帳號名，
// runner 對每台資產以此範圍解析帳號，通道與跳過語義與計劃完全相同。
func (s *ChangeSecretBatchService) Create(req *ChangeSecretBatchRequest, requesterID uint,
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
	credentialName, err := s.validateSharedCredentialName(req)
	if err != nil {
		return nil, nil, err
	}

	accounts, err := s.matchingAccounts(username)
	if err != nil {
		return nil, nil, err
	}
	targets, err := selectTargets(accounts, req)
	if err != nil {
		return nil, nil, err
	}
	if len(targets) == 0 {
		return nil, nil, ErrBatchNoTargets
	}

	batch := &model.ChangeSecretBatch{
		Username:     username,
		PasswordMode: req.PasswordMode,
		TargetCount:  len(targets),
		Status:       model.ChangeSecretBatchRunning,
		RequestedBy:  requesterID, RequestedByName: requesterName,
		StartedAt: time.Now(),
	}
	batch.SharedCredentialName = credentialName
	applyBatchPasswordPolicy(batch, req)
	if err := s.db.Create(batch).Error; err != nil {
		return nil, nil, err
	}

	assetIDs := make([]uint, 0, len(targets))
	for i := range targets {
		assetIDs = append(assetIDs, targets[i].AssetID)
	}
	return batch, assetIDs, nil
}

// validateSharedCredentialName 整批同一組模式的憑證名稱檢核（送出前先擋，
// 不讓操作者改完一批機器才被名稱撞名擋下來）。回傳正規化後的名稱；其他模式回空字串。
func (s *ChangeSecretBatchService) validateSharedCredentialName(req *ChangeSecretBatchRequest) (string, error) {
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
	if err := assertSharedNameFree(s.db, name, 0); err != nil {
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
