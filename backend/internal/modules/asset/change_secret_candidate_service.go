package asset

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 重試節奏（design D4）：指數退避 ＋ 上限 ＋ 總期限。
//
// 固定短間隔不可行——「遠端其實沒改成」時會對目標機連打數百次錯誤密碼，
// 足以觸發目標端的帳號鎖定或 fail2ban，把一個可修復的狀態變成兩個問題
const (
	candidateRetryBase     = 5 * time.Minute
	candidateRetryMax      = time.Hour
	candidateRetryDeadline = 24 * time.Hour
)

// 候選憑證錯誤（handler 以 errors.Is 分流）
var (
	ErrCandidateExists   = errors.New("該帳號已有未驗證的候選憑證")
	ErrCandidateNotFound = errors.New("候選憑證不存在")
)

// ChangeSecretCandidateService 未驗證候選憑證的生命週期（design D1／D2／D4）。
//
// 候選秘密**只在本服務內解密**，且解密結果只交給 runner 用於「登入驗證」與
// 「提交為帳號憑證」兩件事，不回傳給任何 handler。
type ChangeSecretCandidateService struct {
	db           *gorm.DB
	crypto       crypto.ColumnCodec
	assetService *AssetService
	auditTx      port.TxSink
}

// NewChangeSecretCandidateService 建立服務
func NewChangeSecretCandidateService(db *gorm.DB, codec crypto.ColumnCodec,
	assetService *AssetService, auditTx port.TxSink) (*ChangeSecretCandidateService, error) {
	if codec == nil {
		return nil, fmt.Errorf("初始化候選憑證服務失敗: codec 為必要參數")
	}
	return &ChangeSecretCandidateService{db: db, crypto: codec, assetService: assetService, auditTx: auditTx}, nil
}

// CandidateInput 建立候選的輸入（明文秘密只在此結構內短暫存在）
type CandidateInput struct {
	AssetID           uint
	AccountID         uint
	AccountUsername   string
	PlanID            uint
	SecretType        string
	Password          string
	PrivateKey        string
	PublicKey         string
	PreviousPublicKey string
}

// CandidateSecret 解密後的候選秘密（僅 runner 與重試排程使用，不出服務層邊界）
type CandidateSecret struct {
	Password   string
	PrivateKey string
}

// Create 建立候選列。**呼叫點必須在動遠端之前**（design D2）：後端在
// 「已下達改密、尚未驗證」的窗口被砍時，候選若只在記憶體即永久遺失。
//
// AccountID 唯一鍵衝突回 ErrCandidateExists——同一帳號不疊加第二個未知狀態。
func (s *ChangeSecretCandidateService) Create(ctx context.Context, in CandidateInput) (*model.ChangeSecretCandidate, error) {
	cand := &model.ChangeSecretCandidate{
		AssetID:           in.AssetID,
		AccountID:         in.AccountID,
		AccountUsername:   in.AccountUsername,
		PlanID:            in.PlanID,
		SecretType:        in.SecretType,
		PublicKey:         in.PublicKey,
		PreviousPublicKey: in.PreviousPublicKey,
		NextAttemptAt:     time.Now().Add(candidateRetryBase),
	}
	if in.Password != "" {
		enc, err := s.crypto.EncryptFor(ctx, keyvault.RefChangeSecretCandidatePassword, in.Password)
		if err != nil {
			return nil, fmt.Errorf("加密候選密碼失敗: %w", err)
		}
		cand.PasswordEnc = enc
	}
	if in.PrivateKey != "" {
		enc, err := s.crypto.EncryptFor(ctx, keyvault.RefChangeSecretCandidatePrivateKey, in.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("加密候選私鑰失敗: %w", err)
		}
		cand.PrivateKeyEnc = enc
	}
	if err := s.db.Create(cand).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || dberr.IsUniqueViolation(err) {
			return nil, ErrCandidateExists
		}
		return nil, err
	}
	return cand, nil
}

// Secret 解密候選秘密。回傳值 SHALL NOT 進入任何 API 回應、日誌或審計欄位
func (s *ChangeSecretCandidateService) Secret(ctx context.Context, cand *model.ChangeSecretCandidate) (CandidateSecret, error) {
	var out CandidateSecret
	if cand.PasswordEnc != "" {
		pw, err := s.crypto.DecryptFor(ctx, keyvault.RefChangeSecretCandidatePassword, cand.PasswordEnc)
		if err != nil {
			return out, fmt.Errorf("解密候選密碼失敗: %w", err)
		}
		out.Password = pw
	}
	if cand.PrivateKeyEnc != "" {
		key, err := s.crypto.DecryptFor(ctx, keyvault.RefChangeSecretCandidatePrivateKey, cand.PrivateKeyEnc)
		if err != nil {
			return out, fmt.Errorf("解密候選私鑰失敗: %w", err)
		}
		out.PrivateKey = key
	}
	return out, nil
}

// MarkApplied 標記遠端變更指令已回報成功。false 的候選代表遠端狀態不可知
// （下達過程中被中斷），只影響呈現與告警文案，不影響重試邏輯
func (s *ChangeSecretCandidateService) MarkApplied(id uint) error {
	return s.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", id).
		Update("applied", true).Error
}

// FindByAccount 取該帳號的候選（無則回 nil, nil）
func (s *ChangeSecretCandidateService) FindByAccount(accountID uint) (*model.ChangeSecretCandidate, error) {
	var cand model.ChangeSecretCandidate
	err := s.db.Where("account_id = ?", accountID).First(&cand).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &cand, nil
}

// Get 取單筆候選
func (s *ChangeSecretCandidateService) Get(id uint) (*model.ChangeSecretCandidate, error) {
	var cand model.ChangeSecretCandidate
	err := s.db.First(&cand, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrCandidateNotFound
	}
	if err != nil {
		return nil, err
	}
	return &cand, nil
}

// List 全部候選（新到舊），供 admin 檢視未驗證憑證清單
func (s *ChangeSecretCandidateService) List() ([]model.ChangeSecretCandidate, error) {
	var out []model.ChangeSecretCandidate
	if err := s.db.Order("id desc").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// DueForRetry 到期且尚未放棄的候選（有界批次）
func (s *ChangeSecretCandidateService) DueForRetry(limit int) ([]model.ChangeSecretCandidate, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []model.ChangeSecretCandidate
	if err := s.db.Where("abandoned = ? AND next_attempt_at <= ?", false, time.Now()).
		Order("next_attempt_at").Limit(limit).Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// Promote 候選驗證成功：提交為帳號憑證後刪除候選列。
//
// **順序是「先提交、後刪列」**：提交後刪列失敗只會讓重試再提交一次同一個值
// （冪等、無害）；反過來先刪列則在提交失敗時失去唯一副本，帳號永久鎖死。
func (s *ChangeSecretCandidateService) Promote(ctx context.Context, cand *model.ChangeSecretCandidate) error {
	secret, err := s.Secret(ctx, cand)
	if err != nil {
		return err
	}
	switch cand.SecretType {
	case model.ChangeSecretTypeSSHKey:
		if secret.PrivateKey == "" {
			return fmt.Errorf("候選私鑰為空")
		}
		err = s.assetService.UpdatePrivateKey(cand.AssetID, cand.AccountID, cand.AccountUsername, secret.PrivateKey)
	default:
		if secret.Password == "" {
			return fmt.Errorf("候選密碼為空")
		}
		err = s.assetService.UpdatePassword(cand.AssetID, cand.AccountID, cand.AccountUsername, secret.Password)
	}
	if err != nil {
		return err
	}
	return s.db.Delete(&model.ChangeSecretCandidate{}, cand.ID).Error
}

// Discard 刪除候選列（遠端確定未變更時由 runner 呼叫；無審計——那條路徑
// 由改密記錄本身留痕）
func (s *ChangeSecretCandidateService) Discard(id uint) error {
	return s.db.Delete(&model.ChangeSecretCandidate{}, id).Error
}

// RecordFailure 記一次驗證失敗：累計次數、指數退避、逾期即放棄。
// 回傳 abandoned 表示本次轉為已放棄（供呼叫端推送高等級告警）
func (s *ChangeSecretCandidateService) RecordFailure(cand *model.ChangeSecretCandidate, errMsg string) (bool, error) {
	now := time.Now()
	attempts := cand.AttemptCount + 1
	abandoned := now.Sub(cand.CreatedAt) >= candidateRetryDeadline
	updates := map[string]any{
		"attempt_count":   attempts,
		"last_attempt_at": now,
		"last_error":      truncateCandidateError(errMsg),
		"next_attempt_at": now.Add(candidateBackoff(attempts)),
		"abandoned":       abandoned,
	}
	if err := s.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
		Updates(updates).Error; err != nil {
		return false, err
	}
	return abandoned && !cand.Abandoned, nil
}

// candidateBackoff 指數退避：base × 2^(attempts-1)，上限 candidateRetryMax
func candidateBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := candidateRetryBase
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= candidateRetryMax {
			return candidateRetryMax
		}
	}
	if d > candidateRetryMax {
		return candidateRetryMax
	}
	return d
}

func truncateCandidateError(msg string) string {
	const limit = 500
	if len(msg) <= limit {
		return msg
	}
	return msg[:limit]
}

// DiscardByAdmin admin 顯式清除候選（design D4 的逃生口）。
//
// 這是**破壞性操作**：候選是那把可能已在遠端生效的秘密的唯一副本，清除後
// 若遠端確實已改密，該帳號只能由管理員以帶外途徑（主機 console）重設憑證救回。
// 故必須留痕——審計只記欄位名，不記任何秘密材料。
func (s *ChangeSecretCandidateService) DiscardByAdmin(id uint, userID uint, operator string) error {
	cand, err := s.Get(id)
	if err != nil {
		return err
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Delete(&model.ChangeSecretCandidate{}, id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrCandidateNotFound
		}
		return writeAssetAccountAudit(s.auditTx, tx, model.AssetAccountAudit{
			AssetID:   cand.AssetID,
			AccountID: cand.AccountID,
			Username:  cand.AccountUsername,
			Operation: model.AccountOpDiscardCandidate,
			Fields:    []string{"change_secret_candidate"},
		}, userID, operator)
	})
}
