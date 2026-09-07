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

// 重試節奏：指數退避 ＋ 上限 ＋ 總期限。
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

// ChangeSecretCandidateService 未驗證候選憑證的生命週期。
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
	AssetID         uint
	AccountID       uint
	AccountUsername string
	PlanID          uint
	// BatchID 來源批次（0＝來自計劃）
	BatchID           uint
	SecretType        string
	Password          string
	PrivateKey        string
	PublicKey         string
	PreviousPublicKey string
	// CredentialID／TargetVersionID 建立當下該掛載引用的憑證與轉正後要就位的版本。
	// 0＝呼叫端尚未解析到憑證（既有的計劃與批次路徑）；輪替路徑一律帶上，
	// 使補跑時「這把秘密是哪一輪、要就位成哪一版」不必回頭猜
	CredentialID uint
	// CredentialName 憑證名稱快照（同 record 的理由：憑證可能改名或被回收）
	CredentialName  string
	TargetVersionID uint
}

// CandidateSecret 解密後的候選秘密（僅 runner 與重試排程使用，不出服務層邊界）
type CandidateSecret struct {
	Password   string
	PrivateKey string
}

// Create 建立候選列。**呼叫點必須在動遠端之前**：後端在
// 「已下達改密、尚未驗證」的窗口被砍時，候選若只在記憶體即永久遺失。
//
// AccountID 唯一鍵衝突回 ErrCandidateExists——同一帳號不疊加第二個未知狀態。
func (s *ChangeSecretCandidateService) Create(ctx context.Context, in CandidateInput) (*model.ChangeSecretCandidate, error) {
	return s.CreateInTx(ctx, s.db, in)
}

// CreateInTx 於呼叫端的交易內建立候選列。
//
// 起始交易要同時鎖住憑證、快照成員並為每台備妥候選；候選若落在交易外，
// 交易回滾後會留下一批沒有主人的候選，而它們會擋住該掛載後續全部的改密。
func (s *ChangeSecretCandidateService) CreateInTx(ctx context.Context, tx *gorm.DB,
	in CandidateInput) (*model.ChangeSecretCandidate, error) {

	cand := &model.ChangeSecretCandidate{
		AssetID:           in.AssetID,
		AccountID:         in.AccountID,
		AccountUsername:   in.AccountUsername,
		PlanID:            in.PlanID,
		BatchID:           in.BatchID,
		CredentialID:      in.CredentialID,
		CredentialName:    in.CredentialName,
		TargetVersionID:   in.TargetVersionID,
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
	if err := tx.Create(cand).Error; err != nil {
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
	// 候選自帶憑證與目標版本＝那組秘密的落點已經先建好了（整批同一組的具名共用憑證）：
	// 此時要做的是把掛載改綁過去並設就位版本，而不是在原憑證上再開一版——
	// 後者會把同一組密文複製到多筆專用憑證，共用關係在憑證庫上就看不見了
	if cand.CredentialID != 0 && cand.TargetVersionID != 0 {
		return s.promoteToCredential(ctx, cand)
	}
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

// promoteToCredential 把掛載改綁到候選所帶的憑證並設就位版本（同一交易內刪候選）。
//
// **改綁與就位必須同交易**：掛載的就位版本一定要屬於它引用的憑證，兩步分開做
// 會在中間留下一個「指向別筆憑證的版本」的窗口，而取密會照著它去解一組不屬於
// 這台的秘密。舊憑證若因此成為零掛載的專用憑證，同交易回收。
func (s *ChangeSecretCandidateService) promoteToCredential(ctx context.Context,
	cand *model.ChangeSecretCandidate) error {

	userID, operator := model.UserFromContext(ctx)
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, cand.AssetID); err != nil {
			return err
		}
		account, err := resolveAssetAccount(tx, cand.AssetID, cand.AccountID)
		if err != nil {
			return err
		}
		// 釘住帳號名：執行期間改名即代表這一列已是另一個系統身分，不得把新秘密算到它頭上
		if account == nil || account.Username != cand.AccountUsername {
			return ErrAssetAccountNotFound
		}
		// 舊憑證與目標憑證一併依識別升冪取鎖：改綁同時動兩列，兩條方向相反的
		// 改綁若各按自己的順序取，會各持對方要的那一列
		// （rebindBindingToCredential 稍後重取的舊憑證列鎖已在此持有）
		locked, err := lockCredentialRowsOrdered(tx, account.CredentialID, cand.CredentialID)
		if err != nil {
			return err
		}
		target := locked[cand.CredentialID]
		if err := assertNoActiveRotation(target); err != nil {
			return err
		}
		if account.CredentialID == target.ID {
			if err := setBindingEffectiveVersion(tx, account, cand.TargetVersionID); err != nil {
				return err
			}
		} else if err := rebindBindingToCredential(tx, account, target, cand); err != nil {
			return err
		}
		if err := writeCredentialAudit(s.auditTx, tx, credentialAudit{
			CredentialID: target.ID,
			Operation:    credentialOpRebind,
			Scope:        target.Scope,
			Fields:       []string{"credential_id", "effective_version_id"},
			AssetID:      account.AssetID,
			AccountID:    account.ID,
		}, userID, operator); err != nil {
			return err
		}
		return tx.Delete(&model.ChangeSecretCandidate{}, cand.ID).Error
	})
}

// rebindBindingToCredential 把掛載自舊憑證改綁到目標憑證並設就位版本。
func rebindBindingToCredential(tx *gorm.DB, account *model.AssetAccount,
	target *model.Credential, cand *model.ChangeSecretCandidate) error {

	oldCred, err := lockCredentialRow(tx, account.CredentialID)
	if err != nil {
		return err
	}
	if err := assertNoActiveRotation(oldCred); err != nil {
		return err
	}
	res := tx.Model(&model.AssetAccount{}).
		Where("id = ? AND credential_id = ? AND username = ?",
			account.ID, oldCred.ID, cand.AccountUsername).
		Updates(map[string]any{
			"credential_id":        target.ID,
			"username":             target.Username,
			"auth_method":          target.AuthMethod,
			"effective_version_id": cand.TargetVersionID,
		})
	if res.Error != nil {
		return accountUniqueViolation(res.Error, "改綁掛載憑證失敗")
	}
	// 零列＝掛載於本交易可見範圍內被移除、改名或已被改綁；絕不記成功
	if res.RowsAffected == 0 {
		return ErrAssetAccountNotFound
	}
	versionID := cand.TargetVersionID
	account.CredentialID = target.ID
	account.Username = target.Username
	account.AuthMethod = target.AuthMethod
	account.EffectiveVersionID = &versionID
	if account.IsDefault {
		if err := mirrorDefaultAccountToAsset(tx, account); err != nil {
			return err
		}
	}
	return deleteDedicatedIfOrphaned(tx, oldCred)
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

// DiscardByAdmin admin 顯式清除候選（逃生口）。
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
		credID, credScope := credentialAuditRef(tx, cand.CredentialID)
		return writeAssetAccountAudit(s.auditTx, tx, model.AssetAccountAudit{
			AssetID:         cand.AssetID,
			AccountID:       cand.AccountID,
			Username:        cand.AccountUsername,
			Operation:       model.AccountOpDiscardCandidate,
			Fields:          []string{"change_secret_candidate"},
			CredentialID:    credID,
			CredentialScope: credScope,
		}, userID, operator)
	})
}
