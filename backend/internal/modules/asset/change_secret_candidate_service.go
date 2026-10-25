package asset

import (
	"context"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/material"
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
	bytesCrypto  material.BytesColumnCodec
	assetService *AssetService
	auditTx      port.TxSink
	// confirmedCommitHook 測試掛點：承接路徑的提交交易在消耗承接紀錄之後、提交之前呼叫，回錯誤即回滾整筆
	confirmedCommitHook func(tx *gorm.DB) error
	// scope 讀取投影與重試的範圍判定；未注入＝不限範圍（見 change_secret_candidate_view.go）
	scope ChangeSecretScopePort
}

// NewChangeSecretCandidateService 建立服務
func NewChangeSecretCandidateService(db *gorm.DB, codec crypto.ColumnCodec,
	assetService *AssetService, auditTx port.TxSink) (*ChangeSecretCandidateService, error) {
	if codec == nil {
		return nil, fmt.Errorf("初始化候選憑證服務失敗: codec 為必要參數")
	}
	bytesCodec, ok := codec.(material.BytesColumnCodec)
	if !ok {
		return nil, fmt.Errorf("candidate service requires bytes column codec")
	}
	return &ChangeSecretCandidateService{db: db, crypto: codec, bytesCrypto: bytesCodec, assetService: assetService, auditTx: auditTx}, nil
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
	// AuthorizationID 產生本候選的工作授權脈絡（0＝無）
	AuthorizationID uint
	// CredentialName 憑證名稱快照（同 record 的理由：憑證可能改名或被回收）
	CredentialName  string
	TargetVersionID uint
}

// CandidateSecret 解密後的候選秘密（僅 runner 與重試排程使用，不出服務層邊界）
type CandidateSecret struct {
	Password   *material.Secret
	PrivateKey *material.Secret
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

	password, key := material.Adopt([]byte(in.Password)), material.Adopt([]byte(in.PrivateKey))
	defer password.Destroy()
	defer key.Destroy()
	return s.createOwnedInTx(ctx, tx, in, password, key)
}

func (s *ChangeSecretCandidateService) createOwnedInTx(ctx context.Context, tx *gorm.DB,
	in CandidateInput, password, key *material.Secret) (*model.ChangeSecretCandidate, error) {

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
		// 新版建立：尚未完成任何金鑰交換，與升級前的 legacy 可區分
		HostKeyBinding: model.HostKeyBindingPending,
	}
	if in.AuthorizationID != 0 {
		authID := in.AuthorizationID
		cand.AuthorizationID = &authID
	}
	// 目標指紋取建立當下的事實；算不出來就留空（之後的失權有限驗證因無從證實目標而不放行）
	if fp, err := loadTargetFingerprint(tx, in.AccountID); err == nil {
		cand.TargetFingerprint = fp
	}
	if !password.IsEmpty() {
		enc, err := material.Use(password, func(raw []byte) (string, error) {
			return s.bytesCrypto.EncryptBytesFor(ctx, keyvault.RefChangeSecretCandidatePassword, raw)
		})
		if err != nil {
			return nil, fmt.Errorf("加密候選密碼失敗: %w", err)
		}
		cand.PasswordEnc = enc
	}
	if !key.IsEmpty() {
		enc, err := material.Use(key, func(raw []byte) (string, error) {
			return s.bytesCrypto.EncryptBytesFor(ctx, keyvault.RefChangeSecretCandidatePrivateKey, raw)
		})
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

// PinTargetFingerprint 把候選的目標指紋固定為當下的事實（舊候選經具權者明示確認後使用）。
// 只在指紋仍為空時寫入，不覆蓋建立當下留下的指紋。
func (s *ChangeSecretCandidateService) PinTargetFingerprint(id, accountID uint) error {
	fp, err := loadTargetFingerprint(s.db, accountID)
	if err != nil {
		return err
	}
	return s.db.Model(&model.ChangeSecretCandidate{}).
		Where("id = ? AND target_fingerprint = ''", id).
		Update("target_fingerprint", fp).Error
}

// Secret 解密候選秘密。回傳值 SHALL NOT 進入任何 API 回應、日誌或審計欄位
func (s *ChangeSecretCandidateService) Secret(ctx context.Context, cand *model.ChangeSecretCandidate) (CandidateSecret, error) {
	var out CandidateSecret
	if cand.PasswordEnc != "" {
		pw, err := s.bytesCrypto.DecryptBytesFor(ctx, keyvault.RefChangeSecretCandidatePassword, cand.PasswordEnc)
		if err != nil {
			out.Destroy()
			return CandidateSecret{}, fmt.Errorf("解密候選密碼失敗: %w", err)
		}
		out.Password = pw
	}
	if cand.PrivateKeyEnc != "" {
		key, err := s.bytesCrypto.DecryptBytesFor(ctx, keyvault.RefChangeSecretCandidatePrivateKey, cand.PrivateKeyEnc)
		if err != nil {
			out.Destroy()
			return CandidateSecret{}, fmt.Errorf("解密候選私鑰失敗: %w", err)
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
	return s.promote(ctx, cand, nil)
}

// PromoteConfirmed 人工承接驗證成功後的提交：主機身分以承接紀錄為預期，
// 並在同一提交交易內以條件式更新消耗該紀錄（outcome=verified）；受影響列數不為 1 即整筆回滾。
func (s *ChangeSecretCandidateService) PromoteConfirmed(ctx context.Context, cand *model.ChangeSecretCandidate,
	confirm *model.CredentialHostIdentityConfirmation) error {

	if confirm == nil {
		return ErrHostIdentityConfirmInvalid
	}
	return s.promote(ctx, cand, confirm)
}

// promote 提交的共同實作；confirm 非 nil 即承接路徑。
func (s *ChangeSecretCandidateService) promote(ctx context.Context, cand *model.ChangeSecretCandidate,
	confirm *model.CredentialHostIdentityConfirmation) error {

	// 候選自帶憑證與目標版本＝那組秘密的落點已經先建好了（整批同一組的具名共用憑證）：
	// 此時要做的是把掛載改綁過去並設就位版本，而不是在原憑證上再開一版——
	// 後者會把同一組密文複製到多筆專用憑證，共用關係在憑證庫上就看不見了
	if cand.CredentialID != 0 && cand.TargetVersionID != 0 {
		return s.promoteToCredential(ctx, cand, confirm)
	}
	secret, err := s.Secret(ctx, cand)
	if err != nil {
		return err
	}
	defer secret.Destroy()
	switch cand.SecretType {
	case model.ChangeSecretTypeSSHKey:
		if secret.PrivateKey.IsEmpty() {
			return fmt.Errorf("候選私鑰為空")
		}
	default:
		if secret.Password.IsEmpty() {
			return fmt.Errorf("候選密碼為空")
		}
	}
	// 目的欄位加密在開交易之前做完：加密可能查資料金鑰表、呼叫外部保管處解封，
	// 不得發生在持有資產列鎖與主機金鑰鎖的交易內（比照拆分路徑）
	var encrypted string
	switch cand.SecretType {
	case model.ChangeSecretTypeSSHKey:
		encrypted, err = s.assetService.encryptOwnedPrivateKey(secret.PrivateKey)
	default:
		encrypted, err = s.assetService.encryptOwnedPassword(secret.Password)
	}
	if err != nil {
		return err
	}
	// 主機身分比對、版本新增、就位、鏡像、審計與刪候選同一交易：比對通過到寫入之間，
	// 主機身分不可能再被換掉而仍提交
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, cand.AssetID); err != nil {
			return err
		}
		if err := assertCandidateHostIdentityConfirmedTx(tx, cand.ID, confirm); err != nil {
			return err
		}
		switch cand.SecretType {
		case model.ChangeSecretTypeSSHKey:
			err = s.assetService.updateOwnedPrivateKeyTx(tx, cand.AssetID, cand.AccountID, cand.AccountUsername, encrypted)
		default:
			err = s.assetService.updateOwnedPasswordTx(tx, cand.AssetID, cand.AccountID, cand.AccountUsername, encrypted)
		}
		if err != nil {
			return err
		}
		if err := deleteCandidateInTx(tx, cand.ID); err != nil {
			return err
		}
		return s.consumeConfirmationInTx(tx, confirm)
	})
}

// deleteCandidateInTx 在提交交易內消耗候選列，並以受影響列數確認它仍在：
// 重讀通過之後、刪除之前若被並行清除，影響 0 列，整筆交易必須回滾（版本、就位、鏡像、審計一併撤銷），
// 不能在候選已不存在的情況下仍把轉正提交下去。
func deleteCandidateInTx(tx *gorm.DB, candidateID uint) error {
	res := tx.Delete(&model.ChangeSecretCandidate{}, candidateID)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrCandidateNotFound
	}
	return nil
}

// assertCandidateHostIdentityTx 提交前在交易內重讀候選列，以它當下的主機身分綁定快照做 (c) 比對。
// 候選列在綁定之後才有快照，呼叫端手上的物件可能是綁定前建立的複本，故一律以交易內重讀為準；
// 呼叫端須已取得資產帳號集鎖，且在取任何憑證列之前呼叫。列不存在回 ErrCandidateNotFound。
func assertCandidateHostIdentityTx(tx *gorm.DB, candidateID uint) error {
	var row model.ChangeSecretCandidate
	if err := tx.Where("id = ?", candidateID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrCandidateNotFound
		}
		return fmt.Errorf("%w: %v", ErrHostKeyCheckFailed, err)
	}
	return assertHostIdentityUnchangedTx(tx, hostIdentityJobOfCandidate(&row), nil)
}

// promoteToCredential 把掛載改綁到候選所帶的憑證並設就位版本（同一交易內刪候選）。
//
// **改綁與就位必須同交易**：掛載的就位版本一定要屬於它引用的憑證，兩步分開做
// 會在中間留下一個「指向別筆憑證的版本」的窗口，而取密會照著它去解一組不屬於
// 這台的秘密。舊憑證若因此成為零掛載的專用憑證，同交易回收。
func (s *ChangeSecretCandidateService) promoteToCredential(ctx context.Context,
	cand *model.ChangeSecretCandidate, confirm *model.CredentialHostIdentityConfirmation) error {

	userID, operator := model.UserFromContext(ctx)
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockAssetForAccountMutation(tx, cand.AssetID); err != nil {
			return err
		}
		// 主機身分比對在資產列鎖之後、任何憑證列之前
		if err := assertCandidateHostIdentityConfirmedTx(tx, cand.ID, confirm); err != nil {
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
		if err := deleteCandidateInTx(tx, cand.ID); err != nil {
			return err
		}
		return s.consumeConfirmationInTx(tx, confirm)
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

// Defer 只把候選的下次嘗試時刻挪到 until：次數、原因碼與逾期放棄一律不動。
//
// 給「到期了但這一輪不該由候選排程處理」的候選用——不挪走，它每一輪都會被撈到，
// 並依到期先後佔掉單輪批次的位置。
func (s *ChangeSecretCandidateService) Defer(id uint, until time.Time) error {
	return s.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", id).
		Update("next_attempt_at", until).Error
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
	_, err := s.discard(id, userID, operator, nil)
	return err
}

// discard 刪除候選並留痕（同一交易），回傳被清除候選所屬的資產。guard 非 nil 時是交易的第一個動作
// （範圍判定：先取拓撲鎖再判定），候選在其後以交易內視圖讀出。
func (s *ChangeSecretCandidateService) discard(id, userID uint, operator string,
	guard func(tx *gorm.DB) error) (uint, error) {

	var assetID uint
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if guard != nil {
			if err := guard(tx); err != nil {
				return err
			}
		}
		var cand model.ChangeSecretCandidate
		if err := tx.First(&cand, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrCandidateNotFound
			}
			return err
		}
		res := tx.Delete(&model.ChangeSecretCandidate{}, id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrCandidateNotFound
		}
		assetID = cand.AssetID
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
	return assetID, err
}

func (s *CandidateSecret) Destroy() {
	if s != nil {
		s.Password.Destroy()
		s.PrivateKey.Destroy()
	}
}
