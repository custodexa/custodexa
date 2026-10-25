package asset

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 人工承接的單次邏輯驗證與紀錄消耗（一般候選）。
//
// 驗證在交易外：以承接紀錄為預期身分，只 Verify，不下達、不刪舊鑰、不還原、不產生秘密。
// 成功後的本地提交與紀錄消耗在同一交易（條件式更新，受影響列數不為 1 即整筆回滾）；
// 失敗路徑的結果在提交交易回滾之後另寫，且不動候選列（原期限、退避、原因碼都不重設）。

// 承接紀錄的結果值（outcome 欄）。
const (
	takeoverOutcomeVerified     = "verified"
	takeoverOutcomeVerifyFailed = "verify_failed"
	takeoverOutcomeMoved        = "identity_moved"
	takeoverOutcomeCommitFailed = "commit_failed"
)

var (
	// ErrHostIdentityVerifyFailed 承接後的單次驗證沒有通過（候選保留，可再次確認）。
	ErrHostIdentityVerifyFailed = errors.New("主機身分承接後的驗證未通過")
	// ErrConfirmationNotConsumable 承接紀錄不存在、已被消耗或不屬於這個工作：提交必須回滾。
	ErrConfirmationNotConsumable = errors.New("承接紀錄無法消耗")
)

// WithCandidateRunner 注入一般候選的驗證與轉正執行器；缺席時候選的確認停在建立紀錄（回未完成）。
func (s *HostIdentityTakeoverService) WithCandidateRunner(r *ChangeSecretRetryRunner) *HostIdentityTakeoverService {
	s.candidateRunner = r
	return s
}

// confirmedExpected 承接紀錄所確認的身分，作為提交前比對的預期。
func confirmedExpected(rec *model.CredentialHostIdentityConfirmation) *hostIdentityExpected {
	return &hostIdentityExpected{RecordID: rec.ConfirmedRecordID, Generation: rec.ConfirmedGeneration,
		Pin: HostKeyPin{Algorithm: rec.ConfirmedAlgorithm, Fingerprint: rec.ConfirmedFingerprint}}
}

// assertCandidateHostIdentityConfirmedTx 提交前同交易重讀候選列並比對主機身分。
// confirm 為 nil 時以候選列自身快照為預期；非 nil 時以承接紀錄為預期（候選列的原快照不覆寫）。
func assertCandidateHostIdentityConfirmedTx(tx *gorm.DB, candidateID uint,
	confirm *model.CredentialHostIdentityConfirmation) error {

	if confirm == nil {
		return assertCandidateHostIdentityTx(tx, candidateID)
	}
	var row model.ChangeSecretCandidate
	if err := tx.Where("id = ?", candidateID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrCandidateNotFound
		}
		return fmt.Errorf("%w: %v", ErrHostKeyCheckFailed, err)
	}
	if err := confirmedTargetHoldsTx(tx, row.AccountID, row.TargetFingerprint, confirm); err != nil {
		return err
	}
	job := hostIdentityJobOfCandidate(&row)
	job.Transport = confirm.ConfirmedTransport
	return assertHostIdentityUnchangedTx(tx, job, confirmedExpected(confirm))
}

// loadConfirmedTargetBinding 讀當下的掛載；列已不存在＝目標已改變，其他讀取失敗＝無法判定（fail closed）。
func loadConfirmedTargetBinding(db *gorm.DB, accountID uint) (*model.AssetAccount, error) {
	var binding model.AssetAccount
	if err := db.Where("id = ?", accountID).First(&binding).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrHostIdentityConfirmTargetChanged
		}
		return nil, fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	return &binding, nil
}

// confirmedDialTargetHolds 撥號前以「實際要撥號的」資產快照與當下掛載重算目標指紋，必須等於工作建立時記下的。
// 檢查與撥號共用同一份資產快照，兩者之間沒有第二次讀取；傳輸與身分由 confirmedIdentityHolds 在同一份快照上核對。
// 不符回 ErrHostIdentityConfirmTargetChanged（工作列的指紋不改寫）。
func confirmedDialTargetHolds(db *gorm.DB, dial *model.Asset, accountID uint, stored string) error {
	binding, err := loadConfirmedTargetBinding(db, accountID)
	if err != nil {
		return err
	}
	if stored == "" || targetFingerprintOf(dial, binding) != stored {
		return ErrHostIdentityConfirmTargetChanged
	}
	return nil
}

// confirmedTargetHoldsTx 承接的本地提交交易內（呼叫端已持資產列鎖）再核一次：當下目標指紋仍等於工作原值、
// 資產當下的傳輸仍是確認的傳輸（SSH 與 WinRM 兩個方向都核）。目標不符回 ErrHostIdentityConfirmTargetChanged，
// 傳輸不符回 ErrHostIdentityChanged，讀取失敗為無法判定。
func confirmedTargetHoldsTx(tx *gorm.DB, accountID uint, stored string,
	confirm *model.CredentialHostIdentityConfirmation) error {

	binding, err := loadConfirmedTargetBinding(tx, accountID)
	if err != nil {
		return err
	}
	var asset model.Asset
	if err := tx.Where("id = ?", binding.AssetID).First(&asset).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrHostIdentityConfirmTargetChanged
		}
		return fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	if stored == "" || targetFingerprintOf(&asset, binding) != stored {
		return ErrHostIdentityConfirmTargetChanged
	}
	if rotationTransportOf(&asset) != confirm.ConfirmedTransport {
		return ErrHostIdentityChanged
	}
	return nil
}

// targetChangedConfirmation 承接紀錄建立之後才發現目標已改變：消耗紀錄並回目標變更（不是身分異動）。
// 撥號前發現記 verify_failed（沒有送出任何認證、沒有就位）；驗證之後、提交時發現記 commit_failed（不就位）。
func targetChangedConfirmation(db *gorm.DB, rec *model.CredentialHostIdentityConfirmation, outcome string) error {
	return failConfirmationOn(db, rec, outcome, ErrHostIdentityConfirmTargetChanged)
}

// consumeConfirmationInTx 提交交易內的條件式消耗：confirm 為 nil（一般路徑）不做事。
// 受影響列數不為 1 回 ErrConfirmationNotConsumable，呼叫端交易整筆回滾。
func (s *ChangeSecretCandidateService) consumeConfirmationInTx(tx *gorm.DB,
	confirm *model.CredentialHostIdentityConfirmation) error {

	if confirm == nil {
		return nil
	}
	if err := consumeConfirmation(tx, confirm, takeoverOutcomeVerified); err != nil {
		return err
	}
	if s.confirmedCommitHook != nil {
		return s.confirmedCommitHook(tx)
	}
	return nil
}

// consumeConfirmation 以條件式更新把未消耗的紀錄寫為已消耗；列數不為 1 即失敗。
func consumeConfirmation(db *gorm.DB, rec *model.CredentialHostIdentityConfirmation, outcome string) error {
	res := db.Model(&model.CredentialHostIdentityConfirmation{}).
		Where("id = ? AND kind = ? AND job_id = ? AND revision = ? AND consumed_at IS NULL AND outcome = ''",
			rec.ID, rec.Kind, rec.JobID, rec.Revision).
		Updates(map[string]any{"consumed_at": time.Now(), "outcome": outcome})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return ErrConfirmationNotConsumable
	}
	return nil
}

// runCandidate 一般候選的承接後半段：單次驗證、本地提交與消耗。回 nil 即已轉正。
func (s *HostIdentityTakeoverService) runCandidate(ctx context.Context,
	rec *model.CredentialHostIdentityConfirmation) error {

	return s.candidateRunner.verifyConfirmedCandidate(ctx, rec)
}

// failConfirmation 在提交交易回滾之後另寫失敗結果；寫不進去只記日誌（紀錄仍未消耗，啟動收束會處理）。
func (r *ChangeSecretRetryRunner) failConfirmation(rec *model.CredentialHostIdentityConfirmation, outcome string, cause error) error {
	return failConfirmationOn(r.db, rec, outcome, cause)
}

func failConfirmationOn(db *gorm.DB, rec *model.CredentialHostIdentityConfirmation, outcome string, cause error) error {
	if err := consumeConfirmation(db, rec, outcome); err != nil {
		log.Printf("[HostIdentityTakeover] 寫入承接結果失敗 confirmation=%d outcome=%s: %v", rec.ID, outcome, err)
	}
	return cause
}

// confirmedIdentityHolds 驗證前（交易外）核對資產當下身分仍等於承接紀錄確認的身分。
func confirmedIdentityHolds(db *gorm.DB, asset *model.Asset, rec *model.CredentialHostIdentityConfirmation) error {
	if rec.ConfirmedTransport == model.HostKeyTransportWinRM {
		if rotationTransportOf(asset) != model.HostKeyTransportWinRM {
			return ErrHostIdentityChanged
		}
		return nil
	}
	if rotationTransportOf(asset) != model.HostKeyTransportSSH {
		return ErrHostIdentityChanged
	}
	var own model.AssetHostKey
	if err := db.Where("asset_id = ?", asset.ID).First(&own).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrHostIdentityChanged
		}
		return fmt.Errorf("%w: %v", ErrHostKeyCheckFailed, err)
	}
	if own.ResetPending || own.ID != rec.ConfirmedRecordID || own.TrustGeneration != rec.ConfirmedGeneration ||
		own.Fingerprint != rec.ConfirmedFingerprint || own.Algorithm != rec.ConfirmedAlgorithm {
		return ErrHostIdentityChanged
	}
	return nil
}

// verifyConfirmedCandidate 承接紀錄已建立之後：以紀錄為預期身分做一次邏輯驗證，成功才提交並消耗。
func (r *ChangeSecretRetryRunner) verifyConfirmedCandidate(ctx context.Context,
	rec *model.CredentialHostIdentityConfirmation) error {

	moved := func() error { return r.failConfirmation(rec, takeoverOutcomeMoved, takeoverConflict("")) }
	verifyFailed := func(cause error) error {
		return r.failConfirmation(rec, takeoverOutcomeVerifyFailed, fmt.Errorf("%w: %v", ErrHostIdentityVerifyFailed, cause))
	}

	var cand model.ChangeSecretCandidate
	if err := r.db.Where("id = ?", rec.JobID).First(&cand).Error; err != nil {
		return verifyFailed(ErrCandidateNotFound)
	}
	asset, err := r.assets.GetByID(cand.AssetID)
	if err != nil {
		return verifyFailed(err)
	}
	// 交易外的前置核對（以下撥號只用這一份資產快照）：入口判定之後目標被改（位址、通道、掛載），
	// 或確認到執行之間記錄已變，撥號前就停（不送出任何認證）
	if err := confirmedDialTargetHolds(r.db, asset, cand.AccountID, cand.TargetFingerprint); err != nil {
		if errors.Is(err, ErrHostIdentityConfirmTargetChanged) {
			return targetChangedConfirmation(r.db, rec, takeoverOutcomeVerifyFailed)
		}
		return r.failConfirmation(rec, takeoverOutcomeVerifyFailed, err)
	}
	if err := confirmedIdentityHolds(r.db, asset, rec); err != nil {
		if errors.Is(err, ErrHostIdentityChanged) {
			return moved()
		}
		return verifyFailed(err)
	}
	secret, err := r.candidates.Secret(ctx, &cand)
	if err != nil {
		return verifyFailed(err)
	}
	defer secret.Destroy()

	channel := asset.EffectiveRotationChannel()
	guard := &immediateVerifyGuard{db: r.db, pinnedFn: r.hostKeys.CallbackForPinned,
		dc: HostKeyDialContext{AssetID: cand.AssetID, Path: HostKeyPathCredentialChange,
			UserID: rec.ConfirmedBy, Username: rec.ConfirmedByName, AccountID: cand.AccountID,
			ConnectionRef: fmt.Sprintf("change_secret_candidate:%d", cand.ID)}}
	rt := rotationTarget{asset: asset, channel: channel, username: cand.AccountUsername,
		secretType: cand.SecretType, addr: rotationAddr(asset, channel)}
	if rec.ConfirmedTransport == model.HostKeyTransportSSH {
		rt.hostKeyCB = guard.countPasses(guard.svcPinned(HostKeyPin{
			Algorithm: rec.ConfirmedAlgorithm, Fingerprint: rec.ConfirmedFingerprint}))
	}
	newSecret := secret.Password
	if cand.SecretType == model.ChangeSecretTypeSSHKey {
		newSecret = secret.PrivateKey
	}
	if err := withProtocolSecret(newSecret, func(next []byte) error { return r.executors(channel).Verify(ctx, rt, next) }); err != nil {
		if errors.Is(err, ErrHostIdentityChanged) {
			return moved()
		}
		return verifyFailed(err)
	}
	secret.Destroy()
	if r.crashAfterVerify != nil {
		if err := r.crashAfterVerify(); err != nil {
			return err
		}
	}

	if err := r.candidates.PromoteConfirmed(ctx, &cand, rec); err != nil {
		switch {
		case errors.Is(err, ErrHostIdentityConfirmTargetChanged):
			// 驗證過的是原目標，提交時目標已改：不把它記成新目標的就位憑證
			return targetChangedConfirmation(r.db, rec, takeoverOutcomeCommitFailed)
		case errors.Is(err, ErrHostIdentityChanged):
			return moved()
		default:
			return r.failConfirmation(rec, takeoverOutcomeCommitFailed, fmt.Errorf("承接後本地提交失敗: %w", err))
		}
	}
	if cand.CredentialID != 0 && cand.TargetVersionID != 0 {
		settleBatchSharedCredential(r.db, cand.CredentialID)
	}
	r.recordPromotion(&cand, false)
	return nil
}
