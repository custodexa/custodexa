package asset

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 輪替成員的人工承接：未逾期、已下達未驗證（changed_unverified）的成員。
//
// 驗證在交易外，以承接紀錄為預期身分，只 Verify，不下達、不刪舊鑰、不產生秘密；
// 目標秘密的來源與一般補跑相同（整組取目標版本、拆分取該掛載自己的候選）。
// 成功後的就位提交與紀錄消耗在同一交易；失敗路徑不動成員列（原期限、退避、原因碼都不變），
// 結果在提交交易回滾之後另寫。承接路徑只記 outcome，不寫停止審計。

// WithMemberRunner 注入成員的驗證與就位執行器；缺席時成員的確認停在建立紀錄（回未完成）。
func (s *HostIdentityTakeoverService) WithMemberRunner(r *CredentialRotationService) *HostIdentityTakeoverService {
	s.memberRunner = r
	return s
}

// failConfirmation 在提交交易回滾之後另寫失敗結果；寫不進去只記日誌（紀錄仍未消耗，留給啟動收束）。
func (s *CredentialRotationService) failConfirmation(rec *model.CredentialHostIdentityConfirmation,
	outcome string, cause error) error {

	return failConfirmationOn(s.db, rec, outcome, cause)
}

// assertMemberHostIdentityTx 提交前同交易比對成員的主機身分：confirm 為 nil 以成員列自身快照為預期，
// 非 nil 時以承接紀錄為預期（成員列的原快照不覆寫），並先核對當下目標指紋仍等於成員列記下的、
// 資產當下的傳輸仍是確認的傳輸（兩個方向）。m 是交易內重讀的成員列。
func assertMemberHostIdentityTx(tx *gorm.DB, m *model.CredentialRotationMember, groupCandidate bool,
	confirm *model.CredentialHostIdentityConfirmation) error {

	job := hostIdentityJobOfMember(m, groupCandidate)
	if confirm == nil {
		return assertHostIdentityUnchangedTx(tx, job, nil)
	}
	if err := confirmedTargetHoldsTx(tx, m.AccountID, m.TargetFingerprint, confirm); err != nil {
		return err
	}
	job.Transport = confirm.ConfirmedTransport
	return assertHostIdentityUnchangedTx(tx, job, confirmedExpected(confirm))
}

// consumeConfirmationHooked 提交交易內的條件式消耗：confirm 為 nil（一般路徑）不做事；
// 受影響列數不為 1 回 ErrConfirmationNotConsumable，呼叫端交易整筆回滾。hook 為測試掛點。
func consumeConfirmationHooked(tx *gorm.DB, confirm *model.CredentialHostIdentityConfirmation,
	alreadyConsumed bool, hook func(tx *gorm.DB) error) error {

	if confirm == nil {
		return nil
	}
	// 逾期成員的紀錄已由就位轉移在同一交易內消耗（受影響列數同樣驗為 1），這裡只留掛點
	if !alreadyConsumed {
		if err := consumeConfirmation(tx, confirm, takeoverOutcomeVerified); err != nil {
			return err
		}
	}
	if hook != nil {
		return hook(tx)
	}
	return nil
}

// verifyConfirmedMember 承接紀錄已建立之後：以紀錄為預期身分做一次邏輯驗證，成功才就位並消耗。
// 成員不在 changed_unverified 也不是逾期終局（終局失敗、已收束）時不處理，回未完成，紀錄留給後續收束。
func (s *CredentialRotationService) verifyConfirmedMember(ctx context.Context,
	rec *model.CredentialHostIdentityConfirmation) error {

	moved := func() error { return s.failConfirmation(rec, takeoverOutcomeMoved, takeoverConflict("")) }
	verifyFailed := func(cause error) error {
		return s.failConfirmation(rec, takeoverOutcomeVerifyFailed, fmt.Errorf("%w: %v", ErrHostIdentityVerifyFailed, cause))
	}

	var member model.CredentialRotationMember
	if err := s.db.Where("id = ?", rec.JobID).First(&member).Error; err != nil {
		return verifyFailed(err)
	}
	release := lockRotationAccount(member.AccountID)
	defer release()
	// 取鎖後重讀：等鎖期間別的路徑可能已經推進過本成員
	m, err := loadRotationMember(s.db, member.RotationID, member.ID)
	if err != nil {
		return verifyFailed(err)
	}
	if m.State != model.CredentialMemberChangedUnverified && !isExpiredMemberState(m.State) {
		return ErrHostIdentityConfirmIncomplete
	}
	rot, err := loadRotation(s.db, m.RotationID)
	if err != nil {
		return verifyFailed(err)
	}
	if rot.Status == model.CredentialRotationCompleted {
		return verifyFailed(ErrCredentialRotationNotRunning)
	}
	if err := assertRotationTargetStillPending(s.db, rot); err != nil {
		return verifyFailed(err)
	}
	// targetHolds 交易外的前置核對：入口判定之後目標被改（位址、通道、掛載），或確認到執行之間記錄已變，
	// 撥號前就停（不送出任何認證）。目標與身分都在傳入的同一份資產快照上判定。
	targetHolds := func(asset *model.Asset) error {
		if err := confirmedDialTargetHolds(s.db, asset, m.AccountID, m.TargetFingerprint); err != nil {
			if errors.Is(err, ErrHostIdentityConfirmTargetChanged) {
				return targetChangedConfirmation(s.db, rec, takeoverOutcomeVerifyFailed)
			}
			return s.failConfirmation(rec, takeoverOutcomeVerifyFailed, err)
		}
		if err := confirmedIdentityHolds(s.db, asset, rec); err != nil {
			if errors.Is(err, ErrHostIdentityChanged) {
				return moved()
			}
			return verifyFailed(err)
		}
		return nil
	}
	asset, err := s.assets.GetByID(m.AssetID)
	if err != nil {
		return verifyFailed(err)
	}
	// 第一道預檢（早於取回秘密）
	if err := targetHolds(asset); err != nil {
		return err
	}
	if s.verifyPrecheckHook != nil {
		s.verifyPrecheckHook()
	}
	run := memberRun{
		credentialName: credentialNameSnapshot(s.db, m.CredentialID),
		secretType:     credentialSecretType(s.db, m.CredentialID),
	}
	mc, reason := s.prepareMember(ctx, rot, m)
	if reason != "" {
		// 準備在通道或帳號名改變時提前返回、不會走到下方的實際目標重核：先以當下資產快照判一次目標，
		// 目標確實已改變回目標變更（不送出任何認證），其餘維持一般驗證未通過
		if reason == model.ChangeSecretReasonChannelNotConfigured || reason == model.ChangeSecretReasonAccountChanged {
			fresh, gerr := s.assets.GetByID(m.AssetID)
			if gerr != nil {
				return verifyFailed(gerr)
			}
			if terr := confirmedDialTargetHolds(s.db, fresh, m.AccountID, m.TargetFingerprint); terr != nil {
				if errors.Is(terr, ErrHostIdentityConfirmTargetChanged) {
					return targetChangedConfirmation(s.db, rec, takeoverOutcomeVerifyFailed)
				}
				return s.failConfirmation(rec, takeoverOutcomeVerifyFailed, terr)
			}
		}
		return verifyFailed(errors.New(reason))
	}
	defer mc.Destroy()
	// prepareMember 重讀了資產，實際撥號的目標與執行器以它為準：對這一份快照再判一次目標、傳輸與身分，
	// 通過才掛 pinned 回呼（與一般補跑對實際目標再守衛同一作法）
	if err := targetHolds(mc.target.asset); err != nil {
		return err
	}

	guard := &immediateVerifyGuard{db: s.db, pinnedFn: s.hostKeys.CallbackForPinned,
		dc: HostKeyDialContext{AssetID: m.AssetID, Path: HostKeyPathCredentialRotation,
			UserID: rec.ConfirmedBy, Username: rec.ConfirmedByName, AccountID: m.AccountID,
			ConnectionRef: fmt.Sprintf("credential_rotation_member:%d", m.ID)}}
	if rec.ConfirmedTransport == model.HostKeyTransportSSH {
		mc.target.hostKeyCB = guard.countPasses(guard.svcPinned(HostKeyPin{
			Algorithm: rec.ConfirmedAlgorithm, Fingerprint: rec.ConfirmedFingerprint}))
	}
	newSecret := mc.newPassword
	if mc.secretType == model.ChangeSecretTypeSSHKey {
		newSecret = mc.newPrivateKey
	}
	if err := withProtocolSecret(newSecret, func(next []byte) error { return mc.exec.Verify(ctx, mc.target, next) }); err != nil {
		if errors.Is(err, ErrHostIdentityChanged) {
			return moved()
		}
		return verifyFailed(err)
	}

	if s.crashAfterVerify != nil {
		if err := s.crashAfterVerify(); err != nil {
			return err
		}
	}
	// 單次邏輯驗證回 nil 之後，才有驗證成功的結果；這是此型別在正式碼唯一的建構點
	applied := memberTransition{Verified: &verifiedConfirmation{kind: rec.Kind, jobID: rec.JobID,
		confirmationID: rec.ID, revision: rec.Revision, transport: rec.ConfirmedTransport,
		algorithm: rec.ConfirmedAlgorithm, fingerprint: rec.ConfirmedFingerprint}}
	var commitErr error
	if rot.Mode == model.CredentialRotationModeSplit {
		commitErr = s.commitSplitApplied(ctx, rot, m, mc, rec, applied)
	} else {
		commitErr = s.commitGroupApplied(ctx, rot, m, rec, applied)
	}
	if commitErr != nil {
		logMemberTransitionFailure(m, model.CredentialMemberApplied, commitErr)
		if errors.Is(commitErr, ErrHostIdentityConfirmTargetChanged) {
			// 驗證過的是原目標，提交時目標已改：不就位、不記成新目標的就位憑證
			return targetChangedConfirmation(s.db, rec, takeoverOutcomeCommitFailed)
		}
		if errors.Is(commitErr, ErrHostIdentityChanged) {
			return moved()
		}
		return s.failConfirmation(rec, takeoverOutcomeCommitFailed, fmt.Errorf("承接後本地提交失敗: %w", commitErr))
	}
	s.recordMember(m, model.ChangeSecretSuccess, "", run)
	return nil
}
