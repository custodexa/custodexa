package asset

import (
	"errors"
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 重試路徑（排程與手動共用）的主機身分守衛：候選已送出的秘密會在重試的 Verify 再送一次認證，
// 撥號前先查庫、撥號只認工作列綁定的金鑰。守衛獨立於授權重驗的結果：授權正常、失權後的有限驗證、
// 失權後重新取得能力都走同一道。

// retryIdentityGuard 以候選列建立立即驗證守衛（重讀候選列取當下快照；截止時間為建立時間加 24 小時）。
func (r *ChangeSecretRetryRunner) retryIdentityGuard(cand *model.ChangeSecretCandidate,
	initiatorID uint, initiatorName string) *immediateVerifyGuard {

	dc := HostKeyDialContext{
		AssetID: cand.AssetID, Path: HostKeyPathCredentialChange,
		UserID: initiatorID, Username: initiatorName, AccountID: cand.AccountID,
		ConnectionRef: fmt.Sprintf("change_secret_candidate:%d", cand.ID),
	}
	return &immediateVerifyGuard{
		db: r.db, sink: r.auditTx, notify: ChangeSecretStopNotifier(r.notifier), dc: dc,
		pinnedFn: r.hostKeys.CallbackForPinned,
		load: func() (hostIdentityStopInput, error) {
			var c model.ChangeSecretCandidate
			if err := r.db.First(&c, cand.ID).Error; err != nil {
				return hostIdentityStopInput{}, err
			}
			deadline := c.CreatedAt.Add(candidateRetryDeadline)
			return hostIdentityStopInput{
				Job: hostIdentityJobOfCandidate(&c), CandidateID: c.ID, PlanID: c.PlanID, BatchID: c.BatchID,
				AccountID: c.AccountID, CredentialID: c.CredentialID,
				InitiatorID: initiatorID, InitiatorName: initiatorName, Deadline: &deadline,
				CandidateApplied: c.Applied,
			}, nil
		},
	}
}

// retryHostKeyCallback 重試 Verify 的撥號回呼。已綁定或升級前的候選走撥號前查庫與預期身分回呼。
// 握手前中斷、尚未綁定的候選（pending）從未送出過秘密，這次重試就是首次派送：與首次派送同一規則，
// 在送出任何認證之前用綁定回呼把當下的主機身分綁到候選列（WinRM 通道則在撥號前寫入自始為 WinRM 的綁定）。
func (r *ChangeSecretRetryRunner) retryHostKeyCallback(guard *immediateVerifyGuard,
	asset *model.Asset) (ssh.HostKeyCallback, error) {

	in, err := guard.load()
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// 候選列在這次重試的讀取與撥號之間已不在（另一條路徑先轉正，或管理員清除）：不是身分問題
		return nil, ErrCandidateNotFound
	}
	if err == nil && in.Job.Binding == model.HostKeyBindingPending {
		target := HostKeyBindTarget{CandidateID: in.CandidateID}
		if rotationTransportOf(asset) == model.HostKeyTransportWinRM {
			if berr := r.hostKeys.BindWinRM(target); berr != nil {
				return nil, fmt.Errorf("%w: %v", ErrHostKeyCheckFailed, berr)
			}
			return nil, nil
		}
		cb, _ := r.hostKeys.CallbackForBinding(guard.dc, target)
		return guard.countPasses(cb), nil
	}
	return guard.prepare(asset)
}

// recordRecoveryIdentityStop 失權後的有限驗證在判定時被主機身分擋下：沒有撥號，補寫停止審計，回傳唯讀檢視。
func (r *ChangeSecretRetryRunner) recordRecoveryIdentityStop(cand *model.ChangeSecretCandidate) *HostIdentityView {
	asset, err := r.assets.GetByID(cand.AssetID)
	if err != nil {
		log.Printf("[ChangeSecretRetry] 身分停止審計讀取資產失敗 id=%d: %v", cand.ID, err)
		return nil
	}
	var initiatorID uint
	var initiatorName string
	if auth, aerr := loadJobAuthorization(r.db, cand.AuthorizationID); aerr == nil {
		initiatorID, initiatorName = auth.ActorID, auth.ActorName
	}
	guard := r.retryIdentityGuard(cand, initiatorID, initiatorName)
	in, err := guard.load()
	if err != nil {
		log.Printf("[ChangeSecretRetry] 身分停止審計讀取候選失敗 id=%d: %v", cand.ID, err)
		return nil
	}
	detail := hostIdentityVerdict(r.db, in.Job, asset)
	if detail == "" {
		return nil
	}
	_ = guard.stopPrecheck(detail)
	guard.recordStop(asset)
	return guard.lastView()
}

// retryVerifyFailureReason 重試驗證失敗的原因碼：綁定寫入或查庫失敗（握手前即中止）用主機金鑰檢查失敗碼，
// 其餘沿用驗證失敗分流。
func retryVerifyFailureReason(err error) string {
	if errors.Is(err, ErrHostKeyCheckFailed) && !errors.Is(err, ErrHostIdentityChanged) {
		return model.ChangeSecretReasonHostKeyCheckFailed
	}
	return verifyFailureReason(err, model.ChangeSecretReasonRetryLoginFailed)
}
