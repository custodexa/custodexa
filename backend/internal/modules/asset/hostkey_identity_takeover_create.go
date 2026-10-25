package asset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 承接紀錄的建立短交易。
//
// 取鎖序：主機金鑰信任鎖 -> 自身列 -> 工作列 -> 承接紀錄 -> 審計。沒有任何反向取鎖。
// 紀錄與審計同一交易：任一失敗整筆回滾，不留孤立紀錄，也不留沒有紀錄的審計。
// 本檔只建立紀錄；之後的單次驗證、消耗與就位轉移不在這裡。

// 承接衝突的細節（對外 detail）。
const (
	takeoverDetailDifferentKeyNotAccepted = "different_key_not_accepted"
	takeoverDetailConfirmationPending     = "confirmation_pending"
	takeoverDetailNotConfirmable          = "not_confirmable"
)

// ErrHostIdentityMoved 確認的身分與當下不同、或工作目前不可承接：對外為 409 CONFLICT_HOST_IDENTITY_MOVED。
var ErrHostIdentityMoved = errors.New("CONFLICT_HOST_IDENTITY_MOVED")

// HostIdentityConflictError 承接衝突，Detail 為對外細節（空字串＝身分已變動）。
type HostIdentityConflictError struct{ Detail string }

func (e *HostIdentityConflictError) Error() string {
	if e.Detail == "" {
		return ErrHostIdentityMoved.Error()
	}
	return ErrHostIdentityMoved.Error() + ": " + e.Detail
}

func (e *HostIdentityConflictError) Is(target error) bool { return target == ErrHostIdentityMoved }

func takeoverConflict(detail string) error { return &HostIdentityConflictError{Detail: detail} }

// SetAuditTxSink 注入承接審計的交易內落地面；缺席時所有確認 fail closed（回滾、不留紀錄）。
func (s *HostIdentityTakeoverService) SetAuditTxSink(sink port.TxSink) { s.sink = sink }

// takeoverJob 短交易內重讀的工作列事實。
type takeoverJob struct {
	job        hostIdentityJob
	candidate  *model.ChangeSecretCandidate
	member     *model.CredentialRotationMember
	rotation   *model.CredentialRotation
	authID     *uint
	deadline   time.Time
	lastError  string
	planID     uint
	batchID    uint
	credential uint
}

// lockTakeoverJob 以 FOR UPDATE（PG）重讀並鎖住工作列，回傳其守衛視圖。
func lockTakeoverJob(tx *gorm.DB, kind string, jobID uint) (*takeoverJob, error) {
	q := tx.Where("id = ?", jobID)
	if tx.Dialector.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	switch kind {
	case takeoverKindCandidate:
		var c model.ChangeSecretCandidate
		if err := q.First(&c).Error; err != nil {
			return nil, takeoverLoadError(err)
		}
		return &takeoverJob{job: hostIdentityJobOfCandidate(&c), candidate: &c, authID: c.AuthorizationID,
			deadline: c.CreatedAt.Add(candidateRetryDeadline), lastError: c.LastError,
			planID: c.PlanID, batchID: c.BatchID, credential: c.CredentialID}, nil
	case takeoverKindMember:
		var m model.CredentialRotationMember
		if err := q.First(&m).Error; err != nil {
			return nil, takeoverLoadError(err)
		}
		var rot model.CredentialRotation
		if err := tx.Where("id = ?", m.RotationID).First(&rot).Error; err != nil {
			return nil, takeoverLoadError(err)
		}
		groupCandidate := false
		if rot.Mode != model.CredentialRotationModeSplit {
			var n int64
			if err := tx.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", m.AccountID).
				Count(&n).Error; err != nil {
				return nil, fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
			}
			groupCandidate = n > 0
		}
		return &takeoverJob{job: hostIdentityJobOfMember(&m, groupCandidate), member: &m, rotation: &rot,
			authID: rot.AuthorizationID, deadline: rot.StartedAt.Add(candidateRetryDeadline), lastError: m.LastError,
			credential: m.CredentialID}, nil
	}
	return nil, fmt.Errorf("%w: 未知的工作種類", ErrHostIdentityConfirmInvalid)
}

// confirmable 工作是否仍處於可承接狀態並有派送證據；不是回 409 not_confirmable。
func (j *takeoverJob) confirmable(now time.Time) bool {
	if j.job.Binding == model.HostKeyBindingPending {
		return false
	}
	if j.member == nil {
		return true // 一般候選：列存在即有派送證據、尚未被清除
	}
	switch j.member.State {
	case model.CredentialMemberChangedUnverified:
	case model.CredentialMemberTerminalFailed, model.CredentialMemberAbandoned:
		if !now.After(j.deadline) {
			return false
		}
	default:
		return false
	}
	if j.job.Binding == model.HostKeyBindingLegacy {
		return j.job.LegacySentOrUnknown
	}
	return j.job.SecretSent
}

// createConfirmation 承接建立短交易：重讀比對、判定、寫紀錄與審計。回傳新紀錄。
func (s *HostIdentityTakeoverService) createConfirmation(ctx context.Context, kind string, jobID uint,
	req HostIdentityConfirmRequest, subject *takeoverSubject, decision CredentialManagementDecision) (*model.CredentialHostIdentityConfirmation, error) {

	userID, username := model.UserFromContext(ctx)
	if userID == 0 {
		return nil, ErrCredentialBindForbidden
	}
	// pinned 本次交易是否替成員補記了目標指紋（交易重試時重置）
	var pinned bool
	// 層 0：與派送、其他承接共用的行程內帳號互斥
	unlock := lockRotationAccount(subject.accountID)
	defer unlock()

	var created *model.CredentialHostIdentityConfirmation
	err := s.db.Transaction(func(tx *gorm.DB) error {
		pinned = false
		if err := lockAssetHostKey(tx, subject.assetID); err != nil {
			return fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
		}
		var asset model.Asset
		if err := tx.Where("id = ?", subject.assetID).First(&asset).Error; err != nil {
			return takeoverLoadError(err)
		}
		if err := checkConfirmedIdentity(tx, &asset, req); err != nil {
			return err
		}
		tj, err := lockTakeoverJob(tx, kind, jobID)
		if err != nil {
			return err
		}
		now := time.Now()
		if !tj.confirmable(now) {
			return takeoverConflict(takeoverDetailNotConfirmable)
		}
		if req.Transport == model.HostKeyTransportWinRM &&
			tj.job.Binding != model.HostKeyBindingLegacy && tj.job.Transport != model.HostKeyTransportWinRM {
			return takeoverConflict("")
		}
		verdict := hostIdentityVerdict(tx, tj.job, &asset)
		if verdict == hostIdentityTransportChanged {
			// 沒有可核對的端點身分：任何確認都不可承接，出口是改回原通道或另開新工作
			return takeoverConflict(takeoverDetailNotConfirmable)
		}
		if verdict == "" && tj.lastError != model.ChangeSecretReasonHostIdentityChanged {
			return takeoverConflict(takeoverDetailNotConfirmable)
		}
		differentKey := req.Transport == model.HostKeyTransportSSH &&
			tj.job.Binding != model.HostKeyBindingLegacy && tj.job.Pin.Fingerprint != "" &&
			tj.job.Pin.Fingerprint != req.Fingerprint
		if differentKey && !req.AcceptDifferentKey {
			return takeoverConflict(takeoverDetailDifferentKeyNotAccepted)
		}

		var existing, open int64
		if err := tx.Model(&model.CredentialHostIdentityConfirmation{}).
			Where("kind = ? AND job_id = ?", kind, jobID).Count(&existing).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.CredentialHostIdentityConfirmation{}).
			Where("kind = ? AND job_id = ? AND consumed_at IS NULL", kind, jobID).Count(&open).Error; err != nil {
			return err
		}
		if open > 0 {
			return takeoverConflict(takeoverDetailConfirmationPending)
		}

		rec := &model.CredentialHostIdentityConfirmation{
			Kind: kind, JobID: jobID, Revision: existing + 1,
			AssetID: subject.assetID, AccountID: subject.accountID,
			ConfirmedBy: userID, ConfirmedByName: username, ConfirmedTransport: req.Transport,
			ConfirmedRecordID: req.RecordID, ConfirmedAlgorithm: req.Algorithm,
			ConfirmedFingerprint: req.Fingerprint, ConfirmedGeneration: req.Generation,
			AcceptDifferentKey: req.AcceptDifferentKey,
			OriginalBinding:    tj.job.Binding, AuthzVersion: decision.AuthzVersion,
			ClientIP: clientIPFromContext(ctx), CreatedAt: now, StartedAt: &now,
		}
		if tj.job.Binding != model.HostKeyBindingLegacy {
			rec.OriginalTransport, rec.OriginalRecordID = tj.job.Transport, tj.job.RecordID
			rec.OriginalFingerprint, rec.OriginalGeneration = tj.job.Pin.Fingerprint, tj.job.Generation
		}
		if tj.member != nil && tj.member.TargetFingerprint == "" {
			if err := pinMemberTargetInTx(tx, tj.member, subject); err != nil {
				return err
			}
			pinned = true
		}
		if err := s.recordInitiator(tx, tj, subject, rec); err != nil {
			return err
		}
		if err := tx.Create(rec).Error; err != nil {
			return fmt.Errorf("寫入承接紀錄失敗: %w", err)
		}
		if err := s.writeConfirmAudit(tx, tj, rec, differentKey, now.After(tj.deadline), pinned); err != nil {
			return err
		}
		if s.createTxBarrier != nil {
			if err := s.createTxBarrier(tx); err != nil {
				return err
			}
		}
		created = rec
		return nil
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// pinMemberTargetInTx 目標指紋為空的輪替成員（指紋欄位出現之前建立）：確認者明示承接＝以當下的目標為準，
// 在承接短交易內（已持主機金鑰鎖與工作列鎖；資產列鎖不在此交易，提交交易會在資產列鎖內再核一次目標）把指紋固定為當下的事實，之後的撥號前與提交交易內核對沿用既有規則。
// 掛載已不在、掛載已不屬於成員的資產、或資產已不存在，都無法證實目標，回目標變更。
func pinMemberTargetInTx(tx *gorm.DB, m *model.CredentialRotationMember, subject *takeoverSubject) error {
	binding, err := loadConfirmedTargetBinding(tx, subject.accountID)
	if err != nil {
		return err
	}
	if binding.AssetID != subject.assetID {
		return ErrHostIdentityConfirmTargetChanged
	}
	var asset model.Asset
	if err := tx.Where("id = ?", binding.AssetID).First(&asset).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrHostIdentityConfirmTargetChanged
		}
		return fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	fp := targetFingerprintOf(&asset, binding)
	res := tx.Model(&model.CredentialRotationMember{}).
		Where("id = ? AND target_fingerprint = ''", m.ID).Update("target_fingerprint", fp)
	if res.Error != nil {
		return fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, res.Error)
	}
	if res.RowsAffected != 1 {
		return fmt.Errorf("%w: 補記目標指紋未生效", ErrCredentialAuthzUnavailable)
	}
	m.TargetFingerprint = fp
	return nil
}

// checkConfirmedIdentity 確認的身分必須等於資產當下有效狀態；任一不等回 409。
func checkConfirmedIdentity(tx *gorm.DB, asset *model.Asset, req HostIdentityConfirmRequest) error {
	if req.Transport == model.HostKeyTransportWinRM {
		if rotationTransportOf(asset) != model.HostKeyTransportWinRM {
			return takeoverConflict("")
		}
		return nil
	}
	if rotationTransportOf(asset) != model.HostKeyTransportSSH {
		return takeoverConflict("")
	}
	q := tx.Where("asset_id = ?", asset.ID)
	if tx.Dialector.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var own model.AssetHostKey
	if err := q.First(&own).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return takeoverConflict("")
		}
		return fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	if own.ResetPending || own.ID != req.RecordID || own.TrustGeneration != req.Generation ||
		own.Fingerprint != req.Fingerprint || own.Algorithm != req.Algorithm {
		return takeoverConflict("")
	}
	return nil
}

// recordInitiator 只記錄原發起者與還原世代，不改任何授權列。
func (s *HostIdentityTakeoverService) recordInitiator(tx *gorm.DB, tj *takeoverJob, subject *takeoverSubject,
	rec *model.CredentialHostIdentityConfirmation) error {

	if !sameAuthRef(tj.authID, subject.authID) {
		return fmt.Errorf("%w: 授權脈絡引用在判權後已改變", ErrCredentialAuthzUnavailable)
	}
	auth, err := loadJobAuthorization(tx, tj.authID)
	if errors.Is(err, ErrJobAuthorizationMissing) {
		// 工作確實沒有授權引用（升級前）：原發起者未知
		rec.OriginalInitiatorUnknown = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	rec.OriginalInitiatorID = auth.ActorID
	mismatch, err := s.mgmt.restoreMismatch(tx, auth.RestoreGeneration)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	if mismatch {
		gen, _, gerr := s.mgmt.currentRestoreGeneration(tx)
		if gerr != nil {
			return fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, gerr)
		}
		rec.RestoreGeneration = gen
	}
	return nil
}

// writeConfirmAudit 承接審計（AuditOpHostIdentityConfirm）：與承接紀錄同一交易。
func (s *HostIdentityTakeoverService) writeConfirmAudit(tx *gorm.DB, tj *takeoverJob,
	rec *model.CredentialHostIdentityConfirmation, differentKey, expired, pinned bool) error {

	resource := model.ResourceChangeSecretPlan
	var resourceID *uint
	if tj.planID != 0 {
		id := tj.planID
		resourceID = &id
	}
	if tj.member != nil {
		resource = model.ResourceCredential
		resourceID = nil
		if tj.credential != 0 {
			id := tj.credential
			resourceID = &id
		}
	}
	assetID := rec.AssetID
	details, _ := json.Marshal(map[string]any{
		"resource": string(resource), "operation": model.AuditOpHostIdentityConfirm,
		"job_kind": rec.Kind, "job_id": rec.JobID, "revision": rec.Revision,
		"account_id": rec.AccountID, "plan_id": tj.planID, "batch_id": tj.batchID,
		"credential_id": tj.credential,
		"confirmed_by":  rec.ConfirmedBy,
		"original": map[string]any{
			"binding": rec.OriginalBinding, "transport": rec.OriginalTransport,
			"record_id": rec.OriginalRecordID, "fingerprint": rec.OriginalFingerprint,
			"generation": rec.OriginalGeneration,
		},
		"confirmed": map[string]any{
			"transport": rec.ConfirmedTransport, "record_id": rec.ConfirmedRecordID,
			"algorithm": rec.ConfirmedAlgorithm, "fingerprint": rec.ConfirmedFingerprint,
			"generation": rec.ConfirmedGeneration,
		},
		"transport":                  rec.ConfirmedTransport,
		"authz_version":              rec.AuthzVersion,
		"original_initiator_id":      rec.OriginalInitiatorID,
		"original_initiator_unknown": rec.OriginalInitiatorUnknown,
		"restore_generation":         rec.RestoreGeneration,
		"different_key":              differentKey,
		"target_pinned_at_confirm":   pinned,
		"verify_only":                true, "deadline_reset": false, "expired": expired,
	})
	return port.WriteInTx(s.sink, tx, port.AuditEvent{
		OccurredAt: time.Now(),
		Actor:      gatewayapi.Actor{UserID: rec.ConfirmedBy, Username: rec.ConfirmedByName},
		Action:     string(model.ActionUpdate),
		Resource:   string(resource),
		ResourceID: resourceID,
		AssetID:    &assetID,
		Status:     string(model.StatusSuccess),
		Details:    string(details),
	})
}

// sameAuthRef 兩個授權引用是否指向同一列；nil 與 0 都視為沒有引用。
func sameAuthRef(a, b *uint) bool {
	var x, y uint
	if a != nil {
		x = *a
	}
	if b != nil {
		y = *b
	}
	return x == y
}
