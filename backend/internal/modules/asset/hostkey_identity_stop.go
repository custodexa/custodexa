package asset

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 主機身分異動而停止的審計、去重與通知。
//
// 同一個身分狀態只留一筆審計、只通知一次：去重鍵（工作列的 host_identity_alerted_key）與審計
// 在同一個交易裡推進，審計寫不進去整筆回滾，鍵不前進，下一輪還會再試；不存在審計失敗卻
// 把工作標成已通知的路徑。通知在交易提交之後才發，且只發一次。

// 停止所在的比對階段（只表示停在哪一道比對，與是否送出過認證分開記）
const (
	hostIdentityPhasePrecheck  = "precheck"
	hostIdentityPhaseHandshake = "handshake"
	hostIdentityPhaseCommit    = "commit"
)

// verification_sent 的三個值：本次停止所屬的這一次邏輯驗證是否已用候選秘密送出過認證
const (
	verificationSentTrue    = "true"
	verificationSentFalse   = "false"
	verificationSentUnknown = "unknown"
)

// 提交前新增的偵測 detail：提交交易內看到的世代已變
const hostIdentityCommitGenerationChanged = "commit_generation_changed"

// hostIdentityStopRule 停止通知的規則名稱（與授權失效的停止通知分開）
const hostIdentityStopRule = "改密工作因主機身分異動停止"

// hostIdentityVerificationSent 由階段與預期身分回呼的放行計數算 verification_sent：
// precheck 尚未撥號為 false；commit 驗證已成功為 true；handshake 看回呼放行過幾次
// （任何一次通過比對，其後即送出認證），計數不可得時為 unknown，不猜 false。
func hostIdentityVerificationSent(phase string, passes int, countKnown bool) string {
	switch phase {
	case hostIdentityPhasePrecheck:
		return verificationSentFalse
	case hostIdentityPhaseCommit:
		return verificationSentTrue
	case hostIdentityPhaseHandshake:
		if !countKnown {
			return verificationSentUnknown
		}
		if passes > 0 {
			return verificationSentTrue
		}
		return verificationSentFalse
	default:
		return verificationSentUnknown
	}
}

// hostIdentityCurrent 停止當下觀察到的自身記錄（無記錄時整個為 nil）。
type hostIdentityCurrent struct {
	RecordID     uint
	Algorithm    string
	Fingerprint  string
	Generation   int64
	ResetPending bool
	// RecordedAt 自身列的最近更新時刻（唯讀檢視用）
	RecordedAt time.Time
}

// hostIdentityStateToken 當下身分狀態的去重 token：同一狀態退避多輪不重複，
// 刪列重建（不同記錄 ID）或記錄首次缺席都因 token 不同而各寫一筆。
func hostIdentityStateToken(detail string, cur *hostIdentityCurrent, currentTransport string) string {
	switch detail {
	case hostIdentityUnboundLegacy:
		return "legacy"
	case hostIdentityTransportChanged:
		return "transport:" + currentTransport
	case hostIdentityRecordMissing:
		return "missing"
	}
	if cur == nil {
		return "missing"
	}
	id := strconv.FormatUint(uint64(cur.RecordID), 10) + ":" + strconv.FormatInt(cur.Generation, 10)
	if cur.ResetPending || detail == hostIdentityResetPending {
		return "reset:" + id
	}
	return id
}

// hostIdentityStopInput 一次身分停止的事實。候選與輪替成員二選一（CandidateID 與 MemberID 恰一個非零）。
type hostIdentityStopInput struct {
	Job hostIdentityJob
	// 工作識別
	CandidateID, MemberID uint
	PlanID, BatchID       uint
	RotationID            uint
	AccountID             uint
	CredentialID          uint
	// 原發起者（無授權脈絡時為零值，審計以系統身分記）
	InitiatorID   uint
	InitiatorName string

	Detail           string
	Phase            string
	VerificationSent string
	Current          *hostIdentityCurrent
	CurrentTransport string
	// Deadline 工作原本的截止時間（沿用，不重設）
	Deadline *time.Time
	// CandidateApplied 遠端變更指令是否已回報成功（唯讀檢視用，不進停止審計）
	CandidateApplied bool
}

func (in hostIdentityStopInput) isMember() bool { return in.MemberID != 0 }

func (in hostIdentityStopInput) validate() error {
	if (in.CandidateID == 0) == (in.MemberID == 0) {
		return errors.New("身分停止須恰為候選或成員其一")
	}
	if in.Detail == "" {
		return errors.New("身分停止缺少 detail")
	}
	switch in.Phase {
	case hostIdentityPhasePrecheck, hostIdentityPhaseHandshake, hostIdentityPhaseCommit:
	default:
		return fmt.Errorf("身分停止的階段不合法: %q", in.Phase)
	}
	return nil
}

func (in hostIdentityStopInput) verificationSent() string {
	switch in.VerificationSent {
	case verificationSentTrue, verificationSentFalse:
		return in.VerificationSent
	default:
		return verificationSentUnknown
	}
}

// writeHostIdentityStopAudit 條件式推進去重鍵並在同一交易寫停止審計。
// written=true 表示本次推進了去重鍵、審計已隨交易提交；false 且無錯誤表示同一身分狀態已留過痕。
// 審計落地面缺席或寫入失敗回錯誤，整筆回滾（去重鍵不前進）。
func writeHostIdentityStopAudit(sink port.TxSink, db *gorm.DB, in hostIdentityStopInput) (written bool, err error) {
	if err := in.validate(); err != nil {
		return false, err
	}
	if sink == nil {
		return false, port.ErrTxSinkMissing
	}
	token := hostIdentityStateToken(in.Detail, in.Current, in.CurrentTransport)
	details, _ := json.Marshal(in.auditDetails())

	resource := model.ResourceChangeSecretPlan
	var resourceID *uint
	var table any = &model.ChangeSecretCandidate{}
	jobID := in.CandidateID
	if in.isMember() {
		resource = model.ResourceCredential
		table = &model.CredentialRotationMember{}
		jobID = in.MemberID
		if in.CredentialID != 0 {
			id := in.CredentialID
			resourceID = &id
		}
	} else if in.PlanID != 0 {
		id := in.PlanID
		resourceID = &id
	}
	assetID := in.Job.AssetID
	actor := gatewayapi.Actor{UserID: in.InitiatorID, Username: in.InitiatorName}
	if actor.Username == "" {
		actor.Username = "system"
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(table).
			Where("id = ? AND (host_identity_alerted_key IS NULL OR host_identity_alerted_key <> ?)", jobID, token).
			Update("host_identity_alerted_key", token)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return nil
		}
		if err := port.WriteInTx(sink, tx, port.AuditEvent{
			OccurredAt: time.Now(),
			Actor:      actor,
			Action:     string(model.ActionUpdate),
			Resource:   string(resource),
			ResourceID: resourceID,
			AssetID:    &assetID,
			Status:     string(model.StatusDenied),
			Details:    string(details),
		}); err != nil {
			return err
		}
		written = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return written, nil
}

// auditDetails 停止審計的 details：不含秘密、公鑰本體或 SSH 錯誤原文。
func (in hostIdentityStopInput) auditDetails() map[string]any {
	resource := model.ResourceChangeSecretPlan
	kind, jobID := "candidate", in.CandidateID
	if in.isMember() {
		resource, kind, jobID = model.ResourceCredential, "member", in.MemberID
	}
	original := map[string]any{
		"binding": in.Job.Binding, "transport": in.Job.Transport,
		"record_id": in.Job.RecordID, "algorithm": in.Job.Pin.Algorithm,
		"fingerprint": in.Job.Pin.Fingerprint, "generation": in.Job.Generation,
	}
	current := map[string]any{"transport": in.CurrentTransport}
	if c := in.Current; c != nil {
		current["record_id"] = c.RecordID
		current["algorithm"] = c.Algorithm
		current["fingerprint"] = c.Fingerprint
		current["generation"] = c.Generation
		current["reset_pending"] = c.ResetPending
	}
	d := map[string]any{
		"resource": string(resource), "operation": model.AuditOpHostIdentityStop,
		"job_kind": kind, "job_id": jobID, "plan_id": in.PlanID, "batch_id": in.BatchID,
		"rotation_id": in.RotationID, "member_id": in.MemberID, "candidate_id": in.CandidateID,
		"account_id": in.AccountID, "credential_id": in.CredentialID,
		"initiator_id": in.InitiatorID,
		"reason":       model.ChangeSecretReasonHostIdentityChanged,
		"detail":       in.Detail, "phase": in.Phase, "verification_sent": in.verificationSent(),
		"candidate_retained": true, "original": original, "current": current,
	}
	if in.Deadline != nil {
		d["deadline"] = in.Deadline.UTC().Format(time.RFC3339)
	}
	return d
}

// hostIdentityStopNotice 依 verification_sent（不依 phase）選通知文案；不承諾沒有登入過，
// 只在確定沒有撥號放行時才說「沒有拿新憑證去登入」。
func hostIdentityStopNotice(verificationSent string) string {
	switch verificationSent {
	case verificationSentFalse:
		return "主機身分已異動，舊工作待人工確認（候選保留，這次沒有拿新憑證去登入）"
	case verificationSentTrue:
		return "主機身分異動，本地未提交（候選保留，這次已用新憑證登入驗證過）"
	default:
		return "主機身分異動，本地未提交（候選保留，無法確定這次是否已用新憑證登入）"
	}
}

// recordHostIdentityStop 寫停止審計與去重鍵（同交易），提交之後最佳努力通知一次。
// 同一身分狀態已留過痕時不通知；審計失敗回錯誤、不通知，由呼叫端保持停止狀態並於下一輪重試。
// 不承諾崩潰情形下恰一次通知。
func recordHostIdentityStop(sink port.TxSink, db *gorm.DB, notify func(rule, message string),
	in hostIdentityStopInput) (written bool, err error) {
	written, err = writeHostIdentityStopAudit(sink, db, in)
	if err != nil {
		log.Printf("[HostIdentity] 停止審計寫入失敗（去重鍵未前進，下一輪再試）asset=%d detail=%s phase=%s: %v",
			in.Job.AssetID, in.Detail, in.Phase, err)
		return false, err
	}
	if !written || notify == nil {
		return written, nil
	}
	kind, id := "candidate", in.CandidateID
	if in.isMember() {
		kind, id = "member", in.MemberID
	}
	notify(hostIdentityStopRule, fmt.Sprintf("%s=%d asset_id=%d detail=%s phase=%s：%s",
		kind, id, in.Job.AssetID, in.Detail, in.Phase, hostIdentityStopNotice(in.verificationSent())))
	return true, nil
}
