package asset

import (
	"context"
	"errors"
	"log"
	"sync"

	"github.com/custodexa/backend/internal/model"
)

// 輪替成員路徑的主機身分守衛：下達前的停止、下達後的立即驗證與補跑驗證共用同一個守衛物件，
// 守衛每次重讀成員列取當下快照；停在哪一道由守衛記下，停止審計依此寫 phase 與 verification_sent。

// memberVerifyGuard 以成員列建立立即驗證守衛。守衛只用在新秘密已送出或即將重送的驗證，
// 因此判定時一律視為已送出：金鑰型別的下達與驗證在同一條連線內完成，派送標記要等整段結束才寫，
// 若照列上的標記判定，歷次都是乾淨失敗的 bound 成員會被當成「可重新首次派送」而放行。
func (s *CredentialRotationService) memberVerifyGuard(rot *model.CredentialRotation,
	member *model.CredentialRotationMember) *immediateVerifyGuard {

	groupCandidate, candidateApplied := false, false
	if rot.Mode != model.CredentialRotationModeSplit {
		if cand, err := s.candidates.FindByAccount(member.AccountID); err == nil && cand != nil {
			groupCandidate, candidateApplied = true, cand.Applied
		}
	}
	deadline := rot.StartedAt.Add(candidateRetryDeadline)
	return &immediateVerifyGuard{
		db: s.db, sink: s.auditTx, notify: s.stopNotify, dc: memberHostKeyDialContext(rot, member),
		pinnedFn: s.hostKeys.CallbackForPinned,
		onView:   s.memberViewSink(member.ID),
		load: func() (hostIdentityStopInput, error) {
			m, err := loadRotationMember(s.db, rot.ID, member.ID)
			if err != nil {
				return hostIdentityStopInput{}, err
			}
			job := hostIdentityJobOfMember(m, groupCandidate)
			job.SecretSent, job.LegacySentOrUnknown = true, true
			return hostIdentityStopInput{
				Job: job, MemberID: m.ID, RotationID: rot.ID,
				AccountID: m.AccountID, CredentialID: m.CredentialID,
				InitiatorID: rot.RequestedBy, InitiatorName: rot.RequestedByName, Deadline: &deadline,
				CandidateApplied: candidateApplied,
			}, nil
		},
	}
}

// recordMemberPrecheckStop 撥號前判定不放行（沒有撥號）：補寫停止審計。
func (s *CredentialRotationService) recordMemberPrecheckStop(rot *model.CredentialRotation,
	member *model.CredentialRotationMember, detail string) {

	asset, err := s.assets.GetByID(member.AssetID)
	if err != nil {
		log.Printf("[CredentialRotation] 身分停止審計讀取資產失敗 member=%d: %v", member.ID, err)
		return
	}
	guard := s.memberVerifyGuard(rot, member)
	_ = guard.stopPrecheck(detail)
	guard.recordStop(asset)
}

// memberIdentityStopped 驗證或下達遇到主機身分守衛的停止（撥號前或握手）時補寫停止審計；
// 回傳是否為身分停止。
func (s *CredentialRotationService) memberIdentityStopped(guard *immediateVerifyGuard,
	member *model.CredentialRotationMember, err error) bool {

	if !errors.Is(err, ErrHostIdentityChanged) {
		return false
	}
	asset, aerr := s.assets.GetByID(member.AssetID)
	if aerr != nil {
		log.Printf("[CredentialRotation] 身分停止審計讀取資產失敗 member=%d: %v", member.ID, aerr)
		return true
	}
	guard.recordStop(asset)
	return true
}

// recordMemberRecoveryStop 失權後的有限驗證在判定階段被主機身分擋下：沒有撥號，補寫停止審計。
func (s *CredentialRotationService) recordMemberRecoveryStop(rot *model.CredentialRotation,
	member *model.CredentialRotationMember) {

	asset, err := s.assets.GetByID(member.AssetID)
	if err != nil {
		log.Printf("[CredentialRotation] 身分停止審計讀取資產失敗 member=%d: %v", member.ID, err)
		return
	}
	guard := s.memberVerifyGuard(rot, member)
	in, err := guard.load()
	if err != nil {
		log.Printf("[CredentialRotation] 身分停止審計讀取成員失敗 member=%d: %v", member.ID, err)
		return
	}
	detail := hostIdentityVerdict(s.db, in.Job, asset)
	if detail == "" {
		return
	}
	_ = guard.stopPrecheck(detail)
	guard.recordStop(asset)
}

// recordMemberCommitStop 提交交易內的主機身分比對不符：驗證已成功，補寫 phase=commit 的停止審計。
func (s *CredentialRotationService) recordMemberCommitStop(rot *model.CredentialRotation,
	member *model.CredentialRotationMember) {

	asset, err := s.assets.GetByID(member.AssetID)
	if err != nil {
		log.Printf("[CredentialRotation] 身分停止審計讀取資產失敗 member=%d: %v", member.ID, err)
		return
	}
	s.memberVerifyGuard(rot, member).recordCommitStop(asset)
}

// memberStopCollector 一次逐台補跑期間收集該成員最近一次停止的唯讀檢視。
type memberStopCollector struct {
	mu   sync.Mutex
	view *HostIdentityView
}

// memberViewSink 守衛產生檢視時的通知出口：只有登記過收集器的補跑才收，背景排程不累積任何狀態。
func (s *CredentialRotationService) memberViewSink(memberID uint) func(*HostIdentityView) {
	return func(v *HostIdentityView) {
		if c, ok := s.stopCollectors.Load(memberID); ok {
			col := c.(*memberStopCollector)
			col.mu.Lock()
			col.view = v
			col.mu.Unlock()
		}
	}
}

// RunMemberResult 同 RunMember，並帶回本次補跑被主機身分守衛擋下時的唯讀檢視。
// 同一成員同時只收一份：後到的呼叫沿用已登記的收集器，不覆蓋。
func (s *CredentialRotationService) RunMemberResult(ctx context.Context, rotationID, memberID uint,
	origin RotationRecordOrigin) (*MemberRunResult, error) {

	col := &memberStopCollector{}
	if actual, loaded := s.stopCollectors.LoadOrStore(memberID, col); loaded {
		col = actual.(*memberStopCollector)
	} else {
		defer s.stopCollectors.Delete(memberID)
	}
	if err := s.RunMemberFor(ctx, rotationID, memberID, origin); err != nil {
		return nil, err
	}
	col.mu.Lock()
	defer col.mu.Unlock()
	return &MemberRunResult{HostIdentity: col.view}, nil
}
