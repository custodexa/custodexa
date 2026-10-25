package asset

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// immediateVerifyGuard 派送後立即 Verify 的主機身分守衛：新秘密已送出，驗證會再送一次認證，
// 若主機在派送與驗證之間被換掉，驗證就把新秘密交給了冒充主機。
//
// 兩道關口：prepare 在撥號前重讀工作列並做撥號前查庫（hostIdentityVerdict）；通過後回傳
// 只認工作列綁定金鑰的 pinned 回呼（不寫入、不 TOFU），並計算回呼放行次數。
// 任何一道不放行，呼叫端以 recordStop 寫停止審計（去重、通知見 recordHostIdentityStop）。
type immediateVerifyGuard struct {
	db     *gorm.DB
	sink   port.TxSink
	notify func(rule, message string)
	dc     HostKeyDialContext
	// load 重讀工作列並組出停止審計的基底輸入（Job 為當下快照，Detail／Phase 由守衛填）
	load func() (hostIdentityStopInput, error)
	// pinnedFn 建預期身分回呼（正式為 HostKeyService.CallbackForPinned）
	pinnedFn func(HostKeyDialContext, HostKeyPin) ssh.HostKeyCallback

	mu     sync.Mutex
	passes int
	// stage 停在哪一道：空＝尚未停止；precheck 為撥號前查庫，handshake 為握手回呼
	stage  string
	detail string
	// counted 是否有回呼經過放行計數；握手停止時沒有計數來源就記 unknown，不以 0 代替
	counted bool
	// view 最近一次停止的唯讀檢視（沒有停止為 nil）；onView 若有設定，每次產生檢視時同步通知
	view   *HostIdentityView
	onView func(*HostIdentityView)
}

// reached 這個守衛是否已走到撥號前查庫或握手計數（即驗證階段已開始）。
func (g *immediateVerifyGuard) reached() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.counted || g.stage != ""
}

// passCount 回呼放行次數與是否有回呼經過計數（沒有計數來源時第二值為 false）。
func (g *immediateVerifyGuard) passCount() (int, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.passes, g.counted
}

// countPasses 包一層放行計數：回呼回 nil（通過比對或完成綁定，其後即送出認證）才計一次。
// 綁定回呼與預期身分回呼共用，nil 回呼原樣回傳。
func (g *immediateVerifyGuard) countPasses(cb ssh.HostKeyCallback) ssh.HostKeyCallback {
	if cb == nil {
		return nil
	}
	g.mu.Lock()
	g.counted = true
	g.mu.Unlock()
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := cb(hostname, remote, key); err != nil {
			return err
		}
		g.mu.Lock()
		g.passes++
		g.mu.Unlock()
		return nil
	}
}

// ErrHostIdentityLookupFailed 撥號前讀不到工作列或自身記錄（資料庫錯誤）：無從核對，fail-closed 不撥號，
// 但這不是「主機身分已變更」，原因碼對映無法判定權限（AUTHZ_UNAVAILABLE），不寫身分異動停止審計。
var ErrHostIdentityLookupFailed = errors.New("主機身分查核不可用，已拒絕撥號")

// stopLookup 撥號前查庫本身失敗：記下停在撥號前，回查詢不可用錯誤（不包 ErrHostIdentityChanged）。
func (g *immediateVerifyGuard) stopLookup() error {
	g.mu.Lock()
	g.stage, g.detail = hostIdentityPhasePrecheck, hostIdentityLookupFailed
	g.mu.Unlock()
	return fmt.Errorf("%w: %s", ErrHostIdentityLookupFailed, hostIdentityLookupFailed)
}

// precheckStopReason 撥號前查庫不放行的原因碼：查詢不可用歸無法判定權限，其餘歸主機身分變更。
func precheckStopReason(err error) string {
	if errors.Is(err, ErrHostIdentityLookupFailed) {
		return model.ChangeSecretReasonAuthzUnavailable
	}
	return model.ChangeSecretReasonHostIdentityChanged
}

func (g *immediateVerifyGuard) stopPrecheck(detail string) error {
	g.mu.Lock()
	g.stage, g.detail = hostIdentityPhasePrecheck, detail
	g.mu.Unlock()
	return fmt.Errorf("%w: %s", ErrHostIdentityChanged, detail)
}

// prepare 撥號前查庫，通過後回傳 pinned 回呼；傳輸為 WinRM 的工作沒有主機金鑰可比，回 nil 回呼。
// 回錯誤一律不得撥號：身分不符包著 ErrHostIdentityChanged；查庫本身失敗包著 ErrHostIdentityLookupFailed（兩者互斥）。
func (g *immediateVerifyGuard) prepare(asset *model.Asset) (ssh.HostKeyCallback, error) {
	in, err := g.load()
	if err != nil {
		log.Printf("[HostIdentity] 立即驗證前讀取工作列失敗（fail-closed）asset=%d: %v", g.dc.AssetID, err)
		return nil, g.stopLookup()
	}
	if detail := hostIdentityVerdict(g.db, in.Job, asset); detail != "" {
		if detail == hostIdentityLookupFailed {
			return nil, g.stopLookup()
		}
		return nil, g.stopPrecheck(detail)
	}
	if in.Job.Transport == model.HostKeyTransportWinRM {
		return nil, nil
	}
	return g.countPasses(g.svcPinned(in.Job.Pin)), nil
}

// recordStop 立即驗證被主機身分守衛擋下之後寫停止審計。停在撥號前查庫時沿用查庫的 detail；
// 停在握手時重跑一次查庫取 detail（查庫已放行的競態以 generation_changed 記）。
func (g *immediateVerifyGuard) recordStop(asset *model.Asset) {
	in, err := g.load()
	if err != nil {
		log.Printf("[HostIdentity] 停止審計讀取工作列失敗 asset=%d: %v", g.dc.AssetID, err)
		return
	}
	g.mu.Lock()
	stage, detail, passes, counted := g.stage, g.detail, g.passes, g.counted
	g.mu.Unlock()
	phase := hostIdentityPhaseHandshake
	if stage == hostIdentityPhasePrecheck {
		phase = hostIdentityPhasePrecheck
	} else if detail = hostIdentityVerdict(g.db, in.Job, asset); detail == "" {
		detail = hostIdentityGenerationChanged
	}
	in.VerificationSent = hostIdentityVerificationSent(phase, passes, counted)
	g.writeStop(asset, in, detail, phase)
}

// recordCommitStop 本地提交交易內的主機身分比對不符：驗證已成功（用候選秘密送出過認證），
// 提交被擋下、候選保留，補寫 phase=commit 的停止審計。
func (g *immediateVerifyGuard) recordCommitStop(asset *model.Asset) {
	in, err := g.load()
	if err != nil {
		log.Printf("[HostIdentity] 提交階段停止審計讀取工作列失敗 asset=%d: %v", g.dc.AssetID, err)
		return
	}
	in.VerificationSent = hostIdentityVerificationSent(hostIdentityPhaseCommit, 0, true)
	g.writeStop(asset, in, hostIdentityCommitGenerationChanged, hostIdentityPhaseCommit)
}

// writeStop 補上當下傳輸與自身記錄後寫停止審計。
func (g *immediateVerifyGuard) writeStop(asset *model.Asset, in hostIdentityStopInput, detail, phase string) {
	in.Detail, in.Phase = detail, phase
	in.CurrentTransport = rotationTransportOf(asset)
	var own model.AssetHostKey
	if err := g.db.Where("asset_id = ?", asset.ID).First(&own).Error; err == nil {
		in.Current = &hostIdentityCurrent{RecordID: own.ID, Algorithm: own.Algorithm,
			Fingerprint: own.Fingerprint, Generation: own.TrustGeneration, ResetPending: own.ResetPending,
			RecordedAt: own.UpdatedAt}
	}
	g.setView(newHostIdentityView(in, time.Now()))
	if _, err := recordHostIdentityStop(g.sink, g.db, g.notify, in); err != nil {
		log.Printf("[HostIdentity] 停止審計失敗 asset=%d detail=%s phase=%s: %v", g.dc.AssetID, detail, phase, err)
	}
}

// setView 記下最近一次停止的唯讀檢視（去重後不寫審計的停止也要有檢視）。
func (g *immediateVerifyGuard) setView(v *HostIdentityView) {
	g.mu.Lock()
	g.view = v
	cb := g.onView
	g.mu.Unlock()
	if cb != nil && v != nil {
		cb(v)
	}
}

// lastView 最近一次停止的唯讀檢視。
func (g *immediateVerifyGuard) lastView() *HostIdentityView {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.view
}

// svcPinned 以工作列快照建預期身分回呼；獨立成方法讓守衛不直接持有 HostKeyService。
func (g *immediateVerifyGuard) svcPinned(pin HostKeyPin) ssh.HostKeyCallback {
	return g.pinnedFn(g.dc, pin)
}

// candidateVerifyGuard 一般改密候選的立即驗證守衛。
func (r *ChangeSecretRunner) candidateVerifyGuard(job rotationJob, tgt changeSecretTarget, candID uint) *immediateVerifyGuard {
	dc := HostKeyDialContext{
		AssetID: tgt.assetID, Path: HostKeyPathCredentialChange,
		UserID: job.initiatorID, Username: job.initiatorName, AccountID: tgt.accountID,
		ConnectionRef: changeSecretJobRef(job),
	}
	return &immediateVerifyGuard{
		db: r.db, sink: r.auditTx, notify: ChangeSecretStopNotifier(r.notifier), dc: dc,
		pinnedFn: r.hostKeys.CallbackForPinned,
		load: func() (hostIdentityStopInput, error) {
			var c model.ChangeSecretCandidate
			if err := r.db.First(&c, candID).Error; err != nil {
				return hostIdentityStopInput{}, err
			}
			deadline := c.CreatedAt.Add(candidateRetryDeadline)
			return hostIdentityStopInput{
				Job: hostIdentityJobOfCandidate(&c), CandidateID: c.ID, PlanID: c.PlanID, BatchID: c.BatchID,
				AccountID: c.AccountID, CredentialID: c.CredentialID,
				InitiatorID: job.initiatorID, InitiatorName: job.initiatorName, Deadline: &deadline,
				CandidateApplied: c.Applied,
			}, nil
		},
	}
}
