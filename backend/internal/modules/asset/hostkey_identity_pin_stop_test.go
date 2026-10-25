package asset

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 主機身分停止的審計、去重與通知子案例（root：TestCredentialRecoveryHostIdentityPin，前綴 3.5/）。
// 直接呼叫 writer，不經停止分支；夾具的綁定與主機金鑰記錄都經替身的正式回呼建立。

// stopNotifyCapture 收集通知（規則名與內文）。
type stopNotifyCapture struct {
	mu   sync.Mutex
	msgs []string
	rule []string
}

func (c *stopNotifyCapture) fn(rule, message string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rule = append(c.rule, rule)
	c.msgs = append(c.msgs, message)
}

func (c *stopNotifyCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

func (c *stopNotifyCapture) last() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.msgs[len(c.msgs)-1]
}

// stopFixture 一台已經由正式回呼綁定的成員與候選，主機金鑰世代在驗證後被推進（身分異動）。
type stopFixture struct {
	f         *batchFixture
	member    *model.CredentialRotationMember
	candidate *model.ChangeSecretCandidate
	current   *hostIdentityCurrent

	// 正式停止分支在建立夾具時已留下的審計與去重鍵（產品中審計不可刪，不清除，後續一律以差值斷言）。
	baseAuditID uint
	baseMemKey  *string
	baseCandKey *string
}

func setupStopFixture(t *testing.T) *stopFixture {
	t.Helper()
	f := setupBatchFixture(t)
	credID, accounts := f.sharedOn(t, "身分停止", "ops", "old-shared", "10.35.1.1", "10.35.1.2")
	assetID := f.bindingOf(t, accounts[1]).AssetID
	rec := newSecretRecorder()
	fired := bumpGenerationAfterVerify(t, f, rec, "10.35.1.2", assetID)
	f.useRotationExecutor(rec)
	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
	require.EqualValues(t, 1, fired.Load(), "注入器必須真的觸發（否則為假綠）")
	// 正式提交分支在這一步已留下停止審計與去重鍵，這些不刪（產品中審計不可刪）。
	// 再把世代推進一格，使 writer 案例面對的是新的身分狀態 token，並以基線之後的差值斷言。
	// 直寫自身列（design 明准的壞資料／故障注入，非綁定也非採用）：世代再推進一格，換一個身分狀態 token
	require.NoError(t, f.db.Model(&model.AssetHostKey{}).Where("asset_id = ?", assetID).
		UpdateColumn("trust_generation", 100).Error)
	var baseLog model.AuditLog
	require.NoError(t, f.db.Where("details LIKE ?", `%"operation":"host_identity_stop"%`).
		Order("id DESC").Limit(1).Find(&baseLog).Error)

	m := f.memberOf(t, rot.ID, accounts[1])
	require.Equal(t, model.HostKeyBindingBound, m.HostKeyBinding, "成員綁定經正式回呼建立")
	cand := f.candidateByAccount(t, accounts[1])
	var own model.AssetHostKey
	require.NoError(t, f.db.Where("asset_id = ?", assetID).First(&own).Error)
	require.EqualValues(t, 100, own.TrustGeneration)
	s := &stopFixture{f: f, member: m, candidate: cand, baseAuditID: baseLog.ID, current: &hostIdentityCurrent{
		RecordID: own.ID, Algorithm: own.Algorithm, Fingerprint: own.Fingerprint, Generation: own.TrustGeneration,
	}}
	s.baseMemKey, s.baseCandKey = s.memberKey(t), s.candidateKey(t)
	return s
}

func (s *stopFixture) memberInput(phase, sent string) hostIdentityStopInput {
	return hostIdentityStopInput{
		Job: hostIdentityJobOfMember(s.member, true), MemberID: s.member.ID, RotationID: s.member.RotationID,
		AccountID: s.member.AccountID, CredentialID: s.member.CredentialID,
		Detail: hostIdentityGenerationChanged, Phase: phase, VerificationSent: sent,
		Current: s.current, CurrentTransport: model.HostKeyTransportSSH,
	}
}

func (s *stopFixture) candidateInput(phase, sent string) hostIdentityStopInput {
	return hostIdentityStopInput{
		Job: hostIdentityJobOfCandidate(s.candidate), CandidateID: s.candidate.ID, PlanID: s.candidate.PlanID,
		BatchID: s.candidate.BatchID, AccountID: s.candidate.AccountID,
		Detail: hostIdentityGenerationChanged, Phase: phase, VerificationSent: sent,
		Current: s.current, CurrentTransport: model.HostKeyTransportSSH,
	}
}

func (s *stopFixture) stopAudits(t *testing.T) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, s.f.db.Where("details LIKE ? AND id > ?", `%"operation":"host_identity_stop"%`, s.baseAuditID).Order("id ASC").Find(&rows).Error)
	return rows
}

func (s *stopFixture) memberKey(t *testing.T) *string {
	t.Helper()
	var m model.CredentialRotationMember
	require.NoError(t, s.f.db.First(&m, s.member.ID).Error)
	return m.HostIdentityAlertedKey
}

func (s *stopFixture) candidateKey(t *testing.T) *string {
	t.Helper()
	var c model.ChangeSecretCandidate
	require.NoError(t, s.f.db.First(&c, s.candidate.ID).Error)
	return c.HostIdentityAlertedKey
}

func runStopWriterDedup(t *testing.T) {
	s := setupStopFixture(t)
	sink := audit.NewTxSink()
	token := hostIdentityStateToken(hostIdentityGenerationChanged, s.current, model.HostKeyTransportSSH)
	require.NotNil(t, s.baseMemKey, "正式停止分支已留下舊狀態的去重鍵")
	require.NotEqual(t, token, *s.baseMemKey, "基線 token 與本案例的新狀態不同")

	written, err := writeHostIdentityStopAudit(sink, s.f.db, s.memberInput(hostIdentityPhaseCommit, verificationSentTrue))
	require.NoError(t, err)
	require.True(t, written)
	require.NotNil(t, s.memberKey(t))
	assert.Equal(t, token, *s.memberKey(t))
	assert.Len(t, s.stopAudits(t), 1)

	// 同 token 兩次只一筆
	written, err = writeHostIdentityStopAudit(sink, s.f.db, s.memberInput(hostIdentityPhaseHandshake, verificationSentFalse))
	require.NoError(t, err)
	assert.False(t, written, "同一身分狀態已留過痕")
	assert.Len(t, s.stopAudits(t), 1)

	// 狀態變了（記錄首次缺席、重置待記錄、世代再推進、刪列重建）各寫一筆
	next := func(detail string, cur *hostIdentityCurrent, wantToken string) {
		in := s.memberInput(hostIdentityPhasePrecheck, verificationSentFalse)
		in.Detail, in.Current = detail, cur
		before := len(s.stopAudits(t))
		w, err := writeHostIdentityStopAudit(sink, s.f.db, in)
		require.NoError(t, err)
		require.True(t, w, wantToken)
		assert.Equal(t, wantToken, *s.memberKey(t))
		assert.Len(t, s.stopAudits(t), before+1)
	}
	next(hostIdentityRecordMissing, nil, "missing")
	cur := *s.current
	next(hostIdentityResetPending, &hostIdentityCurrent{RecordID: cur.RecordID, Generation: cur.Generation, ResetPending: true},
		"reset:"+hostIdentityStateToken("", &hostIdentityCurrent{RecordID: cur.RecordID, Generation: cur.Generation}, ""))
	next(hostIdentityGenerationChanged, &hostIdentityCurrent{RecordID: cur.RecordID + 7, Generation: cur.Generation},
		fmt.Sprintf("%d:%d", cur.RecordID+7, cur.Generation))

	// 候選：另一張表、另一個 resource
	w, err := writeHostIdentityStopAudit(sink, s.f.db, s.candidateInput(hostIdentityPhasePrecheck, verificationSentFalse))
	require.NoError(t, err)
	require.True(t, w)
	require.NotNil(t, s.candidateKey(t))
	assert.Equal(t, token, *s.candidateKey(t))
	w, err = writeHostIdentityStopAudit(sink, s.f.db, s.candidateInput(hostIdentityPhasePrecheck, verificationSentFalse))
	require.NoError(t, err)
	assert.False(t, w)

	// transport / legacy token
	assert.Equal(t, "transport:winrm", hostIdentityStateToken(hostIdentityTransportChanged, nil, "winrm"))
	assert.Equal(t, "legacy", hostIdentityStateToken(hostIdentityUnboundLegacy, nil, "ssh"))
	assert.Equal(t, "missing", hostIdentityStateToken(hostIdentityRecordMissing, s.current, "ssh"))
}

func runStopAuditContent(t *testing.T) {
	s := setupStopFixture(t)
	sink := audit.NewTxSink()
	deadline := s.candidate.CreatedAt.Add(candidateRetryDeadline)

	cin := s.candidateInput(hostIdentityPhaseHandshake, verificationSentFalse)
	cin.Deadline = &deadline
	_, err := writeHostIdentityStopAudit(sink, s.f.db, cin)
	require.NoError(t, err)
	_, err = writeHostIdentityStopAudit(sink, s.f.db, s.memberInput(hostIdentityPhaseCommit, verificationSentTrue))
	require.NoError(t, err)

	rows := s.stopAudits(t)
	require.Len(t, rows, 2)
	byRes := map[model.AuditResource]model.AuditLog{}
	for _, r := range rows {
		byRes[r.Resource] = r
	}
	cand, ok := byRes[model.ResourceChangeSecretPlan]
	require.True(t, ok, "候選歸 change_secret_plan")
	mem, ok := byRes[model.ResourceCredential]
	require.True(t, ok, "成員歸 credential")
	for _, r := range rows {
		assert.Equal(t, string(model.StatusDenied), string(r.Status))
		require.NotNil(t, r.AssetID)
		assert.Equal(t, s.member.AssetID, *r.AssetID)
	}

	var cd, md map[string]any
	require.NoError(t, json.Unmarshal([]byte(cand.Details), &cd))
	require.NoError(t, json.Unmarshal([]byte(mem.Details), &md))
	assert.Equal(t, "host_identity_stop", cd["operation"])
	assert.Equal(t, "handshake", cd["phase"])
	assert.Equal(t, "false", cd["verification_sent"])
	assert.Equal(t, "candidate", cd["job_kind"])
	assert.Equal(t, true, cd["candidate_retained"])
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, cd["reason"])
	assert.NotEmpty(t, cd["deadline"], "沿用原截止時間")
	assert.Equal(t, "commit", md["phase"])
	assert.Equal(t, "true", md["verification_sent"])
	assert.Equal(t, "member", md["job_kind"])
	orig := md["original"].(map[string]any)
	assert.Equal(t, s.member.HostKeyFingerprint, orig["fingerprint"])
	curr := md["current"].(map[string]any)
	assert.Equal(t, s.current.Fingerprint, curr["fingerprint"])
	for _, raw := range []string{cand.Details, mem.Details} {
		low := strings.ToLower(raw)
		for _, banned := range []string{"password", "private_key", "begin ", "ssh-ed25519 aaa", "authorized"} {
			assert.NotContains(t, low, banned, "details 不得含秘密或公鑰本體")
		}
	}

	// 輸入驗證
	_, err = writeHostIdentityStopAudit(sink, s.f.db, hostIdentityStopInput{Detail: "x", Phase: hostIdentityPhaseCommit})
	assert.Error(t, err, "候選與成員都未指定")
	bad := s.memberInput("nowhere", verificationSentTrue)
	_, err = writeHostIdentityStopAudit(sink, s.f.db, bad)
	assert.Error(t, err, "階段不合法")
}

func runStopAuditFailureKeepsKey(t *testing.T) {
	s := setupStopFixture(t)
	boom := errors.New("audit down")
	for name, sink := range map[string]port.TxSink{"注入失敗": failingTxSink{err: boom}, "落地面缺席": nil} {
		t.Run(name, func(t *testing.T) {
			w, err := writeHostIdentityStopAudit(sink, s.f.db, s.memberInput(hostIdentityPhaseCommit, verificationSentTrue))
			require.Error(t, err)
			assert.False(t, w)
			assert.Equal(t, s.baseMemKey, s.memberKey(t), "審計失敗：去重鍵不前進")
			assert.Empty(t, s.stopAudits(t))
		})
	}
	// 失敗之後換成好的落地面，同一狀態仍會被寫入（沒有被誤判為已留痕）
	w, err := writeHostIdentityStopAudit(audit.NewTxSink(), s.f.db, s.memberInput(hostIdentityPhaseCommit, verificationSentTrue))
	require.NoError(t, err)
	assert.True(t, w)
	assert.Len(t, s.stopAudits(t), 1)
	assert.NotNil(t, s.memberKey(t))
}

func runStopNotifyOnceByVerificationSent(t *testing.T) {
	s := setupStopFixture(t)
	sink := audit.NewTxSink()
	cap := &stopNotifyCapture{}

	// 三個 verification_sent 值各用不同身分狀態（不同 token），每個狀態通知恰一次
	steps := []struct {
		sent    string
		detail  string
		cur     *hostIdentityCurrent
		wantSub string
	}{
		{verificationSentFalse, hostIdentityRecordMissing, nil, "這次沒有拿新憑證去登入"},
		{verificationSentTrue, hostIdentityGenerationChanged, s.current, "這次已用新憑證登入驗證過"},
		{verificationSentUnknown, hostIdentityResetPending, &hostIdentityCurrent{RecordID: 5, Generation: 2, ResetPending: true},
			"無法確定這次是否已用新憑證登入"},
	}
	seen := map[string]bool{}
	for _, st := range steps {
		in := s.memberInput(hostIdentityPhaseHandshake, st.sent)
		in.Detail, in.Current = st.detail, st.cur
		before := cap.count()
		w, err := recordHostIdentityStop(sink, s.f.db, cap.fn, in)
		require.NoError(t, err)
		require.True(t, w)
		require.Equal(t, before+1, cap.count(), "提交後恰通知一次")
		msg := cap.last()
		assert.Contains(t, msg, st.wantSub)
		assert.NotContains(t, msg, "未送出任何憑證", "不過度保證")
		seen[msg] = true

		// 同一狀態再來一次：不寫審計、不通知
		w, err = recordHostIdentityStop(sink, s.f.db, cap.fn, in)
		require.NoError(t, err)
		assert.False(t, w)
		assert.Equal(t, before+1, cap.count(), "同一狀態不重複通知")
	}
	assert.Len(t, seen, 3, "三種文案互異")
	for _, r := range cap.rule {
		assert.Equal(t, hostIdentityStopRule, r)
		assert.NotEqual(t, "改密工作因授權失效停止", r)
	}

	// 審計失敗：不通知，去重鍵不前進，之後同一狀態仍可通知
	s2 := setupStopFixture(t)
	cap2 := &stopNotifyCapture{}
	_, err := recordHostIdentityStop(failingTxSink{err: errors.New("audit down")}, s2.f.db, cap2.fn,
		s2.memberInput(hostIdentityPhaseCommit, verificationSentTrue))
	require.Error(t, err)
	assert.Zero(t, cap2.count(), "審計沒落地不通知")
	assert.Equal(t, s2.baseMemKey, s2.memberKey(t), "審計失敗：去重鍵不前進")
	w, err := recordHostIdentityStop(audit.NewTxSink(), s2.f.db, cap2.fn, s2.memberInput(hostIdentityPhaseCommit, verificationSentTrue))
	require.NoError(t, err)
	assert.True(t, w)
	assert.Equal(t, 1, cap2.count())

	// notify 為 nil 不 panic
	s3 := setupStopFixture(t)
	w, err = recordHostIdentityStop(audit.NewTxSink(), s3.f.db, nil, s3.candidateInput(hostIdentityPhasePrecheck, verificationSentFalse))
	require.NoError(t, err)
	assert.True(t, w)
}

func runStopVerificationSentMapping(t *testing.T) {
	cases := []struct {
		phase  string
		passes int
		known  bool
		want   string
	}{
		{hostIdentityPhasePrecheck, 0, true, verificationSentFalse},
		{hostIdentityPhasePrecheck, 3, false, verificationSentFalse},
		{hostIdentityPhaseCommit, 0, false, verificationSentTrue},
		{hostIdentityPhaseHandshake, 0, true, verificationSentFalse},
		{hostIdentityPhaseHandshake, 2, true, verificationSentTrue},
		{hostIdentityPhaseHandshake, 0, false, verificationSentUnknown},
		{"", 0, true, verificationSentUnknown},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, hostIdentityVerificationSent(c.phase, c.passes, c.known), "%s/%d/%v", c.phase, c.passes, c.known)
	}
	// 不認得的值一律當 unknown，不猜 false
	in := hostIdentityStopInput{VerificationSent: "maybe"}
	assert.Equal(t, verificationSentUnknown, in.verificationSent())
}
