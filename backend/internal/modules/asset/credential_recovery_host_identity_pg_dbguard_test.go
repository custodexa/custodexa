package asset

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 本檔是 TestCredentialRecoveryHostIdentityPG 的補強子測試（M-6A-e）：
// confirm_db_layer_only（行程內互斥不作用時，資料庫層單獨擋下雙重承接）、
// member_pin_concurrent（空指紋成員的補記並發）。

// detachProcessLock 讓之後取同一掛載行程內互斥的呼叫拿到另一把全新的鎖：已持有舊鎖的呼叫不受影響
// （它的解鎖函式綁在舊鎖上），新來的呼叫不會被它擋住。等於兩個互不相識的行程。
func detachProcessLock(accountID uint) {
	rotationAccountLocks.Store(accountID, &sync.Mutex{})
}

// blockedBackends 本測試自己的連線中，正在等任何鎖（advisory、列鎖的 transactionid、tuple）的後端數。
func (e *pgIdentityEnv) blockedBackends(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, e.db2.Raw(`SELECT count(*) FROM pg_locks l WHERE l.granted = false
		AND l.locktype IN ('advisory','transactionid','tuple')
		AND l.pid IN (SELECT pid FROM pg_stat_activity WHERE application_name = ?)`, e.appName).Scan(&n).Error)
	return n
}

// 兩個確認各走獨立服務與獨立連線池，且行程內帳號互斥被分開（第二個拿到另一把鎖）：
// 第二個必須是被資料庫層擋住（等鎖），第一個提交後讀到未結案紀錄而回 confirmation_pending，恰一列、恰一次驗證。
func runConcurrentConfirmDBOnly(t *testing.T, e *pgIdentityEnv) {
	g := newPGConfirmTarget(t, e)
	req := acceptDifferent(g.req)
	attBase := g.attempts()
	inTx, paused := make(chan struct{}), make(chan struct{})
	goTx, goRec := make(chan struct{}), make(chan struct{})
	var txOnce, recOnce atomic.Bool
	var relTx, relRec sync.Once
	defer relTx.Do(func() { close(goTx) })
	defer relRec.Do(func() { close(goRec) })
	g.svc.createTxBarrier = func(*gorm.DB) error {
		if txOnce.CompareAndSwap(false, true) {
			close(inTx)
			<-goTx
		}
		return nil
	}
	g.svc.crashAfterRecord = func() error {
		if recOnce.CompareAndSwap(false, true) {
			close(paused)
			<-goRec
		}
		return nil
	}
	res1, res2 := make(chan error, 1), make(chan error, 1)
	go func() { res1 <- g.confirm(g.svc, req) }()
	recvSignal(t, inTx, "第一個確認進入建立交易（持行程內互斥與資料庫鎖）")
	require.Zero(t, e.blockedBackends(t), "前置：此刻沒有任何等鎖者")

	var accountID uint
	require.NoError(t, e.db2.Raw(`SELECT account_id FROM change_secret_candidates WHERE id = ?`, g.jobID).Scan(&accountID).Error)
	require.NotZero(t, accountID)
	detachProcessLock(accountID)

	go func() { res2 <- g.confirm(g.svc2, req) }()
	pollUntil(t, "第二個確認越過行程內互斥、被資料庫層的鎖擋住", 15*time.Second, func() bool { return e.blockedBackends(t) >= 1 })
	select {
	case err := <-res2:
		t.Fatalf("第二個確認不該在第一個交易未提交時返回：%v", err)
	default:
	}
	relTx.Do(func() { close(goTx) })
	recvSignal(t, paused, "第一個確認的紀錄提交")
	requireConflict(t, recvErr(t, res2, "第二個確認的結果"), takeoverDetailConfirmationPending)
	assert.Len(t, confirmRecords(t, g.takeoverTarget), 1, "此刻只有一列")
	relRec.Do(func() { close(goRec) })
	require.NoError(t, recvErr(t, res1, "第一個確認完成"))

	rows := confirmRecords(t, g.takeoverTarget)
	require.Len(t, rows, 1, "恰一列承接紀錄生效")
	assert.EqualValues(t, 1, rows[0].Revision)
	assert.Equal(t, takeoverOutcomeVerified, rows[0].Outcome)
	assert.EqualValues(t, 1, confirmAuditCount(t, g.db), "恰一筆確認審計")
	assert.Equal(t, attBase+1, g.attempts(), "恰一次邏輯驗證")
	assert.EqualValues(t, 1, g.verifies.Load())
}

// --- member_pin_concurrent ---

// pgPinMember 升級前形狀的成員：目標指紋為空、綁定 legacy、帶送出標記。
type pgPinMember struct {
	e       *pgIdentityEnv
	memID   uint
	subject *takeoverSubject
	req     HostIdentityConfirmRequest
	svc1    *HostIdentityTakeoverService
	svc2    *HostIdentityTakeoverService
}

func newPGPinMember(t *testing.T, e *pgIdentityEnv) *pgPinMember {
	t.Helper()
	f := e.f
	require.NoError(t, f.db.AutoMigrate(&model.CredentialRotation{}, &model.CredentialRotationMember{},
		&model.CredentialHostIdentityConfirmation{}))
	e.seedOwnRecord(t)
	now := time.Now()
	rot := model.CredentialRotation{CredentialID: 1, Mode: model.CredentialRotationModeGroup,
		Status: model.CredentialRotationRunning, RequestedBy: 1, RequestedByName: "admin", StartedAt: now}
	require.NoError(t, f.db.Create(&rot).Error)
	mem := model.CredentialRotationMember{RotationID: rot.ID, AccountID: f.accountID, CredentialID: 1,
		Username: f.username, AssetID: f.assetID, State: model.CredentialMemberChangedUnverified,
		SecretSentAt: &now, HostKeyBinding: model.HostKeyBindingLegacy}
	require.NoError(t, f.db.Create(&mem).Error)
	require.Empty(t, mem.TargetFingerprint, "前置：升級前形狀，目標指紋為空")

	authz := newAllowAllAuthorizer()
	p := &pgPinMember{e: e, memID: mem.ID, req: validConfirmRequest(t, f.db, f.assetID),
		subject: &takeoverSubject{assetID: f.assetID, accountID: f.accountID, credentialID: 1}}
	p.svc1 = NewHostIdentityTakeoverService(f.db, authz)
	p.svc1.SetAuditTxSink(audit.NewTxSink())
	p.svc2 = NewHostIdentityTakeoverService(e.db2, authz)
	p.svc2.SetAuditTxSink(audit.NewTxSink())
	return p
}

func (p *pgPinMember) row(t *testing.T) model.CredentialRotationMember {
	t.Helper()
	var m model.CredentialRotationMember
	require.NoError(t, p.e.f.db.Where("id = ?", p.memID).First(&m).Error)
	return m
}

// 補記本身：兩個交易（兩條獨立連線）帶著同一份「指紋仍為空」的舊讀值同時補記。
// 第一個寫入未提交時，第二個被列鎖擋住；第一個提交後第二個的條件式更新不再命中，必須失敗而不覆寫。
// 兩次算出的指紋刻意不同（第一個之後、第二個之前改了資產位址），讓「不覆寫」可由值證明。
func runMemberPinTwoTx(t *testing.T, e *pgIdentityEnv) {
	p := newPGPinMember(t, e)
	stale1, stale2 := p.row(t), p.row(t)

	tx1 := e.f.db.Begin()
	require.NoError(t, tx1.Error)
	defer tx1.Rollback()
	require.NoError(t, pinMemberTargetInTx(tx1, &stale1, p.subject), "第一個補記成功（未提交）")
	first := stale1.TargetFingerprint
	require.NotEmpty(t, first)

	// 資產位址在第一個提交前改變（第三條連線，已提交）：第二個交易會算出不同的指紋
	require.NoError(t, e.db2.Model(&model.Asset{}).Where("id = ?", e.f.assetID).Update("host", "10.77.0.9").Error)

	tx2 := e.db2.Begin()
	require.NoError(t, tx2.Error)
	defer tx2.Rollback()
	res := make(chan error, 1)
	go func() { res <- pinMemberTargetInTx(tx2, &stale2, p.subject) }()
	pollUntil(t, "第二個補記被擋在第一個交易的未提交列上", 10*time.Second, func() bool { return e.blockedBackends(t) >= 1 })
	select {
	case err := <-res:
		t.Fatalf("第二個補記不該在第一個未提交時返回：%v", err)
	default:
	}
	require.NoError(t, tx1.Commit().Error)
	err := recvErr(t, res, "第二個補記的結果")
	require.Error(t, err, "第二個補記必須失敗（條件式更新不命中）")
	assert.ErrorIs(t, err, ErrCredentialAuthzUnavailable)
	assert.True(t, strings.Contains(err.Error(), "補記目標指紋未生效"), "失敗原因為補記未生效：%v", err)
	require.NoError(t, tx2.Rollback().Error)

	assert.Equal(t, first, p.row(t).TargetFingerprint, "既有指紋不被第二個補記覆寫")
	now2, err := loadTargetFingerprint(e.f.db, e.f.accountID)
	require.NoError(t, err)
	assert.NotEqual(t, first, now2, "前置：兩次算出的指紋確實不同（否則覆寫與否無從分辨）")
}

// 兩個確認（獨立服務、獨立連線池、行程內互斥分開）同時對同一個空指紋成員：
// 恰一個補記並建立紀錄，另一個回 confirmation_pending；指紋是第一個補記的值、補記審計恰一筆。
func runMemberPinConcurrentConfirm(t *testing.T, e *pgIdentityEnv) {
	p := newPGPinMember(t, e)
	inTx := make(chan struct{})
	goTx := make(chan struct{})
	var once atomic.Bool
	var rel sync.Once
	defer rel.Do(func() { close(goTx) })
	p.svc1.createTxBarrier = func(*gorm.DB) error {
		if once.CompareAndSwap(false, true) {
			close(inTx)
			<-goTx
		}
		return nil
	}
	res1, res2 := make(chan error, 1), make(chan error, 1)
	create := func(svc *HostIdentityTakeoverService, out chan<- error) {
		_, err := svc.createConfirmation(adminCtx(), takeoverKindMember, p.memID, p.req, p.subject, CredentialManagementDecision{Allowed: true, AuthzVersion: 1})
		out <- err
	}
	go create(p.svc1, res1)
	recvSignal(t, inTx, "第一個確認在建立交易內（已補記、未提交）")
	detachProcessLock(e.f.accountID)
	go create(p.svc2, res2)
	pollUntil(t, "第二個確認被資料庫層的鎖擋住", 15*time.Second, func() bool { return e.blockedBackends(t) >= 1 })
	rel.Do(func() { close(goTx) })
	require.NoError(t, recvErr(t, res1, "第一個確認"))
	requireConflict(t, recvErr(t, res2, "第二個確認"), takeoverDetailConfirmationPending)

	want, err := loadTargetFingerprint(e.f.db, e.f.accountID)
	require.NoError(t, err)
	assert.Equal(t, want, p.row(t).TargetFingerprint, "補記為當下值，且只補記一次")
	var recs []model.CredentialHostIdentityConfirmation
	require.NoError(t, e.f.db.Where("kind = ? AND job_id = ?", takeoverKindMember, p.memID).Find(&recs).Error)
	require.Len(t, recs, 1, "恰一列承接紀錄")
	assert.EqualValues(t, 1, confirmAuditCount(t, e.f.db), "恰一筆確認審計")
	var pinnedAudits int64
	require.NoError(t, e.f.db.Model(&model.AuditLog{}).Where("details LIKE ?", `%"target_pinned_at_confirm":true%`).Count(&pinnedAudits).Error)
	assert.EqualValues(t, 1, pinnedAudits, "恰一筆審計帶補記布林")
}
