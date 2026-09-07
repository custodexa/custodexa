package asset

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 共用憑證整組改密的行為鎖定：啟動快照、成員狀態轉移表、部分成功、收斂、
// 重試與補跑、放棄不回滾、期間鎖定與金鑰型別。
//
// 遠端協定不是本檔的責任：以可換的執行器注入，不連任何目標機。真連線行為由
// 改密可靠性測試承擔。

// --- 裝配 ---

type rotationFixture struct {
	db         *gorm.DB
	assets     *AssetService
	accounts   *AssetAccountService
	creds      *CredentialService
	rotations  *CredentialRotationService
	candidates *ChangeSecretCandidateService
	remote     *rotationRecorder
	// perms 輪替引擎所用的權限判定樁：預設全放行，需要驗拒絕面的測試逐台改寫
	perms *fakePermissionChecker
}

// rotationRecorder 可換的執行器：記下每台收到的新秘密與各階段的呼叫次數。
//
// **次數要記**：「兩台各自以自己的版本連線，且各只發生一次登入嘗試」這條不變式，
// 沒有計數就只能驗到前半段。
type rotationRecorder struct {
	mu           sync.Mutex
	rotated      map[string]string
	verified     map[string]string
	rotateCalls  map[string]int
	verifyCalls  map[string]int
	rotateErr    map[string]error
	verifyErr    map[string]error
	keyDelivered map[string]string
}

func newRotationRecorder() *rotationRecorder {
	return &rotationRecorder{
		rotated: map[string]string{}, verified: map[string]string{},
		rotateCalls: map[string]int{}, verifyCalls: map[string]int{},
		rotateErr: map[string]error{}, verifyErr: map[string]error{},
		keyDelivered: map[string]string{},
	}
}

func (r *rotationRecorder) Rotate(_ context.Context, t rotationTarget, _, newSecret string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rotateCalls[t.asset.Host]++
	if err := r.rotateErr[t.asset.Host]; err != nil {
		return err
	}
	r.rotated[t.asset.Host] = newSecret
	return nil
}

func (r *rotationRecorder) Verify(_ context.Context, t rotationTarget, newSecret string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verifyCalls[t.asset.Host]++
	if err := r.verifyErr[t.asset.Host]; err != nil {
		return err
	}
	r.verified[t.asset.Host] = newSecret
	return nil
}

func (r *rotationRecorder) setRotateErr(host string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rotateErr[host] = err
}

func (r *rotationRecorder) setVerifyErr(host string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verifyErr[host] = err
}

func (r *rotationRecorder) snapshot() (map[string]string, map[string]int, map[string]int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]string{}
	for k, v := range r.rotated {
		out[k] = v
	}
	rc := map[string]int{}
	for k, v := range r.rotateCalls {
		rc[k] = v
	}
	vc := map[string]int{}
	for k, v := range r.verifyCalls {
		vc[k] = v
	}
	return out, rc, vc
}

// keyApplier 金鑰三段式的可換替身：記下每台收到的私鑰並沿用同一組錯誤分流。
func (r *rotationRecorder) applyKey(ctx context.Context, exec rotationExecutor, rt rotationTarget,
	_ changeSecretTarget, _, _, newPrivate, _, _, _ string, onDelivered func()) error {

	r.mu.Lock()
	r.rotateCalls[rt.asset.Host]++
	if err := r.rotateErr[rt.asset.Host]; err != nil {
		r.mu.Unlock()
		return err
	}
	r.keyDelivered[rt.asset.Host] = newPrivate
	r.mu.Unlock()
	if onDelivered != nil {
		onDelivered()
	}
	return exec.Verify(ctx, rt, newPrivate)
}

func setupRotationFixture(t *testing.T) *rotationFixture {
	t.Helper()
	db := setupCredentialDB(t)
	require.NoError(t, db.AutoMigrate(
		&model.CredentialRotation{}, &model.CredentialRotationMember{},
		&model.AssetHostKey{}, &model.ChangeSecretRecord{},
	))
	codec := aesColumnCodec(t, make([]byte, 32))
	assets, err := NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	accounts := NewAssetAccountService(assets, codec, audit.NewTxSink())
	creds := NewCredentialService(assets, codec, audit.NewTxSink())
	candidates, err := NewChangeSecretCandidateService(db, codec, assets, audit.NewTxSink())
	require.NoError(t, err)
	perms := &fakePermissionChecker{allow: map[uint]bool{}, defaultAllow: true}
	rotations := NewCredentialRotationService(db, assets, candidates, NewHostKeyService(db),
		codec, audit.NewTxSink(), perms)
	remote := newRotationRecorder()
	rotations.executors = func(string) rotationExecutor { return remote }
	rotations.keyApplier = remote.applyKey
	return &rotationFixture{
		db: db, assets: assets, accounts: accounts, creds: creds,
		rotations: rotations, candidates: candidates, remote: remote, perms: perms,
	}
}

// sharedOn 建一筆共用憑證並掛到指定的幾台 SSH 資產上，回傳憑證 id 與逐台掛載 id。
func (f *rotationFixture) sharedOn(t *testing.T, name, username, secret string, hosts ...string) (uint, []uint) {
	t.Helper()
	req := &CreateCredentialRequest{
		Name: name, Username: username, ProtocolFamily: model.ProtocolFamilySSH,
		Password: secret,
	}
	cred, err := f.creds.Create(adminCtx(), req)
	require.NoError(t, err)

	accountIDs := make([]uint, 0, len(hosts))
	for _, host := range hosts {
		asset := newSSHAsset(t, f.assets, host, host)
		binding, berr := f.creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: asset.ID})
		require.NoError(t, berr)
		accountIDs = append(accountIDs, binding.ID)
	}
	return cred.ID, accountIDs
}

func (f *rotationFixture) credential(t *testing.T, id uint) *model.Credential {
	t.Helper()
	cred, err := loadCredential(f.db, id)
	require.NoError(t, err)
	return cred
}

func (f *rotationFixture) binding(t *testing.T, accountID uint) *model.AssetAccount {
	t.Helper()
	var acc model.AssetAccount
	require.NoError(t, f.db.Where("id = ?", accountID).First(&acc).Error)
	return &acc
}

func (f *rotationFixture) memberFor(t *testing.T, rotationID, accountID uint) *model.CredentialRotationMember {
	t.Helper()
	var m model.CredentialRotationMember
	require.NoError(t, f.db.Where("rotation_id = ? AND account_id = ?", rotationID, accountID).
		First(&m).Error)
	return &m
}

// secretOfBinding 以解析器取回該掛載當下用以連線的密碼（就位版本）。
func (f *rotationFixture) secretOfBinding(t *testing.T, accountID uint) string {
	t.Helper()
	acc := f.binding(t, accountID)
	resolved, err := f.assets.resolver.ResolveForBinding(context.Background(), acc.AssetID, acc.ID)
	require.NoError(t, err)
	return resolved.Password
}

func (f *rotationFixture) versionCount(t *testing.T, credentialID uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&model.CredentialSecretVersion{}).
		Where("credential_id = ?", credentialID).Count(&n).Error)
	return n
}

func (f *rotationFixture) candidateCountFor(t *testing.T, accountID uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).
		Where("account_id = ?", accountID).Count(&n).Error)
	return n
}

// --- 4.1 啟動交易 ---

// 啟動即快照全部掛載為成員列，並遞增輪替代數
func TestCredentialRotationStartSnapshotsAllBindings(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用甲", "ops", "old-shared", "10.9.0.1", "10.9.0.2", "10.9.0.3")
	before := f.credential(t, credID)

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)

	members, err := f.rotations.Members(rot.ID)
	require.NoError(t, err)
	require.Len(t, members, len(accounts), "成員數等於掛載數")

	got := make([]uint, 0, len(members))
	for i := range members {
		got = append(got, members[i].AccountID)
		assert.Equal(t, model.CredentialMemberQueued, members[i].State)
		assert.Equal(t, credID, members[i].CredentialID, "成員快照憑證識別")
		assert.Equal(t, "ops", members[i].Username, "成員快照登入帳號名")
		assert.NotZero(t, members[i].AssetID)
		assert.NotEmpty(t, members[i].AssetName, "成員快照資產名")
		require.NotNil(t, members[i].TargetVersionID)
		assert.Equal(t, *rot.TargetVersionID, *members[i].TargetVersionID)
	}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	want := append([]uint(nil), accounts...)
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	assert.Equal(t, want, got, "成員逐一對應當下的掛載")

	after := f.credential(t, credID)
	assert.Equal(t, before.RotationEpoch+1, after.RotationEpoch, "輪替代數遞增")
	assert.Equal(t, rot.Epoch, after.RotationEpoch, "成員快照的代數與憑證一致")
	require.NotNil(t, after.ActiveRotationID)
	assert.Equal(t, rot.ID, *after.ActiveRotationID)
	require.NotNil(t, after.PendingVersionID)
	assert.Equal(t, *rot.TargetVersionID, *after.PendingVersionID)
	assert.NotEqual(t, *after.PendingVersionID, *after.CurrentVersionID,
		"待生效版本是新的一版，現行版本此刻不動")

	// 待生效版本已落庫，但沒有任何一台的就位版本被提前改指
	for _, accountID := range accounts {
		acc := f.binding(t, accountID)
		require.NotNil(t, acc.EffectiveVersionID)
		assert.Equal(t, *before.CurrentVersionID, *acc.EffectiveVersionID,
			"系統產生的密文未經驗證不得改寫就位版本")
	}
	state, err := f.rotations.AggregateState(credID)
	require.NoError(t, err)
	assert.Equal(t, CredentialAggregateQueued, state)
}

// --- 4.2／4.3 成員狀態轉移表（守衛） ---

// wantMemberTransitions 轉移表的**字面釘子**。
//
// 與生產表逐格比對而非由它推導：由生產表推導出期望值的守衛，在「有人多加一條
// 非法轉移」時會跟著一起改變期望，永遠不會轉紅。
var wantMemberTransitions = map[string][]string{
	model.CredentialMemberQueued: {model.CredentialMemberChanging, model.CredentialMemberAbandoned},
	// changing／changed_unverified 多出的 abandoned：待生效版本被操作者宣告的密文
	// 取代時，本輪未就位的成員就地收束（supersedePendingRotation）
	model.CredentialMemberChanging:          {model.CredentialMemberChangedUnverified, model.CredentialMemberRetryWait, model.CredentialMemberTerminalFailed, model.CredentialMemberAbandoned},
	model.CredentialMemberChangedUnverified: {model.CredentialMemberApplied, model.CredentialMemberTerminalFailed, model.CredentialMemberAbandoned},
	model.CredentialMemberApplied:           {},
	model.CredentialMemberRetryWait:         {model.CredentialMemberChanging, model.CredentialMemberTerminalFailed, model.CredentialMemberAbandoned},
	model.CredentialMemberTerminalFailed:    {model.CredentialMemberQueued},
	model.CredentialMemberAbandoned:         {model.CredentialMemberQueued},
}

// stateCell 一格轉移的測試對象：一筆掛載、它的兩個版本與一列成員。
type stateCell struct {
	member    *model.CredentialRotationMember
	accountID uint
	fromVer   uint
	targetVer uint
}

// seedStateCell 為單一格造一個獨立的成員列（每格互不影響）。
func (f *rotationFixture) seedStateCell(t *testing.T, host, state string) *stateCell {
	t.Helper()
	asset := newSSHAsset(t, f.assets, host, host)
	var acc model.AssetAccount
	require.NoError(t, f.db.Where("asset_id = ?", asset.ID).First(&acc).Error)
	require.NotNil(t, acc.EffectiveVersionID)
	fromVer := *acc.EffectiveVersionID

	var target *model.CredentialSecretVersion
	require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
		v, err := appendCredentialVersion(tx, acc.CredentialID,
			model.ChangeSecretTypePassword, "enc-next", "", model.CredentialVersionReasonRotation)
		target = v
		return err
	}))

	rot := &model.CredentialRotation{
		CredentialID: acc.CredentialID, Epoch: 1, Mode: model.CredentialRotationModeGroup,
		TargetVersionID: &target.ID, Status: model.CredentialRotationRunning, StartedAt: time.Now(),
	}
	require.NoError(t, f.db.Create(rot).Error)
	member := &model.CredentialRotationMember{
		RotationID: rot.ID, AccountID: acc.ID, CredentialID: acc.CredentialID,
		Username: acc.Username, AssetID: asset.ID, AssetName: asset.Name,
		FromVersionID: &fromVer, TargetVersionID: &target.ID, State: state,
	}
	require.NoError(t, f.db.Create(member).Error)
	return &stateCell{member: member, accountID: acc.ID, fromVer: fromVer, targetVer: target.ID}
}

// 轉移表逐格：合法轉移成功、非法轉移被拒，且非 applied 的轉移一律不改就位版本
func TestCredentialRotationMemberStateTable(t *testing.T) {
	// 1) 生產表與字面釘子逐格相等——多一條或少一條都轉紅
	assert.Equal(t, len(wantMemberTransitions), len(credentialMemberTransitions),
		"轉移表的狀態數與期望不符")
	for from, want := range wantMemberTransitions {
		got, ok := credentialMemberTransitions[from]
		require.True(t, ok, "轉移表缺少狀態 %s", from)
		assert.ElementsMatch(t, want, got, "狀態 %s 的可轉入集合與期望不符", from)
	}
	for from := range credentialMemberTransitions {
		_, ok := wantMemberTransitions[from]
		assert.True(t, ok, "轉移表出現期望之外的狀態 %s", from)
	}
	assert.ElementsMatch(t, credentialMemberStates, keysOf(wantMemberTransitions),
		"狀態全集與轉移表的鍵不一致")

	// 2) 逐格行為：7 × 7 全部走一次真的轉移
	f := setupRotationFixture(t)
	n := 0
	for _, from := range credentialMemberStates {
		for _, to := range credentialMemberStates {
			n++
			host := "10.8." + strconv.Itoa(n/250) + "." + strconv.Itoa(n%250)
			cell := f.seedStateCell(t, host, from)
			err := f.db.Transaction(func(tx *gorm.DB) error {
				return transitionMember(tx, cell.member, to, memberTransition{})
			})
			allowed := containsState(wantMemberTransitions[from], to)
			if allowed {
				require.NoErrorf(t, err, "合法轉移被拒: %s -> %s", from, to)
			} else {
				require.ErrorIsf(t, err, ErrMemberTransitionNotAllowed,
					"非法轉移未被拒: %s -> %s", from, to)
			}

			acc := f.binding(t, cell.accountID)
			require.NotNil(t, acc.EffectiveVersionID)
			if allowed && to == model.CredentialMemberApplied {
				assert.Equalf(t, cell.targetVer, *acc.EffectiveVersionID,
					"轉入 applied 應把就位版本改為目標版本: %s -> %s", from, to)
				continue
			}
			assert.Equalf(t, cell.fromVer, *acc.EffectiveVersionID,
				"非 applied 的轉移不得改動就位版本: %s -> %s", from, to)
		}
	}
	assert.Equal(t, len(credentialMemberStates)*len(credentialMemberStates), n,
		"轉移表的每一格都要有案例")
}

func keysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func containsState(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// --- 受影響資產的權限 ---

// 發起類動作須驗操作者對受影響資產的權限：其中一台無權即整筆拒絕，遠端零觸碰。
//
// 整組改密與拆分動的是憑證當下的**全部掛載**，故逐台驗；單台脫離只動那一台，
// 故驗那一台。被拒時遠端一次都不能被碰——「先改了一台才發現另一台沒權」與
// 沒驗權在後果上沒有分別，那台機器的秘密已經換掉了。
func TestCredentialRotationRequiresPermissionOnBoundAssets(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "驗權共用", "ops", "old-shared", "10.14.0.1", "10.14.0.2")
	deniedAccount := accounts[1]
	deniedAsset := f.binding(t, deniedAccount).AssetID
	f.perms.denyAsset(deniedAsset)

	before := f.credential(t, credID)
	versionsBefore := f.versionCount(t, credID)

	_, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	assert.ErrorIs(t, err, ErrCredentialBindForbidden, "整組改密的射程是全部掛載")

	_, err = f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
	assert.ErrorIs(t, err, ErrCredentialBindForbidden, "拆分同樣動全部掛載的遠端秘密")

	_, err = f.rotations.Detach(adminCtx(), credID, deniedAccount, DetachCredentialRequest{
		Source: DetachSourceRandom,
	})
	assert.ErrorIs(t, err, ErrCredentialBindForbidden, "脫離動的是那一台的遠端秘密")

	rotated, rotateCalls, verifyCalls := f.remote.snapshot()
	assert.Empty(t, rotated, "被拒的動作不得觸碰任何遠端")
	assert.Empty(t, rotateCalls)
	assert.Empty(t, verifyCalls)

	after := f.credential(t, credID)
	assert.Equal(t, before.RotationEpoch, after.RotationEpoch, "被拒的動作不得遞增輪替代數")
	assert.Nil(t, after.ActiveRotationID, "被拒的動作不得留下進行中的輪替")
	assert.Nil(t, after.PendingVersionID, "被拒的動作不得留下待生效版本")
	assert.Equal(t, versionsBefore, f.versionCount(t, credID), "被拒的動作不得追加密文版本")
	var rotationRows int64
	require.NoError(t, f.db.Model(&model.CredentialRotation{}).
		Where("credential_id = ?", credID).Count(&rotationRows).Error)
	assert.EqualValues(t, 0, rotationRows, "被拒的動作不得留下輪替列")
	assert.EqualValues(t, 0, f.candidateCountFor(t, deniedAccount), "被拒的脫離不得留下候選")

	// 反假綠：補齊那一台的權限後同一個動作即成立，且兩台都被問過
	f.perms.allow[deniedAsset] = true
	f.perms.asked = nil
	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NotNil(t, rot)
	for _, accountID := range accounts {
		assert.Contains(t, f.perms.asked, f.binding(t, accountID).AssetID,
			"每一台掛載資產都必須被問過")
	}
}

// 判定器缺席時發起類動作一律拒絕：無從判定權限不得以放行收場。
//
// 建構期必填已在編譯期擋下大部分情形，本測試釘的是「顯式帶 nil 進來」的殘餘路徑。
func TestCredentialRotationFailsClosedWithoutAuthorization(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "無判定器", "ops", "old-shared", "10.14.1.1", "10.14.1.2")
	f.rotations.authz = nil

	_, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	assert.ErrorIs(t, err, ErrCredentialAuthzUnavailable, "整組改密")
	_, err = f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
	assert.ErrorIs(t, err, ErrCredentialAuthzUnavailable, "拆分")
	_, err = f.rotations.Detach(adminCtx(), credID, accounts[0], DetachCredentialRequest{
		Source: DetachSourceRandom,
	})
	assert.ErrorIs(t, err, ErrCredentialAuthzUnavailable, "單台脫離")

	rotated, rotateCalls, _ := f.remote.snapshot()
	assert.Empty(t, rotated, "判定器缺席時遠端零觸碰")
	assert.Empty(t, rotateCalls)
}
