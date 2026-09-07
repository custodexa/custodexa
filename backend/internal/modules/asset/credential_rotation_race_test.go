package asset

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 輪替與掛載拓撲之間的交錯序列，以及全域鎖次序的守衛。
//
// # 為什麼交錯要用回呼注入而不是 goroutine
//
// 測試裝配的 sqlite `:memory:` 只有一條連線（多連線＝多個各自獨立的空庫），
// 第二個 goroutine 在交易持有連線期間動不了資料庫，「等鎖期間別人已提交」
// 這件事沒有辦法用並行表達。改以查詢回呼在**交錯點就地提交**：序列、可重現，
// 且落在被測程式碼真正的那一瞬間。
//
// 代價要寫明：注入的寫入與被測交易同屬一條交易，被測交易回滾時它一併回滾。
// 故「拒絕之後不得留下損害」這半段只斷言到「沒有任何指標被清成空」，
// 不斷言注入的那一組值仍在——後者在真實的兩交易情境才成立。

// injectOnce 於某張表的下一次查詢完成後，在同一條連線上提交一次外部改動。
//
// 回傳的旗標必須被斷言：注入點沒打中時測試會以「什麼都沒發生」的形式綠燈，
// 而那正是最看不出來的假綠。
func injectOnce(t *testing.T, db *gorm.DB, table string, fn func(gorm.ConnPool)) *bool {
	t.Helper()
	name := "test:inject:" + table
	fired := false
	require.NoError(t, db.Callback().Query().After("gorm:query").
		Register(name, func(tx *gorm.DB) {
			if fired || tx.Statement == nil || tx.Statement.Table != table {
				return
			}
			fired = true
			fn(tx.Statement.ConnPool)
		}))
	t.Cleanup(func() { _ = db.Callback().Query().Remove(name) })
	return &fired
}

// abandonToOutOfSync 跑一輪、指定幾台的驗證失敗，再放棄，使憑證停在未同步。
func (f *rotationFixture) abandonToOutOfSync(t *testing.T, credID uint,
	failHosts ...string) *model.CredentialRotation {

	t.Helper()
	for _, host := range failHosts {
		f.remote.setVerifyErr(host, errRemoteDropped)
	}
	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
	require.NoError(t, f.rotations.Abandon(adminCtx(), rot.ID))
	state, err := f.rotations.AggregateState(credID)
	require.NoError(t, err)
	require.Equal(t, CredentialAggregateOutOfSync, state, "前提：放棄後停在未同步")
	return rot
}

// --- 發現 1：Abandon 取憑證列鎖後未重讀 ---

// 等鎖期間本輪已收斂、新一輪已成為進行中：放棄必須拒絕，不得清掉新一輪的指標
func TestCredentialAbandonStaleReadRejected(t *testing.T) {
	f := setupRotationFixture(t)
	credID, _ := f.sharedOn(t, "共用-競態", "ops", "old-shared", "10.7.1.1")

	first, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)

	// 「另一條交易」建立的新一輪，欄位形狀與 Start 寫出的同一組
	next := &model.CredentialRotation{
		CredentialID:    credID,
		Epoch:           first.Epoch + 1,
		Mode:            model.CredentialRotationModeGroup,
		TargetVersionID: first.TargetVersionID,
		Status:          model.CredentialRotationRunning,
		StartedAt:       time.Now(),
	}
	require.NoError(t, f.db.Create(next).Error)

	// 注入點＝放棄讀完輪替列、尚未取得憑證列鎖的那一瞬間
	fired := injectOnce(t, f.db, "credential_rotations", func(pool gorm.ConnPool) {
		_, _ = pool.ExecContext(context.Background(),
			"UPDATE credential_rotations SET status = ? WHERE id = ?",
			model.CredentialRotationCompleted, first.ID)
		_, _ = pool.ExecContext(context.Background(),
			"UPDATE credentials SET active_rotation_id = ? WHERE id = ?", next.ID, credID)
	})

	err = f.rotations.Abandon(adminCtx(), first.ID)
	require.True(t, *fired, "注入點必須真的打中，否則本測試什麼都沒驗到")
	require.Error(t, err, "本輪已非憑證進行中的那一輪，放棄必須拒絕")

	cred := f.credential(t, credID)
	require.NotNil(t, cred.ActiveRotationID,
		"拒絕之後不得留下損害：進行中的輪替指標不可被清成空")
	assert.NotZero(t, *cred.ActiveRotationID)
}

// --- 發現 2：未同步期間的掛載拓撲 ---

// 待生效版本仍在時不得掛上新的一台
func TestBindRejectedWhileCredentialOutOfSync(t *testing.T) {
	f := setupRotationFixture(t)
	credID, _ := f.sharedOn(t, "共用-未同步", "ops", "old-shared", "10.7.2.1")
	f.abandonToOutOfSync(t, credID, "10.7.2.1")

	other := newSSHAsset(t, f.assets, "10.7.2.9", "10.7.2.9")
	_, err := f.creds.Bind(adminCtx(), credID, &BindCredentialRequest{AssetID: other.ID})
	assert.ErrorIs(t, err, ErrCredentialOutOfSync, "未同步期間不得改變掛載集合")

	var count int64
	require.NoError(t, f.db.Model(&model.AssetAccount{}).
		Where("credential_id = ?", credID).Count(&count).Error)
	assert.EqualValues(t, 1, count, "掛載集合不變")
}

// 待生效版本仍在時不得改綁走既有的一台
func TestRebindRejectedWhileCredentialOutOfSync(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用-未同步-改綁", "ops", "old-shared", "10.7.3.1")
	f.abandonToOutOfSync(t, credID, "10.7.3.1")
	acc := f.binding(t, accounts[0])

	target, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "閒置乙", Username: "ops2",
		ProtocolFamily: model.ProtocolFamilySSH, Password: "idle-pw",
	})
	require.NoError(t, err)

	_, err = f.creds.Rebind(adminCtx(), acc.AssetID, acc.ID, target.ID)
	assert.ErrorIs(t, err, ErrCredentialOutOfSync, "未同步期間不得改綁")
	assert.Equal(t, credID, f.binding(t, accounts[0]).CredentialID, "掛載仍指向原憑證")
}

// 卸載仍然允許：死主機要能移除，否則未同步沒有出口
func TestUnbindAllowedWhileCredentialOutOfSync(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用-未同步-卸載", "ops", "old-shared",
		"10.7.3.5", "10.7.3.6")
	f.abandonToOutOfSync(t, credID, "10.7.3.5", "10.7.3.6")

	require.NoError(t, f.creds.Unbind(adminCtx(), credID, accounts[1]))
	var count int64
	require.NoError(t, f.db.Model(&model.AssetAccount{}).
		Where("credential_id = ?", credID).Count(&count).Error)
	assert.EqualValues(t, 1, count, "死主機已被移除")
}

// 收斂以**當下存活的掛載**為準：被卸載的成員不再擋住收斂
func TestConvergeIgnoresUnboundMember(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用-收斂", "ops", "old-shared",
		"10.7.4.1", "10.7.4.2")
	rot := f.abandonToOutOfSync(t, credID, "10.7.4.1", "10.7.4.2")

	// 第二台是死主機：卸載（未同步期間唯一被允許的拓撲變更）
	require.NoError(t, f.creds.Unbind(adminCtx(), credID, accounts[1]))

	// 第一台恢復並補跑至就位
	f.remote.setVerifyErr("10.7.4.1", nil)
	member := f.memberFor(t, rot.ID, accounts[0])
	require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, member.ID))

	cred := f.credential(t, credID)
	assert.Nil(t, cred.PendingVersionID, "存活掛載全數就位即收斂")
	require.NotNil(t, cred.CurrentVersionID)
	assert.Equal(t, *rot.TargetVersionID, *cred.CurrentVersionID, "待生效版本提升為現行")
	state, err := f.rotations.AggregateState(credID)
	require.NoError(t, err)
	assert.Equal(t, CredentialAggregateIdle, state)
}

// 卸載掉最後一台未就位的主機：卸載本身即完成收斂，不需要再補跑任何一台
func TestUnbindLastPendingMemberConverges(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用-卸載收斂", "ops", "old-shared",
		"10.7.4.5", "10.7.4.6")
	rot := f.abandonToOutOfSync(t, credID, "10.7.4.6")

	require.Equal(t, model.CredentialMemberApplied,
		f.memberFor(t, rot.ID, accounts[0]).State, "前提：第一台已就位")

	require.NoError(t, f.creds.Unbind(adminCtx(), credID, accounts[1]))

	cred := f.credential(t, credID)
	assert.Nil(t, cred.PendingVersionID, "存活掛載全數就位即收斂")
	require.NotNil(t, cred.CurrentVersionID)
	assert.Equal(t, *rot.TargetVersionID, *cred.CurrentVersionID)
	state, err := f.rotations.AggregateState(credID)
	require.NoError(t, err)
	assert.Equal(t, CredentialAggregateIdle, state)
}

// --- 發現 3：SetSecret 於未同步期間取代待生效版本 ---

// 操作者宣告的密文取代舊輪替：待生效版本清空、舊輪替不得再推進
func TestSetSecretSupersedesPendingRotation(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用-取代", "ops", "old-shared", "10.7.5.1")
	rot := f.abandonToOutOfSync(t, credID, "10.7.5.1")
	_, before, _ := f.remote.snapshot()

	_, err := f.creds.SetSecret(adminCtx(), credID,
		&SetCredentialSecretRequest{Password: "declared-now"})
	require.NoError(t, err)

	cred := f.credential(t, credID)
	assert.Nil(t, cred.PendingVersionID, "宣告的密文取代待生效版本")
	assert.Equal(t, "declared-now", f.secretOfBinding(t, accounts[0]),
		"全部掛載就位到宣告的版本")

	// 遠端恢復正常：補跑若被放行就會成功，並把就位版本改寫回舊的待生效版本。
	// 這正是要擋掉的那件事，故必須在「補跑會成功」的前提下驗拒絕
	f.remote.setVerifyErr("10.7.5.1", nil)
	member := f.memberFor(t, rot.ID, accounts[0])
	assert.Error(t, f.rotations.RunMember(adminCtx(), rot.ID, member.ID),
		"已被取代的輪替不得再推進")

	_, after, _ := f.remote.snapshot()
	assert.Equal(t, before["10.7.5.1"], after["10.7.5.1"],
		"不得再對遠端下達已被取代的秘密")
	assert.Equal(t, "declared-now", f.secretOfBinding(t, accounts[0]),
		"就位版本未被舊輪替改寫回去")
	state, err := f.rotations.AggregateState(credID)
	require.NoError(t, err)
	assert.Equal(t, CredentialAggregateIdle, state)
}

// --- 發現 4：遠端在途與放棄並發 ---

// hookedExecutor 在遠端下達的當下插入一次外部動作（不改既有 recorder 的形狀）。
type hookedExecutor struct {
	inner    rotationExecutor
	onRotate func()
}

func (h *hookedExecutor) Rotate(ctx context.Context, t rotationTarget, old, next string) error {
	if h.onRotate != nil {
		fn := h.onRotate
		h.onRotate = nil
		fn()
	}
	return h.inner.Rotate(ctx, t, old, next)
}

func (h *hookedExecutor) Verify(ctx context.Context, t rotationTarget, secret string) error {
	return h.inner.Verify(ctx, t, secret)
}

// 成員在途時放棄本輪：遠端隨後成功，就位是**事實為真**，收斂結果與設計一致
func TestAbandonDuringInflightMemberKeepsAppliedFactTrue(t *testing.T) {
	f := setupRotationFixture(t)
	credID, accounts := f.sharedOn(t, "共用-在途", "ops", "old-shared", "10.7.6.1")

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)

	hooked := &hookedExecutor{inner: f.remote}
	abandoned := false
	hooked.onRotate = func() {
		require.NoError(t, f.rotations.Abandon(adminCtx(), rot.ID))
		abandoned = true
	}
	f.rotations.executors = func(string) rotationExecutor { return hooked }

	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
	require.True(t, abandoned, "前提：放棄確實發生在遠端下達的當下")

	member := f.memberFor(t, rot.ID, accounts[0])
	assert.Equal(t, model.CredentialMemberApplied, member.State,
		"遠端確實收下並驗證通過：就位是事實為真")

	delivered, _, _ := f.remote.snapshot()
	assert.Equal(t, f.secretOfBinding(t, accounts[0]), delivered["10.7.6.1"],
		"就位版本正是遠端當下生效的那一組")

	cred := f.credential(t, credID)
	assert.Nil(t, cred.ActiveRotationID)
	assert.Nil(t, cred.PendingVersionID)
	require.NotNil(t, cred.CurrentVersionID)
	assert.Equal(t, *rot.TargetVersionID, *cred.CurrentVersionID)

	var reloaded model.CredentialRotation
	require.NoError(t, f.db.Where("id = ?", rot.ID).First(&reloaded).Error)
	assert.Equal(t, model.CredentialRotationCompleted, reloaded.Status,
		"放棄的輪替全員就位後照樣收斂為完成（逐台補跑的出口語義）")
}

// --- 發現 5：全域鎖次序 ---

// lockOrderSources 參與掃描的檔案（本套件的非測試碼）。
func lockOrderSources(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	require.NoError(t, err)
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		out = append(out, p)
	}
	require.NotEmpty(t, out)
	return out
}

// lockEvents 某個函式本體（含巢狀 func literal）內兩把持久列鎖的呼叫次序。
//
// 只看**直接呼叫**，不追進被呼叫的函式：跨函式展開會把不同分支的鎖事件混成一串，
// 於是幾乎每個入口都被判成違規，而那種訊號分不出真假（實測 12 筆全為誤報）。
// 跨函式的次序改由檔頭的清單與 lockAssetsOfCredential 這類「先鎖再進去」的
// 寫法承擔，本守衛負責的是同一個本體內寫反的那一種。
func lockEvents(body ast.Node) (firstAsset, firstCredential int) {
	firstAsset, firstCredential = -1, -1
	idx := 0
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		switch ident.Name {
		case "lockAssetForAccountMutation", "lockAssetsOfCredential":
			if firstAsset < 0 {
				firstAsset = idx
			}
		case "lockCredentialRow", "lockCredentialRowsOrdered":
			if firstCredential < 0 {
				firstCredential = idx
			}
		default:
			return true
		}
		idx++
		return true
	})
	return firstAsset, firstCredential
}

// 全域鎖次序＝先資產列、後憑證列。同一個函式本體同時取兩把鎖時，資產列必須在前
// ——次序反過來的那一條路徑會與其餘路徑交錯死鎖，而死鎖只在並行下出現、
// 單測永遠看不到。
func TestRowLockOrderAssetBeforeCredential(t *testing.T) {
	both := make([]string, 0, 8)
	for _, path := range lockOrderSources(t) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, err, path)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			asset, credential := lockEvents(fn.Body)
			if asset < 0 || credential < 0 {
				continue
			}
			both = append(both, fn.Name.Name)
			assert.Less(t, asset, credential,
				"%s（%s）先取憑證列鎖再取資產列鎖，違反全域鎖次序（先資產、後憑證）",
				fn.Name.Name, path)
		}
	}
	sort.Strings(both)
	// 命中數歸零時上面的迴圈一句斷言也沒跑，那是最看不出來的假綠
	require.GreaterOrEqual(t, len(both), 5,
		"同時取兩把鎖的函式少於預期，掃描可能已失效（命中：%v）", both)
}

// funcKey 以「接收者型別.函式名」為鍵：本套件有九個 Create、兩個 Delete，
// 只用函式名的表會把不同型別的方法混成同一列，而混掉的那一列不會有任何訊號。
func funcKey(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	typ := fn.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if ident, ok := typ.(*ast.Ident); ok {
		return ident.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// 只取憑證列鎖、資產列鎖由呼叫端負責的那些函式必須逐筆列名。
//
// **這張表是釘子不是推導值**：新長出一條只鎖憑證的路徑時，作者必須回到這裡回答
// 「它的呼叫端有沒有先鎖資產」，而不是讓它靜靜地加入一個由生產碼算出來的集合。
func TestCredentialOnlyLockSitesAreEnumerated(t *testing.T) {
	want := map[string]string{
		"lockCredentialRowsOrdered":                    "取鎖本體（依憑證識別升冪）",
		"lockCredentialsForBindingRemoval":             "呼叫端 removeAssetBindings 已先取資產列鎖",
		"appendDeclaredSecret":                         "呼叫端（帳號／資產更新）已先取資產列鎖",
		"rebindBindingToCredential":                    "呼叫端 promoteToCredential 已先取資產列鎖",
		"CredentialService.ConvertScope":               "只動憑證列",
		"CredentialService.SetSecret":                  "只動憑證與版本列",
		"CredentialService.Delete":                     "只動憑證列",
		"CredentialRotationService.Start":              "只動憑證列",
		"CredentialRotationService.Abandon":            "只動憑證列",
		"CredentialRotationService.startSplitRotation": "只動憑證列",
		"settleBatchSharedCredential":                  "只動憑證列（範圍收尾）",
		// 新建資產的掛載：那一列此刻還不存在，資產列鎖無物可鎖（見
		// lockAssetForAccountMutation 的註解），互斥由建立本身的唯一性承擔
		"AssetService.Create": "掛載列於本交易內才建立，無既有列可鎖",
	}
	got := map[string]bool{}
	for _, path := range lockOrderSources(t) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, err, path)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			asset, credential := lockEvents(fn.Body)
			if credential >= 0 && asset < 0 {
				got[funcKey(fn)] = true
			}
		}
	}
	for name := range got {
		_, listed := want[name]
		assert.True(t, listed,
			"%s 只取憑證列鎖：確認它的呼叫端已先取資產列鎖之後，補進本表", name)
	}
	for name := range want {
		assert.True(t, got[name], "%s 已不再只取憑證列鎖，本表該刪這一列", name)
	}
}
