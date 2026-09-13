package keyvault

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
	"gorm.io/gorm"
)

// DEK 快取存活期的行為測試。
//
// 全部以 fake KEK provider 驅動：本組要驗的是 keyvault 呼叫層的生命期、
// single-flight、故障處置與封印優先序，不是任何 driver 的傳輸行為。

// fakeKEK 可計次、可注入故障、可阻塞的 KEK provider。
type fakeKEK struct {
	inner crypto.KEKProvider

	mu sync.Mutex
	// unwraps Unwrap 的呼叫次數（single-flight 的觀測點）
	unwraps int
	// wraps Wrap 的呼叫次數：包裹是具副作用的一側（寫金鑰表），
	// 解封重試若把它一起重做，這個數字就會漲
	wraps int
	// failWith 非 nil 時 Unwrap 直接回這個錯（模擬保管處故障或拒絕）
	failWith error
	// entered 每次進入 Unwrap 時送一則（測試據此得知遠端呼叫已開始）
	entered chan struct{}
	// gate 非 nil 時 Unwrap 阻塞直到它被關閉
	gate chan struct{}
}

func newFakeKEK(t *testing.T, b byte) *fakeKEK {
	t.Helper()
	inner, err := crypto.NewEnvKEKProvider(kmTestKey(b))
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	return &fakeKEK{inner: inner, entered: make(chan struct{}, 64)}
}

func (f *fakeKEK) Wrap(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	f.mu.Lock()
	f.wraps++
	f.mu.Unlock()
	return f.inner.Wrap(ctx, plaintext, aad)
}
func (f *fakeKEK) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	f.mu.Lock()
	f.unwraps++
	fail, gate := f.failWith, f.gate
	f.mu.Unlock()
	select {
	case f.entered <- struct{}{}:
	default:
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if fail != nil {
		return nil, fail
	}
	return f.inner.Unwrap(ctx, wrapped, aad)
}
func (f *fakeKEK) KeyRef() crypto.KeyRef { return f.inner.KeyRef() }
func (f *fakeKEK) Mode() string          { return f.inner.Mode() }
func (f *fakeKEK) FormatTag() string     { return f.inner.FormatTag() }
func (f *fakeKEK) ReEncrypt(ctx context.Context, wrapped, aad []byte, from crypto.KEKProvider) ([]byte, error) {
	return f.inner.ReEncrypt(ctx, wrapped, aad, from)
}
func (f *fakeKEK) unwrapCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.unwraps }
func (f *fakeKEK) wrapCount() int   { f.mu.Lock(); defer f.mu.Unlock(); return f.wraps }
func (f *fakeKEK) setFail(err error) { f.mu.Lock(); f.failWith = err; f.mu.Unlock() }
func (f *fakeKEK) setGate(c chan struct{}) { f.mu.Lock(); f.gate = c; f.mu.Unlock() }

// fakeTTLPolicy 存活期政策的測試來源。
type fakeTTLPolicy struct{ ttl atomic.Value }

func (p *fakeTTLPolicy) set(v string) { p.ttl.Store(v) }
func (p *fakeTTLPolicy) Get(key string) string {
	if key != policy.PolicyDekCacheTTLSeconds {
		return ""
	}
	v, _ := p.ttl.Load().(string)
	return v
}
func (p *fakeTTLPolicy) GetInt(string) int { return 100000 }

// dekTestRig 一組已 bootstrap 的 KeyManager＋fake provider＋可調政策＋可推進的時鐘。
type dekTestRig struct {
	km   *KeyManagerService
	kek  *fakeKEK
	pol  *fakeTTLPolicy
	db   *gorm.DB
	base time.Time
	// advanceNanos 相對 base 的推進量（原子，供 -race 下的併發讀）
	advanceNanos atomic.Int64
}

func newDEKTestRig(t *testing.T, ttl string) *dekTestRig {
	t.Helper()
	db := newMigrationDB(t)
	kek := newFakeKEK(t, 1)
	km, err := InitKeyManager(db, kek)
	if err != nil {
		t.Fatalf("InitKeyManager: %v", err)
	}
	rig := &dekTestRig{km: km, kek: kek, pol: &fakeTTLPolicy{}, db: db, base: time.Now()}
	rig.pol.set(ttl)
	km.SetPolicySource(rig.pol)
	km.nowFn = func() time.Time { return rig.base.Add(time.Duration(rig.advanceNanos.Load())) }
	return rig
}

func (r *dekTestRig) advance(d time.Duration) { r.advanceNanos.Add(int64(d)) }

func (r *dekTestRig) ref() crypto.CipherRef {
	return crypto.CipherRef{Table: "assets", Column: "password_enc"}
}

// dataMaterial 目前快取中的 data DEK 材料（測試專用直讀）。
func (r *dekTestRig) dataMaterial(ver int) []byte {
	r.km.mu.RLock()
	defer r.km.mu.RUnlock()
	return r.km.keys[model.DataKeyPurposeData][ver]
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// TestDekUnsetTTLKeepsCurrentBehaviour 未設定存活期＝現行行為零退化：
// 運行期加解密不觸發任何 KEK 操作。
func TestDekUnsetTTLKeepsCurrentBehaviour(t *testing.T) {
	rig := newDEKTestRig(t, "")
	before := rig.kek.unwrapCount()
	for i := 0; i < 5; i++ {
		ct, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("secret"))
		if err != nil {
			t.Fatalf("加密失敗: %v", err)
		}
		got, err := rig.km.DecryptBytesFor(context.Background(), rig.ref(), ct)
		if err != nil {
			t.Fatalf("解密失敗: %v", err)
		}
		got.Destroy()
	}
	if after := rig.kek.unwrapCount(); after != before {
		t.Errorf("未設定存活期時運行期觸發了 %d 次 KEK 解封，應為 0", after-before)
	}
}

// TestDekFixedTTLExpiresAndZeroizes 固定期限到期後重解，且原 buffer 逐位元組歸零。
//
// **只 `delete(map)` 的實作會被本測試擋下**：`ciphers[ver]` 與 `keys[data][ver]`
// 持有同一段 slice，丟參考時 raw 仍是原內容，allZero 立刻為 false。
func TestDekFixedTTLExpiresAndZeroizes(t *testing.T) {
	rig := newDEKTestRig(t, "300")
	ct, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("secret"))
	if err != nil {
		t.Fatalf("加密失敗: %v", err)
	}
	raw := rig.dataMaterial(1)
	if raw == nil || allZero(raw) {
		t.Fatalf("前提不成立：快取中無 data DEK 材料")
	}
	captured := raw // 同一段 slice，覆寫後由此觀察

	rig.advance(299 * time.Second)
	before := rig.kek.unwrapCount()
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err != nil {
		t.Fatalf("期限內加密失敗: %v", err)
	}
	if got := rig.kek.unwrapCount(); got != before {
		t.Errorf("期限內觸發了 %d 次解封，應為 0（存取不得續期，但也不得提前到期）", got-before)
	}

	rig.advance(2 * time.Second) // 越過第 300 秒
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("y")); err != nil {
		t.Fatalf("到期後加密失敗: %v", err)
	}
	if got := rig.kek.unwrapCount(); got != before+1 {
		t.Errorf("到期後解封次數 = %d, want %d（到期須重解）", got, before+1)
	}
	if !allZero(captured) {
		t.Error("到期清除只丟了參考：原 buffer 仍非全零，材料還在記憶體裡")
	}
	// 重解後歷史密文仍可解
	plain, err := rig.km.DecryptBytesFor(context.Background(), rig.ref(), ct)
	if err != nil {
		t.Fatalf("重解後解密失敗: %v", err)
	}
	plain.Destroy()
}

// TestDekFixedTTLDoesNotRenewOnAccess 固定期限不因存取續期。
func TestDekFixedTTLDoesNotRenewOnAccess(t *testing.T) {
	rig := newDEKTestRig(t, "100")
	before := rig.kek.unwrapCount()
	for i := 0; i < 9; i++ {
		rig.advance(10 * time.Second) // 每 10 秒用一次，共走到第 90 秒
		if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err != nil {
			t.Fatalf("加密失敗: %v", err)
		}
	}
	if got := rig.kek.unwrapCount(); got != before {
		t.Fatalf("第 90 秒前就重解了 %d 次", got-before)
	}
	rig.advance(20 * time.Second) // 第 110 秒：即使一路都在用，仍須到期
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err != nil {
		t.Fatalf("加密失敗: %v", err)
	}
	if got := rig.kek.unwrapCount(); got != before+1 {
		t.Errorf("持續存取後解封次數 = %d, want %d：期限被存取續期了", got, before+1)
	}
}

// TestDekZeroTTLUnwrapsPerOperationAndWipes 設 0 時每次操作各自解封，用完抹掉。
func TestDekZeroTTLUnwrapsPerOperationAndWipes(t *testing.T) {
	rig := newDEKTestRig(t, "0")
	// 出廠載入的材料在第一次取用時即被驅逐（0 秒＝任何快取都已到期）
	resident := rig.dataMaterial(1)
	before := rig.kek.unwrapCount()
	for i := 0; i < 3; i++ {
		if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err != nil {
			t.Fatalf("加密失敗: %v", err)
		}
	}
	if got := rig.kek.unwrapCount(); got != before+3 {
		t.Errorf("解封次數 = %d, want %d（每次操作各解一次）", got-before, 3)
	}
	if resident != nil && !allZero(resident) {
		t.Error("設 0 後啟動期載入的材料未被覆寫，仍留在記憶體")
	}
	if m := rig.dataMaterial(1); m != nil {
		t.Errorf("設 0 時仍有跨操作留存的材料：%d bytes", len(m))
	}
}

// TestDekSingleFlightCollapsesConcurrentMisses 併發缺失只發一次保管處請求。
func TestDekSingleFlightCollapsesConcurrentMisses(t *testing.T) {
	rig := newDEKTestRig(t, "0")
	gate := make(chan struct{})
	rig.kek.setGate(gate)
	before := rig.kek.unwrapCount()

	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	started := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			started <- struct{}{}
			_, errs[i] = rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x"))
		}(i)
	}
	for i := 0; i < n; i++ {
		<-started
	}
	// 等到遠端呼叫確實已開始，再給併發者足夠時間全部加入同一次 flight
	<-rig.kek.entered
	time.Sleep(150 * time.Millisecond)
	close(gate)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("第 %d 個併發加密失敗: %v", i, err)
		}
	}
	if got := rig.kek.unwrapCount() - before; got != 1 {
		t.Errorf("%d 個併發缺失發出 %d 次保管處請求, want 1", n, got)
	}
}

// TestDekSealedResultIsNotInstalled 封印瞬間回來的材料一律抹除、不安裝。
func TestDekSealedResultIsNotInstalled(t *testing.T) {
	rig := newDEKTestRig(t, "300")
	rig.advance(400 * time.Second) // 先讓出廠載入的材料到期
	gate := make(chan struct{})
	rig.kek.setGate(gate)

	done := make(chan error, 1)
	go func() {
		_, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x"))
		done <- err
	}()
	<-rig.kek.entered            // 遠端呼叫已開始
	rig.km.materialGate.CloseWith(nil) // 關閘（seal 的第一步）
	close(gate)                  // 解封結果此刻才回來

	err := <-done
	if !errors.Is(err, seal.ErrMaterialSealed) {
		t.Fatalf("封印後的取用 = %v, want ErrMaterialSealed", err)
	}
	rig.km.mu.RLock()
	defer rig.km.mu.RUnlock()
	if rig.km.ciphers[1] != nil || rig.km.keys[model.DataKeyPurposeData][1] != nil {
		t.Error("封印瞬間回來的材料被寫回快取：封印退化成路由層假象")
	}
}

// TestDekSealBeatsTTL seal 立即使快取失效，不等存活期屆滿。
func TestDekSealBeatsTTL(t *testing.T) {
	rig := newDEKTestRig(t, "3600")
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err != nil {
		t.Fatalf("加密失敗: %v", err)
	}
	captured := rig.dataMaterial(1)
	if captured == nil {
		t.Fatal("前提不成立：期限內快取應有材料")
	}
	rig.km.ZeroizeForRelease() // seal 的實體動作
	if !allZero(captured) {
		t.Error("seal 後材料未歸零")
	}
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); !errors.Is(err, seal.ErrMaterialSealed) {
		t.Errorf("seal 後的取用 = %v, want ErrMaterialSealed", err)
	}
}

// TestDekExpiryDoesNotTouchKeyTableOrGeneration 存活期屆滿只是快取層事件：
// 不改封印狀態、不動世代、不改寫金鑰表。
func TestDekExpiryDoesNotTouchKeyTableOrGeneration(t *testing.T) {
	rig := newDEKTestRig(t, "60")
	var before []model.DataKey
	if err := rig.db.Order("purpose, version").Find(&before).Error; err != nil {
		t.Fatalf("find: %v", err)
	}
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err != nil {
		t.Fatalf("加密失敗: %v", err)
	}
	rig.advance(120 * time.Second)
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err != nil {
		t.Fatalf("到期後加密失敗: %v", err)
	}
	if rig.km.materialGate.Closed() {
		t.Error("存活期屆滿把材料柵欄關掉了：到期不得等同封印")
	}
	var after []model.DataKey
	if err := rig.db.Order("purpose, version").Find(&after).Error; err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(before) != len(after) {
		t.Fatalf("金鑰表列數 %d → %d", len(before), len(after))
	}
	for i := range before {
		if before[i].WrappedKey != after[i].WrappedKey || before[i].Status != after[i].Status ||
			before[i].Version != after[i].Version {
			t.Errorf("金鑰表第 %d 列被改寫: %+v → %+v", i, before[i], after[i])
		}
	}
}

// TestDekInFlightOperationSurvivesExpiry 到期時的在途操作沿租約完成，
// 材料不被中途抽走；其後才歸零。
func TestDekInFlightOperationSurvivesExpiry(t *testing.T) {
	rig := newDEKTestRig(t, "60")
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err != nil {
		t.Fatalf("加密失敗: %v", err)
	}
	captured := rig.dataMaterial(1)

	// 手工模擬一個在途操作：取得租約後才讓期限屆滿
	c, release, err := rig.km.acquireDataCipher(1)
	if err != nil || c == nil {
		t.Fatalf("取得材料失敗: %v", err)
	}
	rig.advance(120 * time.Second)
	// 另一個操作觸發到期掃描（它會重解，在途者不受影響）
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("y")); err != nil {
		t.Fatalf("到期後加密失敗: %v", err)
	}
	// 在途者仍能以手上的材料完成，而不是讀到已清除的內容
	out, err := c.EncryptBytesAAD([]byte("inflight"), rig.ref().AAD())
	if err != nil || len(out) == 0 {
		t.Fatalf("在途操作被中途抽走材料: %v", err)
	}
	if allZero(captured) {
		t.Error("在途租約尚未收束，材料就被覆寫了")
	}
	release()
	if !allZero(captured) {
		t.Error("在途收束後材料仍未覆寫：額外駐留超出「在途完成」的界")
	}
}

// TestDekScopeExcludesAuditStamping 存活期只管 data 用途：
// 設 0 且保管處全故障時，審計蓋章與簽章鑰仍可取用。
func TestDekScopeExcludesAuditStamping(t *testing.T) {
	rig := newDEKTestRig(t, "0")
	rig.kek.setFail(vaulttransit.ErrDenied)

	ver, key := rig.km.ActiveHMACKey()
	if ver == 0 || len(key) != 32 {
		t.Fatalf("保管處故障時取不到審計蓋章鑰: v%d/%d bytes", ver, len(key))
	}
	if k := rig.km.HMACKeyByVersion(ver); len(k) != 32 {
		t.Errorf("保管處故障時取不到指定版本蓋章鑰: %d bytes", len(k))
	}
	// 對照：同一時刻的 data 用途確實失敗（否則上面兩格可能是故障沒生效）
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err == nil {
		t.Error("保管處故障時 data 加密仍成功：故障注入未生效，本測試的對照失效")
	}
}

// TestDekUnwrapFailureIsDistinctFromStartupMismatch 執行期解封失敗與啟動期
// 「KEK 與金鑰表不符」分流：錯誤可辨識、不含「檢查 ENCRYPTION_KEY」的指引、不回傳明文。
func TestDekUnwrapFailureIsDistinctFromStartupMismatch(t *testing.T) {
	rig := newDEKTestRig(t, "0")
	ctPlain := []byte("secret-value")
	ct, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), ctPlain)
	if err != nil {
		t.Fatalf("加密失敗: %v", err)
	}
	rig.kek.setFail(vaulttransit.ErrDenied)

	got, err := rig.km.DecryptBytesFor(context.Background(), rig.ref(), ct)
	if err == nil {
		t.Fatal("保管處拒絕時解密仍成功")
	}
	if got != nil {
		t.Error("失敗路徑回傳了非 nil 的明文載體")
	}
	if !errors.Is(err, ErrDEKUnwrap) {
		t.Errorf("錯誤 = %v，應可由 ErrDEKUnwrap 辨識", err)
	}
	if errors.Is(err, ErrKEKMismatch) {
		t.Error("執行期解封失敗被折進啟動期的 KEK 不符判定")
	}
	if strings.Contains(err.Error(), "ENCRYPTION_KEY") {
		t.Errorf("錯誤訊息帶啟動期指引，操作者會照著改環境變數而白忙: %v", err)
	}
	var de *DEKUnwrapError
	if !errors.As(err, &de) || de.Reason != DEKFailDenied {
		t.Errorf("原因分類 = %+v, want %s", de, DEKFailDenied)
	}
}

// TestDekFailureDoesNotFallBackToStaleCache 保管處故障時明確失敗，
// 不回退到已到期的舊快取。
func TestDekFailureDoesNotFallBackToStaleCache(t *testing.T) {
	rig := newDEKTestRig(t, "60")
	secret := []byte("no-fallback")
	ct, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), secret)
	if err != nil {
		t.Fatalf("加密失敗: %v", err)
	}
	// 期限內解得開（確認密文與快取都正常）
	ok, err := rig.km.DecryptBytesFor(context.Background(), rig.ref(), ct)
	if err != nil {
		t.Fatalf("期限內解密失敗: %v", err)
	}
	ok.Destroy()

	rig.advance(120 * time.Second)
	rig.kek.setFail(vaulttransit.ErrDenied)
	got, err := rig.km.DecryptBytesFor(context.Background(), rig.ref(), ct)
	if err == nil {
		t.Fatal("到期後保管處故障，解密卻成功：回退到了已到期的舊快取")
	}
	if got != nil {
		t.Error("失敗路徑回傳了明文載體")
	}
	if m := rig.dataMaterial(1); m != nil && !allZero(m) {
		t.Error("到期材料在故障後仍留在記憶體")
	}
}

// TestDekUnwrapRetriesOnlyUnwrap 有限重試只重做 unwrap：
// 不可達類重試至上限、拒絕類不重試。
func TestDekUnwrapRetriesOnlyUnwrap(t *testing.T) {
	t.Run("不可達類重試至上限且不重做具副作用的動作", func(t *testing.T) {
		rig := newDEKTestRig(t, "0")
		rig.kek.setFail(errors.New("dial tcp: connection refused"))
		beforeUnwrap, beforeWrap := rig.kek.unwrapCount(), rig.kek.wrapCount()
		var beforeRows int64
		rig.db.Model(&model.DataKey{}).Count(&beforeRows)

		if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err == nil {
			t.Fatal("保管處不可達時加密仍成功")
		}
		if got := rig.kek.unwrapCount() - beforeUnwrap; got != dekUnwrapAttempts {
			t.Errorf("嘗試次數 = %d, want %d", got, dekUnwrapAttempts)
		}
		// 重試只重做 unwrap：包裹（寫金鑰表的那一側）一次都不得被重做
		if got := rig.kek.wrapCount() - beforeWrap; got != 0 {
			t.Errorf("解封重試順帶重做了 %d 次包裹：業務副作用被綁進了解封重試", got)
		}
		var afterRows int64
		rig.db.Model(&model.DataKey{}).Count(&afterRows)
		if afterRows != beforeRows {
			t.Errorf("解封重試改動了金鑰表列數 %d → %d", beforeRows, afterRows)
		}
	})
	t.Run("拒絕類不重試", func(t *testing.T) {
		rig := newDEKTestRig(t, "0")
		rig.kek.setFail(vaulttransit.ErrDenied)
		before := rig.kek.unwrapCount()
		if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err == nil {
			t.Fatal("保管處拒絕時加密仍成功")
		}
		if got := rig.kek.unwrapCount() - before; got != 1 {
			t.Errorf("拒絕類嘗試次數 = %d, want 1（重試只會把一次組態錯誤放大成多次稽核紀錄）", got)
		}
	})
}

// TestDekEncryptLocksVersionAndDecryptFollowsCiphertext
// 加密路徑鎖定版本後不中途改綁；解密路徑按密文自帶的版本取材料。
func TestDekEncryptLocksVersionAndDecryptFollowsCiphertext(t *testing.T) {
	rig := newDEKTestRig(t, "300")
	oldCT, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("v1-secret"))
	if err != nil {
		t.Fatalf("加密失敗: %v", err)
	}
	if _, ver, _, ok, err := crypto.ParseEnvelopeFull(oldCT); err != nil || !ok || ver != 1 {
		t.Fatalf("前提不成立：首筆密文版本 = %d (ok=%v err=%v)", ver, ok, err)
	}
	if _, err := rig.km.RotateDataDEK(); err != nil {
		t.Fatalf("輪替失敗: %v", err)
	}
	newCT, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("v2-secret"))
	if err != nil {
		t.Fatalf("輪替後加密失敗: %v", err)
	}
	_, newVer, _, _, _ := crypto.ParseEnvelopeFull(newCT)
	if newVer != 2 {
		t.Errorf("輪替後新密文版本 = %d, want 2", newVer)
	}
	// 歷史版本密文仍以其自帶版本解開，逐版本獨立計時
	plain, err := rig.km.DecryptBytesFor(context.Background(), rig.ref(), oldCT)
	if err != nil {
		t.Fatalf("歷史版本密文解不開: %v", err)
	}
	defer plain.Destroy()
	if err := plain.Borrow(func(b []byte) error {
		if string(b) != "v1-secret" {
			t.Errorf("歷史版本明文 = %q", string(b))
		}
		return nil
	}); err != nil {
		t.Fatalf("borrow: %v", err)
	}
	// 到期後重解時，歷史版本走的仍是它自己的那把鑰
	rig.advance(600 * time.Second)
	again, err := rig.km.DecryptBytesFor(context.Background(), rig.ref(), oldCT)
	if err != nil {
		t.Fatalf("到期重解後歷史版本密文解不開: %v", err)
	}
	again.Destroy()
}

// TestDekRewrapHoldsMaterialAcrossExpiry 重包期間材料不被到期計時器抽走：
// 解封重試與業務動作分離的具體落點。
func TestDekRewrapHoldsMaterialAcrossExpiry(t *testing.T) {
	rig := newDEKTestRig(t, "1")
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err != nil {
		t.Fatalf("加密失敗: %v", err)
	}
	rig.advance(10 * time.Second) // 快取早已到期
	// 釘選期間到期掃描不得清掉材料（釘選是重包迴圈進場時做的第一件事）
	unpin := rig.km.pinDataVersions()
	rig.km.mu.Lock()
	pinnedMaterial := rig.km.keys[model.DataKeyPurposeData][1]
	rig.km.sweepExpiredLocked(time.Second, dekTTLFixed)
	rig.km.mu.Unlock()
	if pinnedMaterial == nil || allZero(pinnedMaterial) {
		t.Fatal("釘選期間材料被到期掃描清掉：重包會以「未載入」失敗")
	}
	unpin()
	if m := rig.dataMaterial(1); m != nil {
		t.Error("解除釘選後未補做到期清除：釘選變成了永久豁免")
	}
	if !allZero(pinnedMaterial) {
		t.Error("解除釘選後材料只被丟參考，未覆寫")
	}
}

// TestDekRewrapWorksWithZeroTTL 設 0（快取一把都不留）時 KEK 重包仍可完成：
// 重包迴圈讀的是原材料，進場前必須先把它們解回來並釘住。
func TestDekRewrapWorksWithZeroTTL(t *testing.T) {
	rig := newDEKTestRig(t, "0")
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err != nil {
		t.Fatalf("加密失敗: %v", err)
	}
	if m := rig.dataMaterial(1); m != nil {
		t.Fatalf("前提不成立：設 0 時不應有常駐材料")
	}
	target := localTargetForTest(t, newTestKEKMaterial(t))
	if _, err := rig.km.RewrapKEK(context.Background(), target); err != nil {
		t.Fatalf("設 0 時重包失敗: %v", err)
	}
	if m := rig.dataMaterial(1); m != nil {
		t.Error("重包結束後材料仍常駐：釘選變成了永久豁免")
	}
}

// TestDekConsecutiveFailuresAlertOnce 連續解封失敗達門檻才上報，單次抖動不告警；
// 一次成功即結案。
func TestDekConsecutiveFailuresAlertOnce(t *testing.T) {
	rig := newDEKTestRig(t, "0")
	rep := &recordingFailureReporter{}
	rig.km.SetDEKFailureReporter(rep)
	rig.kek.setFail(vaulttransit.ErrDenied)

	for i := 1; i < dekFailureAlertThreshold; i++ {
		_, _ = rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x"))
		if n := rep.reports(); n != 0 {
			t.Fatalf("第 %d 次失敗就發了 %d 則告警：單次抖動不得告警", i, n)
		}
	}
	_, _ = rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x"))
	if n := rep.reports(); n != 1 {
		t.Fatalf("達門檻後告警數 = %d, want 1", n)
	}
	// 再失敗不重複開列（去重由失效事件族既有機制承擔，本處不重複上報）
	_, _ = rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x"))
	if n := rep.reports(); n != 1 {
		t.Errorf("持續失敗重複上報 %d 次", n)
	}
	rig.kek.setFail(nil)
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err != nil {
		t.Fatalf("恢復後加密失敗: %v", err)
	}
	if n := rep.resolves(); n != 1 {
		t.Errorf("恢復後結案數 = %d, want 1", n)
	}
}

// TestDekObserverSeesResultsAndTTL 解封的結果、在途數與現行設定值都送到出口。
func TestDekObserverSeesResultsAndTTL(t *testing.T) {
	rig := newDEKTestRig(t, "0")
	obs := &recordingDEKObserver{}
	rig.km.SetDEKObserver(obs)
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err != nil {
		t.Fatalf("加密失敗: %v", err)
	}
	rig.kek.setFail(vaulttransit.ErrDenied)
	_, _ = rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x"))

	obs.mu.Lock()
	defer obs.mu.Unlock()
	if obs.results["success|"] != 1 {
		t.Errorf("成功計數 = %d, want 1", obs.results["success|"])
	}
	if obs.results["failure|"+DEKFailDenied] != 1 {
		t.Errorf("拒絕類失敗計數 = %d, want 1", obs.results["failure|"+DEKFailDenied])
	}
	if !obs.ttlPresent || obs.ttlSeconds != 0 {
		t.Errorf("設定值 = (%d, present=%v), want (0, true)", obs.ttlSeconds, obs.ttlPresent)
	}
	if obs.maxInflight < 1 {
		t.Errorf("在途數峰值 = %d, want ≥1", obs.maxInflight)
	}
}

// TestDekUnsetTTLReportsAbsentSetting 未設定時設定值以「缺席」表達，不以 0 冒充。
func TestDekUnsetTTLReportsAbsentSetting(t *testing.T) {
	rig := newDEKTestRig(t, "")
	obs := &recordingDEKObserver{}
	rig.km.SetDEKObserver(obs)
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x")); err != nil {
		t.Fatalf("加密失敗: %v", err)
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if obs.ttlPresent {
		t.Error("未設定卻回報了設定值：0 在本鍵是「不留快取」，語義相反")
	}
}

// recordingFailureReporter 記錄上報與結案次數的 AuditFailureReporter。
type recordingFailureReporter struct {
	mu       sync.Mutex
	reported int
	resolved int
}

func (r *recordingFailureReporter) AlertEnabled() bool { return true }
func (r *recordingFailureReporter) Report(string, string, map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reported++
}
func (r *recordingFailureReporter) Resolve(string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolved++
}
func (r *recordingFailureReporter) AdoptOpenEvent(string) bool                  { return false }
func (r *recordingFailureReporter) EnsureEventRow(string, string, map[string]string) {}
func (r *recordingFailureReporter) NotifyOngoing(notifycat.Event, map[string]string)  {}
func (r *recordingFailureReporter) reports() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reported
}
func (r *recordingFailureReporter) resolves() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resolved
}

// recordingDEKObserver 記錄解封觀測值的 DEKUnwrapObserver。
type recordingDEKObserver struct {
	mu          sync.Mutex
	results     map[string]int
	maxInflight int
	ttlSeconds  int
	ttlPresent  bool
}

func (o *recordingDEKObserver) ObserveUnwrap(result, reason string, _ time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.results == nil {
		o.results = map[string]int{}
	}
	o.results[result+"|"+reason]++
}
func (o *recordingDEKObserver) SetUnwrapInflight(n int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if n > o.maxInflight {
		o.maxInflight = n
	}
}
func (o *recordingDEKObserver) SetCacheTTL(seconds int, present bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ttlSeconds, o.ttlPresent = seconds, present
}

// TestDekSwitchBackToUnsetTTLRecoversMaterial 政策由 `0`／已到期的 `N` 改回空值後，
// 快取已空，取用仍須沿同一條重解路徑把材料取回來。
//
// **這一格就是「空值＝維持現行行為」的承諾**：契約說的是政策值，不是「行程從未設過
// 非空值」。少了這條路徑，改回空值的部署會全面解不開資料，復原手段只剩重啟或
// seal→unseal，而失敗還不留任何解封失敗的痕跡。
func TestDekSwitchBackToUnsetTTLRecoversMaterial(t *testing.T) {
	const probe = "back-to-unset"

	t.Run("0 改回空值", func(t *testing.T) {
		rig := newDEKTestRig(t, "0")
		ct, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte(probe))
		if err != nil {
			t.Fatalf("設 0 時加密失敗: %v", err)
		}
		if m := rig.dataMaterial(1); m != nil {
			t.Fatalf("前提不成立：設 0 時不應有跨操作留存的材料（%d bytes）", len(m))
		}
		rig.pol.set("")
		assertRecoversAndStaysResident(t, rig, ct, probe)
	})

	t.Run("N 到期後改回空值", func(t *testing.T) {
		rig := newDEKTestRig(t, "60")
		ct, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte(probe))
		if err != nil {
			t.Fatalf("設 60 時加密失敗: %v", err)
		}
		// 到期由計時器回呼收走（不經取用路徑），即實跑中「等到期後才改政策」的序列
		rig.advance(120 * time.Second)
		rig.km.onExpiryTimer(1)
		if m := rig.dataMaterial(1); m != nil {
			t.Fatalf("前提不成立：到期後快取仍有材料（%d bytes）", len(m))
		}
		rig.pol.set("")
		assertRecoversAndStaysResident(t, rig, ct, probe)
	})

	t.Run("空值下重解失敗留痕", func(t *testing.T) {
		rig := newDEKTestRig(t, "0")
		if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte(probe)); err != nil {
			t.Fatalf("設 0 時加密失敗: %v", err)
		}
		rig.pol.set("")
		rep := &recordingFailureReporter{}
		rig.km.SetDEKFailureReporter(rep)
		rig.kek.setFail(vaulttransit.ErrDenied)

		var last error
		for i := 0; i < dekFailureAlertThreshold; i++ {
			_, last = rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("x"))
		}
		if !errors.Is(last, ErrDEKUnwrap) {
			t.Errorf("空值模式的重解失敗 = %v，應可由 ErrDEKUnwrap 辨識（否則只呈現為憑證讀取失敗）", last)
		}
		if n := rep.reports(); n != 1 {
			t.Errorf("連續 %d 次失敗的告警數 = %d, want 1：這條失敗未計入既有解封失敗計數",
				dekFailureAlertThreshold, n)
		}
	})
}

// assertRecoversAndStaysResident 空值模式下快取已空時：首次取用重解一次即恢復，
// 且材料安裝為長駐（其後不再打保管處）。
func assertRecoversAndStaysResident(t *testing.T, rig *dekTestRig, ct, want string) {
	t.Helper()
	before := rig.kek.unwrapCount()
	plain, err := rig.km.DecryptBytesFor(context.Background(), rig.ref(), ct)
	if err != nil {
		t.Fatalf("改回空值後解密失敗（快取已空且無重解路徑）: %v", err)
	}
	if err := plain.Borrow(func(b []byte) error {
		if string(b) != want {
			t.Errorf("解出的明文 = %q, want %q", string(b), want)
		}
		return nil
	}); err != nil {
		t.Fatalf("borrow: %v", err)
	}
	plain.Destroy()
	if got := rig.kek.unwrapCount() - before; got != 1 {
		t.Fatalf("改回空值後首次取用的解封次數 = %d, want 1", got)
	}
	if _, err := rig.km.EncryptBytesFor(context.Background(), rig.ref(), []byte("again")); err != nil {
		t.Fatalf("恢復後再次加密失敗: %v", err)
	}
	if got := rig.kek.unwrapCount() - before; got != 1 {
		t.Errorf("空值模式的材料未安裝為長駐：第二次取用又解封了（累計 %d 次）", got)
	}
}
