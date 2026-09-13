package keyvault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/gcpkms"
	"github.com/custodexa/backend/pkg/crypto/kms"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
)

// DEK cache lifetime: the `dek_cache_ttl_seconds` policy decides how long an
// unwrapped data DEK may stay in process memory.
//
// 三態（政策鍵值域見 policy 套件的定義註解）：
//   - 空值：不限期，解封後留到 seal 或行程結束。**出廠預設，行為與本機制引入前相同**。
//   - `0`：不留快取，每次用到才向 KEK 保管處解封，該次操作結束即覆寫。
//   - `N>0`：自**解封成功時點**起算 N 秒的固定期限，不因存取續期。
//
// **只管 `data` 用途**：`audit_integrity` 蓋章鑰與兩支簽章服務的私鑰不受本機制
// 約束——蓋章是每一列審計都要做的事，把它綁到保管處可達性上等於讓保管處
// 決定審計能不能寫，而審計不可缺是既有紅線。涵蓋範圍的邊界寫在契約與文件裡，
// 本機制 SHALL NOT 被描述為「金鑰不再常駐」。

// 執行參數初值（取值理由見本套件的設計說明）。
const (
	// dekMaxInflightUnwrap 在途解封總數上限。single-flight 已把同一
	// (用途, 版本) 收斂為一次請求，故在途數的上界等於「同時被需要的相異版本數」，
	// 而版本數＝輪替次數，實務上是個位數。上限的用途是讓「版本鏈異常膨脹」或
	// 「single-flight 失效」立刻可見，不是做流量整形
	dekMaxInflightUnwrap = 8
	// dekUnwrapBudget 一次解封的端到端預算（含全部重試與退避）。
	// 不長於最短的 driver 單次傳輸預算（Vault 5 秒），避免出現
	// 「driver 已放棄、呼叫層還在等」的空轉段
	dekUnwrapBudget = 5 * time.Second
	// dekUnwrapAttempts 總嘗試次數（1 次加上至多 2 次重試）：
	// 涵蓋一次瞬時抖動與其後一次確認的最小次數
	dekUnwrapAttempts = 3
	// dekUnwrapBackoffBase 首次重試前的退避基準，逐次倍增並帶 ±50% 抖動。
	// 約為同區域往返估計的數倍，重試不會落在同一個抖動窗內
	dekUnwrapBackoffBase = 100 * time.Millisecond
	// dekFailureAlertThreshold 連續解封失敗達此次數才上報告警。
	// 單次抖動發告警只會訓練出忽略告警的操作者
	dekFailureAlertThreshold = 3
)

// dekTTLMode 存活期政策的三態。
type dekTTLMode int

const (
	// dekTTLUnlimited 未設定：解封後全程快取（出廠預設）
	dekTTLUnlimited dekTTLMode = iota
	// dekTTLNoCache 設為 0：不留快取，用完即清
	dekTTLNoCache
	// dekTTLFixed 設為 N>0：自解封成功起算的固定期限
	dekTTLFixed
)

// 執行期解封失敗的可辨識類別。
//
// **與 ErrKEKMismatch 分流**：後者的語義是「開機 KEK 與金鑰表不符，拒絕啟動、
// 請確認 ENCRYPTION_KEY」。把一次網路抖動折進去，操作者會照著那條指引去改
// 環境變數而白忙一場，而真正該看的是保管處的可達性。
var ErrDEKUnwrap = errors.New("DEK 解封失敗")

// 解封失敗的原因分類（同時是指標 `reason` 標籤的值域）。
const (
	// DEKFailUnavailable 保管處不可達、傳輸失敗或回應無法解讀
	DEKFailUnavailable = "unavailable"
	// DEKFailDenied 保管處明確拒絕（認證失效、權限不足、金鑰狀態不允許）。
	// **不重試**：重試必然同樣失敗，只會把一次組態錯誤放大成三次保管處稽核紀錄
	DEKFailDenied = "denied"
	// DEKFailTimeout 端到端預算用盡
	DEKFailTimeout = "timeout"
)

// DEKUnwrapError 執行期解封失敗。攜帶用途、版本與原因分類，供指標與告警取用。
type DEKUnwrapError struct {
	Purpose string
	Version int
	Reason  string
	Err     error
}

func (e *DEKUnwrapError) Error() string {
	return fmt.Sprintf("%s（%s v%d，原因 %s）: %v", ErrDEKUnwrap.Error(), e.Purpose, e.Version, e.Reason, e.Err)
}
func (e *DEKUnwrapError) Unwrap() error { return ErrDEKUnwrap }

// DEKUnwrapObserver 解封可觀測性的注入面（**keyvault 自宣告的窄介面**）。
//
// 本包不 import `internal/observability`——那會讓業務模組依賴曝光層，而曝光層
// 的註冊時機由組裝根決定。實作在 cmd/server 側包一層 Metrics，注入在 stage2。
type DEKUnwrapObserver interface {
	// ObserveUnwrap 一次解封的結果與耗時；result 為 success 或 failure，
	// reason 僅於失敗時帶值（DEKFail* 三者之一）
	ObserveUnwrap(result, reason string, d time.Duration)
	// SetUnwrapInflight 在途解封數
	SetUnwrapInflight(n int)
	// SetCacheTTL 現行設定值；present=false 表示未設定（序列須缺席，不得以 0 冒充）
	SetCacheTTL(seconds int, present bool)
}

// dekCacheEntry 一個 data DEK 版本的存活期簿記。受 s.mu 保護。
//
// **entry 自持材料參考**：驅逐後同一版本可能立刻被重解並安裝出新的 entry，
// 若以版本號查表歸還租約，舊 entry 的在途計數就會記到新 entry 上，
// 舊材料因而永遠等不到「最後一位歸還者」而留在記憶體裡。
type dekCacheEntry struct {
	// version 所屬的 data DEK 版本（診斷與清理用）
	version int
	// raw 材料本體：與 keys[data][version]／ciphers[version] 是同一段 slice
	raw []byte
	// unwrappedAt 解封成功的時點：固定期限自此起算，不因存取推進
	unwrappedAt time.Time
	// inUse 在途租約數：到期時已在途的操作沿租約完成，材料不被中途抽走
	inUse int
	// pinned 長期操作（重包）的釘選數：釘選期間不驅逐
	pinned int
	// evicted 已自快取移出、等在途收束後覆寫。新的借用一律看不到它
	evicted bool
}

// dekFlight 一次 single-flight 解封。
type dekFlight struct {
	done chan struct{}
	// joined 加入本次解封的取用者數：完成時據以預先計入租約，
	// 避免「安裝完成到取得租約」之間出現可被驅逐的空窗
	joined int
	err    error
	// raw／ciph 僅 dekTTLNoCache 用：材料不入快取，由本次 flight 的
	// 共享者共同持有，最後一位釋放者覆寫
	raw   []byte
	ciph  *crypto.AESCrypto
	refs  int
}

// dekCacheTTL 讀現行政策：回 (存活期, 三態)。政策未接時視為未設定。
func (s *KeyManagerService) dekCacheTTL() (time.Duration, dekTTLMode) {
	s.mu.RLock()
	src := s.policies
	s.mu.RUnlock()
	if src == nil {
		return 0, dekTTLUnlimited
	}
	raw := src.Get(policy.PolicyDekCacheTTLSeconds)
	if raw == "" {
		return 0, dekTTLUnlimited
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		// 政策層已驗過值域；讀到非法值只可能是繞過 API 的資料庫直寫。
		// **退回不限期而非最嚴格**：本鍵的嚴格端會讓保管處進入運行路徑，
		// 以一個壞掉的值把部署推進那條路徑，是拿可用性去賭一個猜測
		log.Printf("[KeyManager] DEK 快取存活期政策值 %q 非法，視為未設定", raw)
		return 0, dekTTLUnlimited
	}
	if n == 0 {
		return 0, dekTTLNoCache
	}
	return time.Duration(n) * time.Second, dekTTLFixed
}

func (s *KeyManagerService) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

// acquireDataCipher 取得 data DEK v`ver` 的加解密器與其釋放函式。
//
// **三態的分岔全部收在這裡**，呼叫端（加密與解密路徑）只看到「拿到器材、用完釋放」。
// 未設定存活期且材料在快取內時，走的是與本機制引入前逐字相同的路徑：持
// `s.mu.RLock` 讀 `ciphers`，不查政策以外的任何狀態、不可能觸發遠端呼叫。
//
// **不限期不代表材料必然在場**：同一個行程若曾以 `0` 運行、或曾以 `N` 運行且期限已過，
// 快取就是空的。把不限期做成「讀到 nil 就放棄」，會讓政策改回空值的部署再也解不開
// 任何資料，且只能重啟或 seal→unseal 復原——而契約承諾的正是「空值維持現行行為」。
// 故快取缺席時三態共用**同一條**受柵欄保護的重解路徑（single-flight、安裝前重驗封印、
// 故障不回退），不限期模式解回的材料以「無到期」安裝，之後即回到上面那條快路徑。
func (s *KeyManagerService) acquireDataCipher(ver int) (*crypto.AESCrypto, func(), error) {
	ttl, mode := s.dekCacheTTL()
	s.reportTTL(ttl, mode)
	if mode == dekTTLUnlimited {
		s.mu.RLock()
		if c := s.ciphers[ver]; c != nil {
			return c, func() { s.mu.RUnlock() }, nil
		}
		s.mu.RUnlock()
		if s.db == nil || s.dekFlights == nil {
			// 未經 InitKeyManager 組裝的手工實例（契約測試用）沒有金鑰表與 flight
			// 簿記可用：維持本機制引入前的「取不到就是取不到」，不在此處造第二條路徑
			return nil, nil, nil
		}
	}

	s.mu.Lock()
	// 到期即就地驅逐，不等計時器：計時器只負責「沒有人存取時也會被清掉」，
	// 到期判定的權威是本處的時點比較
	s.sweepExpiredLocked(ttl, mode)
	if e := s.dek[ver]; e != nil && !e.evicted {
		e.inUse++
		c := s.ciphers[ver]
		s.mu.Unlock()
		return c, func() { s.releaseEntry(e) }, nil
	}
	f := s.dekFlights[ver]
	if f == nil {
		if s.dekInflight >= dekMaxInflightUnwrap {
			s.mu.Unlock()
			return nil, nil, &DEKUnwrapError{
				Purpose: model.DataKeyPurposeData, Version: ver, Reason: DEKFailUnavailable,
				Err:     fmt.Errorf("在途解封已達上限 %d", dekMaxInflightUnwrap),
			}
		}
		f = &dekFlight{done: make(chan struct{})}
		s.dekFlights[ver] = f
		s.dekInflight++
		s.reportInflightLocked()
		go s.runUnwrapFlight(ver, ttl, mode, f)
	}
	f.joined++
	s.mu.Unlock()

	<-f.done

	s.mu.Lock()
	defer s.mu.Unlock()
	if f.err != nil {
		return nil, nil, f.err
	}
	if mode == dekTTLNoCache {
		// 材料不入快取：本次 flight 的共享者共同持有，最後一位釋放者覆寫
		return f.ciph, func() { s.releaseFlight(f) }, nil
	}
	e := s.dek[ver]
	if e == nil || e.evicted {
		// 安裝後、取得租約前遭 seal 清除：不回退到任何舊材料
		return nil, nil, seal.ErrMaterialSealed
	}
	c := s.ciphers[ver]
	return c, func() { s.releaseEntry(e) }, nil
}

// runUnwrapFlight 於鎖外執行遠端解封，回來後在鎖內安裝並喚醒等待者。
//
// **遠端呼叫一定在鎖外**：把毫秒級的往返放進寫鎖，等於讓所有加解密排在同一把鎖後面。
func (s *KeyManagerService) runUnwrapFlight(ver int, ttl time.Duration, mode dekTTLMode, f *dekFlight) {
	defer func() {
		if r := recover(); r != nil {
			// goroutine 內的 panic 會殺掉整個行程；解封失敗只是失敗，不該是當機
			log.Printf("[KeyManager] DEK 解封 goroutine panic 已攔下 (v%d): %v", ver, r)
			s.finishFlight(ver, f, nil, &DEKUnwrapError{
				Purpose: model.DataKeyPurposeData, Version: ver, Reason: DEKFailUnavailable,
				Err:     errors.New("解封執行緒異常終止"),
			}, ttl, mode)
		}
	}()
	raw, err := s.unwrapDataMaterial(ver)
	s.finishFlight(ver, f, raw, err, ttl, mode)
}

// unwrapDataMaterial 帶端到端預算、有限重試與退避抖動的解封。
//
// **只重做 unwrap**：重試不觸碰任何具副作用的業務動作（改密、輪替、重包）——
// 那些動作的重試語義由它們自己的呼叫端決定，與保管處的抖動無關。
func (s *KeyManagerService) unwrapDataMaterial(ver int) ([]byte, error) {
	row, err := s.currentDataKeyRow(ver)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), dekUnwrapBudget)
	defer cancel()

	var last error
	for attempt := 0; attempt < dekUnwrapAttempts; attempt++ {
		if attempt > 0 {
			wait := dekBackoff(attempt)
			select {
			case <-ctx.Done():
				return nil, s.recordUnwrapFailure(ver, DEKFailTimeout, ctx.Err())
			case <-time.After(wait):
			}
		}
		started := s.now()
		raw, err := unwrapMaterialCtx(ctx, s.kek, model.DataKeyPurposeData, ver, row.WrappedKey)
		elapsed := time.Since(started)
		if err == nil {
			s.observeUnwrap("success", "", elapsed)
			s.noteUnwrapSuccess()
			return raw, nil
		}
		last = err
		reason := classifyUnwrapError(ctx, err)
		s.observeUnwrap("failure", reason, elapsed)
		if reason == DEKFailDenied {
			return nil, s.recordUnwrapFailure(ver, reason, err)
		}
		if ctx.Err() != nil {
			return nil, s.recordUnwrapFailure(ver, DEKFailTimeout, err)
		}
	}
	return nil, s.recordUnwrapFailure(ver, classifyUnwrapError(ctx, last), last)
}

// dekBackoff 第 attempt 次重試前的等待：基準倍增並帶 ±50% 抖動。
// 抖動的用途是讓建線洪峰下的多個等待者不同拍重試。
func dekBackoff(attempt int) time.Duration {
	base := dekUnwrapBackoffBase << (attempt - 1)
	jitter := time.Duration(rand.Int63n(int64(base))) - base/2
	return base + jitter
}

// classifyUnwrapError 把 driver 的錯誤折成三類原因。
//
// **分類在 keyvault 層做，driver 一行不改**：三個 driver 的逾時與錯誤形狀是
// 它們各自的傳輸預算，把重試與分類塞進去會讓每個 driver 各自演化出一套語義。
func classifyUnwrapError(ctx context.Context, err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled),
		ctx != nil && ctx.Err() != nil:
		return DEKFailTimeout
	case errors.Is(err, vaulttransit.ErrAuth), errors.Is(err, vaulttransit.ErrDenied),
		errors.Is(err, kms.ErrKMSRejected), errors.Is(err, gcpkms.ErrMetadata):
		return DEKFailDenied
	default:
		// AWS driver 目前只回包裝字串、無哨兵，故落在此處與其他傳輸類同歸
		// 「不可達」——**朝可重試的方向歸類**：把拒絕誤判為不可達只是多兩次
		// 徒勞的請求，把不可達誤判為拒絕則會讓一次可自癒的抖動立刻失敗
		return DEKFailUnavailable
	}
}

// unwrapMaterialCtx 帶 context 的解包（`unwrapMaterial` 的等價，差別只在 ctx 由呼叫端給）。
func unwrapMaterialCtx(ctx context.Context, kek crypto.KEKProvider, purpose string, version int, column string) ([]byte, error) {
	tag, wrapped, err := crypto.ParseWrappedKey(column)
	if err != nil {
		return nil, err
	}
	if tag != kek.FormatTag() {
		return nil, fmt.Errorf("%w（列格式標記 %q，現行 provider 為 %q）",
			crypto.ErrKEKFormatMismatch, tag, kek.FormatTag())
	}
	raw, err := kek.Unwrap(ctx, wrapped, crypto.DEKAAD(purpose, version))
	if err != nil {
		material.Wipe(raw)
		return nil, err
	}
	return raw, nil
}

// currentDataKeyRow 取該版本現行 KEK 的代表列（重解的來源）。
func (s *KeyManagerService) currentDataKeyRow(ver int) (*model.DataKey, error) {
	var row model.DataKey
	err := s.db.Where("purpose = ? AND version = ? AND kek_id = ? AND kek_retired_at IS NULL",
		model.DataKeyPurposeData, ver, s.kekKeyID()).First(&row).Error
	if err != nil {
		return nil, &DEKUnwrapError{
			Purpose: model.DataKeyPurposeData, Version: ver, Reason: DEKFailUnavailable,
			Err:     fmt.Errorf("讀取金鑰表失敗: %w", err),
		}
	}
	if row.WrappedKey == "" {
		return nil, &DEKUnwrapError{
			Purpose: model.DataKeyPurposeData, Version: ver, Reason: DEKFailDenied,
			Err:     errors.New("該版本材料已顯式清理，無可解封來源"),
		}
	}
	return &row, nil
}

// recordUnwrapFailure 計入連續失敗並在達門檻時沿既有告警通道上報。
func (s *KeyManagerService) recordUnwrapFailure(ver int, reason string, cause error) error {
	s.mu.Lock()
	s.dekFailStreak++
	streak := s.dekFailStreak
	reporter := s.dekFailReporter
	s.mu.Unlock()
	if reporter != nil && streak == dekFailureAlertThreshold {
		reporter.Report(model.MechanismDEKUnwrap, model.CauseDEKUnwrapFailed, map[string]string{
			model.FailureParamUnwrapFailures: strconv.Itoa(streak),
		})
	}
	return &DEKUnwrapError{Purpose: model.DataKeyPurposeData, Version: ver, Reason: reason, Err: cause}
}

// noteUnwrapSuccess 一次成功即歸零連續失敗計數，並結掉進行中的失效事件。
func (s *KeyManagerService) noteUnwrapSuccess() {
	s.mu.Lock()
	was := s.dekFailStreak
	s.dekFailStreak = 0
	reporter := s.dekFailReporter
	s.mu.Unlock()
	if reporter != nil && was >= dekFailureAlertThreshold {
		reporter.Resolve(model.MechanismDEKUnwrap)
	}
}

// finishFlight 安裝解封結果並喚醒等待者。安裝前重驗柵欄仍開。
func (s *KeyManagerService) finishFlight(ver int, f *dekFlight, raw []byte, err error, ttl time.Duration, mode dekTTLMode) {
	s.mu.Lock()
	delete(s.dekFlights, ver)
	s.dekInflight--
	s.reportInflightLocked()
	switch {
	case err != nil:
		f.err = err
	case s.materialGate.Closed():
		// **封印瞬間回來的材料一律抹除、不安裝**：寫回已清空的 map 等於
		// 讓一次晚到的遠端回應把「封印」退化成路由層假象
		material.Wipe(raw)
		f.err = seal.ErrMaterialSealed
	case mode == dekTTLNoCache:
		c, cerr := crypto.NewAESCrypto(raw)
		if cerr != nil {
			material.Wipe(raw)
			f.err = &DEKUnwrapError{Purpose: model.DataKeyPurposeData, Version: ver,
				Reason: DEKFailUnavailable, Err: cerr}
			break
		}
		f.raw, f.ciph, f.refs = raw, c, f.joined
		if f.refs == 0 {
			material.Wipe(f.raw)
			f.raw, f.ciph = nil, nil
		}
	default:
		s.putKey(model.DataKeyPurposeData, ver, raw)
		// 租約於安裝的同一個臨界區內預先計入：安裝完成到取得租約之間若有空窗，
		// 一次到期掃描就能把還沒被借走的材料清掉，等待者醒來只會看到空快取
		if e := s.dek[ver]; e != nil {
			e.inUse = f.joined
		}
		// 不限期模式的 ttl 為 0，armExpiryLocked 於此不排計時器＝安裝為長駐
		s.armExpiryLocked(ver, ttl)
	}
	s.mu.Unlock()
	close(f.done)
}

// releaseEntry 歸還一次快取租約；已驅逐者由最後一位歸還者負責覆寫。
func (s *KeyManagerService) releaseEntry(e *dekCacheEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.inUse > 0 {
		e.inUse--
	}
	s.wipeEntryIfIdleLocked(e)
}

// wipeEntryIfIdleLocked 已驅逐且無在途、無釘選時逐位元組覆寫並移出待清列。
func (s *KeyManagerService) wipeEntryIfIdleLocked(e *dekCacheEntry) {
	if !e.evicted || e.inUse > 0 || e.pinned > 0 {
		return
	}
	for i := range e.raw {
		e.raw[i] = 0
	}
	e.raw = nil
	// 逐項複製而非 `append(a[:i], a[i+1:]...)`：GCP 端點守衛掃全模組的 variadic
	// 展開（`pkg/crypto/gcpkms/endpoint_gate_test.go`），而該守衛不改
	kept := make([]*dekCacheEntry, 0, len(s.dekRetiring))
	for _, r := range s.dekRetiring {
		if r != e {
			kept = append(kept, r)
		}
	}
	s.dekRetiring = kept
}

// releaseFlight 歸還一次「不留快取」模式的共享材料；最後一位釋放者覆寫。
func (s *KeyManagerService) releaseFlight(f *dekFlight) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.refs > 0 {
		f.refs--
	}
	if f.refs == 0 && f.raw != nil {
		material.Wipe(f.raw)
		f.raw, f.ciph = nil, nil
	}
}

// sweepExpiredLocked 驅逐全部已到期的版本（呼叫端須持 s.mu 寫鎖）。
func (s *KeyManagerService) sweepExpiredLocked(ttl time.Duration, mode dekTTLMode) {
	if mode == dekTTLUnlimited {
		return
	}
	now := s.now()
	for ver, e := range s.dek {
		if e.evicted || e.pinned > 0 {
			continue
		}
		if mode == dekTTLNoCache || !now.Before(e.unwrappedAt.Add(ttl)) {
			s.evictLocked(ver)
		}
	}
}

// evictLocked 使一個版本自快取失效：先關掉新的借用，在途租約收束後才覆寫。
//
// **不是只 `delete(map)`**：`ciphers[ver]` 與 `keys["data"][ver]` 持有同一段
// slice，丟參考等於材料還在記憶體裡。覆寫由 wipeDataVersionLocked 負責。
func (s *KeyManagerService) evictLocked(ver int) {
	e := s.dek[ver]
	if e == nil || e.evicted {
		return
	}
	e.evicted = true
	// 新的借用自此看不到這把鑰；材料本體的參考留在 entry 上，等在途收束後覆寫
	delete(s.ciphers, ver)
	delete(s.dek, ver)
	if versions := s.keys[model.DataKeyPurposeData]; versions != nil {
		delete(versions, ver)
	}
	if t := s.dekTimers[ver]; t != nil {
		t.Stop()
		delete(s.dekTimers, ver)
	}
	s.dekRetiring = append(s.dekRetiring, e)
	s.wipeEntryIfIdleLocked(e)
}

// armExpiryLocked 為一個版本安排到期清除。
//
// 計時器只負責「沒有人再存取時材料也會被清掉」；到期判定的權威是存取路徑上的
// 時點比較。回呼裡重讀政策，故管理員在期間內改小存活期也不會讓舊的期限硬留著。
func (s *KeyManagerService) armExpiryLocked(ver int, ttl time.Duration) {
	if t := s.dekTimers[ver]; t != nil {
		t.Stop()
	}
	if ttl <= 0 {
		delete(s.dekTimers, ver)
		return
	}
	s.dekTimers[ver] = time.AfterFunc(ttl, func() { s.onExpiryTimer(ver) })
}

// onExpiryTimer 計時器回呼：重讀政策後掃一次到期。
func (s *KeyManagerService) onExpiryTimer(ver int) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[KeyManager] DEK 到期清除 panic 已攔下 (v%d): %v", ver, r)
		}
	}()
	ttl, mode := s.dekCacheTTL()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepExpiredLocked(ttl, mode)
	// 政策在期間內被放寬時，尚未到期者重新排程；否則本版本的計時器就此結束
	if e := s.dek[ver]; e != nil && !e.evicted && mode == dekTTLFixed {
		remaining := e.unwrappedAt.Add(ttl).Sub(s.now())
		if remaining > 0 {
			s.armExpiryLocked(ver, remaining)
		}
	}
}

// pinDataVersions 釘選全部已載入的 data 版本，供重包這類「整段期間都要讀原材料」
// 的操作使用；回傳解除釘選的函式。
//
// **存在理由是與業務動作分離**：重包迴圈直接讀 `keys` 的原材料，若計時器在迴圈
// 中途把材料抽掉，重包會以「未載入」失敗，而那與保管處抖動無關。釘選期間不驅逐，
// 解除時立刻補做一次到期掃描，故釘選只推遲清除、不取消清除。
func (s *KeyManagerService) pinDataVersions() func() {
	s.materializeDataVersionsForPin()
	s.mu.Lock()
	pinned := make([]*dekCacheEntry, 0, len(s.dek))
	for _, e := range s.dek {
		if e.evicted {
			continue
		}
		e.pinned++
		pinned = append(pinned, e)
	}
	s.mu.Unlock()
	return func() {
		ttl, mode := s.dekCacheTTL()
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, e := range pinned {
			if e.pinned > 0 {
				e.pinned--
			}
			s.wipeEntryIfIdleLocked(e)
		}
		s.sweepExpiredLocked(ttl, mode)
	}
}

// materializeDataVersionsForPin 把現行 KEK 下所有 data 版本先解回快取，供釘選。
//
// **存在理由**：設有存活期時，快取裡可能一把 data DEK 都沒有，而重包迴圈是直接讀
// `keys[data][version]` 的原材料——不先解回來，設 `0` 的部署會連 KEK 都換不成，
// 錯誤還是誤導性的「金鑰未載入」。解回來的材料由隨後的釘選持有，
// 解除釘選時立刻補做到期掃描，故它只是把清除推遲到重包結束。
//
// best-effort：解不開的版本留給重包迴圈以既有錯誤回報，本處不吞也不改那條路徑。
//
// **不限期模式不在此處補材料**：重包的 KEK 呼叫必須全部落在該次請求的交易內
// （`key_rewrap_gcp_*_test.go` 的「KMS call outside transaction」與「cached plaintext
// replaced persisted source」兩道守衛在守這件事），在這裡先解一輪會踩到它們。
// 曾以 `0`／已到期 `N` 運行後改回空值的行程要重包時，材料由取用路徑
// （`acquireDataCipher` 的重解分支）補回，不繞過那道守衛。
func (s *KeyManagerService) materializeDataVersionsForPin() {
	ttl, mode := s.dekCacheTTL()
	if mode == dekTTLUnlimited {
		return
	}
	var rows []model.DataKey
	if err := s.db.Where("purpose = ? AND kek_id = ? AND kek_retired_at IS NULL AND wrapped_key <> ''",
		model.DataKeyPurposeData, s.kekKeyID()).Find(&rows).Error; err != nil {
		log.Printf("[KeyManager] 重包前讀取 data 金鑰列失敗: %v", err)
		return
	}
	for _, row := range rows {
		s.mu.Lock()
		_, resident := s.dek[row.Version]
		s.mu.Unlock()
		if resident {
			continue
		}
		raw, err := s.unwrapDataMaterial(row.Version)
		if err != nil {
			log.Printf("[KeyManager] 重包前重解 data v%d 失敗: %v", row.Version, err)
			continue
		}
		s.mu.Lock()
		if s.materialGate.Closed() {
			material.Wipe(raw)
			s.mu.Unlock()
			return
		}
		if _, exists := s.dek[row.Version]; exists {
			material.Wipe(raw) // 期間內被別人裝好了，丟掉自己這份
		} else {
			s.putKey(model.DataKeyPurposeData, row.Version, raw)
			s.armExpiryLocked(row.Version, ttl)
		}
		s.mu.Unlock()
	}
}

// SetDEKObserver 注入解封可觀測性出口（組裝根呼叫；nil 表示不曝光）。
func (s *KeyManagerService) SetDEKObserver(o DEKUnwrapObserver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dekObserver = o
}

// SetDEKFailureReporter 注入失效事件上報面（組裝根呼叫；nil 表示不上報）。
func (s *KeyManagerService) SetDEKFailureReporter(r AuditFailureReporter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dekFailReporter = r
}

func (s *KeyManagerService) observeUnwrap(result, reason string, d time.Duration) {
	s.mu.RLock()
	o := s.dekObserver
	s.mu.RUnlock()
	if o != nil {
		o.ObserveUnwrap(result, reason, d)
	}
}

func (s *KeyManagerService) reportInflightLocked() {
	if s.dekObserver != nil {
		s.dekObserver.SetUnwrapInflight(s.dekInflight)
	}
}

func (s *KeyManagerService) reportTTL(ttl time.Duration, mode dekTTLMode) {
	s.mu.RLock()
	o := s.dekObserver
	s.mu.RUnlock()
	if o == nil {
		return
	}
	if mode == dekTTLUnlimited {
		o.SetCacheTTL(0, false)
		return
	}
	o.SetCacheTTL(int(ttl/time.Second), true)
}

// resetDEKCacheStateLocked 清空全部存活期簿記（seal 收束與顯式清理共用）。
func (s *KeyManagerService) resetDEKCacheStateLocked() {
	for ver, t := range s.dekTimers {
		t.Stop()
		delete(s.dekTimers, ver)
	}
	// 待清列裡的材料已不在 keys 表內，ZeroizeForRelease 的逐表覆寫掃不到它們
	for _, e := range s.dekRetiring {
		for i := range e.raw {
			e.raw[i] = 0
		}
		e.raw = nil
	}
	s.dekRetiring = nil
	s.dek = map[int]*dekCacheEntry{}
	s.dekFailStreak = 0
}
