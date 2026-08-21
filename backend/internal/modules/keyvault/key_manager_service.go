package keyvault

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// ErrKEKMismatch 開機 KEK 與金鑰表不符（key-management-envelope D8）：
// 拒絕啟動，不靜默退回 legacy 路徑帶病運行
var ErrKEKMismatch = errors.New("KEK 與金鑰表不符：請確認 ENCRYPTION_KEY 是否為換鑰精靈重包後的新值（或誤改回舊值）")

// KeyManagerService 信封加密金鑰管理（key-management-envelope D1-D5）：
// 資料由 DEK 加密、DEK 被 KEK 包裹落庫（data_keys 表）。
// 實作 crypto.ColumnCodec（data 用途）：EncryptFor 以 active DEK 寫帶 AAD 的
// 版本化信封格式（`enc:a1:v<N>`），DecryptFor 依列身分驗證 AAD 後解密。
//
// **終態（release-transitional-cleanup）**：無 AAD 寫入能力與 legacy 單鑰解密
// 路徑皆已整組刪除——非 `enc:a1` 之值一律 fail-close（ErrNonFinalCiphertext）。
// 審計 HMAC 鑰（audit_integrity 用途）以原始位元組提供給完整性服務。
type KeyManagerService struct {
	db  *gorm.DB
	kek crypto.KEKProvider
	mu  sync.RWMutex
	// keys[purpose][version] = 金鑰明文材料（32 bytes）
	keys map[string]map[int][]byte
	// ciphers data 用途的 AESCrypto 快取（避免每次重建）
	ciphers map[int]*crypto.AESCrypto
	// active[purpose] = 現行版本
	active map[string]int
	// rewrapPending KEK 重包已執行但尚未以新 KEK 開機（清冊顯示「重包未完成」）
	rewrapPending bool
	// lastSwitch 本次啟動偵測並收尾的 KEK 切換結果（key-inventory-transparency）：
	// 供 main 於 audit 就緒後 best-effort 補記審計；證據主體為退役列本身。
	// nil＝本次啟動無切換收尾。
	lastSwitch *KEKSwitchResult
	// lastFinalizeErr 本次啟動收尾失敗原因（kek-rewrap-hygiene-hardening D5）：
	// KeyManager 初始化早於告警服務，此處僅記錄；main 於 InitAuditFailure＋
	// InitAlertNotifier 就緒後讀取上報（沿 LastKEKSwitch 補記模式）。
	// nil＝本次啟動收尾成功或無收尾。取鎖跳過不記（非失敗）。
	lastFinalizeErr error
	// policies 單次重加密上限的執行期來源（安全政策頁）；nil＝未接，退回 env
	policies rotationPolicySource
}

// KEKSwitchResult 本次啟動 KEK 切換收尾結果（供審計與退役史 from→to）
type KEKSwitchResult struct {
	ToKEKID      string         // 切換到的新 KEK 指紋（現行）
	Retired      map[string]int // 各舊 KEK 指紋 → 退役筆數（逐把審計，codex 實作審 D6）
	RetiredCount int            // 退役總數
}

// kekSlot 金鑰邏輯槽位（用途＋版本），跨 load/validateKeyChain 共用
type kekSlot struct {
	purpose string
	version int
}

// InitKeyManager 載入金鑰表並完成 bootstrap（冪等）：
//   - 表空 → 生成 data DEK v1 與 audit_integrity v1（皆 active）
//   - KEK 一致性：某 (purpose,version) 僅存在其他 KEK 包裹的列 → ErrKEKMismatch
//   - 重包收尾：同 (purpose,version) 新舊 KEK 並存且本 KEK 為較新者 → 清除舊列
//
// **legacy 單鑰參數已刪除**（release-transitional-cleanup D3）：系統不具備任何
// legacy 解密路徑，無前綴密文於解密時即 fail-close。
func InitKeyManager(db *gorm.DB, kek crypto.KEKProvider) (*KeyManagerService, error) {
	s := &KeyManagerService{
		db:      db,
		kek:     kek,
		keys:    map[string]map[int][]byte{},
		ciphers: map[int]*crypto.AESCrypto{},
		active:  map[string]int{},
	}
	// bootstrap 閘門（key-inventory-transparency）：僅金鑰表完全為空時補鑄；
	// 非空表由 load 驗證完整性（缺代表／斷號／損毀即 fail-close，不補鑄），
	// 避免退役列使某 slot 只剩歷史而被誤判為空、補出新鑰使歷史密文永久不可解
	var count int64
	if err := s.db.Model(&model.DataKey{}).Count(&count).Error; err != nil {
		return nil, fmt.Errorf("讀取金鑰表筆數失敗: %w", err)
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	if count == 0 {
		if err := s.bootstrap(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// load 讀取金鑰表、驗證形狀與完整性、以現行 KEK 代表列解密、偵測並收尾 KEK 切換。
// 狀態靠明確欄位（KEKPending/KEKRetiredAt/KEKRetiredBy）而非 CreatedAt 推導；
// 收尾為軟刪除退役、best-effort：失敗不阻塞啟動、下次啟動重試（key-inventory-transparency）
func (s *KeyManagerService) load() error {
	var rows []model.DataKey
	if err := s.db.Order("purpose, version, created_at").Find(&rows).Error; err != nil {
		return fmt.Errorf("讀取金鑰表失敗: %w", err)
	}
	if len(rows) == 0 {
		return nil // 全新部署，交由 bootstrap（僅空表）
	}
	env := s.kekKeyID()

	// 0. 委託模式的 kek_id 形式守衛（D11.1 裁決 1）：只偵測、不改寫。
	// 本地 provider 下為 no-op；委託下僅檢查可證明為本 provider 委託格式的列。
	if err := guardDelegatedKEKIDCanonical(rows, s.kek); err != nil {
		return err
	}

	// 1. 欄位形狀驗證：每列須屬 live/pending/retired 三形狀之一（非法＝資料損毀）
	for _, r := range rows {
		if !kekShapeValid(r) {
			return fmt.Errorf("%w（金鑰列 %s v%d kek=%s 欄位狀態非法）", ErrKEKMismatch, r.Purpose, r.Version, r.KEKID)
		}
	}

	// 2. campaign 不變式：所有 pending 僅屬單一 KEK 指紋，且不與 env 混雜
	pendingKEKs := map[string]struct{}{}
	envPending, foreignPending := false, false
	for _, r := range rows {
		if r.KEKPending {
			pendingKEKs[r.KEKID] = struct{}{}
			if r.KEKID == env {
				envPending = true
			} else {
				foreignPending = true
			}
		}
	}
	if len(pendingKEKs) > 1 {
		return fmt.Errorf("%w（存在多組 pending KEK 指紋，非單一重包 campaign）", ErrKEKMismatch)
	}
	if envPending && foreignPending {
		return fmt.Errorf("%w（pending 同時含現行與外來 KEK）", ErrKEKMismatch)
	}

	// 3. slot 清冊與現行代表列（kek_id==env 且未退役）：每既有 slot 須恰一列
	reps := map[kekSlot]*model.DataKey{}
	slots := map[kekSlot]bool{}
	for i := range rows {
		r := &rows[i]
		sk := kekSlot{r.Purpose, r.Version}
		slots[sk] = true
		if r.KEKID == env && r.KEKRetiredAt == nil {
			if reps[sk] != nil {
				return fmt.Errorf("%w（slot %s v%d 有多個現行 KEK 代表列）", ErrKEKMismatch, r.Purpose, r.Version)
			}
			reps[sk] = r
		}
	}
	// 定向回退指引（kek-rewrap-hygiene-hardening D9）：env 為已退役且材料尚未
	// 清理的 KEK 時，fail-close 不變，但錯誤指明回退路徑（取代籠統 mismatch）。
	// 材料已清理者不觸發——訊息不洩漏退役史之外的資訊。不做自動 un-retire：
	// 切換完成後誤設舊 env 幾乎必為操作失誤，自動反轉會靜默撤銷金鑰儀式。
	// 指引依退役原因分流（opus 第二輪審 M2）：switched＝曾在役、「回退」語義
	// 成立；abandoned＝從未在役、「回退」是誤稱，照 runbook 復原退役列等於
	// 靜默撤銷一次刻意的放棄決策——指引改為重跑重包
	envRetiredReason := ""
	for _, r := range rows {
		if r.KEKID == env && r.KEKRetiredAt != nil && r.WrappedKey != "" {
			envRetiredReason = r.KEKRetiredReason
			if envRetiredReason == "" {
				envRetiredReason = model.KEKRetireReasonSwitched // 舊資料 backfill 前的保守解讀
			}
			break
		}
	}
	for sk := range slots {
		if reps[sk] == nil {
			switch envRetiredReason {
			case model.KEKRetireReasonAbandoned:
				return fmt.Errorf("%w（KEK %s 的重包已被放棄、從未在役：請將 ENCRYPTION_KEY 改回現行 KEK；"+
					"若確要改用此 KEK 請以現行 KEK 啟動後重新執行重包）", ErrKEKMismatch, env)
			case model.KEKRetireReasonSwitched:
				return fmt.Errorf("%w（KEK %s 已退役但材料尚未清理：若確要回退至此 KEK，"+
					"依 runbook 手動復原其退役列後重啟；若為誤設請將 ENCRYPTION_KEY 改回現行 KEK）",
					ErrKEKMismatch, env)
			}
			return fmt.Errorf("%w（slot %s v%d 無現行 KEK %s 代表列）", ErrKEKMismatch, sk.purpose, sk.version, env)
		}
	}

	// 4. 解密現行代表列，建 in-memory keys/ciphers/active。
	// 已清理佔位（顯式清理後的退役版本，wrapped 空）跳過 unwrap——
	// 材料已銷毀、僅佔位保鏈；引用掃描閘保證清理當下無存量引用
	for _, r := range reps {
		if r.WrappedKey == "" && r.Status == model.DataKeyStatusRetired {
			continue
		}
		raw, err := s.unwrapRow(*r)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.putKey(r.Purpose, r.Version, raw)
		if r.Status == model.DataKeyStatusActive {
			s.active[r.Purpose] = r.Version
		}
		s.mu.Unlock()
	}

	// 5. 金鑰鏈完整性：Status 合法、每必要用途恰一 active、版本連續（不待讀密文才失敗）
	if err := validateKeyChain(reps); err != nil {
		return err
	}

	// 6. 切換偵測與 best-effort 原子收尾（收尾自行鎖內重讀，不用本函式的舊快照）。
	// 寫入持 s.mu 與 getter 對稱（opus 第一輪審 L7）——目前僅 Init 期單執行緒，
	// 但鎖用法不對稱是未來線上重載改動的地雷
	s.mu.Lock()
	s.rewrapPending = foreignPending // env 為舊 KEK＋有 foreign pending＝待切換（UI 提示用）
	s.mu.Unlock()
	s.finalizeSwitch(env)
	if foreignPending {
		log.Printf("[KeyManager] 偵測到 KEK 重包未完成：新 KEK 包裹列已備妥，等待更新 env 後重啟切換")
	}
	return nil
}

// kekShapeValid 驗證單列 KEK 欄位形狀合法（key-inventory-transparency＋
// kek-rewrap-hygiene-hardening D9 軟刪除）：
// live（非 pending、未退役、有 wrapped）／pending（待切換、未退役、有 wrapped）／
// retired-switched（切換退役：有 replacement）／retired-abandoned（放棄退役：
// 無 replacement）。退役列的 wrapped 保留至顯式清理（清理後為空）——兩態皆合法。
// 相容既有資料：migration 20260801 已 backfill 既有退役列 reason='switched'。
// 角色（現行／待退役 predecessor／backlog／待切換／退役歷史）另由形狀＋
// kek_id vs env 推導，不在此判定。
func kekShapeValid(r model.DataKey) bool {
	live := !r.KEKPending && r.KEKRetiredAt == nil && r.KEKRetiredBy == "" &&
		r.KEKRetiredReason == "" && r.WrappedKey != ""
	pending := r.KEKPending && r.KEKRetiredAt == nil && r.KEKRetiredBy == "" &&
		r.KEKRetiredReason == "" && r.WrappedKey != ""
	retiredSwitched := !r.KEKPending && r.KEKRetiredAt != nil &&
		r.KEKRetiredReason == model.KEKRetireReasonSwitched && r.KEKRetiredBy != ""
	retiredAbandoned := !r.KEKPending && r.KEKRetiredAt != nil &&
		r.KEKRetiredReason == model.KEKRetireReasonAbandoned && r.KEKRetiredBy == ""
	// 已清理佔位（D9 顯式清理後的退役 DEK 版本現行列）：材料已銷毀、
	// 列保留使版本鏈不斷號；load 跳過 unwrap、不再供解密。
	// 佔位亦可為 pending（KEK 重包時佔位隨行複製，切換後轉正保鏈）
	purgedPlaceholder := r.KEKRetiredAt == nil && r.KEKRetiredBy == "" &&
		r.KEKRetiredReason == "" && r.WrappedKey == "" && r.Status == model.DataKeyStatusRetired
	return live || pending || retiredSwitched || retiredAbandoned || purgedPlaceholder
}

// ErrPreReleaseKeyTable 金鑰表含發佈前過渡格式（version 0 之列）。
//
// **為何必須顯式拒絕而非靠既有閘攔下**（release-transitional-cleanup D4）：
// v0 列既不構成版本斷號（它在 1..max 之外）也不使某用途缺 active，故既有的
// 連續性／active 數檢查會**放行**它，而放行的後果是該 v0 鑰被載入——
// `key_version=0` 的舊審計列反而驗章成功，推翻「系統無 v0 鑰」的不變式。
var ErrPreReleaseKeyTable = errors.New("資料庫含發佈前過渡格式（金鑰表存在 version 0 之列），請重建資料庫")

// validateKeyChain 驗證現行代表列形成的金鑰鏈完整性（key-inventory-transparency）：
// Status ∈ {active,retired}、每必要用途恰一 active、data 與 audit_integrity 版本
// 皆自 1 至 max 連續、**任何用途之 version 0 列一律拒絕啟動**。
// 缺用途／缺 active／多 active／斷號／非法 Status／v0 殘列 → fail-close
func validateKeyChain(reps map[kekSlot]*model.DataKey) error {
	versByPurpose := map[string][]int{}
	activeByPurpose := map[string]int{}
	for sk, r := range reps {
		// v0 殘列閘（D4）：**任何用途**，不限 audit_integrity——判定放在其他
		// 檢查之前，使錯誤訊息直指「須重建」而非籠統的金鑰表損毀
		if sk.version == 0 {
			return fmt.Errorf("%w（%s v0）", ErrPreReleaseKeyTable, sk.purpose)
		}
		if r.Status != model.DataKeyStatusActive && r.Status != model.DataKeyStatusRetired {
			return fmt.Errorf("%w（%s v%d Status 非法: %q）", ErrKEKMismatch, sk.purpose, sk.version, r.Status)
		}
		versByPurpose[sk.purpose] = append(versByPurpose[sk.purpose], sk.version)
		if r.Status == model.DataKeyStatusActive {
			activeByPurpose[sk.purpose]++
		}
	}
	// 兩用途的版本鏈皆自 v1 起（audit v0 快照已拆除）
	required := map[string]int{
		model.DataKeyPurposeData:           1,
		model.DataKeyPurposeAuditIntegrity: 1,
	}
	for purpose, minVer := range required {
		vers := versByPurpose[purpose]
		if len(vers) == 0 {
			return fmt.Errorf("%w（缺必要用途 %s 的金鑰）", ErrKEKMismatch, purpose)
		}
		if activeByPurpose[purpose] != 1 {
			return fmt.Errorf("%w（用途 %s 的 active 數 %d != 1）", ErrKEKMismatch, purpose, activeByPurpose[purpose])
		}
		sort.Ints(vers)
		for i, v := range vers {
			if v != minVer+i {
				return fmt.Errorf("%w（用途 %s 版本斷號：期望 v%d 得 v%d）", ErrKEKMismatch, purpose, minVer+i, v)
			}
		}
	}
	return nil
}

// finalizeSwitch 切換收尾（key-inventory-transparency＋kek-rewrap-hygiene-hardening
// D3/D4/D9）：現行代表為 env pending（切換完成待轉正）者轉正；kek_id<>env 的 live
// 舊列（待退役 predecessor／退役 backlog）軟退役（reason=switched，材料保留至
// 顯式清理）。整段在跨實例互斥鎖內、判定以鎖內重讀為準（鎖外 load 快照不可信——
// 另一實例的 abandon 可能已改動 pending 集合）。
//
// 語義守衛（D4，鎖擋「同時」、守衛擋「先後皆合法但組合致命」）：
//   - promote 影響列數必須等於鎖內重讀的預期數，否則整筆 rollback；
//   - 逐 slot 驗證退役後仍存在 env 的 live 代表列，否則整筆 rollback。
//
// 任一順序的 abandon／收尾交錯都不可能使 data_keys 失去現行 live 列。
//
// best-effort：取鎖失敗跳過本次（下次啟動重試）、其他失敗僅 log 不阻塞啟動；
// 失敗記錄於 lastFinalizeErr 供告警接線（main 於告警服務就緒後上報）。
func (s *KeyManagerService) finalizeSwitch(env string) {
	var retired int64
	fromCount := map[string]int{}
	err := s.withDataKeysLock(func(tx *gorm.DB) error {
		// 鎖內重讀：判定一律以本交易所見為準
		var rows []model.DataKey
		if err := tx.Order("purpose, version, created_at").Find(&rows).Error; err != nil {
			return fmt.Errorf("鎖內重讀金鑰表失敗: %w", err)
		}
		var toPromote, toRetire []uint
		retireSlots := map[kekSlot]bool{}
		fromCount = map[string]int{}
		for _, r := range rows {
			if r.KEKPending && r.KEKID == env {
				toPromote = append(toPromote, r.ID)
			}
			if !r.KEKPending && r.KEKRetiredAt == nil && r.KEKID != env {
				toRetire = append(toRetire, r.ID)
				retireSlots[kekSlot{r.Purpose, r.Version}] = true
				fromCount[r.KEKID]++
			}
		}
		if len(toPromote) == 0 && len(toRetire) == 0 {
			return nil
		}
		// promote：影響列數守衛（clones 若已被另一實例放棄退役，此處不符即中止，
		// 不進入退役步驟——舊列原封不動）
		if len(toPromote) > 0 {
			res := tx.Model(&model.DataKey{}).
				Where("id IN ? AND kek_pending = ? AND kek_retired_at IS NULL", toPromote, true).
				Update("kek_pending", false)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != int64(len(toPromote)) {
				return fmt.Errorf("promote 影響列數 %d != 預期 %d（clones 狀態已變，中止收尾）",
					res.RowsAffected, len(toPromote))
			}
		}
		// 退役前逐 slot 驗證：退役後該 slot 仍須有 env 的 live 代表列
		for sk := range retireSlots {
			var liveEnv int64
			if err := tx.Model(&model.DataKey{}).
				Where("purpose = ? AND version = ? AND kek_id = ? AND kek_pending = ? AND kek_retired_at IS NULL",
					sk.purpose, sk.version, env, false).
				Count(&liveEnv).Error; err != nil {
				return fmt.Errorf("退役守衛查詢失敗: %w", err)
			}
			if liveEnv == 0 {
				return fmt.Errorf("slot %s v%d 退役後將無現行 KEK live 代表列，中止收尾",
					sk.purpose, sk.version)
			}
		}
		if len(toRetire) > 0 {
			now := time.Now()
			// 軟退役（D9）：僅改狀態欄位，wrapped_key 保留至顯式清理
			res := tx.Model(&model.DataKey{}).
				Where("id IN ? AND kek_retired_at IS NULL", toRetire).
				Updates(map[string]interface{}{
					"kek_retired_at":     now,
					"kek_retired_by":     env,
					"kek_retired_reason": model.KEKRetireReasonSwitched,
				})
			if res.Error != nil {
				return res.Error
			}
			retired = res.RowsAffected
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrKeyOpBusy) {
			log.Printf("[KeyManager] KEK 切換收尾跳過：另一金鑰操作進行中（下次啟動重試）")
			return
		}
		log.Printf("[KeyManager] KEK 切換收尾失敗（不阻塞啟動，下次重試）: %v", err)
		s.mu.Lock()
		s.lastFinalizeErr = err
		s.mu.Unlock()
		return
	}
	if retired > 0 {
		froms := make([]string, 0, len(fromCount))
		for k := range fromCount {
			froms = append(froms, k)
		}
		s.mu.Lock()
		s.lastSwitch = &KEKSwitchResult{ToKEKID: env, Retired: fromCount, RetiredCount: int(retired)}
		s.mu.Unlock()
		log.Printf("[KeyManager] KEK 切換完成：%v → %s（軟退役 %d 筆舊包裹列，材料保留至顯式清理）", froms, env, retired)
	}
}

func (s *KeyManagerService) unwrapRow(row model.DataKey) ([]byte, error) {
	// 守衛（key-inventory-transparency）：退役列／空 wrapped／非現行 KEK 包裹一律拒絕，
	// 防未來新增 caller 繞過 load 的現行代表列篩選而誤解密
	if row.KEKRetiredAt != nil || row.WrappedKey == "" {
		return nil, fmt.Errorf("%w（金鑰 %s v%d 為退役或空列，不可解密）", ErrKEKMismatch, row.Purpose, row.Version)
	}
	if row.KEKID != s.kekKeyID() {
		return nil, fmt.Errorf("%w（金鑰 %s v%d kek=%s 非現行 KEK %s）", ErrKEKMismatch, row.Purpose, row.Version, row.KEKID, s.kekKeyID())
	}
	raw, err := unwrapMaterial(s.kek, row.Purpose, row.Version, row.WrappedKey)
	if err != nil {
		// **發佈前過渡格式另立一類**（release-transitional-cleanup D5）：無前綴或
		// 判別子 `1` 的值不是 KEK 不符，把它折進 ErrKEKMismatch 會讓操作者照著
		// 「檢查 ENCRYPTION_KEY」的指引白忙——正解是重建資料庫。錯誤保持可辨識。
		if errors.Is(err, crypto.ErrWrappedKeyPreRelease) {
			return nil, fmt.Errorf("%w（金鑰 %s v%d）", err, row.Purpose, row.Version)
		}
		// kek_id 相符但解包失敗＝指紋碰撞或資料損毀，一律視為 KEK 不符拒啟動。
		// **一致性的權威判準是「代表列 Unwrap 成功」，kek_id 比對僅為篩選**（D4／1.5）
		return nil, fmt.Errorf("%w（金鑰 %s v%d 解包失敗: %v）", ErrKEKMismatch, row.Purpose, row.Version, err)
	}
	return raw, nil
}

// kekKeyID 現行 KEK 的金鑰識別（落 kek_id 的值＝KeyRef().KeyID）。
// 執行期模式（env／ui）SHALL NOT 進入此值（D4）。
func (s *KeyManagerService) kekKeyID() string { return s.kek.KeyRef().KeyID }

// KEKRef 現行 KEK 的金鑰引用（清冊與稽核用）
func (s *KeyManagerService) KEKRef() crypto.KeyRef { return s.kek.KeyRef() }

// KEKMode 現行 KEK 的執行期模式（D10 雙軌互證：清冊 SHALL 由此導出，
// SHALL NOT 重讀 os.Getenv、亦 SHALL NOT 由 KeyRef().Provider 推導）
func (s *KeyManagerService) KEKMode() string { return s.kek.Mode() }

// wrapMaterial 以指定 provider 包裹金鑰材料並編為 wrapped_key 欄位值。
// DEK 層 AAD＝`DEKAAD(purpose, version)`（D5，canonical 編碼、不含 kek_id 等
// 可變識別符）。
//
// **恆帶 AAD、恆帶 `wk:2` 前綴**（release-transitional-cleanup D5）：本地格式的
// 相容窗（裸 base64、無 AAD）已拆除，寫入端不再有任何格式分岔。
func wrapMaterial(kek crypto.KEKProvider, purpose string, version int, raw []byte) (string, error) {
	tag := kek.FormatTag()
	wrapped, err := kek.Wrap(context.Background(), raw, crypto.DEKAAD(purpose, version))
	if err != nil {
		return "", fmt.Errorf("包裹金鑰失敗: %w", err)
	}
	return crypto.EncodeWrappedKey(tag, wrapped)
}

// unwrapMaterial 解析 wrapped_key 欄位值並以指定 provider 解包。
//
// **無 fallback（定案 B2）**：合法值恆為 `wk:2:`，一律以 AAD 解包、失敗即失敗。
// 無前綴與判別子 `1` 由 ParseWrappedKey 於解包前拒收（發佈前過渡格式）。
func unwrapMaterial(kek crypto.KEKProvider, purpose string, version int, column string) ([]byte, error) {
	tag, wrapped, err := crypto.ParseWrappedKey(column)
	if err != nil {
		return nil, err
	}
	if tag != kek.FormatTag() {
		return nil, fmt.Errorf("%w（列格式標記 %q，現行 provider 為 %q）",
			crypto.ErrKEKFormatMismatch, tag, kek.FormatTag())
	}
	return kek.Unwrap(context.Background(), wrapped, crypto.DEKAAD(purpose, version))
}

func (s *KeyManagerService) putKey(purpose string, version int, raw []byte) {
	if s.keys[purpose] == nil {
		s.keys[purpose] = map[int][]byte{}
	}
	s.keys[purpose][version] = raw
	if purpose == model.DataKeyPurposeData {
		if c, err := crypto.NewAESCrypto(raw); err == nil {
			s.ciphers[version] = c
		}
	}
}

// bootstrap 冪等補齊缺失金鑰（D3/D4）。
//
// **僅鑄造各必要用途的 v1 active 鑰**（release-transitional-cleanup D4）：
// 原「audit_integrity 快照 legacy 派生鑰為 v0（retired）」已拆除——全新安裝不再
// 出生即帶退役列，版本鏈自 v1 起。此適用於**全部**初始化路徑（env 模式首啟與
// `ui` 模式初始化解封同）。
func (s *KeyManagerService) bootstrap() error {
	// 原子化（key-inventory-transparency，codex 實作審 MED）：三筆初始金鑰包同一交易，
	// 中途失敗 rollback——不留「非空但不完整」的表，致後續啟動的金鑰鏈完整性檢查永久
	// ErrKEKMismatch。記憶體狀態（keys/active）於 commit 成功後才更新。
	// 跨實例互斥（D3，codex 第一輪審 #1）：bootstrap 也是 data_keys 寫入路徑——
	// 空庫多副本同時啟動時，不入鎖會各自鑄出同版本不同材料的 v1（不同 KEK 下
	// 唯一索引攔不住）形成腦裂。入鎖＋鎖內重讀該用途列數：已被他副本補齊即
	// fail-close 要求重啟重載（不可沿用鎖外舊判定續寫）。
	type seeded struct {
		purpose string
		version int
		raw     []byte
		active  bool
	}
	var created []seeded
	err := s.withDataKeysLock(func(tx *gorm.DB) error {
		staleCheck := func(purpose string) (bool, error) {
			var n int64
			if err := tx.Model(&model.DataKey{}).Where("purpose = ?", purpose).
				Count(&n).Error; err != nil {
				return false, fmt.Errorf("bootstrap 鎖內重讀失敗: %w", err)
			}
			return n > 0, nil
		}
		if _, ok := s.active[model.DataKeyPurposeData]; !ok {
			if seededByPeer, err := staleCheck(model.DataKeyPurposeData); err != nil {
				return err
			} else if seededByPeer {
				return fmt.Errorf("bootstrap 競態：%s 金鑰已由另一實例建立，請重啟本實例重新載入", model.DataKeyPurposeData)
			}
			raw, err := s.insertKey(tx, model.DataKeyPurposeData, 1, nil, model.DataKeyStatusActive)
			if err != nil {
				return err
			}
			created = append(created, seeded{model.DataKeyPurposeData, 1, raw, true})
		}
		if _, ok := s.active[model.DataKeyPurposeAuditIntegrity]; !ok {
			if seededByPeer, err := staleCheck(model.DataKeyPurposeAuditIntegrity); err != nil {
				return err
			} else if seededByPeer {
				return fmt.Errorf("bootstrap 競態：%s 金鑰已由另一實例建立，請重啟本實例重新載入", model.DataKeyPurposeAuditIntegrity)
			}
			raw, err := s.insertKey(tx, model.DataKeyPurposeAuditIntegrity, 1, nil, model.DataKeyStatusActive)
			if err != nil {
				return err
			}
			created = append(created, seeded{model.DataKeyPurposeAuditIntegrity, 1, raw, true})
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	for _, k := range created {
		s.putKey(k.purpose, k.version, k.raw)
		if k.active {
			s.active[k.purpose] = k.version
		}
		log.Printf("[KeyManager] bootstrap 生成 %s v%d", k.purpose, k.version)
	}
	s.mu.Unlock()
	return nil
}

// insertKey 生成（material=nil）或收錄指定材料的金鑰，KEK 包裹後落庫。
// db 由呼叫端提供——bootstrap 直用 s.db，輪替傳交易（與 retire 同 commit）
func (s *KeyManagerService) insertKey(db *gorm.DB, purpose string, version int, material []byte, status string) ([]byte, error) {
	raw := material
	if raw == nil {
		raw = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, raw); err != nil {
			return nil, fmt.Errorf("生成金鑰失敗: %w", err)
		}
	}
	column, err := wrapMaterial(s.kek, purpose, version, raw)
	if err != nil {
		return nil, err
	}
	row := model.DataKey{
		Purpose:    purpose,
		Version:    version,
		WrappedKey: column,
		KEKID:      s.kekKeyID(),
		Status:     status,
		CreatedAt:  time.Now(),
	}
	if err := db.Create(&row).Error; err != nil {
		return nil, fmt.Errorf("寫入金鑰列失敗: %w", err)
	}
	return raw, nil
}

// Decrypt 無列身分的解密入口（僅供不帶 AAD 身分的呼叫端）。
// 終態下所有落庫密文皆為 `enc:a1`，故經此入口一律以
// ErrCipherRefIncomplete 拒絕——呼叫端須改用 DecryptFor（否則 AAD 綁定會被
// 靜默繞過）。本入口保留為明確的錯誤面，不是相容路徑。
func (s *KeyManagerService) Decrypt(ciphertext string) (string, error) {
	return s.decryptWith(ciphertext, crypto.CipherRef{})
}

// EncryptFor 以 active data DEK 加密並綁定列身分（D5 資料層 AAD）。
// ref 不完整（缺表／欄／pk）即拒絕——AAD 綁定不得因呼叫端疏漏而靜默退化。
func (s *KeyManagerService) EncryptFor(_ context.Context, ref crypto.CipherRef, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if !ref.Valid() {
		return "", fmt.Errorf("%w（table=%q column=%q）", ErrCipherRefIncomplete, ref.Table, ref.Column)
	}
	s.mu.RLock()
	ver := s.active[model.DataKeyPurposeData]
	c := s.ciphers[ver]
	s.mu.RUnlock()
	if c == nil {
		return "", errors.New("data DEK 未初始化")
	}
	raw, err := c.EncryptBytesAAD([]byte(plaintext), ref.AAD())
	if err != nil {
		return "", err
	}
	return crypto.EncodeEnvelopeAAD(crypto.AADSchemeA1, ver, raw)
}

// DecryptFor 解密並驗證列身分；AAD 不符即解密失敗（跨表跨欄搬移密文擋於此）。
// 非 `enc:a1` 之值一律 fail-close（ErrNonFinalCiphertext），無相容語義。
func (s *KeyManagerService) DecryptFor(_ context.Context, ref crypto.CipherRef, ciphertext string) (string, error) {
	return s.decryptWith(ciphertext, ref)
}

// ErrCipherRefIncomplete 資料層 AAD 綁定所需的列身分不完整
var ErrCipherRefIncomplete = errors.New("密文列身分不完整，無法建立 AAD 綁定")

// decryptWith 解密分派（release-transitional-cleanup D1：AAD 恆強制）。
//
// **兩個非終態分支一律 fail-close 回可辨識格式錯**，SHALL NOT 回退任何其他路徑：
//   - 無前綴（`ok=false`，發佈前的 legacy 純 base64）→ ErrNonFinalCiphertext；
//   - `AADSchemeNone`（發佈前的 `enc:v<N>`）→ ErrNonFinalCiphertext。
//
// 判定落在**本層**而非 `crypto.ParseEnvelopeFull`：後者維持能解析 `enc:v`，
// 因為殘值盤點與退役 DEK 引用掃描以它為判定基礎——收斂解密不等於收斂解析。
func (s *KeyManagerService) decryptWith(ciphertext string, ref crypto.CipherRef) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	scheme, ver, raw, ok, err := crypto.ParseEnvelopeFull(ciphertext)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w（無前綴值）", ErrNonFinalCiphertext)
	}
	if scheme == crypto.AADSchemeNone {
		return "", fmt.Errorf("%w（無 AAD 綁定的 enc:v 值）", ErrNonFinalCiphertext)
	}
	if scheme == crypto.AADSchemeA1 && !ref.Valid() {
		return "", fmt.Errorf("%w（帶 AAD 密文須經 DecryptFor 解密）", ErrCipherRefIncomplete)
	}
	s.mu.RLock()
	c := s.ciphers[ver]
	s.mu.RUnlock()
	if c == nil {
		return "", fmt.Errorf("密文引用不存在的 data DEK v%d", ver)
	}
	var aad []byte
	if scheme == crypto.AADSchemeA1 {
		aad = ref.AAD()
	}
	plain, err := c.DecryptBytesAAD(raw, aad)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ErrNonFinalCiphertext 讀到發佈前過渡格式的密文（無前綴或無 AAD 綁定）。
// 系統不具備任何相容解密路徑，一律 fail-close；此為可辨識的格式錯，
// SHALL NOT 落入籠統的解密失敗。
var ErrNonFinalCiphertext = errors.New("密文為發佈前過渡格式（非 enc:a1）：系統無相容解密路徑，資料庫須重建")

// ActiveHMACKey 現行審計蓋章鑰（版本與材料）
func (s *KeyManagerService) ActiveHMACKey() (int, []byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ver := s.active[model.DataKeyPurposeAuditIntegrity]
	return ver, s.keys[model.DataKeyPurposeAuditIntegrity][ver]
}

// HMACKeyByVersion 指定版本蓋章鑰；不存在回 nil（驗證端計為不符）
func (s *KeyManagerService) HMACKeyByVersion(version int) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys[model.DataKeyPurposeAuditIntegrity][version]
}

// RewrapPending KEK 重包是否待切換（清冊「重包未完成」提示）
func (s *KeyManagerService) RewrapPending() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rewrapPending
}

// KEKKeyID 現行 KEK 指紋（清冊顯示）
func (s *KeyManagerService) KEKKeyID() string {
	return s.kekKeyID()
}

// LastKEKSwitch 本次啟動偵測並收尾的 KEK 切換結果（nil＝無切換），供 main 於
// audit 就緒後 best-effort 補記審計（key-inventory-transparency）
func (s *KeyManagerService) LastKEKSwitch() *KEKSwitchResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSwitch
}

// DEKVersionEntry 清冊 DEK 版本項（D9 顯式清理後補「已清理」衍生態，codex 第一輪
// 審 #7）。material_purged 為 SQL 端衍生布林（wrapped_key 是否已清空）——查詢
// 絕不選取 wrapped_key 本值，服務記憶體也不經手材料。
type DEKVersionEntry struct {
	ID             uint       `json:"id"`
	Purpose        string     `json:"purpose"`
	Version        int        `json:"version"`
	KEKID          string     `gorm:"column:kek_id" json:"kek_id"`
	Status         string     `json:"status"`
	MaterialPurged bool       `gorm:"column:material_purged" json:"material_purged"`
	CreatedAt      time.Time  `json:"created_at"`
	RetiredAt      *time.Time `json:"retired_at,omitempty"`
}

// ListKeys 金鑰清冊主 DEK 版本鏈（DB 側）：僅回現行 KEK 未退役、非 pending 的
// 代表列（key-inventory-transparency D7）——退役史與 pending 各自獨立呈現，
// 版本鏈不摻雜歷史/過渡列。不含任何金鑰材料與 wrapped 值。
func (s *KeyManagerService) ListKeys() ([]DEKVersionEntry, error) {
	var rows []DEKVersionEntry
	if err := s.db.Model(&model.DataKey{}).
		Select("id, purpose, version, kek_id, status, created_at, retired_at, (wrapped_key = '') AS material_purged").
		Where("kek_id = ? AND kek_retired_at IS NULL AND kek_pending = ?", s.kekKeyID(), false).
		Order("purpose, version").Scan(&rows).Error; err != nil {
		return nil, err
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Purpose != rows[j].Purpose {
			return rows[i].Purpose < rows[j].Purpose
		}
		return rows[i].Version < rows[j].Version
	})
	return rows, nil
}

// KEKRetirementRecord KEK 退役史一筆（key-inventory-transparency D6）：
// 按 from(舊 KEK 指紋)/to(replacement 指紋)/退役時間聚合後的一組退役列。
// rows 為該組退役列數；material_rows 為其中材料尚存（未經顯式清理）的列數
// （D9 軟刪除後材料保留至清理，清冊須可驗證銷毀結果）。不含 wrapped_key 本值。
type KEKRetirementRecord struct {
	FromKEKID    string    `json:"from_kek_id"`
	ToKEKID      string    `json:"to_kek_id"`
	RetiredAt    time.Time `json:"retired_at"`
	Rows         int       `json:"rows"`
	MaterialRows int       `json:"material_rows"`
}

// ListRetiredKEKs KEK 退役史（key-inventory-transparency D6/D7）：查退役列
// （kek_retired_at IS NOT NULL），SELECT 僅取指紋/退役中繼欄位與材料存量
// 衍生布林（絕不選 wrapped_key 本值），按 (kek_id, kek_retired_by, retired_at)
// 聚合成 from→to 記錄，依退役時間新→舊排序。多次 A→B→C 切換以 replacement
// 指紋精確區分不誤配。
func (s *KeyManagerService) ListRetiredKEKs() ([]KEKRetirementRecord, error) {
	type retiredRow struct {
		KEKID        string     `gorm:"column:kek_id"`
		KEKRetiredAt *time.Time `gorm:"column:kek_retired_at"`
		KEKRetiredBy string     `gorm:"column:kek_retired_by"`
		HasMaterial  bool       `gorm:"column:has_material"`
	}
	var rows []retiredRow
	if err := s.db.Model(&model.DataKey{}).
		Select("kek_id, kek_retired_at, kek_retired_by, (wrapped_key <> '') AS has_material").
		Where("kek_retired_at IS NOT NULL").Scan(&rows).Error; err != nil {
		return nil, err
	}
	type aggKey struct {
		from string
		to   string
		nano int64 // 以 UnixNano 為聚合鍵，避免 time.Time 表示差異影響分組
	}
	counts := map[aggKey]int{}
	materials := map[aggKey]int{}
	records := map[aggKey]*KEKRetirementRecord{}
	order := []aggKey{}
	for _, r := range rows {
		if r.KEKRetiredAt == nil {
			continue
		}
		k := aggKey{from: r.KEKID, to: r.KEKRetiredBy, nano: r.KEKRetiredAt.UnixNano()}
		if _, ok := counts[k]; !ok {
			order = append(order, k)
			records[k] = &KEKRetirementRecord{
				FromKEKID: r.KEKID, ToKEKID: r.KEKRetiredBy, RetiredAt: *r.KEKRetiredAt,
			}
		}
		counts[k]++
		if r.HasMaterial {
			materials[k]++
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i].nano > order[j].nano })
	out := make([]KEKRetirementRecord, 0, len(order))
	for _, k := range order {
		rec := records[k]
		rec.Rows = counts[k]
		rec.MaterialRows = materials[k]
		out = append(out, *rec)
	}
	return out, nil
}
