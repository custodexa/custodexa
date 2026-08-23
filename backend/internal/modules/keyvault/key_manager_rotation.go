package keyvault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

// 換鑰精靈：全部操作皆管理員手動觸發，
// 系統永不自動輪換任何金鑰。

// rotationMaxPerRunDefault 單次重加密上限預設（沿 retention 慣例）
const rotationMaxPerRunDefault = 100000

// rotationMinPerRun 單次上限的下界：
// 重加密掃描每頁 500 列（envelope_migration_service.go:202），單輪上限低於一頁
// 代表一次觸發連一個掃描頁都推不完——換鑰永遠跑不完而清冊仍顯示可輪替。
// 與 PolicyKeyRotationMaxPerRun 的 Min 同值
const rotationMinPerRun = 500

// rotationPolicySource 單次上限的執行期來源（安全政策頁）
type rotationPolicySource interface {
	GetInt(key string) int
}

// SetPolicySource 接上安全政策頁作為單次重加密上限的執行期事實源。
//
// **每次輪替都重讀而非啟動時快取**：管理員調整上限的目的是控制單次執行時間，
// 若須重啟才生效，正在跑的換鑰活動就調不動
func (s *KeyManagerService) SetPolicySource(p rotationPolicySource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies = p
}

// rotationMaxPerRun 單次重加密上限：政策頁優先，未接政策時退回 env（單元測試與
// 未接政策的組裝路徑）。邊界複查在此重做一次——政策若因資料層直改而落到下界
// 之下，換鑰會退化成每輪推進數列，那正是本鍵下界要防的靜默停擺
func (s *KeyManagerService) rotationMaxPerRun() int64 {
	s.mu.RLock()
	src := s.policies
	s.mu.RUnlock()
	if src != nil {
		n := int64(src.GetInt(policy.PolicyKeyRotationMaxPerRun))
		if n < rotationMinPerRun {
			log.Printf("[KeyManager] 單次換鑰上限 %d 低於下界 %d，改用下界", n, rotationMinPerRun)
			return rotationMinPerRun
		}
		return n
	}
	return rotationMaxPerRunFromEnv()
}

// rotationMaxPerRunFromEnv 未接政策時的退路：env 可調，未設/非法用預設
func rotationMaxPerRunFromEnv() int64 {
	if v := os.Getenv("KEY_ROTATION_MAX_PER_RUN"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
		log.Printf("[KeyManager] KEY_ROTATION_MAX_PER_RUN=%q 非法，改用預設 %d", v, rotationMaxPerRunDefault)
	}
	return rotationMaxPerRunDefault
}

// DEKRotationResult DEK 輪替結果（API 回應與審計 Details）
type DEKRotationResult struct {
	Purpose     string `json:"purpose"`
	FromVersion int    `json:"from_version"`
	ToVersion   int    `json:"to_version"`
	Reencrypted int64  `json:"reencrypted"`
	Failed      int64  `json:"failed"`
	// Pending 本輪後仍待重加密的值數（失敗值；可再次呼叫續跑）
	Pending int64 `json:"pending"`
	// Resumed true＝本輪為續跑（未鑄新版本，補齊現行 active 版本的殘值）
	Resumed bool `json:"resumed"`
}

// ErrRewrapPending KEK 重包待切換期間拒絕輪替：此時新生成的金鑰仍以舊 KEK
// 包裹、不在重包列中，管理員切換新 KEK 重啟會 ErrKEKMismatch 拒啟動
var ErrRewrapPending = errors.New("KEK 重包待切換：請先更新 ENCRYPTION_KEY 並重啟完成切換，再執行金鑰輪替")

// ErrNoRewrapPending 無待切換重包時放棄的守衛
var ErrNoRewrapPending = errors.New("目前無待切換的 KEK 重包，無需放棄")

// ErrRewrapPendingExists 已有待切換 pending 時拒絕新重包：
// 要求先完成切換或放棄重包，不靜默清除既有 pending 而使已交付的新 KEK 失效
var ErrRewrapPendingExists = errors.New("已有待切換的 KEK 重包：請先完成切換（更新 ENCRYPTION_KEY 重啟）或放棄重包，再開始新重包")

// ErrRetireBacklog 前次切換未成功退役的舊列尚未收斂時拒絕新重包
var ErrRetireBacklog = errors.New("前次 KEK 切換的舊列尚未完成退役收斂：請先重啟後端讓其自動收斂，再開始新重包")

// ErrStaleKeyCache 本實例 in-memory 金鑰快取與 DB 現行版本不符：
// 多實例下另一實例已完成輪替、本實例未重啟仍持舊 active——以舊基準續作輪替
// 會鑄錯版本或對讀不懂的新版密文空轉。fail-close 要求重啟重載
var ErrStaleKeyCache = errors.New("本實例金鑰狀態已過期（另一實例已完成輪替或 KEK 切換），請重啟本實例後重試")

// activeVersionTx 鎖內讀 DB 現行 active 版本（env live 代表列；判定以鎖內重讀為準）。
// 查無列＝本實例 KEK 已無 live 代表（另一實例已完成切換、本實例 env 已被退役；
// 這是實測過的情境）——此時絕不可放行輪替，否則會鑄出僅被
// 已退役 KEK 包裹的新版本，令所有實例不可開機
func (s *KeyManagerService) activeVersionTx(tx *gorm.DB, purpose string) (int, error) {
	var row model.DataKey
	if err := tx.Select("version").
		Where("purpose = ? AND kek_id = ? AND status = ? AND kek_pending = ? AND kek_retired_at IS NULL",
			purpose, s.kekKeyID(), model.DataKeyStatusActive, false).
		Order("version DESC").First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, ErrStaleKeyCache
		}
		return 0, fmt.Errorf("讀取現行金鑰版本失敗: %w", err)
	}
	return row.Version, nil
}

// requireFreshActiveTx 鎖內驗證 in-memory active 與 DB 一致，不符即 ErrStaleKeyCache
func (s *KeyManagerService) requireFreshActiveTx(tx *gorm.DB, purpose string) (int, error) {
	s.mu.RLock()
	memVer := s.active[purpose]
	s.mu.RUnlock()
	dbVer, err := s.activeVersionTx(tx, purpose)
	if err != nil {
		return 0, err
	}
	if dbVer != memVer {
		return 0, ErrStaleKeyCache
	}
	return memVer, nil
}

// RotateDataDEK data DEK 輪替：生成新版本→全量重加密→舊版轉 retired。
// 逐值冪等（已為新版本格式即跳過）；中斷或部分失敗後再次呼叫即以現行
// active 版本續跑（不鑄新版本——否則 partial 後每按一次膨脹一代）。
// data_keys 判定與寫入在跨實例互斥鎖內（campaign 判定 DB 現查，不憑
// 行程內旗標——多實例下另一實例的 pending 本行程看不見）；重加密長迴圈
// 在鎖外（不持鎖掃大表）。
func (s *KeyManagerService) RotateDataDEK() (*DEKRotationResult, error) {
	var fromVer, toVer int
	var newRaw []byte
	bumped := false
	err := s.withDataKeysLock(func(tx *gorm.DB) error {
		if err := s.rejectPendingCampaignTx(tx); err != nil {
			return err
		}
		activeVer, err := s.requireFreshActiveTx(tx, model.DataKeyPurposeData)
		if err != nil {
			return err
		}
		fromVer, toVer = activeVer, activeVer
		// 續跑判定：現行版本仍有待重加密值（前次輪替 partial 或遷移殘值）
		// 時補齊現版，殘值歸零後的下一次呼叫才鑄新版本。
		// 經 tx 掃描：sqlite :memory: 測試環境下 tx 進行中另開 s.db 連線
		// 會拿到獨立空 DB（連線池陷阱）；postgres 下亦保持單交易一致視圖
		pending, err := s.rotationPendingCountOn(tx, activeVer)
		if err != nil {
			return fmt.Errorf("檢查輪替進度失敗: %w", err)
		}
		if pending == 0 {
			f, t, raw, err := s.bumpActiveKeyTx(tx, model.DataKeyPurposeData)
			if err != nil {
				return err
			}
			fromVer, toVer, newRaw, bumped = f, t, raw, true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if bumped {
		s.commitBumpedKey(model.DataKeyPurposeData, toVer, newRaw)
	}

	result := &DEKRotationResult{
		Purpose: model.DataKeyPurposeData, FromVersion: fromVer, ToVersion: toVer,
		Resumed: fromVer == toVer,
	}
	scan := &EnvelopeMigrationResult{RanAt: time.Now()}
	// 單次重加密上限（沿 retention 慣例 env 可調，防未來大表長交易）；
	// 達上限即回 partial，再次呼叫續跑（逐值冪等）
	scan.MaxOps = s.rotationMaxPerRun()
	skip := func(v string) bool {
		ver, ok := envelopeVersionOf(v)
		return ok && ver == toVer
	}
	for _, target := range envelopeMigrationTargets {
		reencryptEnvelopeColumn(s.db, s, target, skip, scan)
	}
	result.Reencrypted = scan.Migrated
	result.Failed = scan.Failed
	if result.Pending, err = s.rotationPendingCount(toVer); err != nil {
		// 本輪重加密已落地（逐值冪等），但殘餘量未知——不得以零值謊稱
		// 完成；回錯誤讓管理員重試，續跑判定會從 DB 重算
		log.Printf("[KeyManager] data DEK 輪替 v%d 重加密 %d 筆後殘餘重算失敗: %v", toVer, result.Reencrypted, err)
		return nil, fmt.Errorf("輪替殘餘重算失敗（本輪重加密 %d 筆已生效，重試即續跑）: %w", result.Reencrypted, err)
	}
	if result.Resumed {
		log.Printf("[KeyManager] data DEK 輪替續跑 v%d：重加密 %d 筆、失敗 %d 筆、殘餘 %d 筆", toVer, result.Reencrypted, result.Failed, result.Pending)
	} else {
		log.Printf("[KeyManager] data DEK 輪替 v%d→v%d：重加密 %d 筆、失敗 %d 筆", fromVer, toVer, result.Reencrypted, result.Failed)
	}
	return result, nil
}

// RotateAuditKey 審計蓋章鑰輪替：生成新版本 active、舊版轉 retired。
// 不重算歷史章（版本化的意義）——新列以新鑰蓋章，歷史列以其 key_version 驗證。
// data_keys 判定與寫入在跨實例互斥鎖內。
func (s *KeyManagerService) RotateAuditKey() (*DEKRotationResult, error) {
	var fromVer, toVer int
	var newRaw []byte
	err := s.withDataKeysLock(func(tx *gorm.DB) error {
		if err := s.rejectPendingCampaignTx(tx); err != nil {
			return err
		}
		if _, err := s.requireFreshActiveTx(tx, model.DataKeyPurposeAuditIntegrity); err != nil {
			return err
		}
		var err error
		fromVer, toVer, newRaw, err = s.bumpActiveKeyTx(tx, model.DataKeyPurposeAuditIntegrity)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.commitBumpedKey(model.DataKeyPurposeAuditIntegrity, toVer, newRaw)
	log.Printf("[KeyManager] 審計蓋章鑰輪替 v%d→v%d（歷史章不重算）", fromVer, toVer)
	return &DEKRotationResult{Purpose: model.DataKeyPurposeAuditIntegrity, FromVersion: fromVer, ToVersion: toVer}, nil
}

// rejectPendingCampaignTx campaign 判定（鎖內 DB 現查）：存在任何待切換
// pending 列即拒絕輪替——不憑行程內 rewrapPending 旗標（多實例互不可見）。
func (s *KeyManagerService) rejectPendingCampaignTx(tx *gorm.DB) error {
	var pendingCount int64
	if err := tx.Model(&model.DataKey{}).Where("kek_pending = ?", true).
		Count(&pendingCount).Error; err != nil {
		return fmt.Errorf("檢查待切換狀態失敗: %w", err)
	}
	if pendingCount > 0 {
		return ErrRewrapPending
	}
	return nil
}

// bumpActiveKeyTx 生成 purpose 的下一版本並切換 active（舊版轉 retired），
// 在呼叫端提供的鎖內交易執行——中途失敗整筆 rollback 不留雙 active。
// 不改 in-memory 狀態：commit 成功後由呼叫端 commitBumpedKey 套用
// （交易內先改記憶體會在 rollback 時留下幽靈版本）。
func (s *KeyManagerService) bumpActiveKeyTx(tx *gorm.DB, purpose string) (fromVer, toVer int, raw []byte, err error) {
	s.mu.RLock()
	fromVer = s.active[purpose]
	s.mu.RUnlock()
	toVer = fromVer + 1
	if raw, err = s.insertKey(tx, purpose, toVer, nil, model.DataKeyStatusActive); err != nil {
		return 0, 0, nil, err
	}
	now := time.Now()
	if txErr := tx.Model(&model.DataKey{}).
		Where("purpose = ? AND version = ? AND kek_id = ? AND kek_retired_at IS NULL", purpose, fromVer, s.kekKeyID()).
		Updates(map[string]interface{}{"status": model.DataKeyStatusRetired, "retired_at": now}).Error; txErr != nil {
		return 0, 0, nil, fmt.Errorf("轉置舊版金鑰狀態失敗: %w", txErr)
	}
	return fromVer, toVer, raw, nil
}

// commitBumpedKey 鎖內交易 commit 成功後套用 in-memory 狀態
func (s *KeyManagerService) commitBumpedKey(purpose string, toVer int, raw []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putKey(purpose, toVer, raw)
	s.active[purpose] = toVer
}

// rotationPendingCount 尚未使用 active data DEK 版本的值數（進度查詢）。
// Go 層嚴格 ParseEnvelope 判定，不用 SQL LIKE（前綴撞名明文會被誤計已達標）
func (s *KeyManagerService) rotationPendingCount(activeVer int) (int64, error) {
	return s.rotationPendingCountOn(s.db, activeVer)
}

// rotationPendingCountOn 同上，於指定連線/交易執行（鎖內呼叫必須傳 tx——
// sqlite :memory: 下 tx 進行中另開連線會拿到獨立空 DB）
func (s *KeyManagerService) rotationPendingCountOn(db *gorm.DB, activeVer int) (int64, error) {
	var total int64
	for _, target := range envelopeMigrationTargets {
		n, err := countPendingColumnValues(db, target, func(v string) bool {
			ver, ok := envelopeVersionOf(v)
			return ok && ver == activeVer
		})
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

// RotationPendingCount 現行 data DEK 版本尚未覆蓋的值數（清冊 partial 提示）
func (s *KeyManagerService) RotationPendingCount() (int64, error) {
	s.mu.RLock()
	ver := s.active[model.DataKeyPurposeData]
	s.mu.RUnlock()
	return s.rotationPendingCount(ver)
}

// KEKRewrapResult KEK 重包結果（明文流向反轉後）。
//
// **本型別不含、也不得再新增任何 KEK 明文欄**：材料由呼叫端提供，伺服端不生成、
// 不回傳、不落庫、不落日誌，材料僅存活於請求處理期間。回應只帶非機密的金鑰引用
// 與重包列數。此不變式由 TestRewrapResultHasNoPlaintextField 的形狀守衛釘住。
//
// **回應形狀由 union 判別**：TargetMode 是判別子；本地目標的
// NewKEKID 為材料指紋，委託目標（Phase C 3.3 接上）為外部識別（KMS ARN／
// HSM token:label）。委託分支要增欄位就加在自己的分支上——**明文欄在任何分支都
// 不存在**，故不會有「委託分支以空字串靜默退化」的問題。
type KEKRewrapResult struct {
	// TargetMode 重包目標判別子（local／kms／hsm）
	TargetMode string `json:"target_mode"`
	// NewKEKID 新 KEK 的金鑰引用 KeyID（本地＝指紋；委託＝外部識別）。非機密
	NewKEKID string `json:"new_kek_id"`
	// RewrappedKeys 重包的金鑰列數
	RewrappedKeys int `json:"rewrapped_keys"`
}

// RewrapKEK KEK 重包（明文流向反轉後改為參數化目標）：以呼叫端提供的
// 目標 KEK 重包全部金鑰、新舊包裹並存落庫。管理員將**自己持有的**新 KEK 存入
// env 後重啟：新 KEK 開機驗證成功才軟退役舊列；未換 env 重啟則以舊 KEK 照常
// 啟動（不鎖死）。
//
// **伺服端不生成材料**：本函式不再有任何亂數材料生成路徑，回傳值亦不含
// 明文；材料的唯一來源是 target，而 target 的唯一本地構造入口
// （NewLocalRewrapTarget）已完成格式驗證。
//
// 守衛判定一律鎖內重讀：pending／backlog／指紋碰撞皆以鎖內交易所見為準。
// 本地目標維持「曾出現過即拒」的嚴格語義；委託目標改判「不得存在使用該 kek_id 的
// 未退役列」（理由與代價見守衛 (c) 的註解）。
func (s *KeyManagerService) RewrapKEK(ctx context.Context, target *RewrapTarget) (*KEKRewrapResult, error) {
	if target == nil {
		return nil, fmt.Errorf("%w：未指定重包目標", ErrRewrapTargetModeInvalid)
	}
	// **sink 端重驗不變式**：欄位不導出只擋得住套件外的呼叫端，
	// 同一套件內的 struct literal 可造出未經任何驗證的目標。此處重跑與構造入口
	// 同一組驗證，使「以不合格材料重包」在**任何**呼叫路徑上都不成立。
	// 材料副本用畢即銷毀（誠實邊界見 RewrapTarget.Destroy）。
	if err := target.Validate(); err != nil {
		return nil, err
	}
	defer target.Destroy()

	env := s.kekKeyID()
	newProvider := target.Provider()

	var count int64
	err := s.withDataKeysLock(func(tx *gorm.DB) error {
		// 守衛 (a)：已存在待切換 pending → 拒絕（要求先完成切換或放棄重包，
		// 不靜默清除既有 pending 而使已交付的新 KEK 失效）
		var pendingCount int64
		if err := tx.Model(&model.DataKey{}).Where("kek_pending = ?", true).Count(&pendingCount).Error; err != nil {
			return fmt.Errorf("檢查待切換狀態失敗: %w", err)
		}
		if pendingCount > 0 {
			return ErrRewrapPendingExists
		}
		// 守衛 (b)：退役 backlog（前次切換未成功退役的舊列）→ 拒絕，先重啟收斂
		backlogCount, err := countRetireBacklog(tx, env)
		if err != nil {
			return err
		}
		if backlogCount > 0 {
			return ErrRetireBacklog
		}
		// 守衛 (b2)：目標不得等於現行 KEK。守衛 (c) 亦會擋下
		// （現行 KEK 必有列），但成因不同：此處是「填了同一把鑰」的操作失誤，
		// 需要專屬訊息，不該被歸類為指紋撞見
		if target.KeyRef().Equal(s.kek.KeyRef()) {
			return ErrRewrapTargetSameAsCurrent
		}
		// 守衛 (c)：目標金鑰引用與金鑰表的衝突檢查。
		//
		// **本地與委託的判定範圍刻意不同**：
		//   - 本地：曾出現過即拒（含退役列——退役列自軟刪除後永久保留指紋史）。
		//     前提是「KEK 由伺服器隨機生成、碰撞就換一把」，代價為零；本守衛同時
		//     擋下「重用舊 KEK」的操作失誤與（機率天文級小的）指紋碰撞。
		//   - 委託：目標由操作者指定且 **ARN 不可重生**。沿用嚴格語義的話，
		//     一次 abandon 過的 ARN 將永久無法再被指定為重包目標，而錯誤訊息
		//     「請改用另一把金鑰」對操作者是死路——等於**永久燒毀該 CMK**。
		//     故委託改判「不得存在使用該 kek_id 的**未退役**列」（同鑰重試因此
		//     可行，與 schema 的 partial 唯一索引一致，model/data_key.go:31-33）。
		//
		// **放寬的代價（SHALL NOT 靜默放寬）**：本守衛同時是 DEKAAD 完備性的
		// 依賴之二（pkg/crypto/codec.go:85-90）——AAD 不含 kek_id，其「同
		// (purpose,version) 下不會有兩份可並存材料」的論證有一半靠這道守衛。
		// 放寬後，「同 (purpose,version,kek_id) 下並存兩份材料」的替換 DoS 面
		// 於委託模式重新開啟。可接受的理由：具 DB 寫權者本就在信任邊界外，
		// 且 partial 唯一索引仍擋住未退役列並存。放寬是明示接受的取捨。
		q := tx.Model(&model.DataKey{}).Where("kek_id = ?", newProvider.KeyRef().KeyID)
		if !target.IsLocal() {
			q = q.Where("kek_retired_at IS NULL")
		}
		var exists int64
		if err := q.Count(&exists).Error; err != nil {
			return fmt.Errorf("檢查 KEK 指紋碰撞失敗: %w", err)
		}
		if exists > 0 {
			return ErrRewrapTargetSeen
		}

		s.mu.RLock()
		defer s.mu.RUnlock()
		// 以現行 KEK 的未退役列為藍本重包（含 retired DEK 與 v0——歷史解密/驗章都要跟上）
		var rows []model.DataKey
		if err := tx.Where("kek_id = ? AND kek_retired_at IS NULL", env).Find(&rows).Error; err != nil {
			return fmt.Errorf("讀取金鑰表失敗: %w", err)
		}
		for _, row := range rows {
			// 已清理佔位：材料已銷毀，佔位隨行複製至新 KEK 保版本鏈不斷號
			if row.WrappedKey == "" && row.Status == model.DataKeyStatusRetired {
				placeholder := model.DataKey{
					Purpose: row.Purpose, Version: row.Version, WrappedKey: "",
					KEKID: newProvider.KeyRef().KeyID, Status: row.Status,
					CreatedAt: time.Now(), RetiredAt: row.RetiredAt, KEKPending: true,
				}
				if err := tx.Create(&placeholder).Error; err != nil {
					return fmt.Errorf("寫入佔位重包列失敗: %w", err)
				}
				continue
			}
			raw := s.keys[row.Purpose][row.Version]
			if raw == nil {
				return fmt.Errorf("金鑰 %s v%d 未載入，無法重包", row.Purpose, row.Version)
			}
			column, err := wrapMaterial(newProvider, row.Purpose, row.Version, raw)
			if err != nil {
				return fmt.Errorf("重包 %s v%d 失敗: %w", row.Purpose, row.Version, err)
			}
			clone := model.DataKey{
				Purpose:    row.Purpose,
				Version:    row.Version,
				WrappedKey: column,
				KEKID:      newProvider.KeyRef().KeyID,
				Status:     row.Status,
				CreatedAt:  time.Now(),
				RetiredAt:  row.RetiredAt,
				KEKPending: true, // 待切換 pending：切換完成（env 指向此 clone）後由 load 轉正
			}
			if err := tx.Create(&clone).Error; err != nil {
				return fmt.Errorf("寫入重包列失敗: %w", err)
			}
		}
		count = int64(len(rows))
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.rewrapPending = true
	s.mu.Unlock()
	// 日誌只帶金鑰引用（非機密），**永不含材料**——「不落日誌」的落點之一
	log.Printf("[KeyManager] KEK 重包完成（目標 %s，新金鑰引用 %s，%d 列）：等待管理員更新 env 後重啟切換",
		target.Mode(), newProvider.KeyRef().KeyID, count)
	return &KEKRewrapResult{
		TargetMode:    target.Mode(),
		NewKEKID:      newProvider.KeyRef().KeyID,
		RewrappedKeys: int(count),
	}, nil
}

// AbandonRewrap 放棄尚未切換的 KEK 重包：將以新 KEK 包裹的過渡列（kek_id 不等於
// 現行 KEK 指紋者）**軟退役**（reason=abandoned、材料保留至顯式清理——軟刪除
// 優先），清除待切換旗標，回到重包前狀態——服務續以現行 KEK 運行，既有資料照常
// 可解。供管理員遺失一次性新 KEK 或決定不切換時自 UI 自助脫離鎖定。
// 誤放棄的正常恢復路徑＝重跑重包（clones 可由現行 KEK 再生）。
//
// 安全不變式：退役謂詞硬綁 `kek_id <> s.kekKeyID()`，現行 KEK 列 kek_id 恆等於
// 排除值，本操作不可能動到服務運行所依的現行 KEK 活躍/退休列。
//
// 跨實例互斥（取代舊「單實例部署不變式」文件化緩解）：判定與寫入整段在
// withDataKeysLock 內——與另一實例的啟動收尾／重包／輪替以 DB 層互斥序列化；
// 即使交錯，收尾側的 promote 列數守衛也會偵測 clones 已被放棄而安全中止。
func (s *KeyManagerService) AbandonRewrap() (int, error) {
	env := s.kekKeyID()
	var abandoned int64
	err := s.withDataKeysLock(func(tx *gorm.DB) error {
		// 鎖內重讀（不憑記憶體旗標）：切換完成待轉正的 env pending 正供解密，
		// 不得放棄
		var envPendingCount int64
		if err := tx.Model(&model.DataKey{}).
			Where("kek_pending = ? AND kek_id = ?", true, env).Count(&envPendingCount).Error; err != nil {
			return fmt.Errorf("檢查 pending 歸屬失敗: %w", err)
		}
		if envPendingCount > 0 {
			return ErrNoRewrapPending
		}
		// 軟退役 foreign 待切換 pending（未退役）：材料保留、無 replacement
		now := time.Now()
		res := tx.Model(&model.DataKey{}).
			Where("kek_pending = ? AND kek_retired_at IS NULL AND kek_id <> ?", true, env).
			Updates(map[string]interface{}{
				"kek_pending":        false,
				"kek_retired_at":     now,
				"kek_retired_reason": model.KEKRetireReasonAbandoned,
			})
		if res.Error != nil {
			return fmt.Errorf("軟退役未切換重包列失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrNoRewrapPending
		}
		abandoned = res.RowsAffected
		return nil
	})
	if err != nil {
		return 0, err
	}

	s.mu.Lock()
	s.rewrapPending = false
	s.mu.Unlock()
	log.Printf("[KeyManager] KEK 重包已放棄：軟退役 %d 筆未切換新 KEK 包裹列（材料保留至顯式清理），續以現行 KEK %s 運行", abandoned, env)
	return int(abandoned), nil
}
