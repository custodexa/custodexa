package keyvault

import (
	"errors"
	"fmt"
	"log"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 顯式清理退役金鑰資料（kek-rewrap-hygiene-hardening D9）：
// 唯一的材料銷毀點。列本身、指紋與退役軌跡永久保留（PCI 3.7.5：銷毀是
// 有紀錄的主動操作而非自動副作用）。

// ErrCleanupNotConverged 全收斂閘：有 pending campaign 或 retire backlog 時拒清
var ErrCleanupNotConverged = errors.New("金鑰輪換尚未全數收斂（存在待切換 pending 或退役 backlog），請先完成切換或重啟收斂後再清理")

// ErrCleanupResidueDetected 引用掃描遇不可歸屬殘值：整筆拒清
// （release-transitional-cleanup spec delta「引用掃描遇不可歸屬殘值保守拒清」）。
//
// **為何必須是獨立的閘而非讓引用掃描自行處理**：引用掃描以
// `envelopeVersionOf` 判定「這個值屬於哪個版本」，解析不過的值回 `ok=false`，
// 而 skip 謂詞 `!ok || ver != version` 對它恆為 true——即**不計入任何版本的引用**。
// 於是一個無法歸屬的非終態格式殘值會使每個退役版本都被算成零引用而放行銷毀，
// 該殘值若其實由某退役版本加密，銷毀後即永久不可解。故：命中即整筆拒清。
var ErrCleanupResidueDetected = errors.New("偵測到無法歸屬版本的非終態格式殘值：保守拒絕本次清理（殘值可能由退役版本加密，銷毀其材料將永久不可解）")

// assertNoNonAttributableResidue 引用掃描前置：以與啟動哨兵**同一 SQL 口徑**
// （AADResidueLowerBound）掃全部登記欄位，命中即回 ErrCleanupResidueDetected
// 並逐項附殘值位置與筆數。
//
// 口徑必須與哨兵同一：兩處若各自定義「什麼算殘值」，就會出現「哨兵看得見、
// 清理閘看不見」的縫，而那道縫的後果是不可逆的材料銷毀。
func assertNoNonAttributableResidue(tx *gorm.DB) error {
	residues, total, err := AADResidueLowerBound(tx)
	if err != nil {
		// 殘值狀態未知時 SHALL NOT 以零頂替放行——銷毀不可逆
		return fmt.Errorf("清理中止：殘值掃描失敗（狀態未知，不得以零頂替）: %w", err)
	}
	if total == 0 {
		return nil
	}
	return fmt.Errorf("%w（下界 %d 筆：%s）", ErrCleanupResidueDetected, total, formatAADResidues(residues))
}

// KeyCleanupItem 已清理項（審計與回應用；僅指紋與版本，無材料）
type KeyCleanupItem struct {
	Purpose string `json:"purpose"`
	Version int    `json:"version"`
	KEKID   string `json:"kek_id"`
}

// KeyCleanupSkipped 拒清項與原因（version_referenced＝存量密文仍引用該版本／
// audit_referenced＝審計列仍以該版本驗章）。
// ProtectionClass 為保護類別機器碼（audit_trail／stored_ciphertext…），
// 使稽核可辨識「依何種保護語義而未銷毀」，見 purgeClasses
type KeyCleanupSkipped struct {
	Purpose         string `json:"purpose"`
	Version         int    `json:"version"`
	KEKID           string `json:"kek_id"`
	Refs            int64  `json:"refs"`
	Reason          string `json:"reason"`
	ProtectionClass string `json:"protection_class"`
}

// KeyCleanupResult 清理結果
type KeyCleanupResult struct {
	Purged  []KeyCleanupItem    `json:"purged"`
	Skipped []KeyCleanupSkipped `json:"skipped"`
}

// CleanupRetiredMaterial 清理退役金鑰材料。兩類候選（皆須材料尚存）：
//
//  1. KEK 退役列（kek_retired_at 非空）：舊 KEK 包裹的歷史副本——全收斂下
//     現行 KEK 對每個 slot 皆有 live 列，清掉零資料損失，不需引用掃描。
//  2. 退役 DEK 版本的現行列（status=retired、kek_retired_at 空、kek_id=現行）：
//     其材料是舊版本密文／歷史驗章的唯一解密途徑——逐版本引用掃描，
//     仍有引用即拒清（無此閘的清理＝資料自毀鈕）。
//     清理後該列轉「已清理佔位」：列保留使版本鏈不斷號，load 跳過 unwrap。
//
// 全程在跨實例互斥鎖內；掃描一律經 tx（sqlite :memory: 連線池陷阱＋一致視圖）。
func (s *KeyManagerService) CleanupRetiredMaterial() (*KeyCleanupResult, error) {
	env := s.kekKeyID()
	result := &KeyCleanupResult{Purged: []KeyCleanupItem{}, Skipped: []KeyCleanupSkipped{}}
	err := s.withDataKeysLock(func(tx *gorm.DB) error {
		// 全收斂閘（鎖內重讀）：pending campaign 或 retire backlog 存在即拒
		var pendingCount int64
		if err := tx.Model(&model.DataKey{}).Where("kek_pending = ?", true).
			Count(&pendingCount).Error; err != nil {
			return fmt.Errorf("檢查待切換狀態失敗: %w", err)
		}
		backlogCount, err := countRetireBacklog(tx, env)
		if err != nil {
			return err
		}
		if pendingCount > 0 || backlogCount > 0 {
			return ErrCleanupNotConverged
		}

		// 類 1：KEK 退役列（材料尚存）。「全收斂下現行 KEK 對每 slot 皆有 live 列」
		// 的不變式只在開機被強制——銷毀是不可逆操作，交易內逐 slot 自證：
		// 該 slot 無現行 KEK 的 live 材料列即拒清（opus 第一輪審 M5，論證變機制）
		var kekRetired []model.DataKey
		// 候選只需識別欄位——不投影 wrapped_key，材料觸及面收斂（冷驗收 P6）
		if err := tx.Select("id", "purpose", "version", "kek_id").
			Where("kek_retired_at IS NOT NULL AND wrapped_key <> ''").
			Find(&kekRetired).Error; err != nil {
			return fmt.Errorf("讀取 KEK 退役列失敗: %w", err)
		}
		var purgeIDs []uint
		for _, r := range kekRetired {
			var envRow model.DataKey
			if err := tx.
				Where("purpose = ? AND version = ? AND kek_id = ? AND kek_pending = ? AND kek_retired_at IS NULL AND wrapped_key <> ''",
					r.Purpose, r.Version, env, false).
				First(&envRow).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return fmt.Errorf("清理中止：slot %s v%d 無現行 KEK 的 live 材料列，銷毀退役副本將致該版本永久不可解", r.Purpose, r.Version)
				}
				return fmt.Errorf("清理前置自證查詢失敗: %w", err)
			}
			// 非空不等於有效（codex 第二輪審 H2）：現行列材料須實際以現行 KEK
			// 解包成功，否則退役副本可能是該版本最後的有效材料——拒清
			if _, err := s.unwrapRow(envRow); err != nil {
				return fmt.Errorf("清理中止：slot %s v%d 現行 KEK 材料列無法解包（%v），退役副本可能是最後有效材料", r.Purpose, r.Version, err)
			}
			purgeIDs = append(purgeIDs, r.ID)
			result.Purged = append(result.Purged, KeyCleanupItem{Purpose: r.Purpose, Version: r.Version, KEKID: r.KEKID})
		}

		// 類 2：退役 DEK 版本的現行列——逐版本引用掃描。
		// kek_id=env 在全收斂閘下可由謂詞推導，仍顯式寫明（opus 第二輪審 L5）：
		// 日後放寬收斂閘時不得靜默開始清到他 KEK 的列
		var dekRetired []model.DataKey
		if err := tx.Select("id", "purpose", "version", "kek_id").
			Where("kek_retired_at IS NULL AND status = ? AND kek_id = ? AND wrapped_key <> ''",
				model.DataKeyStatusRetired, env).Find(&dekRetired).Error; err != nil {
			return fmt.Errorf("讀取退役 DEK 版本失敗: %w", err)
		}
		// 引用掃描前置：不可歸屬殘值即整筆拒清（見 ErrCleanupResidueDetected）。
		// 僅在確有須引用掃描的候選時執行——無候選時不發生任何以版本歸屬為前提的
		// 判定，額外阻斷 KEK 退役副本的清理只會製造無來由的死路
		if len(dekRetired) > 0 {
			if err := assertNoNonAttributableResidue(tx); err != nil {
				return err
			}
		}
		// **已知限制：引用掃描與材料清除無法阻止「其他實例以舊記憶體 DEK 寫入」**
		// （P1 雙審 codex high #2）。掃描歸零後、清除生效前，另一個尚未重啟的行程
		// 仍可能以其快取的舊版本 DEK 加密新資料，該筆密文將引用已銷毀的材料而永久
		// 不可讀。**非本 change 引入、單實例部署不可達**——完整解是「加密寫入時檢查
		// 版本仍為現行」的柵欄，屬多副本部署的前置項（與 AlertNotifier 快取一致性
		// 缺口同屬一項），已登記於維護者的私有開發路線圖，未隨公開倉庫發佈。
		// 現有緩解三層：stale 實例的輪替／重包／清理一律 409
		// fail-close（ErrStaleKeyCache）、清理前逐 slot 自證、清理確認文案要求先重啟
		// 所有實例。**上 HA 或滾動更新前必須先做該項，否則會掉資料。**
		for _, r := range dekRetired {
			allowed, refs, class, err := s.assertPurgeAllowed(tx, r.Purpose, r.Version)
			if err != nil {
				return err
			}
			if !allowed {
				result.Skipped = append(result.Skipped, KeyCleanupSkipped{
					Purpose: r.Purpose, Version: r.Version, KEKID: r.KEKID,
					Refs: refs, Reason: class.ReasonCode, ProtectionClass: class.Name})
				continue
			}
			purgeIDs = append(purgeIDs, r.ID)
			result.Purged = append(result.Purged, KeyCleanupItem{Purpose: r.Purpose, Version: r.Version, KEKID: r.KEKID})
		}

		if len(purgeIDs) > 0 {
			if err := tx.Model(&model.DataKey{}).Where("id IN ?", purgeIDs).
				Update("wrapped_key", "").Error; err != nil {
				return fmt.Errorf("清理材料失敗: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// 已清理的現行退役版本自 in-memory 快取移除（材料已銷毀，不得再供解密）
	s.mu.Lock()
	for _, p := range result.Purged {
		if p.KEKID == env {
			if m := s.keys[p.Purpose]; m != nil {
				delete(m, p.Version)
			}
			if p.Purpose == model.DataKeyPurposeData {
				delete(s.ciphers, p.Version)
			}
		}
	}
	s.mu.Unlock()
	return result, nil
}

// ── 金鑰材料的銷毀保護類別 ────────────────────────────────────────────────
//
// 「哪些材料不可銷毀、為什麼」是**宣告式的類別**，不是散落在條件式裡的推導：
// 每個用途在此登記一個保護類別，清理路徑一律經 purgeClassOf 取用。
// 新增用途卻未登記類別＝fail-close（清理整筆中止），不會靜默落入「可清」。
//
// 類別可擴充：新增保護型態只需在此加一筆（例如未來的簽章鑰以其自身的引用來源
// 計數，或以 NeverPurgeable 宣告「不論引用數為何一律不可銷毀」）。

// keyPurgeClass 一種材料保護類別
type keyPurgeClass struct {
	// Name 類別機器碼（回應與審計用，供稽核辨識保護依據）
	Name string
	// ReasonCode 拒清原因碼（前端據此查譯說明「為什麼不能清」）
	ReasonCode string
	// NeverPurgeable true＝不論引用數為何一律拒清（此類別無須引用掃描）
	NeverPurgeable bool
	// CountRefs 存量引用計數；NeverPurgeable 為 true 時可為 nil
	CountRefs func(s *KeyManagerService, tx *gorm.DB, version int) (int64, error)
}

// purgeClasses 用途 → 保護類別登記表（唯一真實來源）
var purgeClasses = map[string]keyPurgeClass{
	// 稽核軌跡保護：材料是歷史審計紀錄的驗章依據——銷毀＝那些紀錄永久無法
	// 驗章、稽核軌跡失去證明力（PCI DSS 10.3/10.5）。此為稽核需求，
	// 系統不得提供任何繞過此閘的介面或參數
	model.DataKeyPurposeAuditIntegrity: {
		Name:       "audit_trail",
		ReasonCode: "audit_referenced",
		CountRefs: func(s *KeyManagerService, tx *gorm.DB, version int) (int64, error) {
			var n int64
			if err := tx.Model(&model.AuditLog{}).Where("key_version = ?", version).
				Count(&n).Error; err != nil {
				return 0, fmt.Errorf("審計引用掃描失敗（v%d）: %w", version, err)
			}
			return n, nil
		},
	},
	// 存量密文保護：材料是既有密文的唯一解密途徑——銷毀＝資料永久不可解
	model.DataKeyPurposeData: {
		Name:       "stored_ciphertext",
		ReasonCode: "version_referenced",
		CountRefs: func(s *KeyManagerService, tx *gorm.DB, version int) (int64, error) {
			var total int64
			for _, target := range envelopeMigrationTargets {
				// countPendingColumnValues 計數「不滿足 skip 謂詞」的值——
				// 引用掃描要數的是「正是該版本」的值，故 skip＝非該版本
				n, err := countPendingColumnValues(tx, target, func(v string) bool {
					ver, ok := envelopeVersionOf(v)
					return !ok || ver != version
				})
				if err != nil {
					return 0, fmt.Errorf("引用掃描失敗（data v%d）: %w", version, err)
				}
				total += n
			}
			return total, nil
		},
	},
}

// unregisteredPurgeClass 未登記用途的保底類別：一律不可銷毀，但**不阻斷整個
// 清理操作**——把「一列未知」升級成「清理功能整組不可用」會讓釋出後的使用者
// 撞牆且無自救手段（只能等新版程式），而少清一列本身零風險。
// 該列逐項回報並說明「需程式更新後才能處理」，開發期由完備性測試先擋。
var unregisteredPurgeClass = keyPurgeClass{
	Name:           "unregistered",
	ReasonCode:     "unregistered_purpose",
	NeverPurgeable: true,
}

// purgeClassOf 取用途的保護類別；未登記者回保底類別（永不可銷毀）＋false，
// 呼叫端據此逐項回報而非中止全案
func purgeClassOf(purpose string) (keyPurgeClass, bool) {
	c, ok := purgeClasses[purpose]
	if !ok {
		return unregisteredPurgeClass, false
	}
	return c, true
}

// assertPurgeAllowed 銷毀前置判定（唯一入口）：回傳是否可銷毀，
// 不可銷毀時附引用數與類別資訊供逐項回報。
// 未登記用途一律不可銷毀（保守），錯誤只發生於引用掃描本身失敗
func (s *KeyManagerService) assertPurgeAllowed(tx *gorm.DB, purpose string, version int) (allowed bool, refs int64, class keyPurgeClass, err error) {
	class, registered := purgeClassOf(purpose)
	if !registered {
		log.Printf("[KeyManager] 清理跳過：金鑰用途 %q 未登記銷毀保護類別（保守保留，須於 purgeClasses 宣告保護語義後方可清理）", purpose)
		return false, 0, class, nil
	}
	if class.NeverPurgeable {
		return false, 0, class, nil
	}
	refs, err = class.CountRefs(s, tx, version)
	if err != nil {
		return false, 0, class, err
	}
	return refs == 0, refs, class, nil
}
