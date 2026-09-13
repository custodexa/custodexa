package main

import (
	"errors"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/modules/keyvault"
)

// 委託設定自環境變數一次性讀入資料庫（升級路徑）。
//
// # 為什麼需要這一步
//
// 升級前的委託部署把區域、保管處位址與角色識別放在 `.env`；升級後那些鍵不再
// 生效。若不讀入，一個原本運作正常的部署會在升級後停在「拓撲尚未設定」，
// 而管理者手上唯一的線索是一份**已經不生效**的 `.env`。
//
// # 三條紀律
//
//  1. **只讀非秘密鍵**：`KEK_VAULT_SECRET_ID` 一類秘密鍵**不讀不存**——本次改動的
//     整個要點就是秘密不落任何持久化位置，讀入一次也不行。
//  2. **冪等**：表內已有列即不覆寫（連提示都照樣印）。重跑不改變任何既有值。
//  3. **讀入之後那些環境鍵一律忽略**：不作為「未設定時的退路」。雙來源會使介面
//     顯示的拓撲與實際送達的目的地分歧，而那正是本次要消滅的狀態。
//
// # 為什麼退場鍵的字面仍出現在本檔
//
// 它們在此**只被讀一次且只為了搬家**，不再是部署旋鈕，故不入 `.env.example`；
// 環境變數漂移守衛的 allowlist 有對應的具名登記。

// retiredDelegatedEnvKeys 已退場的非秘密委託鍵（讀入來源）。
//
// 順序即提示訊息的列出順序（固定，不依 map 迭代）。
var retiredDelegatedEnvKeys = []string{
	"KEK_KMS_REGION",
	"KEK_VAULT_ADDR",
	"KEK_VAULT_ROLE_ID",
	"KEK_KMS_KEY_ID",
}

// retiredDelegatedSecretEnvKeys 已退場的**秘密**委託鍵。
//
// 列在此只為了讓提示訊息能告訴操作者「這個也不再生效」——**本檔不讀它的值**，
// 不寫入任何地方。
var retiredDelegatedSecretEnvKeys = []string{
	"KEK_VAULT_SECRET_ID",
}

// importDelegatedTopologyFromEnv 於啟動時執行一次性讀入並印出提示。
//
// 回傳被讀入的欄位名（供段 2 寫審計列）；未讀入時回 nil。
// **失敗不阻啟動**：讀入是便利功能，管理者仍可在介面上設定；把主服務綁死在它
// 身上只會讓一個可修的設定問題變成開不了機。
func importDelegatedTopologyFromEnv(d *config.KEKDecision) []string {
	if d == nil || d.Mode != config.KEKModeKMS {
		return nil
	}
	present := presentRetiredKeys()
	defer noticeRetiredKeys(present)

	if _, err := keyvault.LoadKEKTopology(database.DB); err == nil {
		// 已有列：不覆寫（冪等），但提示照印。
		return nil
	} else if !errors.Is(err, keyvault.ErrKEKTopologyNotConfigured) {
		log.Printf("[KEKTopology] 讀取拓撲表失敗，略過升級讀入（不阻啟動）: %v", err)
		return nil
	}

	in := keyvault.KEKTopologyInput{Provider: d.KMS.Provider, UpdatedBy: "system:env-import"}
	var imported []string
	set := func(dst *string, key, field string) {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			*dst = v
			imported = append(imported, field)
		}
	}
	switch d.KMS.Provider {
	case keyvault.TopologyProviderAWS:
		set(&in.Region, "KEK_KMS_REGION", "region")
	case keyvault.TopologyProviderVault:
		set(&in.Address, "KEK_VAULT_ADDR", "address")
		set(&in.RoleID, "KEK_VAULT_ROLE_ID", "role_id")
		set(&in.TransitKeyName, "KEK_KMS_KEY_ID", "transit_key_name")
	default:
		// GCP 沒有可設定的拓撲欄位（其完整資源名沿金鑰列的 KEK 引用）。
		return nil
	}
	if len(imported) == 0 {
		return nil
	}
	if err := keyvault.ValidateKEKTopology(in); err != nil {
		// 舊 `.env` 的值不合新的驗證規則（例如位址不是 HTTPS）：不寫入半套，
		// 提示操作者到介面上設定。**不降格放行**——那條連線上走的是資料金鑰材料。
		log.Printf("[KEKTopology] `.env` 內的委託設定不符驗證規則，未讀入（請改於介面設定）: %v", err)
		return nil
	}
	if _, _, err := keyvault.SaveKEKTopology(database.DB, in); err != nil {
		log.Printf("[KEKTopology] 升級讀入寫入失敗（不阻啟動，請改於介面設定）: %v", err)
		return nil
	}
	sort.Strings(imported)
	log.Printf("[KEKTopology] 已將 `.env` 內的委託設定讀入資料庫一次：%s", strings.Join(imported, "、"))
	return imported
}

// presentRetiredKeys 列出環境中仍有值的退場鍵（**只取鍵名，不取值**）。
func presentRetiredKeys() []string {
	var present []string
	for _, key := range append(append([]string{}, retiredDelegatedEnvKeys...), retiredDelegatedSecretEnvKeys...) {
		if strings.TrimSpace(os.Getenv(key)) != "" {
			present = append(present, key)
		}
	}
	return present
}

// noticeRetiredKeys 於啟動日誌提示哪些環境鍵已不再生效。
//
// **只列鍵名、不列值**：其中一個是角色密鑰，把值印進啟動日誌等於把它送進
// 每一份被轉送的日誌副本。
func noticeRetiredKeys(present []string) {
	if len(present) == 0 {
		return
	}
	log.Printf("[KEKTopology] 委託設定已改由介面管理，`.env` 內的下列鍵不再生效：%s",
		strings.Join(present, "、"))
}
