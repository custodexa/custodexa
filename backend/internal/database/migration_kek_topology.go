package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 委託拓撲的資料層增量 migration：單列表 kek_topologies。
// 沿既有增量的紀律：DDL 無條件、不用 IF NOT EXISTS——在已套用的庫上重跑
// 必須大聲失敗，而非靜默 no-op。
//
// # Up 做什麼
//
// 建一張**單列**表，存委託模式的非秘密拓撲（服務商、Vault 位址、Transit 金鑰名、
// AppRole 角色識別、AWS 服務區域）與課責欄（updated_by／updated_at）。
//
// 單列語義由兩道 DB 層守衛保證，缺一不可：
//
//   - `CONSTRAINT kek_topologies_singleton_check CHECK ((singleton = 1))`
//   - `CREATE UNIQUE INDEX idx_kek_topologies_singleton ON kek_topologies (singleton)`
//
// 單靠 unique index 只禁止相同值重複，`singleton=1` 與 `singleton=2` 仍可並存；
// 單靠 CHECK 則擋不住兩列都是 1。同一組合的前例見 ldap_directories。
//
// # 全部欄位明文，**封存狀態下須可讀，不得加密**
//
// 本表的讀取時點在**已封存狀態**（解封頁載入、啟動期建構 provider），此時資料金鑰
// 尚未解出——任何受信封保護的欄位在那個時點都讀不出來，通知管道 url 走信封加密
// 的那條路在此不可用。拓撲為非秘密（位址、區域、角色識別、金鑰名），明文儲存不
// 降低保護等級。**日後不得把本表任一欄改為信封加密欄**：那會讓解封頁在封存狀態
// 白屏，而白屏的時點正是最需要它的時點。
//
// 秘密（AWS 存取金鑰、GCP 服務帳號金鑰檔、Vault 角色密鑰或權杖）**不在本表**，
// 亦不在任何持久化位置；它們只存在於解封世代的記憶體憑證持有者，封存即抹除。
//
// # 為什麼沒有索引（除單列守衛外）
//
// 唯一讀法是「取那一列」，主鍵與 singleton 唯一索引已足夠。
//
// # Down 契約（讀完再用）
//
// **本 Down 有損**：整張表消失，委託部署的拓撲設定沒有第二個地方存著——回退後
// 需重新以介面設定，或依升級說明自 `.env` 回填（`KEK_KMS_REGION`／`KEK_VAULT_ADDR`／
// `KEK_VAULT_ROLE_ID` 三鍵在舊版仍為事實源）。生產沒有回滾入口（RollbackMigration
// 無產品碼呼叫者，回退手段是部署回舊版映像並還原升級前備份，
// docs/ops/upgrade-sop.md §4）。
func kekTopologyDDL() []string {
	return []string{
		`CREATE TABLE kek_topologies (
			id bigserial,
			created_at timestamp with time zone,
			updated_at timestamp with time zone,
			singleton smallint DEFAULT 1 NOT NULL,
			provider character varying(16) DEFAULT ''::character varying NOT NULL,
			address character varying(255) DEFAULT ''::character varying NOT NULL,
			transit_key_name character varying(128) DEFAULT ''::character varying NOT NULL,
			role_id character varying(128) DEFAULT ''::character varying NOT NULL,
			region character varying(64) DEFAULT ''::character varying NOT NULL,
			updated_by character varying(100) DEFAULT ''::character varying NOT NULL,
			CONSTRAINT kek_topologies_pkey PRIMARY KEY (id),
			CONSTRAINT kek_topologies_singleton_check CHECK ((singleton = 1))
		)`,
		`CREATE UNIQUE INDEX idx_kek_topologies_singleton ON kek_topologies (singleton)`,
	}
}

func applyKEKTopology(db *gorm.DB) error {
	for _, stmt := range kekTopologyDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 kek_topology DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackKEKTopology 刪表。見本檔檔頭的 Down 契約。
func rollbackKEKTopology(db *gorm.DB) error {
	if err := db.Exec(`DROP TABLE kek_topologies`).Error; err != nil {
		return fmt.Errorf("回滾 kek_topology 失敗: %w", err)
	}
	return nil
}
