package keyvault

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// envelopeMigrationColumn 登記的信封加密欄位描述。
//
// **`plaintext` 旗標已於 release-transitional-cleanup 移除**：它標示「現值為明文、
// 直接加密收編」，是 legacy 一次性遷移的產物。終態下所有登記欄位的值恆為
// `enc:a1`，「明文收編」分支會使非終態值被靜默當作明文重新加密——正好違反
// 哨兵的 fail-visible 語義（不可能態應被看見，而非被自動洗白）。
type envelopeMigrationColumn struct {
	table  string
	column string
	// pkColumn 主鍵欄名，**僅供逐列掃描的 keyset 分頁使用；SHALL NOT 參與 AAD**
	// （kek-provider-modularization 定案 A2：AAD 綁 table|column，不綁 pk）。
	// **空＝id**——此預設是給 asset-multi-account 的**零改動契約**（交叉相容契約 2）：
	// 其登記形式 {table, column} 無須任何改動。
	pkColumn string
}

// pk 回傳本欄位的主鍵欄名（空即 id）；僅用於掃描分頁與 CAS 寫回條件
func (c envelopeMigrationColumn) pk() string {
	if c.pkColumn == "" {
		return "id"
	}
	return c.pkColumn
}

// cipherRef 本欄位的 AAD 綁定身分（a1 方案：table|column，**與列無關**）
func (c envelopeMigrationColumn) cipherRef() crypto.CipherRef {
	return crypto.CipherRef{Table: c.table, Column: c.column}
}

// envelopeMigrationTargets 全部落庫敏感欄位（設計 Context 盤點）
var envelopeMigrationTargets = []envelopeMigrationColumn{
	{table: "assets", column: "password_enc"},
	{table: "assets", column: "private_key_enc"},
	{table: "assets", column: "sftp_password_enc"},
	// asset-multi-account D1a：帳號表密文與 model 同版入冊——本清單同時是退役 DEK
	// 銷毀前的引用掃描來源，漏登會誤判零引用而銷毀仍在用的金鑰材料
	{table: "asset_accounts", column: "password_enc"},
	{table: "asset_accounts", column: "private_key_enc"},
	// change-secret-ssh-deepening D1：未驗證的候選憑證。與 model 同版入冊——
	// 候選是「可能已在遠端生效」的秘密的唯一副本，漏登會使退役 DEK 誤判零引用而
	// 被銷毀，該候選即永久不可解：其對應帳號在遠端已改密的情形下直接永久鎖死
	{table: "change_secret_candidates", column: "password_enc"},
	{table: "change_secret_candidates", column: "private_key_enc"},
	{table: "users", column: "totp_secret_enc"},
	{table: "export_signing_keys", column: "private_key_enc"},
	// audit-checkpoint-chain D5：檢查點鏈簽章私鑰。與 model 同批入冊——漏登會使
	// 退役 DEK 誤判零引用而被銷毀，該私鑰即永久不可解：以它簽的**全部歷史檢查點
	// 從此不可驗**，等同鏈證據整體損毀且無法救回
	{table: "checkpoint_signing_keys", column: "private_key_enc"},
	// idp-oidc-integration D2：OIDC provider 的 client secret。與 model 同批入冊——
	// 本清單同時是退役 DEK 銷毀前的引用掃描來源，漏登會誤判零引用而銷毀仍在用的
	// 金鑰材料，使該欄密文永久不可解（provider 全數無法登入且無法救回）
	{table: "oidc_providers", column: "client_secret_enc"},
	// ldap-settings-migration D1：LDAP service bind 密碼。設定面自 env 遷入 DB 後
	// 這是本表唯一的密文欄；與 model 同批入冊的理由同上——本清單同時是退役 DEK
	// 銷毀前的引用掃描來源，漏登會誤判零引用而銷毀仍在用的金鑰材料，使 LDAP
	// 設定的 bind 密碼永久不可解（目錄認證全體失效且無法救回）
	{table: "ldap_directories", column: "bind_password_enc"},
	{table: "notification_channels", column: "secret"},
	{table: "notification_channels", column: "url"},
}

// EnvelopeMigrationResult 遷移結果（審計 Details 與清冊狀態用）
type EnvelopeMigrationResult struct {
	Migrated  int64     `json:"migrated"`
	Failed    int64     `json:"failed"`
	Skipped   bool      `json:"skipped"` // 標記已存在，本次未掃描
	Completed bool      `json:"completed"`
	RanAt     time.Time `json:"ran_at"`
	// FailedRefs 失敗值的 table.column#id（上限 20，防撐爆）
	FailedRefs []string `json:"failed_refs,omitempty"`
	// CASConflicts 掃描期間被並發改寫而放棄的列數（CAS 寫回 RowsAffected==0）。
	// **正向遷移不計為失敗**（沿既有語義：是否仍待處理交由 pending 再確認、
	// 下次啟動續跑）；**反向回寫計為失敗**——退版沒有「下次啟動續跑」的機會，
	// 一列殘留的 enc:a1 就是舊版讀不懂的一列。呼叫端據用途決定。
	CASConflicts int64 `json:"cas_conflicts,omitempty"`
	// Residue 結尾重掃仍未達目標的值數（僅反向回寫填寫）。
	// 逐列計數可能因並發而失真，故完成判定以**重掃**為準而非累加計數。
	Residue int64 `json:"residue,omitempty"`
	// MaxOps 單次處理上限（0=無上限）；達上限即停，呼叫端以 pending 判 partial
	MaxOps int64 `json:"-"`
	// ColumnStats 逐欄位的實際分布（key＝`table.column`，codex round-6 M）。
	// 完成審計只記總數時，事後查案無法回答「哪一欄改了幾筆、哪一欄全數失敗」；
	// 掃過的欄位一律建項（含 0/0），故本表同時是「實際掃描範圍」的證據——
	// 與登記集合不一致本身即為線索。
	ColumnStats map[string]EnvelopeColumnStat `json:"column_stats,omitempty"`
}

// EnvelopeColumnStat 單一欄位的遷移累計
type EnvelopeColumnStat struct {
	Migrated int64 `json:"migrated"`
	Failed   int64 `json:"failed"`
	// CASConflicts 該欄位掃描期間被並發改寫而放棄的列數
	CASConflicts int64 `json:"cas_conflicts,omitempty"`
}

// columnStat 取得（必要時建立）指定欄位的統計項；掃描起頭即建項，
// 使 0/0 的欄位也留在分布中
func (r *EnvelopeMigrationResult) columnStat(target envelopeMigrationColumn) *EnvelopeColumnStat {
	if r.ColumnStats == nil {
		r.ColumnStats = map[string]EnvelopeColumnStat{}
	}
	key := target.table + "." + target.column
	stat := r.ColumnStats[key]
	return &stat
}

// putColumnStat 寫回統計項（map 值型別無法就地改，故取—改—寫回）
func (r *EnvelopeMigrationResult) putColumnStat(target envelopeMigrationColumn, stat EnvelopeColumnStat) {
	if r.ColumnStats == nil {
		r.ColumnStats = map[string]EnvelopeColumnStat{}
	}
	r.ColumnStats[target.table+"."+target.column] = stat
}

// bumpColumnStat 以 mutate 更新單一欄位統計
func (r *EnvelopeMigrationResult) bumpColumnStat(target envelopeMigrationColumn, mutate func(*EnvelopeColumnStat)) {
	stat := r.columnStat(target)
	if mutate != nil {
		mutate(stat)
	}
	r.putColumnStat(target, *stat)
}

// envelopeVersionOf 值的信封版本；僅有效信封（ParseEnvelopeFull 全過）回 ok。
// 判定一律在 Go 層以此為準——SQL LIKE 'enc:v%' 會把前綴撞名的明文
// 誤判為已遷移（留明文＋pending 假陰性削弱 KEK 重包守衛）。
//
// **含帶 AAD 方案者（`enc:a1:v<N>`）**（D5 cutover，tasks 1.7）：版本是 DEK 的
// 身分，與 AAD 方案正交。若此處沿用只認 `enc:v` 的 ParseEnvelope，cutover 後
// 兩處會靜默失真——
// (1) DEK 輪替的 skip／pending 永遠視 enc:a1 為「未達標」，輪替永不收斂；
// (2) 退役 DEK 銷毀前的引用掃描（key_manager_cleanup 的 stored_ciphertext）
// 會漏數 enc:a1 值而誤判零引用，銷毀仍在用的金鑰材料＝資料永久不可解。
func envelopeVersionOf(v string) (int, bool) {
	_, ver, _, ok, err := crypto.ParseEnvelopeFull(v)
	if err != nil || !ok {
		return 0, false
	}
	return ver, true
}

// reencryptEnvelopeColumn 單欄位掃描重加密（keyset 分頁，防大表全載）。
// skip 回傳 true 的值視為已達目標跳過——現行唯一用途為 DEK 輪替（僅現行版本
// 可跳）；嚴格判定，非 LIKE 前綴比對。
// recryptFn 單值重加密：一律走 EncryptFor 寫 enc:a1（無 AAD 寫出能力已刪除）。
// ref 為該欄位的 AAD 綁定身分；plaintext 為已解出的明文。
type recryptFn func(ref crypto.CipherRef, plaintext string) (string, error)

// decryptFn 單值解密：AAD 遷移需以列身分驗證既有 enc:a1 值（冪等重跑時會遇到）
type decryptFn func(ref crypto.CipherRef, ciphertext string) (string, error)

// keyset 分頁以主鍵遞增掃描。**目前全部登記欄位的主鍵皆為整數 id**；
// 若日後登記非整數主鍵（UUID），此處的 keyset 需改以字串序推進。
// 主鍵僅是掃描與 CAS 寫回的座標，**不參與 AAD**（定案 A2）。
//
// **寫出格式為 enc:a1**（D5 cutover，tasks 1.7）：本函式服務於 legacy 信封化遷移
// 與 DEK 輪替兩條重加密路徑，兩者都是**寫入端**。若仍寫 enc:v，則 strict 啟用後
// 的一次 DEK 輪替會把全存量降級為不可讀，且「現查殘餘為 0」淪為瞬時快照。
func reencryptEnvelopeColumn(db *gorm.DB, km *KeyManagerService, target envelopeMigrationColumn, skip func(string) bool, result *EnvelopeMigrationResult) {
	reencryptEnvelopeColumnWith(db, target, skip, result,
		func(ref crypto.CipherRef, ct string) (string, error) {
			return km.DecryptFor(context.Background(), ref, ct)
		},
		func(ref crypto.CipherRef, plain string) (string, error) {
			return km.EncryptFor(context.Background(), ref, plain)
		})
}

func reencryptEnvelopeColumnWith(db *gorm.DB, target envelopeMigrationColumn, skip func(string) bool,
	result *EnvelopeMigrationResult, decrypt decryptFn, recrypt recryptFn) {
	type row struct {
		PK    uint
		Value string
	}
	pkCol := target.pk()
	lastID := uint(0)
	// 掃描起頭即建項：未命中任何列的欄位也要出現在分布中（0/0 是資訊，不是空白）
	result.bumpColumnStat(target, nil)
	for {
		if result.MaxOps > 0 && result.Migrated >= result.MaxOps {
			return // 達單次上限，pending 由呼叫端回報、再次呼叫續跑
		}
		var batch []row
		// 值非空即撈回，是否已達目標由 Go 層 skip 判定（軟刪列一併處理，
		// 避免復原後漏網）
		if err := db.Table(target.table).
			Select(fmt.Sprintf("%s AS pk, %s AS value", pkCol, target.column)).
			Where(fmt.Sprintf("%s > ? AND %s <> ''", pkCol, target.column), lastID).
			Order(pkCol).Limit(500).Scan(&batch).Error; err != nil {
			log.Printf("[EnvelopeMigration] 掃描 %s.%s 失敗: %v", target.table, target.column, err)
			result.Failed++
			result.bumpColumnStat(target, func(s *EnvelopeColumnStat) { s.Failed++ })
			return
		}
		if len(batch) == 0 {
			return
		}
		for _, r := range batch {
			lastID = r.PK
			if skip(r.Value) {
				continue
			}
			ref := target.cipherRef()
			// **一律解密**（release-transitional-cleanup 3.3）：原「明文欄位在非
			// 有效信封時原樣採用」的收編分支已移除——終態下非終態格式值是不可能
			// 態，把它當明文重新加密等於靜默洗白，違反哨兵 fail-visible 語義。
			// 該類值於此逐項記為失敗並留位置線索
			plain, err := decrypt(ref, r.Value)
			if err != nil {
				result.recordFailure(target, r.PK, err)
				continue
			}
			enc, err := recrypt(ref, plain)
			if err != nil {
				result.recordFailure(target, r.PK, err)
				continue
			}
			// CAS 寫回：SELECT 與 UPDATE 之間該列可能被並發改寫（如改密
			// live 輪換），無條件覆蓋會吃掉新值；原值不符即放棄本列，
			// 是否仍待處理交由 pending 再確認（marker 守衛／下次輪替）
			res := db.Exec(fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ? AND %s = ?",
				target.table, target.column, pkCol, target.column), enc, r.PK, r.Value)
			if res.Error != nil {
				result.recordFailure(target, r.PK, res.Error)
				continue
			}
			if res.RowsAffected == 0 {
				// 計數但不逕自視為失敗——是否為失敗由呼叫端依用途判定
				// （正向：pending 再確認；反向：直接計入 Failed，見 RevertEnvelopeAADMigration）
				result.CASConflicts++
				result.bumpColumnStat(target, func(s *EnvelopeColumnStat) { s.CASConflicts++ })
				log.Printf("[EnvelopeMigration] %s.%s %s=%d 掃描期間被並發改寫，跳過不覆蓋", target.table, target.column, pkCol, r.PK)
				continue
			}
			result.Migrated++
			result.bumpColumnStat(target, func(s *EnvelopeColumnStat) { s.Migrated++ })
		}
	}
}

func (r *EnvelopeMigrationResult) recordFailure(target envelopeMigrationColumn, id uint, err error) {
	r.Failed++
	r.bumpColumnStat(target, func(s *EnvelopeColumnStat) { s.Failed++ })
	if len(r.FailedRefs) < 20 {
		r.FailedRefs = append(r.FailedRefs, fmt.Sprintf("%s.%s#%d", target.table, target.column, id))
	}
	// 不落值本身，只落位置——失敗值可能是敏感明文
	log.Printf("[EnvelopeMigration] %s.%s id=%d 遷移失敗: %v", target.table, target.column, id, err)
}

// countPendingColumnValues 掃描欄位計數不符 skip 判定的值（keyset 分頁；
// Go 層嚴格判定，與 reencryptEnvelopeColumn 同口徑）
func countPendingColumnValues(db *gorm.DB, target envelopeMigrationColumn, skip func(string) bool) (int64, error) {
	type row struct {
		PK    uint
		Value string
	}
	pkCol := target.pk()
	var total int64
	lastID := uint(0)
	for {
		var batch []row
		if err := db.Table(target.table).
			Select(fmt.Sprintf("%s AS pk, %s AS value", pkCol, target.column)).
			Where(fmt.Sprintf("%s > ? AND %s <> ''", pkCol, target.column), lastID).
			Order(pkCol).Limit(500).Scan(&batch).Error; err != nil {
			return 0, err
		}
		if len(batch) == 0 {
			return total, nil
		}
		for _, r := range batch {
			lastID = r.PK
			if !skip(r.Value) {
				total++
			}
		}
	}
}
