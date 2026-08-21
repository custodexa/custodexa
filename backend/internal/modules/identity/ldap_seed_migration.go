package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// LDAP 設定 env→DB 的一次性 seed（ldap-settings-migration D4）。
//
// **為何在 post-unseal 佇列而非段 1 migration**：seed 要把 bind 密碼信封加密，
// 而 codec 於段 2 `keyvault.InitKeyManager` 才存在；B（ui）封印模式的段 1 連 KEK provider
// 都是 nil。post_unseal_migration.go 的檔頭制度明文禁止需要 codec 的資料 migration
// 留在段 1。段 1 只建表（20260804_ldap_directories），資料一律走本佇列項。

// PostUnsealMigrationLDAPSeed 內建佇列項名。
//
// **命名不含 "aad"**：過渡遷移的負向成員斷言以子字串比對佇列項名
// （internal/modules/keyvault/post_unseal_guard_test.go 的
// TestPostUnsealQueueHasNoTransitionalMigration，與 cmd/server/seal_integration_test.go
// 的 TestPostUnsealMigrationQueueBModeTiming），含 "aad" 的名稱會被誤判為
// 「AAD 正向遷移自動執行」而打紅；本包的 TestLDAPSeedRegisteredInBuiltinQueue
// 另備一格直接釘住此命名約束。
const PostUnsealMigrationLDAPSeed = "ldap_seed"

// ldapSeedMarker seed 的執行標記（形狀比照 envelopeMigrationMarker，同寫入
// schema_migrations）。
//
// **字串定義在 repository**（database.LDAPSeedMarkerVersion）：標記由本檔寫入、
// 由 RollbackLDAPDirectories 清除，兩端必須同值；repository 不得依賴 service
// （相依方向為 service → repository），故常數落在下層由兩端共用。
//
// **語義是「已完成評估」而非「已建立資料」**（R2-codex HIGH）：實際 seed、
// env 未啟用而跳過、表非空而跳過三種**終局**結果皆寫入；只有基礎設施失敗
// （DB 錯誤、加密失敗）不寫，留待下次啟動重試。
//
// 若照直覺只在「成功插入」時寫 marker，則 env 關閉或設定由 UI 建立的部署
// marker 永遠缺席——該列被軟刪再經維運硬刪後，只要 env 仍為 true，下次啟動
// 就會**靜默重建並重新啟用一個外部認證來源**。marker 記錄的是評估已完成，
// 不因資料列由 UI 而非 seed 建立而失效。
const ldapSeedMarker = database.LDAPSeedMarkerVersion

// ldapDirectoriesTable seed 判定用表名（與 model.LDAPDirectory.TableName() 同值）
const ldapDirectoriesTable = "ldap_directories"

// ldapSeedDirectoryName seed 出的列的顯示名（admin 可於 UI 改）
const ldapSeedDirectoryName = "LDAP"

// RegisterLDAPSeedMigration 把 LDAP seed 登記進解封後遷移佇列。
//
// **匯出而非由佇列自行呼叫**（Phase B W1 1.10 / R3.1 §3.1 環 4.9）：原本
// `keyvault.RegisterBuiltinPostUnsealMigrations`（keyvault）直接呼叫本函式的未匯出版本，
// 使 keyvault→identity 成為真出向邊。改為 identity 自行提供登記器、由組裝根
// （`cmd/server/stage2.go` 的 `service.keyvault.RegisterPostUnsealBuiltin`）注入後，
// 方向變成 assembly→{keyvault, identity}，環即斷。
//
// **W4 4.4 新增 auditTx 參數（AP-51）**：seed 的「插列＋審計＋marker」同事務，
// 審計改經 audit 模組的 TxSink 後需要一個落地面，而 keyvault 佇列項的執行體簽名
// （`func(db, codec) error`）表達不了第三個依賴。以登記器的參數承載、由閉包捕獲，
// 是唯一不動佇列契約也不開套件級全域 sink 的形式——後者正是 R3.1 §2.5 拒絕
// 在 model 層做的那件事（可漏接成 nil no-op 的全域旗標）。
func RegisterLDAPSeedMigration(auditTx port.TxSink) {
	keyvault.RegisterPostUnsealMigration(keyvault.PostUnsealMigration{
		Name: PostUnsealMigrationLDAPSeed,
		Run: func(db *gorm.DB, codec crypto.ColumnCodec) error {
			return RunLDAPEnvSeed(db, codec, auditTx)
		},
	})
}

// RunLDAPEnvSeed 執行 env→DB 的一次性 seed。
//
// **判定順序寫死**（D4／R2-opus N6），順序本身承載語義：
//
//  1. 表不存在 → no-op 直接返回（不記失敗、不寫 marker）。單元測試庫普遍
//     無此表；此格若回 error 會把既有測試的失敗計數斷言打紅，且生產上
//     「表還沒建好」本就不是可記錄的終局。
//  2. `LDAP_ENABLED` 未啟用 → 寫 marker 後返回。**排在 marker 檢查之前**是
//     刻意的：全新部署首啟即完成評估並留痕，日後 env 被改成 true 也不會回灌。
//  3. marker 已寫 → 返回（env 自此不參與任何執行期判定）。
//  4. 表非空（Unscoped，含軟刪列）→ 寫 marker 後返回。軟刪列亦算「已有設定」
//     ——admin 顯式刪除的意圖不該被 seed 推翻。
//  5. 執行 seed → 插列＋寫審計＋寫 marker **同一事務**（半完成狀態會使下次啟動
//     重複插列，或使認證來源已建立而審計缺席）。
//
// 步驟 2 先於 3 意味著 marker 會被重複寫入，故 marker 寫入必須冪等
// （ldapSeedWriteMarker：先查再插，重複視為已寫）。
//
// 回傳非 nil error 即基礎設施失敗——佇列只記錄不阻塞，marker 未寫，下次啟動重試。
func RunLDAPEnvSeed(db *gorm.DB, codec crypto.ColumnCodec, auditTx port.TxSink) error {
	// (1) 表不存在 → no-op；catalog 查詢本身失敗則向上傳遞（見 ldapSeedTableExists）
	exists, err := ldapSeedTableExists(db)
	if err != nil {
		return fmt.Errorf("判定 ldap_directories 是否存在失敗: %w", err)
	}
	if !exists {
		return nil
	}

	// (2) env 未啟用 → 寫 marker 返回
	cfg := ldapSeedEnvConfig()
	if !cfg.Enabled {
		if err := ldapSeedWriteMarker(db); err != nil {
			return fmt.Errorf("寫入 LDAP seed 標記失敗（env 未啟用分支）: %w", err)
		}
		return nil
	}

	// (3) marker 已寫 → 返回
	written, err := ldapSeedMarkerWritten(db)
	if err != nil {
		return fmt.Errorf("查詢 LDAP seed 標記失敗: %w", err)
	}
	if written {
		return nil
	}

	// (4)(5) 表非空判定與插列——**同鎖同事務**（設計 D1 並發線性化）
	//
	// 判定必須在鎖內重讀：若在事務外讀 count 再進鎖插列，並行的 CRUD「建立＋軟刪」
	// 會讓 partial unique index 不占位（partial 索引排除軟刪列），而此處的舊讀值
	// 仍是 0 → seed 照插一列 enabled=true，等於**把管理員明確刪除的外部認證來源
	// 靜默重新建立並啟用**。加鎖而沿用舊讀值不解決問題，重讀才是關鍵。
	//
	// 取不到鎖（ErrLDAPDirectoryBusy）＝有 CRUD 寫入進行中：視為基礎設施性的暫時
	// 失敗上傳，marker 不寫、下次啟動重試——不可吞掉當成「已評估」，否則會錯過
	// 唯一一次 seed 機會而使既有部署的 LDAP 靜默失效。
	if codec == nil {
		return fmt.Errorf("LDAP seed 需要 codec（段 2 注入），實得 nil")
	}
	enc := ""
	if cfg.BindPassword != "" {
		enc, err = codec.EncryptFor(context.Background(), keyvault.RefLDAPBindPassword, cfg.BindPassword)
		if err != nil {
			// 加密失敗＝基礎設施失敗：不寫 marker，下次啟動重試
			return fmt.Errorf("加密 LDAP bind 密碼失敗: %w", err)
		}
	}

	row := &model.LDAPDirectory{
		Singleton:       1,
		Name:            ldapSeedDirectoryName,
		URL:             cfg.URL,
		BindDN:          cfg.BindDN,
		BindPasswordEnc: enc,
		BaseDN:          cfg.BaseDN,
		UserFilter:      cfg.UserFilter,
		AttrEmail:       cfg.AttrEmail,
		AttrFullName:    cfg.AttrFullName,
		SkipTLSVerify:   cfg.SkipTLSVerify,
		Enabled:         true,
	}
	// 插列 → 審計 → 寫 marker 三者同一事務（R4-codex HIGH）。
	//
	// **審計不得排在事務之後**：審計表暫時不可寫時，若 seed 列與 marker 已提交，
	// 一個外部認證來源就被永久建立而**沒有任何審計紀錄**，且 marker 使後續啟動
	// 不再補寫——違反「全操作審計」紅線且不可回頭。同事務下任一步失敗即全部
	// 回滾，marker 未寫，下次啟動整體重試（沿用既有的可重試語義）。
	//
	// 審計內容：source=seed、含傳輸風險項；不記密碼與密文。seed 是遷移例外、
	// 不過存檔閘——不可能替部署方補確認；登入當下的傳輸閘仍為最終權威
	// （strict 檔位下 seed 出的不安全設定登入照拒，與升級前一致）。
	seeded := false
	if err := WithLDAPDirectoryLock(db, func(tx *gorm.DB) error {
		// 鎖內重讀：此值才是可信的
		var existing int64
		if err := tx.Unscoped().Model(&model.LDAPDirectory{}).Count(&existing).Error; err != nil {
			return fmt.Errorf("計數 ldap_directories 失敗: %w", err)
		}
		if existing > 0 {
			log.Printf("[LDAPSeed] ldap_directories 已有 %d 列，不 seed（標記為已評估）", existing)
			return ldapSeedWriteMarker(tx)
		}
		if err := tx.Create(row).Error; err != nil {
			return err
		}
		if err := ldapSeedAudit(auditTx, tx, row, cfg); err != nil {
			return err
		}
		if err := ldapSeedWriteMarker(tx); err != nil {
			return err
		}
		seeded = true
		return nil
	}); err != nil {
		return fmt.Errorf("LDAP seed 寫入失敗（列、審計與標記同進退，標記未寫，下次啟動重試）: %w", err)
	}

	if seeded {
		log.Printf("[LDAPSeed] 已自 env seed 一列 LDAP 設定（url=%s、enabled=true）", cfg.URL)
	}
	return nil
}

// ldapSeedEnvValues env 快照（僅 seed 使用；seed 之後 env 不參與任何執行期判定）
type ldapSeedEnvValues struct {
	Enabled       bool
	URL           string
	BindDN        string
	BindPassword  string
	BaseDN        string
	UserFilter    string
	AttrEmail     string
	AttrFullName  string
	SkipTLSVerify bool
}

// ldapSeedEnvConfig 讀 env。
//
// **兩條硬約束**：
//
//  1. 解析語義與 config.getEnv／getEnvBool **完全同源**——布林走
//     `strconv.ParseBool`（接受 `1/t/T/TRUE/true`）、空值取預設。若寫成
//     `os.Getenv("LDAP_ENABLED") == "true"`，`.env` 寫 `LDAP_ENABLED=1`
//     （今日合法可運作）的既有部署升級後會判定為未啟用 → 不 seed、無錯誤、
//     LDAP 全體使用者靜默登不進來，正是「無感升級」要保證的那一格。
//  2. key 必須以**字面字串直接傳給 os.Getenv**——env 漂移守衛
//     （config/env_drift_test.go）只認已知讀取函式的第 0 個字面參數，
//     把 key 收進陣列或自訂 helper 會使守衛掃不到而失去範本同步保證。
//
// 預設值與 config.go 同組（user_filter→`(uid=%s)`、attr_email→`mail`、
// attr_fullname→`cn`），使只設 5 鍵的最小 env 也 seed 出可用設定。
func ldapSeedEnvConfig() ldapSeedEnvValues {
	return ldapSeedEnvValues{
		Enabled:       ldapSeedEnvBool(os.Getenv("LDAP_ENABLED"), false),
		URL:           ldapSeedEnvString(os.Getenv("LDAP_URL"), ""),
		BindDN:        ldapSeedEnvString(os.Getenv("LDAP_BIND_DN"), ""),
		BindPassword:  ldapSeedEnvString(os.Getenv("LDAP_BIND_PASSWORD"), ""),
		BaseDN:        ldapSeedEnvString(os.Getenv("LDAP_BASE_DN"), ""),
		UserFilter:    ldapSeedEnvString(os.Getenv("LDAP_USER_FILTER"), "(uid=%s)"),
		AttrEmail:     ldapSeedEnvString(os.Getenv("LDAP_ATTR_EMAIL"), "mail"),
		AttrFullName:  ldapSeedEnvString(os.Getenv("LDAP_ATTR_FULLNAME"), "cn"),
		SkipTLSVerify: ldapSeedEnvBool(os.Getenv("LDAP_SKIP_TLS_VERIFY"), false),
	}
}

// ldapSeedEnvString config.getEnv 的同語義（空值取預設）
func ldapSeedEnvString(value, defaultValue string) string {
	if value != "" {
		return value
	}
	return defaultValue
}

// ldapSeedEnvBool config.getEnvBool 的同語義（ParseBool；無效值取預設）
func ldapSeedEnvBool(value string, defaultValue bool) bool {
	if value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

// ldapSeedMarkerWritten 標記是否已寫
func ldapSeedMarkerWritten(db *gorm.DB) (bool, error) {
	var n int64
	if err := db.Table("schema_migrations").Where("version = ?", ldapSeedMarker).Count(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
}

// ldapSeedWriteMarker 冪等寫入標記。
//
// **為何必須冪等**（R3-codex）：判定順序把「env 未啟用 → 寫 marker」排在
// 「marker 已寫 → 返回」之前，故 env 關閉的部署每次啟動都會走到這裡；
// 直接 INSERT 會在第二次啟動撞主鍵而使佇列項每次啟動都記一筆失敗。
//
// 先查再插而非 dialect 專屬的 upsert 語法——本函式同時跑在 postgres（生產）
// 與 sqlite（單元測試）上；競態下的重複鍵再查一次確認，仍視為已寫。
func ldapSeedWriteMarker(db *gorm.DB) error {
	written, err := ldapSeedMarkerWritten(db)
	if err != nil {
		return err
	}
	if written {
		return nil
	}
	if err := db.Exec("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
		ldapSeedMarker, time.Now()).Error; err != nil {
		if again, e := ldapSeedMarkerWritten(db); e == nil && again {
			return nil
		}
		return err
	}
	return nil
}

// ldapSeedRisks seed 出的設定的傳輸風險項（與 TransmissionPolicyService.LDAPRisks
// 同判準：非 ldaps 即明文風險，ldaps 但跳過驗證即憑證風險）
func ldapSeedRisks(cfg ldapSeedEnvValues) []string {
	if !strings.HasPrefix(strings.ToLower(cfg.URL), "ldaps://") {
		return []string{policy.RiskLDAPPlaintext}
	}
	if cfg.SkipTLSVerify {
		return []string{policy.RiskLDAPSkipVerify}
	}
	return nil
}

// ldapSeedAudit seed 事件入審計（不記密碼與密文）。
//
// **回傳 error 而非只記 log**（R4-codex HIGH）：呼叫端把本函式放進 seed 的同一
// 事務，審計寫不進去即整批回滾——「認證來源已建立但無審計」不是可接受的終局。
func ldapSeedAudit(auditTx port.TxSink, db *gorm.DB, row *model.LDAPDirectory, cfg ldapSeedEnvValues) error {
	details, err := json.Marshal(map[string]any{
		"source":             "seed",
		"directory_id":       row.ID,
		"url":                row.URL,
		"enabled":            row.Enabled,
		"skip_tls_verify":    row.SkipTLSVerify,
		"has_bind_password":  row.BindPasswordEnc != "",
		"transmission_risks": ldapSeedRisks(cfg),
	})
	if err != nil {
		return fmt.Errorf("序列化 LDAP seed 審計內容失敗: %w", err)
	}
	// W4 4.4 收口（AP-51）：改經 audit 模組的 TxSink。db 參數即呼叫端傳進來的
	// 鎖內 tx——插列、審計、marker 三者同事務的前提就寄在這個句柄上。
	if err := port.WriteInTx(auditTx, db, port.AuditEvent{
		Actor:    gatewayapi.Actor{UserID: 0, Username: "system"},
		Action:   string(model.ActionCreate),
		Resource: string(model.ResourceAuth),
		Status:   string(model.StatusSuccess),
		Details:  string(details),
	}); err != nil {
		return fmt.Errorf("寫入 LDAP seed 審計失敗: %w", err)
	}
	return nil
}

// ldapSeedTableExists 判定 ldap_directories 是否存在。
//
// **不用 GORM `Migrator().HasTable`**（R4-codex LOW）：它只回 bool，catalog 查詢
// 因權限、連線中斷或其他暫時性錯誤而失敗時，與「表確實不存在」無從區分——
// seed 會誤走 no-op 並向佇列回報成功，基礎設施故障靜默不留痕。
//
// 本函式只在「確定不存在」時回 (false, nil)；任何查詢錯誤一律上傳，讓佇列記
// 一筆失敗、marker 不寫、下次啟動重試。
//
// dialect 白名單 fail-close（沿用 WithLocalAdminInvariant／key_manager_lock 的
// 既有語義）：未知 dialect 不猜，直接回錯。生產為 postgres、單元測試為 sqlite。
func ldapSeedTableExists(db *gorm.DB) (bool, error) {
	var n int64
	switch db.Dialector.Name() {
	case "postgres":
		if err := db.Raw(`SELECT count(*) FROM information_schema.tables
			WHERE table_schema = current_schema() AND table_name = ?`,
			ldapDirectoriesTable).Scan(&n).Error; err != nil {
			return false, err
		}
	case "sqlite":
		if err := db.Raw(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`,
			ldapDirectoriesTable).Scan(&n).Error; err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("不支援的資料庫 dialect %q：無法安全判定 %s 是否存在",
			db.Dialector.Name(), ldapDirectoriesTable)
	}
	return n > 0, nil
}
