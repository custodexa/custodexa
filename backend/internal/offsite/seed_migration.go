package offsite

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 離機儲存設定的 env→DB **初次** seed（`OFFSITE_*` 鍵組降為 seed-only）。
//
// # 為何在 post-unseal 佇列而非段 1 migration
//
// seed 要把物件儲存憑證信封加密，而 codec 於段 2 `keyvault.InitKeyManager` 才存在；
// B（ui）封印模式的段 1 連 KEK provider 都是 nil。post_unseal_migration.go 的檔頭制度
// 明文禁止需要 codec 的資料 migration 留在段 1。段 1 只建表，資料一律走本佇列項。
//
// # marker 寫入後 env 不再參與任何執行期判定
//
// 使用者裁決原句：「.env 的設定應該算是初次設定，後面變更由系統頁面設定」。
// quickstart 自動化因此不退步：`.env` 填好首啟即用，之後管理走 UI。

// PostUnsealMigrationOffsiteSeed 內建佇列項名。
//
// **命名不含 "aad"／"legacy"**：過渡遷移的負向成員斷言以子字串比對佇列項名
// （keyvault 的 TestPostUnsealQueueHasNoTransitionalMigration 與
// cmd/server 的 TestPostUnsealMigrationQueueBModeTiming），含該子字串的名稱會被
// 誤判為「過渡遷移自動執行」而打紅。
const PostUnsealMigrationOffsiteSeed = "offsite_seed"

// offsiteSeedMarker seed 的執行標記（形狀比照 ldapSeedMarker）。
//
// **字串定義在 repository**（database.OffsiteSeedMarkerVersion）：標記由本檔寫入、
// 由 fail-close 的未知版本判定讀取，兩端必須同值；repository 不得依賴上層，
// 故常數落在下層由兩端共用。
//
// **語義是「已完成評估」而非「已建立資料」**：實際 seed、env 未設定而跳過、
// 表非空而跳過三種**終局**皆寫入；只有基礎設施失敗與 env 組態矛盾不寫，
// 留待下次啟動重試。
//
// 若照直覺只在「成功插入」時寫 marker，則 env 未設定或設定由 UI 建立的部署
// marker 永遠缺席——該列被管理員停用後，只要 env 仍有值，下次啟動就會**靜默
// 重建並重新啟用一個離機上傳落點**。
const offsiteSeedMarker = database.OffsiteSeedMarkerVersion

// offsiteProfilesTable seed 判定用表名（與 model.OffsiteProfile.TableName() 同值）
const offsiteProfilesTable = "offsite_profiles"

// RegisterOffsiteSeedMigration 把離機設定 seed 登記進解封後遷移佇列。
//
// **匯出而非由佇列自行呼叫**（沿 RegisterLDAPSeedMigration 的拆環形態）：
// 佇列機制屬 keyvault，遷移內容屬本包；由組裝根
// （`cmd/server/stage2.go` 的 `RegisterPostUnsealBuiltin`）注入後，
// 方向是 assembly→{keyvault, offsite}，**不開 keyvault→offsite 出向邊**。
func RegisterOffsiteSeedMigration(journal CustodyJournal) {
	keyvault.RegisterPostUnsealMigration(keyvault.PostUnsealMigration{
		Name: PostUnsealMigrationOffsiteSeed,
		Run: func(db *gorm.DB, codec crypto.ColumnCodec) error {
			return RunOffsiteEnvSeed(db, codec, journal)
		},
	})
}

// offsiteSeedEnv env 快照（**僅 seed 使用**；seed 之後 env 不參與任何執行期判定）。
type offsiteSeedEnv struct {
	Provider string
	Settings SettingsInput
	// Configured 所選 provider 的 bucket 鍵非空
	Configured bool
	// gcsCredentialsFile 憑證檔路徑（讀取失敗＝組態矛盾）
	gcsCredentialsFile string
}

// readOffsiteSeedEnv 讀 env。
//
// **兩條硬約束**（沿 ldapSeedEnvConfig 的既有理由）：
//
//  1. 布林解析語義與 config.getEnvBool 同源（`strconv.ParseBool`，接受
//     `1/t/T/TRUE/true`）——寫成 `== "true"` 會讓 `.env` 填 `1` 的既有部署
//     升級後靜默判定為未啟用。
//  2. key 必須以**字面字串直接傳給 os.Getenv**——env 漂移守衛只認已知讀取函式的
//     第 0 個字面參數，把 key 收進陣列或自訂 helper 會使守衛掃不到而失去範本同步保證。
func readOffsiteSeedEnv() offsiteSeedEnv {
	provider := os.Getenv("OFFSITE_PROVIDER")
	if provider == "" {
		provider = ProviderS3
	}
	out := offsiteSeedEnv{Provider: provider}
	if provider == ProviderGCS {
		out.Settings = SettingsInput{
			Provider: provider,
			Bucket:   os.Getenv("OFFSITE_GCS_BUCKET"),
			Prefix:   os.Getenv("OFFSITE_GCS_PREFIX"),
			Endpoint: os.Getenv("OFFSITE_GCS_ENDPOINT"),
		}
		out.gcsCredentialsFile = os.Getenv("OFFSITE_GCS_CREDENTIALS_FILE")
		out.Configured = out.Settings.Bucket != ""
		return out
	}
	out.Settings = SettingsInput{
		Provider:        provider,
		Bucket:          os.Getenv("OFFSITE_S3_BUCKET"),
		Endpoint:        os.Getenv("OFFSITE_S3_ENDPOINT"),
		Region:          os.Getenv("OFFSITE_S3_REGION"),
		Prefix:          os.Getenv("OFFSITE_S3_PREFIX"),
		PathStyle:       offsiteSeedBool(os.Getenv("OFFSITE_S3_PATH_STYLE"), false),
		AccessKeyID:     os.Getenv("OFFSITE_S3_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("OFFSITE_S3_SECRET_ACCESS_KEY"),
	}
	out.Configured = out.Settings.Bucket != ""
	return out
}

// offsiteSeedBool config.getEnvBool 的同語義（ParseBool；無效值取預設）
func offsiteSeedBool(value string, defaultValue bool) bool {
	if value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

// RunOffsiteEnvSeed 執行 env→DB 的一次性 seed。
//
// **判定順序寫死**，順序本身承載語義：
//
//  1. 表不存在 → no-op 直接返回（不記失敗、不寫 marker）。單元測試庫普遍無此表。
//  2. env 未設定（所選 provider 的 bucket 鍵空）→ 寫 marker 後返回。
//     **排在 marker 檢查之前**是刻意的：全新部署首啟即完成評估並留痕，
//     日後 env 被填上也不會回灌。
//  3. env 組態矛盾（provider 枚舉、端點三成分、憑證半套、s3 端點與 region 皆空、
//     gcs 憑證檔不可讀）→ **不寫列、不寫 marker**、留可見錯誤，下次啟動重試。
//     seed 是便利功能，**不得把主服務綁死在它身上**——服務照常啟動，UI 設定路徑恆可用。
//  4. 【鎖內】marker 已寫 → 返回（env 自此不參與任何執行期判定）。
//  5. 【鎖內】設定表非空 → 寫 marker 後返回（不覆蓋任何既有設定）。
//  6. 【鎖內】seed＝插列＋審計＋marker **同一交易**。
//
// (4)(5)(6) 一律在 `WithOffsiteProfileLock` 內以 tx 重讀——**與 UI 的 Save 共用同一把鎖**。
// 不共用即有「seed 與 UI 都在鎖外看到空表、各插一列」的競態，其一撞 partial unique
// index 而對 admin 回 500。
//
// 步驟 2 先於 4 意味著 marker 會被重複寫入，故 marker 寫入必須冪等。
//
// 回傳非 nil error 即失敗——佇列只記錄不阻塞，marker 未寫，下次啟動重試。
func RunOffsiteEnvSeed(db *gorm.DB, codec crypto.ColumnCodec, journal CustodyJournal) error {
	if journal == nil {
		journal = noopCustodyJournal{}
	}
	// (1) 表不存在 → no-op；catalog 查詢本身失敗則向上傳遞
	exists, err := offsiteSeedTableExists(db)
	if err != nil {
		return fmt.Errorf("判定 offsite_profiles 是否存在失敗: %w", err)
	}
	if !exists {
		return nil
	}

	env := readOffsiteSeedEnv()

	// (2) env 未設定 → 寫 marker 返回
	if !env.Configured {
		if err := offsiteSeedWriteMarker(db); err != nil {
			return fmt.Errorf("寫入離機儲存 seed 標記失敗（env 未設定分支）: %w", err)
		}
		return nil
	}

	// (3) env 組態矛盾 → 不寫列、不寫 marker、留可見錯誤
	settings := env.Settings
	if env.Provider == ProviderGCS && env.gcsCredentialsFile != "" {
		content, readErr := os.ReadFile(env.gcsCredentialsFile)
		if readErr != nil {
			// **不回顯檔案內容**，只指名鍵與路徑（路徑是部署者自己填的，非機密）
			log.Printf("[OffsiteSeed] OFFSITE_GCS_CREDENTIALS_FILE 指向的檔案不存在或不可讀（%s）："+
				"不寫入設定、不寫標記，下次啟動重試；離機設定亦可直接於管理介面完成",
				env.gcsCredentialsFile)
			return fmt.Errorf("讀取離機儲存 gcs 憑證檔失敗（標記未寫，下次啟動重試）")
		}
		settings.ServiceAccountJSON = string(content)
	}
	norm, err := validateAndNormalizeOffsiteSettings(settings)
	if err != nil {
		log.Printf("[OffsiteSeed] env 的離機儲存設定有矛盾（%s）：不寫入設定、不寫標記，"+
			"下次啟動重試；離機設定亦可直接於管理介面完成", ReasonOf(err))
		return fmt.Errorf("離機儲存 env 設定矛盾（標記未寫，下次啟動重試）: %w", err)
	}

	if codec == nil {
		return fmt.Errorf("離機儲存 seed 需要 codec（段 2 注入），實得 nil")
	}
	mode := model.OffsiteCredentialDefaultChain
	enc := ""
	if norm.credentialIntent == credIntentNew {
		enc, err = encryptSeedCredentials(codec, norm.credentialPlain)
		if err != nil {
			// 加密失敗＝基礎設施失敗：不寫 marker，下次啟動重試
			return err
		}
		mode = model.OffsiteCredentialStored
	}

	seeded := false
	if err := WithOffsiteProfileLock(db, func(tx *gorm.DB) error {
		// (4) marker 已寫 → 返回（鎖內重讀）
		written, err := offsiteSeedMarkerWritten(tx)
		if err != nil {
			return err
		}
		if written {
			return nil
		}
		// (5) 表非空 → 寫 marker 返回（鎖內重讀；此值才是可信的）
		var existing int64
		if err := tx.Model(&model.OffsiteProfile{}).Count(&existing).Error; err != nil {
			return fmt.Errorf("計數 offsite_profiles 失敗: %w", err)
		}
		if existing > 0 {
			log.Printf("[OffsiteSeed] offsite_profiles 已有 %d 列，不 seed（標記為已評估）；"+
				"執行期沿用資料庫中的設定", existing)
			return offsiteSeedWriteMarker(tx)
		}
		if offsiteProfilePreWriteHook != nil {
			offsiteProfilePreWriteHook()
		}
		now := time.Now()
		row := &model.OffsiteProfile{
			ProfileFingerprint: norm.fingerprintOf(),
			Singleton:          1,
			Provider:           norm.Provider,
			Endpoint:           norm.EndpointFull,
			Bucket:             norm.Bucket,
			Prefix:             norm.Prefix,
			Region:             norm.Region,
			PathStyle:          norm.PathStyle,
			CredentialMode:     mode,
			CredentialsEnc:     enc,
			CreatedAt:          now,
			ActivatedAt:        now,
		}
		// (6) 插列 → 審計 → marker 三者同一交易。
		//
		// **審計不得排在事務之後**：審計表暫時不可寫時，若設定列與 marker 已提交，
		// 一個離機上傳落點就被永久建立而**沒有任何審計紀錄**，且 marker 使後續啟動
		// 不再補寫——違反「全操作審計」紅線且不可回頭。
		if err := tx.Create(row).Error; err != nil {
			return err
		}
		gen := row.GenerationID
		if err := journal.RecordInTx(tx, CustodyEvent{
			Action:     CustodyActionProfile,
			Resource:   string(model.ResourceSession),
			ResourceID: &gen,
			Status:     string(model.StatusSuccess),
			Details: map[string]any{
				"event":               "offsite_settings_seed",
				"source":              "seed",
				"generation_id":       row.GenerationID,
				"profile_fingerprint": row.ProfileFingerprint,
				"provider":            row.Provider,
				"endpoint_origin":     norm.EndpointOrigin,
				"bucket":              row.Bucket,
				"credential_mode":     row.CredentialMode,
				"has_credentials":     row.CredentialsEnc != "",
			},
		}); err != nil {
			return err
		}
		if err := offsiteSeedWriteMarker(tx); err != nil {
			return err
		}
		seeded = true
		return nil
	}); err != nil {
		return fmt.Errorf("離機儲存 seed 寫入失敗（列、審計與標記同進退，標記未寫，下次啟動重試）: %w", err)
	}

	if seeded {
		log.Printf("[OffsiteSeed] 已自 env seed 一列離機儲存設定（provider=%s、bucket=%s、憑證模式=%s）；"+
			"其後的變更請於系統設定的離機儲存頁進行，改動 .env 不再生效",
			norm.Provider, norm.Bucket, mode)
	}
	return nil
}

// encryptSeedCredentials 加密 seed 憑證。錯誤淨化理由同服務層
// （codec 的錯誤可能夾帶明文片段）。
func encryptSeedCredentials(codec crypto.ColumnCodec, plain string) (string, error) {
	enc, err := codec.EncryptFor(context.Background(), keyvault.RefOffsiteCredentials, plain)
	if err != nil {
		log.Printf("[OffsiteSeed] 憑證信封加密失敗 error_type=%T（底層錯誤已淨化，不入日誌）", err)
		return "", fmt.Errorf("加密離機儲存憑證失敗（標記未寫，下次啟動重試）")
	}
	return enc, nil
}

// offsiteSeedMarkerWritten 標記是否已寫
func offsiteSeedMarkerWritten(db *gorm.DB) (bool, error) {
	var n int64
	if err := db.Table("schema_migrations").Where("version = ?", offsiteSeedMarker).
		Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢離機儲存 seed 標記失敗: %w", err)
	}
	return n > 0, nil
}

// offsiteSeedWriteMarker 冪等寫入標記。
//
// **為何必須冪等**：判定順序把「env 未設定 → 寫 marker」排在「marker 已寫 → 返回」
// 之前，故 env 未設定的部署每次啟動都會走到這裡；直接 INSERT 會在第二次啟動撞主鍵
// 而使佇列項每次啟動都記一筆失敗。
//
// 先查再插而非 dialect 專屬的 upsert 語法——同一份程式碼同時跑在 postgres（生產）
// 與 sqlite（單元測試）上；競態下的重複鍵再查一次確認，仍視為已寫。
func offsiteSeedWriteMarker(db *gorm.DB) error {
	written, err := offsiteSeedMarkerWritten(db)
	if err != nil {
		return err
	}
	if written {
		return nil
	}
	if err := db.Exec("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
		offsiteSeedMarker, time.Now()).Error; err != nil {
		if again, e := offsiteSeedMarkerWritten(db); e == nil && again {
			return nil
		}
		return err
	}
	return nil
}

// offsiteSeedTableExists 判定 offsite_profiles 是否存在。
//
// **不用 GORM `Migrator().HasTable`**：它只回 bool，catalog 查詢因權限、連線中斷或
// 其他暫時性錯誤而失敗時，與「表確實不存在」無從區分——seed 會誤走 no-op 並向佇列
// 回報成功，基礎設施故障靜默不留痕。
//
// dialect 白名單 fail-close：未知 dialect 不猜，直接回錯。
func offsiteSeedTableExists(db *gorm.DB) (bool, error) {
	var n int64
	switch db.Dialector.Name() {
	case "postgres":
		if err := db.Raw(`SELECT count(*) FROM information_schema.tables
			WHERE table_schema = current_schema() AND table_name = ?`,
			offsiteProfilesTable).Scan(&n).Error; err != nil {
			return false, err
		}
	case "sqlite":
		if err := db.Raw(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`,
			offsiteProfilesTable).Scan(&n).Error; err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("不支援的資料庫 dialect %q：無法安全判定 %s 是否存在",
			db.Dialector.Name(), offsiteProfilesTable)
	}
	return n > 0, nil
}
