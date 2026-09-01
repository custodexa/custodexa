package config

// 離機儲存（evidence-offsite-storage）在 config 層**只剩一個容器內路徑鍵**。
//
// # 為什麼這裡幾乎是空的
//
// 設定全 UI 化（使用者裁決）之後，離機儲存的連線參數與憑證由
// `offsite_profiles` 專用表承載、由管理介面維護；`OFFSITE_*` 的其餘鍵降為
// **初次 seed 專用**，只在 post-unseal 佇列的 seed 讀一次
// （`internal/offsite/seed_migration.go`，以字面字串直接呼叫 `os.Getenv`，
// 使 env 漂移守衛掃得到），marker 寫入後不參與任何執行期判定。
//
// 端點淨化、正規化與設定指紋三組純函式已隨語義搬進 `internal/offsite`
// （normalize.go）——它們的來源改為資料庫欄位，留在 config 只會製造第二份規則。
//
// 留在這裡的 `OFFSITE_SPOOL_PATH` 是**取回暫存根**，與
// `EXPORT_ARTIFACT_PATH` 同待遇：容器內路徑、由 compose 的 `environment:` 供給、
// 進漂移守衛 allowlist、**不進 `.env.example`**（容器內路徑不是使用者旋鈕）。

// OffsiteConfig 離機儲存的部署期路徑設定。
type OffsiteConfig struct {
	// SpoolPath 取回暫存根（預設 /var/lib/custodexa/offsite-spool）。
	// **容器本地、非 volume、0700**，且刻意放在資料根之外——放錄影根下會被
	// 儲存量統計與 mtime 清理當成錄影。暫存是快取不是副本：容器重建即消失，
	// 不進備份範圍。
	SpoolPath string
}

// LoadOffsite 自 env 載入離機儲存的路徑設定。
func LoadOffsite() OffsiteConfig {
	return OffsiteConfig{
		SpoolPath: getEnv("OFFSITE_SPOOL_PATH", "/var/lib/custodexa/offsite-spool"),
	}
}
