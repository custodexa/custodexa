package database

// KeystrokeFeatureMigrationVersion 鍵盤紀錄功能的 migration 版本。
// 它在 schema_migrations 的 applied_at 即「鍵盤紀錄上線時間」：查看端點以此判定
// 無紀錄列的會話是「上線前」還是「啟動失敗未建立」。必須與 migrations 內的版本一致
// （由 keystroke_feature_test.go 守衛）。
const KeystrokeFeatureMigrationVersion = "20261105_keystroke_records"
