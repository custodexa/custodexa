package database

import (
	"context"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// paramsWithheldLogger 包住現行的 SQL logger，輸出時只留帶佔位符的 SQL、不帶參數值。
// 記錄等級、慢查詢門檻、錯誤分支（含查無資料）都沿用被包住的 logger：失敗照樣留下
// 「哪一條查詢失敗、錯誤是什麼」的訊號，只是看不到參數。
type paramsWithheldLogger struct {
	logger.Interface
}

// ParamsFilter 參數值一律不進輸出（gorm 在組出要輸出的 SQL 前呼叫）。
func (l paramsWithheldLogger) ParamsFilter(_ context.Context, sql string, _ ...interface{}) (string, []interface{}) {
	return sql, nil
}

// LogMode 調整等級後仍維持不輸出參數。
func (l paramsWithheldLogger) LogMode(level logger.LogLevel) logger.Interface {
	return paramsWithheldLogger{l.Interface.LogMode(level)}
}

// WithheldSQLParams 回傳一個 session：其上執行的 SQL 輸出到 log 時不帶參數值。
// 用在參數本身是敏感值的少數語句（例如以憑證雜湊查詢或寫入），其餘語句的 SQL 紀錄行為不變。
func WithheldSQLParams(db *gorm.DB) *gorm.DB {
	if db == nil || db.Logger == nil {
		return db
	}
	if _, ok := db.Logger.(paramsWithheldLogger); ok {
		return db
	}
	return db.Session(&gorm.Session{Logger: paramsWithheldLogger{db.Logger}})
}
