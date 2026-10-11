package audit

// SetDailyReviewSignBeforeInsertHook 供外部測試套件設定搶簽同步點（僅測試編譯）
func SetDailyReviewSignBeforeInsertHook(f func()) { dailyReviewSignHooks.beforeInsert = f }
