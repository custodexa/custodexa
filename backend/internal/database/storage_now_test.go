package database

import (
	"testing"
	"time"

	"gorm.io/gorm/logger"
)

// TestGormConfigNowFuncStoragePrecision ORM 自動填入的時刻不帶微秒以下的位數，與資料庫保存的精度相同。
// 多帶的位數只存在於寫入當下的記憶體中，寫入回應會比隨後讀取多出幾位。
func TestGormConfigNowFuncStoragePrecision(t *testing.T) {
	cfg := NewGormConfig(logger.Discard)
	if cfg.NowFunc == nil {
		t.Fatal("共用 ORM 設定沒有指定自動填入時刻的取值")
	}
	for i := 0; i < 1000; i++ {
		if ns := cfg.NowFunc().Nanosecond() % int(time.Microsecond); ns != 0 {
			t.Fatalf("自動填入的時刻帶微秒以下的位數：%d ns", ns)
		}
	}
	before := time.Now().Add(-time.Second)
	if got := cfg.NowFunc(); got.Before(before) || got.After(time.Now().Add(time.Second)) {
		t.Fatalf("自動填入的時刻偏離現在：%v", got)
	}
}
