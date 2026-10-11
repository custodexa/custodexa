// Package reviewcal 每日審閱簽核的行事曆計算：由政策變更歷史推得每個所屬日的
// 業務時區、起訖、準時期限與是否在啟用範圍內。
//
// 純計算、不碰資料庫：升級遷移（internal/database）與每日簽核服務
// （internal/modules/audit）都要用同一套解析規則，而前者不得依賴後者。
// 行事曆在讀取時由歷史算出，不物化成每日一列——歷史才是真相。
package reviewcal

import (
	"os"
	"strings"
	"time"

	// 時區資料隨二進位提供：正式版映像沒有時區資料庫，不內嵌的話除了 UTC
	// 以外的業務時區全部無法載入。綁在二進位裡也讓程式與時區規則同版升級
	_ "time/tzdata"
)

// DefaultTimezone 偵測不到伺服器時區時的業務時區
const DefaultTimezone = "UTC"

// LoadTimezone 載入 IANA 時區名稱；`Local` 與空字串一律拒絕
// （兩者都會讓切日退回執行環境的本地時區，與「業務時區由政策決定」相違）。
func LoadTimezone(name string) (*time.Location, bool) {
	if name == "" || name == "Local" {
		return nil, false
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, false
	}
	return loc, true
}

// mustLocation 載入時區，失敗退回 UTC（歷史列的值都已在寫入時驗證過，
// 這裡的退路只防手動改庫留下的壞值讓整個行事曆失效）
func mustLocation(name string) *time.Location {
	if loc, ok := LoadTimezone(name); ok {
		return loc
	}
	return time.UTC
}

// DetectTimezone 偵測伺服器時區：先看 `TZ` 環境變數（可載入才採用），
// 再看 `/etc/localtime` 指向的 zoneinfo 名稱，都失敗則 UTC。
//
// 兩個來源以參數注入，測試不必改動行程環境或檔案系統。
func DetectTimezone(getenv func(string) string, localtimeTarget func() (string, error)) string {
	if getenv != nil {
		tz := strings.TrimPrefix(strings.TrimSpace(getenv("TZ")), ":")
		if _, ok := LoadTimezone(tz); ok {
			return tz
		}
	}
	if localtimeTarget != nil {
		if target, err := localtimeTarget(); err == nil {
			if i := strings.LastIndex(target, "zoneinfo/"); i >= 0 {
				name := target[i+len("zoneinfo/"):]
				if _, ok := LoadTimezone(name); ok {
					return name
				}
			}
		}
	}
	return DefaultTimezone
}

// DetectServerTimezone 以實際的行程環境偵測伺服器時區
func DetectServerTimezone() string {
	return DetectTimezone(os.Getenv, func() (string, error) { return os.Readlink("/etc/localtime") })
}
