package audit

// 主體名稱解析：以識別碼取使用者名與資產名，供稽核面呈現。
//
// **為何 audit 模組可直接讀 users／assets**：這兩條跨模組唯讀存取已登記於資料邊界
// 白名單（`guards/moduleboundary` 的登記表），理由即「指令告警與指令流清單 LEFT JOIN
// 補資產名／使用者名」。audit 對 identity／asset 的 **import** 仍為禁止邊，故不得改走
// 那兩個模組的服務——名稱解析只能在本模組內以唯讀查詢完成。
//
// **抽為套件級函式的理由**：原本是 TimelineService 的兩個方法，而告警通知
// （alert_notifier.go）也需要同一份解析。同模組內維持兩套等價查詢，會讓
// 「含軟刪」這類語義決定有機會在其中一套悄悄漂掉。

import (
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// lookupAssetNamesDB 依識別碼取資產名，**含軟刪資產**（Unscoped）。
//
// 含軟刪是刻意的：調查對象常已下架，查得到事件卻顯示不出名字，會讓稽核員
// 以為資料壞了。查不到的識別碼不會出現在回傳 map 中，由呼叫端決定降級呈現。
func lookupAssetNamesDB(db *gorm.DB, ids []uint) map[uint]string {
	out := map[uint]string{}
	if db == nil || len(ids) == 0 {
		return out
	}
	var rows []struct {
		ID   uint
		Name string
	}
	db.Unscoped().Model(&model.Asset{}).Select("id, name").Where("id IN ?", ids).Scan(&rows)
	for _, r := range rows {
		out[r.ID] = r.Name
	}
	return out
}

// lookupUserNamesDB 依識別碼取使用者名，**含軟刪使用者**（離職者仍是調查對象）。
// 語義與 lookupAssetNamesDB 相同。
func lookupUserNamesDB(db *gorm.DB, ids []uint) map[uint]string {
	out := map[uint]string{}
	if db == nil || len(ids) == 0 {
		return out
	}
	var rows []struct {
		ID       uint
		Username string
	}
	db.Unscoped().Model(&model.User{}).Select("id, username").Where("id IN ?", ids).Scan(&rows)
	for _, r := range rows {
		out[r.ID] = r.Username
	}
	return out
}
