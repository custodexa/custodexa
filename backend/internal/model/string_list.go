package model

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// StringList 以 JSON 陣列文字落庫的字串清單。
//
// **為什麼不是逗號分隔字串**：本型別目前承載資料庫名稱，而資料庫名稱本身可以含
// 逗號與空白，分隔字元一旦可能出現在值裡就沒有無歧義的還原方式。
//
// **為什麼不是 jsonb／text[]**：整個 schema 內沒有其他 json 或陣列欄位，為單一
// 欄位引入新的型別族會讓備份還原、匯出工具與 DB 直查各多一個變數；JSON 文字在
// text 欄裡是自足的，直查即可讀。
//
// 空清單一律寫成 `[]` 而非 NULL：庫內不留「語義待解讀的空值」——稽核直讀該欄
// 即知清單為空，不必再去問「NULL 是沒設定還是設成空」。
type StringList []string

// Value 實作 driver.Valuer：nil 與空清單皆落 `[]`。
func (l StringList) Value() (driver.Value, error) {
	if l == nil {
		l = StringList{}
	}
	buf, err := json.Marshal([]string(l))
	if err != nil {
		return nil, fmt.Errorf("序列化字串清單失敗: %w", err)
	}
	return string(buf), nil
}

// Scan 實作 sql.Scanner：容忍 NULL 與空字串（皆為空清單）。
//
// 非法 JSON 一律回錯而非默默視為空清單——本型別承載的是限制型設定，
// 把讀不懂的內容當成「沒有限制」是把資料損毀直接翻譯成權限放寬。
func (l *StringList) Scan(value interface{}) error {
	if value == nil {
		*l = nil
		return nil
	}
	var raw []byte
	switch v := value.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("字串清單欄位型別非預期: %T", value)
	}
	if len(raw) == 0 || string(raw) == "null" {
		*l = nil
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("解析字串清單失敗: %w", err)
	}
	*l = StringList(out)
	return nil
}

// Contains 逐字元精確比對。
//
// **不做大小寫正規化**：本型別的比對對象是目標端目錄回傳的名稱，而各方言的
// 大小寫語義互不相同（同一個名稱在一端是原樣保存、在另一端已被折成小寫）。
// 在我方任一側做正規化都會製造只在某些方言上出現的誤判。
func (l StringList) Contains(v string) bool {
	for _, item := range l {
		if item == v {
			return true
		}
	}
	return false
}
