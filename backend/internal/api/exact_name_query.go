package api

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// exactNameQuery 解析列表的名稱精確查找參數（資產、節點、使用者群組的 name，使用者的 username）。
//
// 未帶參數回 (nil, true)，列表行為不變；帶了但值為空字串回 400 並指出參數，不當作沒帶。
// 值原樣回傳，不改寫大小寫或空白：這些資源建立時以原樣字串判定名稱重複，查找沿用同一規則。
// 400 只由輸入決定，在任何可見範圍計算之前寫出，與名稱是否存在無關。
// 第二個回傳值為 false 表示已寫出錯誤回應。
func exactNameQuery(c *gin.Context, field string) (*string, bool) {
	raw, present := c.GetQuery(field)
	if !present {
		return nil, true
	}
	if raw == "" {
		respondInvalidQueryParam(c, field)
		return nil, false
	}
	return &raw, true
}

// trimmedExactNameQuery 與 exactNameQuery 相同，但先去頭尾空白：用於建立時先去頭尾空白再判定名稱重複的資源
// （共用憑證）。去空白後為空字串同樣回 400，與建立時名稱必填的判定一致。
func trimmedExactNameQuery(c *gin.Context, field string) (*string, bool) {
	raw, present := c.GetQuery(field)
	if !present {
		return nil, true
	}
	name := strings.TrimSpace(raw)
	if name == "" {
		respondInvalidQueryParam(c, field)
		return nil, false
	}
	return &name, true
}

// keepExactName 只保留名稱與 name 完全相同（位元組相等）的元素；name 為 nil 時原樣回傳。
// 用於已在記憶體內收斂到呼叫者可見集合的列表，與資料庫的二進位等值比對同一語義。
func keepExactName[T any](rows []T, name *string, nameOf func(T) string) []T {
	if name == nil {
		return rows
	}
	out := make([]T, 0, len(rows))
	for _, r := range rows {
		if nameOf(r) == *name {
			out = append(out, r)
		}
	}
	return out
}
