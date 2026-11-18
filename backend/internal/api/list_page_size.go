package api

import "strconv"

// listPageSizeMax 資產列表與使用者列表的每頁筆數上限。超過時套用上限，回應的 page_size 回報實際套用的值。
// 上限約束的是分頁參數與回應的筆數，並讓回報的值與實際套用的一致。
const listPageSizeMax = 1000

// parseListPageSize 解析 page_size：不是數字或小於 1 時沿用預設值（既有處理），超過上限時套用上限。
func parseListPageSize(raw string, def int) int {
	ps, err := strconv.Atoi(raw)
	if err != nil || ps < 1 {
		return def
	}
	if ps > listPageSizeMax {
		return listPageSizeMax
	}
	return ps
}
