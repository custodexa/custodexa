// Package kernel 無領域語義的共用小工具。
//
// `dedupeUint` 原定義於 identity 域的
// `user_group_service.go`，卻被 asset（`asset_group_service.go`、`asset_service.go`）
// 與 authz（`asset_authorization_service.go`）跨模組呼叫，故判為
// 「搬 `internal/kernel`（無域語義）」。
//
// **為何不與 `kernel/dberr` 同包**：`dberr` 的職責是資料庫方言錯誤判定，
// 把切片去重塞進去會讓包名與內容脫節，日後任何「這也算 dberr 嗎」的爭議
// 都會把 dberr 變成雜物間。故落點有兩個（`internal/kernel` 與
// `internal/kernel/dberr`），本包是前者。
//
// 本包 SHALL NOT 依賴 `internal/model` 或任何業務模組。
package kernel

// DedupeUint 保序去重（重複 id 只保留首次出現）。
//
// 保序是契約而非巧合：成員名單、節點清單等呼叫端會把結果直接餵給
// `WHERE id IN ?` 與比對邏輯，順序抖動會讓測試與稽核 diff 產生假訊號。
func DedupeUint(ids []uint) []uint {
	seen := make(map[uint]bool, len(ids))
	out := make([]uint, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
