// Package gatewayapi 承載「gateway API 契約面純度」機械守衛。
//
// # 為什麼是獨立 package（自 cmd/server 拆出）
//
// 本守衛以 `packages.Load` 把**原始碼樹**當輸入，一行都不碰 `package main`
// 的內部符號（掃描根由自帶的 gwModuleRoot 從 go.mod 反查，與守衛檔住哪無關）。
// 它原本與另外八支同型全樹掃描守衛擠在 `cmd/server` 一個 package 內循序執行，
// 整包逼近 `go test` 的 600 秒 per-package 預設上限——照專案文件跑
// `go test ./...`（不帶 `-timeout`）會得到一個「看起來像壞掉」的逾時。
// 且 `cmd/server` 或其任何相依編譯不過時，這支守衛就跑不起來＝靜默失效。
//
// 先例見 `internal/auditcopy`（本目錄同樣刻意只有測試檔）。
// **拆分只換位置，不換判準**：判準、上限、豁免與失敗訊息與拆分前逐字相同。
package gatewayapi
