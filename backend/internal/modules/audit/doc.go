// Package audit 是審計模組的根（modular-architecture W1 任務 1.6 建立的最小骨架）。
//
// **本包目前刻意為空**：W1 只建立介面地基，零檔案跨包移動。既有的 15 個審計相關檔
// 仍在 internal/service，於 W4 才搬入本包（tasks.md 4.11）。在 W1 就先立骨架是為了讓
// TxSink 有一個語義正確的落腳處——它不能放 pkg/gatewayapi（會讓公開包相依 GORM，
// S4 codex 採納項 #2）。
//
// 子包：
//
//	port/  同行程 internal port（TxSink）。刻意不可跨行程。
package audit
