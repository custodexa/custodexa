// Package audit 是審計模組的根。
//
// 骨架先於檔案搬入建立，是為了讓 TxSink 有一個語義正確的落腳處——
// 它不能放 pkg/gatewayapi（會讓公開包相依 GORM，屬第二意見審查的採納項）。
//
// 子包：
//
//	port/  同行程 internal port（TxSink）。刻意不可跨行程。
package audit
