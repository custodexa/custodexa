// Package assets 隨後端二進位一同發佈的靜態資產。
//
// **為何是 embed 而非執行期讀檔**：正式版 image 只 COPY 編譯產物，不帶原始碼目錄；
// 任何以路徑讀取的資產在正式部署上都不存在。編進二進位是唯一能同時滿足
// 「開發與正式行為相同」與「部署形態不變」的做法。
package assets

import _ "embed"

// NotoSansCJKTC 繁體中文與日文皆可正確呈現的無襯線字型（Regular 字重）。
//
// 授權為 SIL Open Font License 1.1，授權原文與此檔同目錄（OFL.txt）；
// 檔案本身的來源、產生步驟與 SHA-256 記於本次變更的研究文件。
//
//go:embed fonts/NotoSansCJKtc-Regular.ttf
var NotoSansCJKTC []byte
