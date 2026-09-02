// Package dbconsole 查詢主控台的方言適配層：對目標資料庫建立**一條**連線、
// 查目錄、切庫、送執行單位、讀結果、取消、探詢狀態。
//
// # 邊界（守衛釘住，見 guard_test.go）
//
//   - **不起子程序**：本套件不得 import `os/exec`、`internal/localpty`、
//     `internal/dbproxy`。命令列路徑是子程序＋螢幕文字，本路徑是 driver 直連；
//     兩者混在一起會讓「憑證有沒有離開後端行程」變成一個要逐條追的問題。
//   - **程序內不存在 DSN 字串**：設定物件一律逐欄位組裝，不呼叫任何
//     `ParseDSN`／`FormatDSN`／`ParseConfig`／`msdsn.Parse`，也不以格式化組出
//     含 `password=`／`:%s@`／`Password=` 的連線字串。DSN 一旦成形就會被複製、
//     被記錄、被印進錯誤訊息，而它整條都是憑證。
//   - **無連線池、不自動重撥**：`database/sql` 只當型別與掃描層用，以一次性
//     connector 包住 driver connector——第一次 `Connect` 成功後設定即清零，
//     池手上沒有可再撥號的材料。目標連線關閉即會話的目標連線終止。
//   - **本套件不寫審計、不碰資料庫層 model**：留痕與狀態機在呼叫端。
//     這裡只回報事實（結果、錯誤分類、是否獲確認、交易態）。
//
// # 誠實邊界
//
// driver 內部物件（`*pgx.Conn` 的 `ConnConfig`、mysql 的 `*mysql.Config`、
// go-mssqldb 的 connector）在握手後至 `Close` 前仍持有一份認證材料，我方無法
// 清除。我方保證的是：自身不持有、不組 DSN、不重撥、會話結束即 `Close`。
package dbconsole
