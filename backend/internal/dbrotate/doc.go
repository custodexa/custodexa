// Package dbrotate 資料庫帳號自改密碼：以帳號自己的連線，把自己的密碼由舊換新。
//
// 涵蓋 MySQL（8.0.13 起）、PostgreSQL（10 起）與 SQL Server。流程與主機帳號改密的
// 五步契約相同：本地前置檢查 → 以舊密碼連線並探測版本與身分 → 單句改密 → 另開
// 連線以新密碼自驗 → 自驗被拒時在第一條連線改回舊密碼。
//
// # 邊界（守衛釘住，見 guard_test.go）
//
//   - 連線一律經 dbconsole.OpenControl（TLS 檔位語義、一次性 connector、不組 DSN）。
//     本套件不得 import os/exec、internal/localpty、internal/dbproxy。
//   - 本套件不記 log：回給呼叫端的錯誤只帶方言、步驟、錯誤碼或錯誤類別
//     （Error 型別），不帶 driver 錯誤原文。MySQL 的語法錯誤訊息會回顯語句片段，
//     片段可能帶出密碼。
//   - 不改動呼叫端的新舊密碼切片：交給連線層的一律是副本（連線層會清零它收到的
//     密碼），回滾與之後的驗證才拿得到原值。
//   - 改密語句的身分由伺服器端決定（MySQL USER()、PostgreSQL SESSION_USER、
//     SQL Server ORIGINAL_LOGIN()），並先核對連上的身分等於帳號快照。
//   - PostgreSQL 送的是用戶端算好的 SCRAM-SHA-256 verifier，改密語句與伺服器的
//     語句記錄不含新密碼明文。登入交換是否送明文取決於目標端的認證方式，不在這個
//     保證內。
//
// # 誠實邊界
//
// MySQL 與 SQL Server 的改密語句本身含明文，這是協定使然；組句時的 Go 字串無法
// 就地清零，存活到 GC 回收。driver 內部在連線關閉前另持有一份認證材料。
package dbrotate
