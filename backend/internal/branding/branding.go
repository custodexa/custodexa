// Package branding 收斂品牌字串（brand-theming L0 樣板）。
//
// **2026-08-14 界定變更**（brand-residual-cleanup）：本檔原註記「技術識別字
// （module 路徑、錄影路徑、審計 HKDF info、seed email）不屬品牌字串，絕不隨更名
// 調整」。該界定成立的前提是「須相容既有部署與既有資料」，而使用者已裁決本專案
// 處於研發階段、不相容既有資料、可清庫重設——前提消失，界定隨之作廢。
//
// 現行界定：**顯示字串用 Name，技術識別字用 Slug**，兩者都隨更名調整。
package branding

// Name 產品顯示名稱：TOTP issuer、通知標頭、終端提示與啟動日誌引用。
const Name = "Custodexa"

// Slug 技術識別字形態（小寫、無空白）：syslog app-name、改密寫入目標主機的
// 帳號 comment、健康檢查的 service 欄、儲存路徑段等。
//
// 與 Name 分開是因為兩者的合法字元集不同——Slug 會進入 syslog 的 APP-NAME 欄
// （RFC 5424 限 PRINTUSASCII 且不得含空白）、檔案路徑、以及目標主機的 comment 欄。
const Slug = "custodexa"
