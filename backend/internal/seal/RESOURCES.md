# 段 2 服務資源釋放盤點

> 規範依據：`openspec/specs/module-boundaries/spec.md` 的「啟停等價與生命週期登記」
> ——該 Requirement 要求「任一順序敏感相依注入失敗時啟動 fail-close 且已建立資源被反向釋放、
> 正常關閉時停止與 zeroize 以啟動的反序發生」。本檔說明該要求在段 2 的落實方式與接線判準。

## 為什麼段 2 的每一項資源都必須登記

段 2（解封後建構的完整服務圖）是**可重跑的**：KEK 介面填鑰模式下，每一次解封都會重建
一次完整的服務圖。因此段 2 建構的每一個持有資源的物件——連線池、檔案控制代碼、外部
用戶端、背景 goroutine、cron 排程器、套件級單例與全域 hook——都必須有可被遍歷呼叫的
釋放路徑。少登記一項，每一代解封就多留一份 goroutine、一個未關的控制代碼，
或一段仍在記憶體中的 KEK 衍生明文。

「以人工記憶在關閉路徑上逐一補 `defer`」不是可接受的做法：那正是漏項的來源。

## 現行登記方式（唯一事實源）

段 2 的組裝根 `backend/cmd/server/stage2.go` 在建構每一項資源之後，隨即以
`g.bag.AddFunc(<名稱>, …)` 登記其釋放函式。`seal.ResourceBag` 依登記順序收集，
並以**反序（LIFO）**釋放——後建者通常依賴先建者（排程器依賴服務、服務依賴 codec），
先關依賴者才不會讓仍在跑的 worker 打到已釋放的物件。

> **要知道目前登記了哪些項目、以什麼順序登記，請直接讀 `stage2.go` 中 `bag.AddFunc`
> 的呼叫序，不要讀任何清單副本。** 順序本身即契約，由
> `backend/cmd/server/lifecycle_manifest_guard_test.go` 的守衛測試逐位釘住：
> 任何搬遷造成的重排會在該測試當場失敗，而不是在某個窗口靜靜地少歸零一段金鑰。

`ResourceBag.Release` 會吞下單項失敗與 panic 並繼續往下釋放，避免中途放棄造成剩餘項
永久洩漏；它自身也是冪等的。

## 登記新資源時的三態判準

- **已有釋放路徑**：型別已具語義正確的 `Stop()`／`Shutdown()`／`Close()`，
  以 `seal.ReleaserFunc` 包成閉包登記即可。
- **需新增**：持有資源但無釋放方法，或方法存在卻不冪等、不可重建——須先補齊再登記。
- **無需釋放**：純計算，或僅引用他人擁有的 handle，重建新持有者時直接丟棄即可。

判為「無需釋放」之前請先確認它真的沒有自己的 goroutine、ticker 或檔案控制代碼；
只存 `cfg` 與 `db` 引用的服務屬此類，起了 `time.NewTicker` 的不屬此類。

## 三類不會隨服務圖被丟棄而消失的隱性全域狀態

這三類即使新的服務圖已建好，舊持有者仍會被呼叫到，故釋放合約必須顯式涵蓋：

1. **套件級單例**——不清單例，getter 仍會取到舊指標。
2. **全域 model hook**——不解 hook，GORM 直寫路徑會打到已釋放的物件。
3. **常駐的解密後材料**——通知通道的 URL 與 secret 明文、Ed25519 私鑰、明文 DEK，
   皆屬 KEK 衍生材料，釋放時必須歸零，否則被丟棄的服務圖仍握著它們。

落點：audit 側的釋放入口集中在 `backend/internal/modules/audit/stage2_release.go`；
金鑰材料的歸零在 `backend/internal/modules/keyvault/release.go`。

## 接線時的已知陷阱

- **多個既有 `Stop()` 非冪等。** 例如 `backend/internal/modules/audit/syslog_forwarder.go:133-139`
  的 `Stop()` 在返回前不重置 `started`，二次呼叫會 `close` 一個已關閉的 channel 而 panic。
  `ResourceBag.Release` 自身冪等，但擋不住外部另有呼叫者，故接線時應以 `sync.Once` 包覆，
  或直接修正該方法的冪等性。
- **排程器的 `Stop()` 是否等待 in-flight job 並不一致。**
  `backend/internal/scheduler/access_request_timeout.go:43-46` 的版本會 `<-ctx.Done()`
  等到執行中的 job 收工，可作為其餘排程器的修正範本；只呼叫 `cron.Stop()` 而不等待者，
  關閉當下仍可能有 job 正在寫資料庫。
- **具外部副作用的步驟前要留取消點。** 段 2 每個具外部副作用的步驟之前應呼叫
  `seal.CheckCancelStep(ctx, 步驟名)`；建立外部連線、開始通知投遞、啟動排程器三類
  為硬性檢查點。少了它，取消訊號只會在整段跑完之後才被看見。
