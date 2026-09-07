package apierror

// 單實例守衛「攔下模式」的出口碼（preservice-pages）。
//
// 攔下模式下服務尚未上線：段 2 未起、無 JWT、寫不了審計列，且該實例
// **不得產生任何資料庫寫入**。這批端點因此是未認證可達的，回應必須：
// 只送機器碼、不送散文；不因失敗成因不同而洩漏可被列舉的差異
// （帳密錯與帳號不存在共用同一碼），但**必須讓操作者分得出「該去做什麼」**
// ——碼不符要重打、憑證錯要換帳號、讀不到使用者表要改走環境變數路徑，
// 三者的處置完全不同，收斂成一碼等於把人困在頁面上。
//
// 本檔與 codes.go 同一 registry，分檔僅為並行開發隔離。
var (
	// CodeInstanceGuardAckIncomplete 三要件（承擔勾選、確認碼、管理員帳密）缺一。
	// 對外 400。三者缺哪一項不個別回報：頁面本來就同時要求三項，逐項回報只是
	// 給未經頁面的呼叫者一份填空提示。
	CodeInstanceGuardAckIncomplete = register("INSTANCE_GUARD_ACK_INCOMPLETE", Descriptor{
		ZhFallback: "確認未完成：需同時勾選已確認另一實例已停止、重新輸入本頁顯示的確認碼，並提供管理員帳號與密碼",
	})

	// CodeInstanceGuardHolderChanged 重打的確認碼不等於**當下**持鎖者的碼。
	// 對外 409，回應體另帶新的持鎖者指紋與確認碼（Terraform force-unlock 形態）。
	CodeInstanceGuardHolderChanged = register("INSTANCE_GUARD_HOLDER_CHANGED", Descriptor{
		ZhFallback: "確認碼與目前持有單實例鎖的工作階段不符（持鎖者可能已變更）；請以本頁顯示的新確認碼重新確認",
	})

	// CodeInstanceGuardAckUnauthorized 管理員帳密驗證失敗。對外 401。
	// **不區分帳號不存在／密碼錯／非管理員／帳號停用**：這是未認證端點，
	// 區分即等於送出一台帳號列舉機。
	CodeInstanceGuardAckUnauthorized = register("INSTANCE_GUARD_ACK_UNAUTHORIZED", Descriptor{
		ZhFallback: "管理員帳號或密碼不正確，未接受此次確認",
	})

	// CodeInstanceGuardAckLocked 同一來源的憑證失敗次數達上限，暫時不受理。
	// 對外 429。攔下模式不得寫入資料庫，故此閘為**行程內**計數，隨行程結束歸零
	// ——它擋的是自動化爆破，不是有主機存取權的人。
	CodeInstanceGuardAckLocked = register("INSTANCE_GUARD_ACK_LOCKED", Descriptor{
		ZhFallback: "嘗試次數過多，已暫時停止受理確認，請稍後再試",
	})

	// CodeInstanceGuardAckUnavailable 攔下模式下讀取使用者表失敗
	// （schema 不相容或連線問題）。對外 503。
	// **不猜測**：讀不到就明說改走環境變數路徑，而不是以「憑證錯誤」頂替未知狀態。
	CodeInstanceGuardAckUnavailable = register("INSTANCE_GUARD_ACK_UNAVAILABLE", Descriptor{
		ZhFallback: "此處無法驗證管理員憑證（資料庫結構與本版本不相容或連線異常）；請改以環境變數 INSTANCE_GUARD_ACK 確認後重啟",
	})

	// CodeInstanceGuardNotHalted 本實例不在攔下模式（鎖已取得或服務已上線）。
	// 對外 409。頁面據此轉為「已啟動，前往登入」。
	CodeInstanceGuardNotHalted = register("INSTANCE_GUARD_NOT_HALTED", Descriptor{
		ZhFallback: "本實例已不在攔下狀態，無需確認",
	})
)
