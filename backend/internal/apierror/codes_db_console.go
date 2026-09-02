package apierror

// 查詢主控台（WebSocket 控制通道與結果匯出端點）的出口碼。
//
// 本檔與 codes.go 同一 registry，分檔僅為並行開發隔離。
//
// 錯誤分類原則：**連線階段永不回目標端訊息原文**，切庫回應永不帶
// 訊息，只有「已建連線上、使用者自己語句的 SQL 層錯誤」才把原文送回——那是他
// 自己的產品內容，而連線與拓撲層的錯誤字串常含主機、埠、憑證主體與主機端規則。

// --- RULE_*（可預期的業務規則攔截）---
var (
	// CodeDBConsoleUnsupportedProtocol 協議閘：主控台只服務三種 SQL 方言。
	// 與「資產非文字終端」分碼是因為前者的正確指引是「改用命令列入口」
	CodeDBConsoleUnsupportedProtocol = register("RULE_DB_CONSOLE_UNSUPPORTED_PROTOCOL",
		Descriptor{ZhFallback: "查詢主控台僅支援 mysql、postgres、mssql 資產"})
	// CodeDBConsoleLimitReached admission 閘：同時進行的主控台會話數達上限。
	// 計數口徑是運行時的連線註冊表，不是會話表的 active 列
	CodeDBConsoleLimitReached = register("RULE_DB_CONSOLE_LIMIT_REACHED",
		Descriptor{ZhFallback: "查詢主控台的同時連線數已達上限。若您另有開啟中的主控台，關閉後即可再試；否則請稍後再試或聯繫管理員"})
	// CodeDBConsoleBusy 單一會話同時只允許一個進行中的送出
	CodeDBConsoleBusy = register("RULE_DB_CONSOLE_BUSY",
		Descriptor{ZhFallback: "上一次送出尚未完成"})
	// CodeDBConsoleAuditUnavailable 語句紀錄寫入失敗即不執行（fail-close）。
	// 主控台的執行者是伺服器自己：拒絕一個請求的代價是一則錯誤訊息，
	// 而「語句已對目標生效但沒有留痕」在本路徑沒有第二個真相來源可補
	CodeDBConsoleAuditUnavailable = register("RULE_DB_CONSOLE_AUDIT_UNAVAILABLE",
		Descriptor{ZhFallback: "語句紀錄無法寫入，已拒絕執行"})
	// CodeDBConsoleBlockerUnavailable 阻斷比對器不可用即不執行（fail-close）。
	// 規則集為空與比對器壞掉是兩件事：前者比對正常回未命中，後者若放行，
	// 刪掉規則就等於關掉阻斷
	CodeDBConsoleBlockerUnavailable = register("RULE_DB_CONSOLE_BLOCKER_UNAVAILABLE",
		Descriptor{ZhFallback: "指令阻斷比對器不可用，已拒絕執行"})
	// CodeDBConsoleStatementBlocked 阻斷規則命中。規則名稱不進 ZhFallback：
	// 它是 opaque 自由字串（規則名僅驗 required），沿 CodeCommandBlocked 的先例
	// 以 params["rule"] 單獨傳遞，由前端組字
	CodeDBConsoleStatementBlocked = register("RULE_DB_CONSOLE_STATEMENT_BLOCKED",
		Descriptor{ZhFallback: "語句命中阻斷規則，未送往目標資料庫"})
	// CodeDBConsoleDatabaseNotAllowed 目標庫不在資產的允許清單內。
	// 限制的是**執行目標**，不解析 SQL——邊界於 spec 明載
	CodeDBConsoleDatabaseNotAllowed = register("RULE_DB_CONSOLE_DATABASE_NOT_ALLOWED",
		Descriptor{ZhFallback: "目標資料庫不在此資產的允許清單內"})
	// CodeDBConsoleConnectFailed 起始連線失敗的泛化碼（認證、TLS、網路三類共用）
	CodeDBConsoleConnectFailed = register("RULE_DB_CONSOLE_CONNECT_FAILED",
		Descriptor{ZhFallback: "無法建立資料庫連線"})
	// CodeDBConsoleDatabaseUnavailable 目標資料庫不可用（拓撲／伺服器狀態類，
	// 含切庫失敗）。回應帶目標端錯誤碼但**不帶訊息**
	CodeDBConsoleDatabaseUnavailable = register("RULE_DB_CONSOLE_DATABASE_UNAVAILABLE",
		Descriptor{ZhFallback: "目標資料庫目前不可用"})
	// CodeDBConsoleConnectionLost 送出後目標連線中斷；該單位的結果為未知，
	// 且**不自動重連**
	CodeDBConsoleConnectionLost = register("RULE_DB_CONSOLE_CONNECTION_LOST",
		Descriptor{ZhFallback: "與目標資料庫的連線已中斷"})
)

// --- VALIDATION_*（請求欄位／參數）---
var (
	// CodeDBConsoleStatementTooLarge 語句文字逾上限。於訊息層拒絕、
	// 不產生語句紀錄列——那不是一個執行單位，是一個畸形請求
	CodeDBConsoleStatementTooLarge = register("VALIDATION_DB_CONSOLE_STATEMENT_TOO_LARGE",
		Descriptor{ZhFallback: "語句長度超過上限（256 KiB）"})
	// CodeDBConsoleGoCountUnsupported MSSQL 的 `GO n` 重複執行語法不支援。
	// 拒絕而非忽略：忽略會讓使用者以為執行了 n 次
	CodeDBConsoleGoCountUnsupported = register("VALIDATION_DB_CONSOLE_GO_COUNT_UNSUPPORTED",
		Descriptor{ZhFallback: "不支援 GO 後接重複次數"})
)

// --- NOTFOUND_*（存在性收斂）---
var (
	// CodeDBConsoleResultNotFound 結果匯出的六種不成立情形共用一碼。
	//
	// **回應必須逐位元組相同**：會話不存在、非本人、非進行中、事件識別非當前快取、
	// 結果集索引逾界、識別格式非法——六者都具「找不到這個結果」的形狀，分述即開出
	// 會話存在性的探測面。真實原因只進審計
	CodeDBConsoleResultNotFound = register("NOTFOUND_DB_CONSOLE_RESULT",
		Descriptor{ZhFallback: "找不到指定的查詢結果"})
)
