package apierror

// 帳號憑證庫的出口碼。
//
// 本檔與 codes.go 同一 registry，分檔僅為並行開發隔離：收 internal/api 的
// credential_handler.go 一檔，外加帳號與資產建立路徑上的憑證來源檢核。
// 命名沿用既有慣例：VALIDATION_*（請求欄位／參數）、CONFLICT_*（唯一性）、
// NOTFOUND_*、RULE_CREDENTIAL_*（可預期的業務規則攔截）、INTERNAL_*（5xx，
// 成因僅落伺服端日誌）。
//
// **不回填憑證名、帳號名與資產名等自由字串**：那些是請求方可控輸入，
// apierror 的 params 只收受控 enum/int（見 ParamSpec）；且回填會讓錯誤回應
// 變成可枚舉名稱的探測器。
//
// **「不存在」與「對操作者不可見」共用同一碼**：分流即製造存在性探測器
// ——請求方以回應差異就能問出「這個識別是不是有東西」。故憑證不存在、
// 憑證被軟刪、操作者對受影響資產無權限三者一律回 NOTFOUND_CREDENTIAL。

// --- VALIDATION_*（請求欄位／參數）---
var (
	// 路徑參數 credential id 解析失敗。不复用 VALIDATION_INVALID_ID：
	// 那支碼的 {resource} 是受控 enum，新增值會連帶要求前端 enum 命名空間補鍵
	CodeInvalidCredentialID = register("VALIDATION_INVALID_CREDENTIAL_ID", Descriptor{ZhFallback: "無效的憑證 ID"})
	// 路徑參數 rotation id 解析失敗
	CodeInvalidRotationID = register("VALIDATION_INVALID_ROTATION_ID", Descriptor{ZhFallback: "無效的改密輪次 ID"})
	// 路徑參數 rotation member id 解析失敗
	CodeInvalidRotationMemberID = register("VALIDATION_INVALID_ROTATION_MEMBER_ID", Descriptor{ZhFallback: "無效的改密對象 ID"})

	// 共用憑證必須具名：名稱是操作者辨識「這組秘密是哪一組」的唯一依據，
	// 缺名的共用憑證在憑證庫上與其他筆無從區分
	CodeCredentialNameRequired = register("VALIDATION_CREDENTIAL_NAME_REQUIRED", Descriptor{ZhFallback: "共用憑證必須提供名稱"})
	CodeCredentialNameTooLong  = register("VALIDATION_CREDENTIAL_NAME_TOO_LONG", Descriptor{ZhFallback: "憑證名稱超過長度上限（128 字元）"})
	// 名稱會進審計快照、稽核報告與介面，控制字元可操縱讀日誌的終端
	CodeCredentialNameInvalid = register("VALIDATION_CREDENTIAL_NAME_INVALID", Descriptor{ZhFallback: "憑證名稱不得含換行或控制字元"})

	CodeCredentialScopeInvalid      = register("VALIDATION_CREDENTIAL_SCOPE_INVALID", Descriptor{ZhFallback: "憑證範圍僅允許專用或共用"})
	CodeCredentialSecretTypeInvalid = register("VALIDATION_CREDENTIAL_SECRET_TYPE_INVALID", Descriptor{ZhFallback: "秘密型別僅允許密碼或 SSH 金鑰"})
	CodeCredentialSecretRequired    = register("VALIDATION_CREDENTIAL_SECRET_REQUIRED", Descriptor{ZhFallback: "建立共用憑證必須提供密碼或私鑰"})
	// 共用憑證的登入帳號名不可改：改名等於讓每一台掛載的登入身分同時變動，
	// 而遠端主機上的帳號並不會跟著改
	CodeCredentialUsernameImmutable   = register("VALIDATION_CREDENTIAL_USERNAME_IMMUTABLE", Descriptor{ZhFallback: "共用憑證的登入帳號名建立後不可修改，請另建憑證並重新掛載"})
	CodeCredentialProtocolFamily      = register("VALIDATION_CREDENTIAL_PROTOCOL_FAMILY_INVALID", Descriptor{ZhFallback: "憑證的協定族不在允許值域內"})
	CodeCredentialDetachSourceInvalid = register("VALIDATION_CREDENTIAL_DETACH_SOURCE_INVALID", Descriptor{ZhFallback: "新秘密來源僅允許隨機產生或自訂"})
	// 改密模式：整組換同一組秘密，或每台各自隨機並解除共用
	CodeCredentialRotationModeInvalid = register("VALIDATION_CREDENTIAL_ROTATION_MODE_INVALID", Descriptor{ZhFallback: "改密模式僅允許整組同一組或每台各自隨機"})
	// 掛載請求的憑證來源二擇一：既有共用憑證或這台專用，同時給就無從判定要寫哪一個
	CodeCredentialSourceAmbiguous = register("VALIDATION_CREDENTIAL_SOURCE_AMBIGUOUS", Descriptor{ZhFallback: "登入憑證來源只能二擇一：既有共用憑證或這台專用"})
	// 「從其他資產帳號複製憑證」的參數已移除：複製出來的兩份密文是同一組秘密的
	// 兩個副本，系統事後無從得知它們是否還一樣，於是「這組秘密被哪些主機使用」
	// 永遠回答不了。共用意圖一律以共用憑證表達
	CodeAccountCopyFromRemoved = register("VALIDATION_ACCOUNT_COPY_FROM_REMOVED", Descriptor{ZhFallback: "已不支援從其他資產帳號複製憑證，請改為選取共用憑證"})

	// 改密計劃的目標種類與目標憑證
	CodePlanTargetKind              = register("VALIDATION_PLAN_TARGET_KIND", Descriptor{ZhFallback: "改密目標種類僅支援帳號或憑證"})
	CodePlanTargetCredentialRequire = register("VALIDATION_PLAN_TARGET_CREDENTIAL_REQUIRED", Descriptor{ZhFallback: "以憑證為目標的計劃必須指定憑證"})
	// 計劃選到共用憑證的成員：單台改密會讓其餘掛載當場失去登入身分，
	// 故於儲存時即擋下並要求改以憑證為目標發起整組改密
	CodePlanSharedCredentialTarget = register("VALIDATION_PLAN_SHARED_CREDENTIAL_TARGET", Descriptor{ZhFallback: "所選目標掛的是共用憑證，請改以憑證為目標發起整組改密"})
	// 批次的「整批同一組」模式須具名：批次會建立一筆共用憑證，缺名即無從辨識
	CodeBatchCredentialNameRequired = register("VALIDATION_BATCH_CREDENTIAL_NAME_REQUIRED", Descriptor{ZhFallback: "整批同一組模式須指定共用憑證名稱"})
)

// --- CONFLICT_* / NOTFOUND_* ---
var (
	CodeCredentialNameExists = register("CONFLICT_CREDENTIAL_NAME", Descriptor{ZhFallback: "已有同名的共用憑證"})
	// 同一資產上已掛載同一憑證
	CodeCredentialBindingExists = register("CONFLICT_CREDENTIAL_BINDING", Descriptor{ZhFallback: "該資產已掛載此憑證"})

	// 憑證不存在、已刪除，或對操作者不可見——三者共用一碼（見檔頭）
	CodeCredentialNotFound = register("NOTFOUND_CREDENTIAL", Descriptor{ZhFallback: "憑證不存在"})
	// 掛載不存在或不屬於路徑上的憑證
	CodeCredentialBindingNotFound = register("NOTFOUND_CREDENTIAL_BINDING", Descriptor{ZhFallback: "掛載不存在或不屬於該憑證"})
	CodeCredentialRotationNotFound = register("NOTFOUND_CREDENTIAL_ROTATION",
		Descriptor{ZhFallback: "改密輪次不存在"})
	CodeCredentialRotationMemberNotFound = register("NOTFOUND_CREDENTIAL_ROTATION_MEMBER",
		Descriptor{ZhFallback: "改密對象不存在或不屬於該輪次"})
)

// --- RULE_CREDENTIAL_*（業務規則；service sentinel 一對一）---
var (
	// 仍有掛載時拒絕刪除。受影響的資產名單另走回應 body，不進錯誤 params
	CodeCredentialInUse = register("RULE_CREDENTIAL_IN_USE", Descriptor{ZhFallback: "憑證仍被資產掛載，請先卸載後再刪除"})
	// 仍有未決候選秘密：那台機器現在吃哪一組秘密尚未確定，刪掉憑證即失去追回的依據
	CodeCredentialPendingCandidate = register("RULE_CREDENTIAL_PENDING_CANDIDATE", Descriptor{ZhFallback: "憑證仍有未決的候選秘密，請先收斂後再刪除"})
	CodeCredentialRotationActive   = register("RULE_CREDENTIAL_ROTATION_ACTIVE", Descriptor{ZhFallback: "憑證的改密進行中，暫不接受此操作"})
	// 上一輪未收斂：各台可能停在不同版本，此時開新一輪會讓「遠端到底是哪一版」永遠答不出來
	CodeCredentialOutOfSync            = register("RULE_CREDENTIAL_OUT_OF_SYNC", Descriptor{ZhFallback: "憑證的上一輪改密尚未收斂，請先逐台補跑"})
	CodeCredentialSharedRequiresName   = register("RULE_CREDENTIAL_SHARED_REQUIRES_NAME", Descriptor{ZhFallback: "轉為共用憑證必須提供名稱"})
	CodeCredentialToDedicatedMulti     = register("RULE_CREDENTIAL_TO_DEDICATED_MULTI_BINDING", Descriptor{ZhFallback: "憑證掛載於多個資產，不可轉為專用"})
	CodeCredentialToDedicatedNoBinding = register("RULE_CREDENTIAL_TO_DEDICATED_NO_BINDING", Descriptor{ZhFallback: "憑證沒有任何掛載，不可轉為專用"})
	CodeCredentialDedicatedSingle      = register("RULE_CREDENTIAL_DEDICATED_SINGLE_BINDING", Descriptor{ZhFallback: "專用憑證恰有一個掛載，不可掛到其他資產"})
	CodeCredentialProtocolMismatch     = register("RULE_CREDENTIAL_PROTOCOL_MISMATCH", Descriptor{ZhFallback: "憑證的協定族與資產協定不相容"})
	// 拆分與脫離只對共用憑證成立
	CodeCredentialNotShared = register("RULE_CREDENTIAL_NOT_SHARED", Descriptor{ZhFallback: "此操作僅適用於共用憑證"})
	// 輪替已結束，不接受推進或放棄
	CodeCredentialRotationNotRunning = register("RULE_CREDENTIAL_ROTATION_NOT_RUNNING", Descriptor{ZhFallback: "該改密輪次已結束"})
	// 零掛載的共用憑證是合法的待用狀態，但對它發起改密沒有任何遠端可動
	CodeCredentialRotationNoBinding = register("RULE_CREDENTIAL_ROTATION_NO_BINDING", Descriptor{ZhFallback: "憑證沒有任何掛載，無可改密的目標"})
	// 成員當下的狀態不接受補跑（已就位或已終止）
	CodeCredentialMemberNotRetryable = register("RULE_CREDENTIAL_MEMBER_NOT_RETRYABLE", Descriptor{ZhFallback: "該對象目前的狀態不接受補跑"})
	// 脫離未完成：該掛載仍在原共用憑證上。終態與機器可讀原因走回應 body 的
	// 專屬欄位，不進錯誤 params——params 只收受控值域
	CodeCredentialDetachFailed = register("RULE_CREDENTIAL_DETACH_FAILED", Descriptor{ZhFallback: "脫離共用未完成，該掛載仍使用原共用憑證"})
	// 對掛在共用憑證上的帳號直接寫入新密文：那組秘密同時是其他主機的登入身分，
	// 由單台帳號端點改寫會讓其餘掛載當場失去登入身分而系統毫無所覺。
	// 出口是憑證層的整組寫入，或先讓這台脫離共用
	CodeAccountSharedCredentialSecret = register("RULE_ACCOUNT_SHARED_CREDENTIAL_SECRET",
		Descriptor{ZhFallback: "此帳號使用共用憑證，請改由憑證庫整組寫入新秘密，或先讓這台脫離共用"})
)

// --- INTERNAL_*（5xx；成因僅落伺服端日誌）---
var (
	CodeInternalCredentialList   = register("INTERNAL_CREDENTIAL_LIST", Descriptor{ZhFallback: "查詢憑證失敗"})
	CodeInternalCredentialGet    = register("INTERNAL_CREDENTIAL_GET", Descriptor{ZhFallback: "查詢憑證詳情失敗"})
	CodeInternalCredentialCreate = register("INTERNAL_CREDENTIAL_CREATE", Descriptor{ZhFallback: "建立憑證失敗"})
	CodeInternalCredentialUpdate = register("INTERNAL_CREDENTIAL_UPDATE", Descriptor{ZhFallback: "更新憑證失敗"})
	CodeInternalCredentialDelete = register("INTERNAL_CREDENTIAL_DELETE", Descriptor{ZhFallback: "刪除憑證失敗"})
	CodeInternalCredentialBind   = register("INTERNAL_CREDENTIAL_BIND", Descriptor{ZhFallback: "掛載憑證失敗"})
	CodeInternalCredentialUnbind = register("INTERNAL_CREDENTIAL_UNBIND", Descriptor{ZhFallback: "卸載憑證失敗"})
	CodeInternalCredentialRebind = register("INTERNAL_CREDENTIAL_REBIND", Descriptor{ZhFallback: "更換掛載憑證失敗"})
	CodeInternalCredentialScope  = register("INTERNAL_CREDENTIAL_SCOPE", Descriptor{ZhFallback: "轉換憑證範圍失敗"})
	CodeInternalCredentialSecret = register("INTERNAL_CREDENTIAL_SECRET", Descriptor{ZhFallback: "寫入憑證新秘密失敗"})
	CodeInternalCredentialDetach = register("INTERNAL_CREDENTIAL_DETACH", Descriptor{ZhFallback: "脫離共用憑證失敗"})

	CodeInternalCredentialRotationStart   = register("INTERNAL_CREDENTIAL_ROTATION_START_FAILED", Descriptor{ZhFallback: "發起整組改密失敗"})
	CodeInternalCredentialRotationGet     = register("INTERNAL_CREDENTIAL_ROTATION_GET", Descriptor{ZhFallback: "查詢改密進度失敗"})
	CodeInternalCredentialRotationRetry   = register("INTERNAL_CREDENTIAL_ROTATION_RETRY", Descriptor{ZhFallback: "補跑改密對象失敗"})
	CodeInternalCredentialRotationAbandon = register("INTERNAL_CREDENTIAL_ROTATION_ABANDON", Descriptor{ZhFallback: "放棄改密輪次失敗"})
)
