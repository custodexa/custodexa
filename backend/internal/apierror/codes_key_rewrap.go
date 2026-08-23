package apierror

// 換鑰精靈重包請求的出口碼。
//
// 與 codes.go 同一 registry，分檔僅為 domain 隔離；命名沿 codes.go 的既有 grammar
// （VALIDATION_* / CONFLICT_*）。三語 apiError.* 由 TestCodeTranslationsComplete
// 的雙射守衛把關，zh-TW 逐字＝此處 ZhFallback。
//
// **明文流向反轉**：重包請求體改由呼叫端提供新 KEK 材料，伺服端不生成、
// 不回傳、不落庫、不落日誌。以下的碼一律**只描述違規類別**，SHALL NOT 於文字或
// Meta 攜帶任何材料片段（含長度以外的形制細節）。
//
// **兩個確認欄位的證明力不同**：
// `new_kek_confirm` 的逐字比對是伺服端**唯一**信任的機械不變式（可獨立驗證
// 「呼叫端當下持有並能完整重述該材料」）；`confirm_saved` 只是使用者意圖聲明，
// **不具授權力**（直打 API 可機械式填 true），SHALL NOT 被描述為安全不變式。
// 兩者各有專屬碼，正是為了讓這個語義差別在 API 面就看得見。
var (
	// CodeKeyRewrapPayload 請求體無法解析、超出大小上限、或含未知欄位。
	// 未知欄位一律拒絕（fail-close）：靜默忽略會讓呼叫端誤以為送出的欄位已生效。
	CodeKeyRewrapPayload = register("VALIDATION_KEY_REWRAP_PAYLOAD",
		Descriptor{ZhFallback: "重包請求內容無法解析或含未知欄位"})

	// CodeKeyRewrapMode discriminated union 的判別子缺漏或不在白名單
	CodeKeyRewrapMode = register("VALIDATION_KEY_REWRAP_MODE",
		Descriptor{ZhFallback: "重包目標模式無效：mode 須為 local、kms 或 hsm 之一"})

	// CodeKeyRewrapPayloadMixed 混合 payload 或 mode 與所帶欄位不符（fail-close）。
	// **SHALL NOT 以欄位優先序擇一處理**——那會留下 provider-confusion 空間：
	// 以優先序繞過本地目標的格式驗證與 paste-back，或把 KEK 明文誤送進本應只收
	// 引用的委託路徑。
	CodeKeyRewrapPayloadMixed = register("VALIDATION_KEY_REWRAP_PAYLOAD_MIXED",
		Descriptor{ZhFallback: "重包請求混用了不屬於該目標模式的欄位：已拒絕受理，請只送出該模式所需欄位"})

	// CodeKeyRewrapConfirm paste-back 二次輸入與第一次不符。
	// **伺服端唯一信任的機械不變式**：不符即拒，且不產生任何 data_keys 寫入。
	CodeKeyRewrapConfirm = register("VALIDATION_KEY_REWRAP_CONFIRM",
		Descriptor{ZhFallback: "二次輸入的新 KEK 與第一次不符：請重新確認後再送出"})

	// CodeKeyRewrapNotSaved 保存確認旗標非真。
	// **誠實界定**：本欄是 UX 意圖聲明，伺服端無法驗證材料是否真的已離線保存。
	CodeKeyRewrapNotSaved = register("VALIDATION_KEY_REWRAP_NOT_SAVED",
		Descriptor{ZhFallback: "請先確認已保存新 KEK：遺失後既有資料將永久不可解，且系統不提供任何救回途徑"})

	// CodeKeyRewrapMaterial 新 KEK 材料未通過伺服端格式驗證。
	// **誠實界定**（沿 JWT_SECRET 長度下限的既有措辭）：格式驗證是降低常見弱值
	// 風險的務實手段，系統 SHALL NOT 宣稱能由單一值驗證其熵。
	CodeKeyRewrapMaterial = register("VALIDATION_KEY_REWRAP_MATERIAL",
		Descriptor{ZhFallback: "新 KEK 材料不合格：須恰 32 個字元、僅限 A-Z a-z 0-9，且不得為出廠預設值"})

	// CodeKeyRewrapTargetUnsupported 委託目標的重包在本部署尚未提供：
	// 該模式未交付（hsm 屬 P4），或本部署未接上委託 provider 建構器。
	// 與 TARGET_UNAVAILABLE 的差別是「本來就做不到」vs「做得到但這次沒通」。
	CodeKeyRewrapTargetUnsupported = register("VALIDATION_KEY_REWRAP_TARGET_UNSUPPORTED",
		Descriptor{ZhFallback: "此委託 KEK 目標的重包在本部署尚未提供：請確認目標模式與部署組態"})

	// CodeKeyRewrapTargetUnavailable 委託目標的連通性預檢失敗（不可達／權限不足／
	// 金鑰不合用）。**細節不回傳呼叫端**：外部系統的錯誤碼與金鑰識別屬伺服端日誌
	// 的範疇，回傳只會把雲端帳號的內部狀態暴露在 API 面。
	CodeKeyRewrapTargetUnavailable = register("INTERNAL_KEY_REWRAP_TARGET_UNAVAILABLE",
		Descriptor{ZhFallback: "委託 KEK 目標的連通性預檢失敗：請確認金鑰存在、狀態可用，且本服務具備 DescribeKey／Encrypt／Decrypt 權限"})

	// CodeKeyRewrapTargetCurrent 目標金鑰引用等於現行 KEK：重包無意義且會與
	// 切換狀態機衝突
	CodeKeyRewrapTargetCurrent = register("CONFLICT_KEY_REWRAP_TARGET_CURRENT",
		Descriptor{ZhFallback: "新 KEK 與現行 KEK 相同：重包目標必須是另一把金鑰"})

	// CodeKeyRewrapTargetSeen 目標金鑰引用曾出現於金鑰表（含已退役列——退役列
	// 自軟刪除後永久保留指紋史）。本地目標維持此嚴格語義。
	CodeKeyRewrapTargetSeen = register("CONFLICT_KEY_REWRAP_TARGET_SEEN",
		Descriptor{ZhFallback: "此 KEK 曾用於本系統（含已退役紀錄）：請改用一把全新的金鑰"})
)
