package policy

import "github.com/custodexa/backend/internal/model"

// 電支基準內建組的種子內容。
//
// 依基準全文逐條盤點後的定稿：條號、人話標題、依據關鍵語與每一筆要求值都寫在
// 這裡。條文分三型：
//
//   - 設定要求——條文給得出可比較的值，或條文涉及某個設定鍵但未定值（後者以
//     未定值呈現，附目前值待稽核判讀）。
//   - 由機構自行確認——條文只給原則或作業週期，產品沒有承載該值的設定鍵。
//   - 系統內建保護——產品無條件提供，沒有可調的設定值。
//
// **不是全部從嚴**：條文明文給定的固定值才寫成要求，條件式或語境式的要求
// （「足夠強度」「應管制」這類）一律以未定值或機構自行確認呈現。替條文發明一個
// 門檻，會讓稽核以為那個數字有出處。
//
// **同一個設定鍵在本組只掛一次**：多條條文指向同一個鍵時，要求掛在條文最貼近該
// 鍵語義的那一條，其餘條文改為由機構自行確認並在依據裡併引。同組內對同一個鍵
// 給出兩個要求，該組就對自己自相矛盾了。
//
// 未列入本組的條文屬支付業務面或機構治理面，非本產品範疇。

// ePaymentGroupCode 電支基準組的組代號
const ePaymentGroupCode = "epayment_baseline"

// selfAttested 由機構自行確認型的條文。
func selfAttested(clauseNo, title, summary string) policyClauseSeed {
	return policyClauseSeed{
		ClauseNo: clauseNo, Title: title, Summary: summary,
		Kind: model.PolicyClauseKindSelfAttested,
	}
}

// builtinProtection 系統內建保護型的條文。
func builtinProtection(clauseNo, title, summary string) policyClauseSeed {
	return policyClauseSeed{
		ClauseNo: clauseNo, Title: title, Summary: summary,
		Kind: model.PolicyClauseKindBuiltinProtection,
	}
}

// ePaymentPolicyGroupSeed 電支基準組的種子。
func ePaymentPolicyGroupSeed() policyGroupSeed {
	return policyGroupSeed{
		Code:    ePaymentGroupCode,
		Name:    "電子支付機構資訊系統標準及安全控管作業基準",
		Version: "113.10.24",
		Clauses: ePaymentClauses(),
	}
}

// ePaymentClauses 本組的全部條文，依基準的條文主題分段。
func ePaymentClauses() []policyClauseSeed {
	var out []policyClauseSeed
	out = append(out, ePaymentPrivilegedAccountClauses()...)
	out = append(out, ePaymentAuthenticationClauses()...)
	out = append(out, ePaymentAccessControlClauses()...)
	out = append(out, ePaymentAuditTrailClauses()...)
	out = append(out, ePaymentTransportClauses()...)
	out = append(out, ePaymentSessionClauses()...)
	out = append(out, ePaymentIncidentClauses()...)
	return out
}

// ePaymentPrivilegedAccountClauses 系統維運人員與特權帳號管理。
func ePaymentPrivilegedAccountClauses() []policyClauseSeed {
	return []policyClauseSeed{
		builtinProtection("15-1", "最小權限配帳號",
			"依最小權限及僅知原則配置適當之權限"),
		{ClauseNo: "15-2", Title: "權限定期審查與離職撤權",
			Summary: "至少每年定期審查帳號與權限之合理性；人員離職或調職時應盡速移除權限",
			Controls: []policyControlSeed{
				// 條文只說「盡速移除權限」，未及既存連線是否一併中斷
				unspecified(PolicyAccessRevokeDisconnect),
			}},
		builtinProtection("15-3(一)", "特權帳號要分開",
			"特權帳號應和日常維運帳號區隔，且應列冊保管"),
		builtinProtection("15-3(二)", "要有特權帳管系統",
			"應使用特權帳號管理系統"),
		{ClauseNo: "15-3(三)", Title: "最高權限先簽核並定期覆核",
			Summary: "最高權限帳號使用時須先取得權責主管同意，並保留稽核軌跡、定期覆核使用結果",
			Controls: []policyControlSeed{
				mustBe(PolicyAccessPolicyDefault, model.AccessPolicyApproval),
				mustBe(PolicyDailyReviewEnabled, "true"),
			}},
		{ClauseNo: "15-3(四)", Title: "對外主機要雙因子",
			Summary: "用於提供網際網路服務之伺服器及目錄服務主機，應採雙因子認證",
			Controls: []policyControlSeed{
				mustBe(PolicyMFARequired, MFARequiredAll),
			}},
		selfAttested("15-4", "可限定來源電腦與網路位置",
			"必要時得限定其使用之機器與網路位置；逐帳號的允許來源網段由機構自行設定"),
		builtinProtection("15-6", "登入操作要留紀錄",
			"登入作業系統進行系統異動或資料庫存取時，應留存人為操作紀錄"),
		builtinProtection("15-7", "一人一個帳號",
			"帳號應採一人一號管理，並能區分人員身分"),
		builtinProtection("15-9", "資料庫工具要控管",
			"具變更權限之公用程式應列冊管理並限制使用"),
	}
}

// ePaymentAuthenticationClauses 身分驗證與密碼。
func ePaymentAuthenticationClauses() []policyClauseSeed {
	return []policyClauseSeed{
		{ClauseNo: "4-7(一)", Title: "密碼至少六位",
			Summary:  "固定密碼長度不應少於六位",
			Controls: []policyControlSeed{atLeast(PolicyPasswordMinLength, "6")}},
		{ClauseNo: "4-7(二)", Title: "密碼混英文和數字",
			// 全條唯一非「應」的一款：語氣是建議，故以參考值呈現
			Summary:  "建議得採英數字混合使用",
			Controls: []policyControlSeed{asReference(mustBe(PolicyPasswordRequireAlnum, "true"))}},
		{ClauseNo: "4-7(五)", Title: "錯五次就鎖住",
			Summary:  "連續錯誤達五次時不得再繼續執行交易",
			Controls: []policyControlSeed{atMost(PolicyLockoutMaxAttempts, "5")}},
		{ClauseNo: "4-7(六)", Title: "新密碼不能同舊的",
			Summary:  "變更後之固定密碼不得與原固定密碼相同",
			Controls: []policyControlSeed{atLeast(PolicyPasswordHistoryCount, "1")}},
		{ClauseNo: "4-7(七)", Title: "首次登入要改密碼",
			Summary:  "首次登入時應強制變更系統產製的預設密碼",
			Controls: []policyControlSeed{mustBe(PolicyForceChangeOnReset, "true")}},
		selfAttested("4-7(八)", "一年沒換要處理",
			"固定密碼超過一年未變更應做妥善處理；處理方式不限於到期強制改密，由機構的作業程序訂定"),
		{ClauseNo: "15-8", Title: "帳號密碼三個月換一次",
			Summary: "提供人員使用之帳號至少三個月變更一次；提供系統連線之帳號至少每三個月一次或採其他補強管控",
			Controls: []policyControlSeed{
				atMost(PolicyPasswordMaxAgeDays, "90"),
				atMost(PolicyAssetSecretMaxAgeDays, "90"),
			}},
		builtinProtection("17-2", "密碼不可還原保存",
			"固定密碼於儲存時應先進行不可逆運算"),
		selfAttested("21-8(三)", "遠端變更要雙重驗證",
			"每次登入採二項以上安全設計並取得主管授權；對應的設定要求併於 15-3(三) 與 15-3(四) 呈現"),
	}
}

// ePaymentAccessControlClauses 存取控制與最小權限。
func ePaymentAccessControlClauses() []policyClauseSeed {
	return []policyClauseSeed{
		builtinProtection("16-3", "按業務需要給權限",
			"應依執行業務之必要，設定相關人員接觸個人資料之權限"),
		builtinProtection("17-4", "金鑰只給必要的人",
			"應減少金鑰儲存的地點，並僅允許必要之管理人員存取金鑰"),
		selfAttested("17-5", "金鑰快到期要換",
			"金鑰使用期限將屆或有洩漏疑慮時應進行替換；提醒天數由機構依自身金鑰期限訂定"),
		selfAttested("21-8(一)", "每年查遠距申請",
			"應審查遠距管理之申請目的、期間、時段、網段與使用設備"),
		selfAttested("21-8(四)", "限定網段與設備",
			"應定義允許可連結之遠端設備；逐帳號的允許來源網段由機構自行設定"),
		builtinProtection("21-8(二)", "授權照申請內容給",
			"應建立授權機制，依據其申請項目提供必要授權"),
	}
}

// ePaymentAuditTrailClauses 日誌與稽核軌跡。
func ePaymentAuditTrailClauses() []policyClauseSeed {
	return []policyClauseSeed{
		{ClauseNo: "24-1", Title: "日誌集中管理、告警與兩年保存",
			Summary: "日誌及稽核軌跡應集中管理、設定合適告警指標，原始日誌及稽核軌跡至少保存二年",
			Controls: []policyControlSeed{
				mustBe(PolicyFailureAlertEnabled, "true"),
				atLeast(PolicyRetentionAuditLogDays, "730"),
				atLeast(PolicyRetentionSessionCommandDays, "730"),
				atLeast(PolicyRetentionAlertDays, "730"),
				atLeast(PolicyRetentionRecordingDays, "730"),
			}},
		selfAttested("19-4", "紀錄要留兩年",
			"留存紀錄應確保數位證據之收集、保護與適當管理，至少留存二年；保存天數的設定要求併於 24-1 呈現"),
		builtinProtection("24-3", "出事要保全證據",
			"應注意處理過程中軌跡紀錄與證據留存之有效性"),
		builtinProtection("16-5", "查個資要留軌跡",
			"應建置留存個人資料使用之稽核軌跡"),
		selfAttested("21-8(五)", "主管要定期覆核",
			"應建立監控機制、留存操作紀錄，並由主管定期覆核；覆核簽核的設定要求併於 15-3(三) 呈現"),
		builtinProtection("19-7", "系統時鐘要同步",
			"各系統的時鐘應以標準時間為基準，所有系統時鐘應取得同步"),
	}
}

// ePaymentTransportClauses 資料傳輸加密。
func ePaymentTransportClauses() []policyClauseSeed {
	return []policyClauseSeed{
		{ClauseNo: "21-6", Title: "遠端管理要加密、通行碼不入工具",
			Summary: "使用遠端連線進行系統管理作業時應使用足夠強度之加密通訊協定，且不得將通行碼紀錄於工具軟體內",
			Controls: []policyControlSeed{
				// 條文說的是「足夠強度」，不是本產品三段枚舉裡的某一段
				unspecified(PolicyTransportRDPLevel),
				unspecified(PolicyTransportVNCLevel),
				unspecified(PolicyTransportDBLevel),
			}},
		{ClauseNo: "17-1(二)", Title: "對外傳輸要加密",
			Summary: "機敏資料於網際網路上傳輸應建立訊息隱密性機制",
			Controls: []policyControlSeed{
				unspecified(PolicyTransportLDAPLevel),
				unspecified(PolicyTransportSyslogLevel),
				unspecified(PolicyTransportNotifyLevel),
			}},
		builtinProtection("6-1", "加密強度有下限",
			"對稱式與非對稱式加密之金鑰長度應達基準所列強度以上"),
	}
}

// ePaymentSessionClauses 閒置與會話控制。
func ePaymentSessionClauses() []policyClauseSeed {
	return []policyClauseSeed{
		{ClauseNo: "15-5", Title: "十分鐘沒動就遮蔽",
			// 條文語境是螢幕上的個資顯示，掛在網頁閒置逾時是解釋性對照
			Summary:  "人員超過十分鐘未操作電腦時，應限制使用者個人資料顯示於螢幕",
			Controls: []policyControlSeed{atMost(PolicyWebIdleMinutes, "10")}},
		selfAttested("21-8(七)3", "閒置就鎖或斷線",
			"應設定虛擬桌面在一段閒置時間後鎖定螢幕或中斷連線；閒置時間長度條文未給值，由機構訂定"),
		{ClauseNo: "21-8(七)1", Title: "兩端不能互相剪貼",
			Summary: "避免透過剪貼簿於兩端剪貼資料",
			Controls: []policyControlSeed{
				mustBe(PolicyClipboardSendEnabled, "false"),
				mustBe(PolicyClipboardRecvEnabled, "false"),
			}},
		{ClauseNo: "16-6", Title: "檔案外傳要管制",
			// 條文要的是「管制」而不是「一律關閉」，故不給值
			Summary: "應建立資料外洩防護機制，管制個人資料檔案之傳輸",
			Controls: []policyControlSeed{
				unspecified(PolicyFileUploadEnabled),
				unspecified(PolicyFileDownloadEnabled),
				unspecified(PolicyFileDeleteEnabled),
			}},
	}
}

// ePaymentIncidentClauses 事故通報。
func ePaymentIncidentClauses() []policyClauseSeed {
	return []policyClauseSeed{
		selfAttested("24-2", "事故要通報處理",
			"應建立資訊安全事故評估、通報、處理、應變及事後追蹤改善作業機制"),
		selfAttested("20-6", "高風險立即應變",
			"應隨時掌握資安事件，針對高風險或重要項目立即進行清查與應變"),
	}
}
