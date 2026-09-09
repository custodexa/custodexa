package policy

import "github.com/custodexa/backend/internal/model"

// PCI DSS 4.0.1 內建組的種子內容。
//
// 條號、標題與每一筆要求值都寫在這裡。標題是同一條號下那組設定的人話說法，
// 供不熟悉條號的讀者辨識；同一條號下有多個設定鍵時合併為一條條文、多筆要求。
//
// **兩個設定鍵刻意不在本組內**：申請時長上限與申請待審超時時限帶有建議值卻沒有
// 條號。沒有條號就沒有可追的出處，把它們掛進本組等於替它們發明一個法源。這是
// 顯式排除，不是漏列——種子測試對這兩個鍵有具名斷言。
//
// **六個傳輸強制等級是未定值**：4.2.1 要求的是「強加密」，而不是本產品三段
// 枚舉裡的某一段。寫死其中一段會有兩個後果：已經設到更嚴一段的部署被判偏離，
// 而「一次滿足所有政策」會建議把它降回來。改以未定值呈現，附目前值由稽核判讀。

// pciGroupCode PCI 組的組代號（對外引用的識別，不隨顯示名稱變動）
const pciGroupCode = "pci_dss_4_0_1"

// pciPolicyGroupSeed PCI 組的種子。
func pciPolicyGroupSeed() policyGroupSeed {
	return policyGroupSeed{
		Code:    pciGroupCode,
		Name:    "PCI DSS 4.0.1",
		Version: "4.0.1",
		Clauses: []policyClauseSeed{
			{ClauseNo: "8.3.4", Title: "登入鎖定機制",
				Controls: []policyControlSeed{
					atMost(PolicyLockoutMaxAttempts, "10"),
					atLeast(PolicyLockoutDurationMinutes, "30"),
				}},
			{ClauseNo: "8.3.6", Title: "密碼複雜度",
				Controls: []policyControlSeed{
					atLeast(PolicyPasswordMinLength, "12"),
					mustBe(PolicyPasswordRequireAlnum, "true"),
				}},
			{ClauseNo: "8.3.7", Title: "密碼歷史限制",
				Controls: []policyControlSeed{atLeast(PolicyPasswordHistoryCount, "4")}},
			{ClauseNo: "8.3.9", Title: "密碼到期",
				Controls: []policyControlSeed{atMost(PolicyPasswordMaxAgeDays, "90")}},
			{ClauseNo: "8.6.3", Title: "資產憑證輪替",
				Controls: []policyControlSeed{asReference(atMost(PolicyAssetSecretMaxAgeDays, "90"))}},
			{ClauseNo: "8.3.5", Title: "重設後強制改密",
				Controls: []policyControlSeed{mustBe(PolicyForceChangeOnReset, "true")}},
			{ClauseNo: "8.4.2", Title: "多因子驗證範圍",
				Controls: []policyControlSeed{mustBe(PolicyMFARequired, MFARequiredAll)}},
			{ClauseNo: "8.2.8", Title: "連線閒置逾時",
				Controls: []policyControlSeed{
					atMost(PolicyWebIdleMinutes, "15"),
					atMost(PolicySessionIdleMinutes, "15"),
				}},
			{ClauseNo: "8.2.6", Title: "閒置帳號停用",
				Controls: []policyControlSeed{atMost(PolicyInactiveDisableDays, "90")}},
			{ClauseNo: "10.5.1", Title: "稽核資料保留",
				Controls: []policyControlSeed{
					atLeast(PolicyRetentionAuditLogDays, "365"),
					atLeast(PolicyRetentionSessionCommandDays, "365"),
					atLeast(PolicyRetentionAlertDays, "365"),
					atLeast(PolicyRetentionRecordingDays, "365"),
				}},
			{ClauseNo: "10.4.1", Title: "每日審閱簽核",
				Controls: []policyControlSeed{mustBe(PolicyDailyReviewEnabled, "true")}},
			{ClauseNo: "10.7.2", Title: "稽核失效告警",
				Controls: []policyControlSeed{mustBe(PolicyFailureAlertEnabled, "true")}},
			{ClauseNo: "10.2", Title: "錄影失敗擋連線",
				Controls: []policyControlSeed{mustBe(PolicyRecordingFailCloseEnabled, "true")}},
			{ClauseNo: "3.7.4", Title: "金鑰輪替提醒",
				Controls: []policyControlSeed{atMost(PolicyKeyCryptoperiodReminderDays, "365")}},
			{ClauseNo: "4.2.1", Title: "傳輸加密強制等級",
				Controls: []policyControlSeed{
					unspecified(PolicyTransportRDPLevel),
					unspecified(PolicyTransportVNCLevel),
					unspecified(PolicyTransportDBLevel),
					unspecified(PolicyTransportLDAPLevel),
					unspecified(PolicyTransportSyslogLevel),
					unspecified(PolicyTransportNotifyLevel),
				}},
			{ClauseNo: "7.2", Title: "存取控制與破窗",
				Controls: []policyControlSeed{
					mustBe(PolicyAccessPolicyDefault, model.AccessPolicyApproval),
					mustBe(PolicyBreakGlassEnabled, "false"),
					atMost(PolicyBreakGlassDurationMinutes, "60"),
					atMost(PolicyBreakGlassReviewTimeoutHours, "24"),
					mustBe(PolicyAccessRevokeDisconnect, "true"),
				}},
		},
	}
}
