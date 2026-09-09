package policy

import (
	"sort"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 判定契約的測試。**受測對象是純函式**：輸入是設定鍵定義、現值與政策組的三張表，
// 輸出是每一（鍵，組）配對的結果。三處呈現都投影這一份輸出，故本檔的斷言即為
// 設定頁偏離數、合規對照頁與套用預覽共同的事實源。

const (
	testKeyPwdLen    = "test_pwd_len"
	testKeyLockout   = "test_lockout"
	testKeyClipboard = "test_clipboard"
	testKeyTransport = "test_transport"
	testKeyOrphan    = "test_orphan"
)

// testComplianceDefs 判定測試用的設定鍵定義：四種比較形態各一，加一個不被任何組
// 對照的鍵（未對照分母的被測對象）。
func testComplianceDefs() []PolicyDef {
	return []PolicyDef{
		{Key: testKeyPwdLen, Type: PolicyTypeInt, Direction: DirectionMin, Default: "12", Label: "密碼最小長度"},
		{Key: testKeyLockout, Type: PolicyTypeInt, Direction: DirectionMax, Default: "10",
			ZeroDisables: true, Label: "登入失敗鎖定次數上限"},
		{Key: testKeyClipboard, Type: PolicyTypeBool, Default: "true", Label: "允許剪貼簿送出"},
		{Key: testKeyTransport, Type: PolicyTypeEnum, Default: "off",
			EnumOrder: []string{"off", "warn", "strict"}, Label: "傳輸安全等級"},
		{Key: testKeyOrphan, Type: PolicyTypeInt, Direction: DirectionMin, Default: "5", Label: "無人對照的鍵"},
	}
}

func testGroup(code string, enabled bool) model.PolicyGroup {
	return model.PolicyGroup{
		Code: code, Name: code, Version: "1.0",
		Source: model.PolicyGroupSourceCustom, Enabled: enabled,
	}
}

func testClause(group, clauseNo, kind, removedIn string) model.PolicyClause {
	return model.PolicyClause{
		GroupCode: group, ClauseNo: clauseNo, Title: clauseNo,
		Kind: kind, RemovedInVersion: removedIn,
	}
}

func testControl(group, clauseNo, key, comparator, expected string, refOnly bool) model.PolicyClauseControl {
	return model.PolicyClauseControl{
		GroupCode: group, ClauseNo: clauseNo, PolicyKey: key,
		Comparator: comparator, ExpectedValue: expected, ReferenceOnly: refOnly,
	}
}

// resultsByPair 把判定攤平成 "鍵@組" → 結果，供逐案比對。
func resultsByPair(snap ComplianceSnapshot) map[string]string {
	out := map[string]string{}
	for _, v := range snap.Verdicts {
		key := v.Key + "@" + v.GroupCode
		out[key] = v.Result
	}
	return out
}

func TestBuildSnapshot(t *testing.T) {
	confirmedAt := time.Date(2026, 9, 1, 8, 30, 0, 0, time.UTC)

	cases := []struct {
		name         string
		groups       []model.PolicyGroup
		clauses      []model.PolicyClause
		controls     []model.PolicyClauseControl
		annotations  []model.PolicyClauseAnnotation
		values       map[string]string
		wantResults  map[string]string
		wantUnmapped []string
	}{
		{
			name:   "四種結果各出現一次",
			groups: []model.PolicyGroup{testGroup("g1", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1-1", model.PolicyClauseKindSetting, ""),
				testClause("g1", "1-2", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1-1", testKeyPwdLen, model.PolicyControlComparatorMin, "12", false),
				testControl("g1", "1-1", testKeyLockout, model.PolicyControlComparatorMax, "5", false),
				testControl("g1", "1-2", testKeyTransport, model.PolicyControlComparatorEquals, "warn", true),
			},
			values: map[string]string{
				testKeyPwdLen: "16", testKeyLockout: "10", testKeyTransport: "off",
				testKeyClipboard: "true", testKeyOrphan: "5",
			},
			wantResults: map[string]string{
				testKeyPwdLen + "@g1":    ComplianceResultCompliant,
				testKeyLockout + "@g1":   ComplianceResultDeviating,
				testKeyTransport + "@g1": ComplianceResultNeedsReview,
				testKeyClipboard + "@":   ComplianceResultUnmapped,
				testKeyOrphan + "@":      ComplianceResultUnmapped,
			},
			wantUnmapped: []string{testKeyClipboard, testKeyOrphan},
		},
		{
			name:   "同一個鍵在兩組有不同要求，各判各的",
			groups: []model.PolicyGroup{testGroup("g1", true), testGroup("g2", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1-1", model.PolicyClauseKindSetting, ""),
				testClause("g2", "2-1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1-1", testKeyPwdLen, model.PolicyControlComparatorMin, "12", false),
				testControl("g2", "2-1", testKeyPwdLen, model.PolicyControlComparatorMin, "20", false),
			},
			values: map[string]string{testKeyPwdLen: "16"},
			wantResults: map[string]string{
				testKeyPwdLen + "@g1":  ComplianceResultCompliant,
				testKeyPwdLen + "@g2":  ComplianceResultDeviating,
				testKeyLockout + "@":   ComplianceResultUnmapped,
				testKeyClipboard + "@": ComplianceResultUnmapped,
				testKeyTransport + "@": ComplianceResultUnmapped,
				testKeyOrphan + "@":    ComplianceResultUnmapped,
			},
			wantUnmapped: []string{testKeyLockout, testKeyClipboard, testKeyTransport, testKeyOrphan},
		},
		{
			name:   "未生效的組不參與判定",
			groups: []model.PolicyGroup{testGroup("g1", true), testGroup("g2", false)},
			clauses: []model.PolicyClause{
				testClause("g1", "1-1", model.PolicyClauseKindSetting, ""),
				testClause("g2", "2-1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1-1", testKeyPwdLen, model.PolicyControlComparatorMin, "12", false),
				testControl("g2", "2-1", testKeyLockout, model.PolicyControlComparatorMax, "5", false),
			},
			values: map[string]string{testKeyPwdLen: "16", testKeyLockout: "10"},
			wantResults: map[string]string{
				testKeyPwdLen + "@g1": ComplianceResultCompliant,
				// 只有未生效的組對照到它，等同沒有人對照
				testKeyLockout + "@":   ComplianceResultUnmapped,
				testKeyClipboard + "@": ComplianceResultUnmapped,
				testKeyTransport + "@": ComplianceResultUnmapped,
				testKeyOrphan + "@":    ComplianceResultUnmapped,
			},
			wantUnmapped: []string{testKeyLockout, testKeyClipboard, testKeyTransport, testKeyOrphan},
		},
		{
			name:   "已標記移除的條文不計入",
			groups: []model.PolicyGroup{testGroup("g1", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1-1", model.PolicyClauseKindSetting, ""),
				testClause("g1", "1-9", model.PolicyClauseKindSetting, "2.0"),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1-1", testKeyPwdLen, model.PolicyControlComparatorMin, "12", false),
				testControl("g1", "1-9", testKeyLockout, model.PolicyControlComparatorMax, "5", false),
			},
			values: map[string]string{testKeyPwdLen: "16", testKeyLockout: "10"},
			wantResults: map[string]string{
				testKeyPwdLen + "@g1": ComplianceResultCompliant,
				// 條文已於某版自規範消失：不判定，且不得被當成符合
				testKeyLockout + "@":   ComplianceResultUnmapped,
				testKeyClipboard + "@": ComplianceResultUnmapped,
				testKeyTransport + "@": ComplianceResultUnmapped,
				testKeyOrphan + "@":    ComplianceResultUnmapped,
			},
			wantUnmapped: []string{testKeyLockout, testKeyClipboard, testKeyTransport, testKeyOrphan},
		},
		{
			name:   "由機構自行確認的條文不產生鍵層判定",
			groups: []model.PolicyGroup{testGroup("g1", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1-1", model.PolicyClauseKindSelfAttested, ""),
			},
			// 資料上掛了控制也不判定：條文型別決定它不進鍵層判定
			controls: []model.PolicyClauseControl{
				testControl("g1", "1-1", testKeyPwdLen, model.PolicyControlComparatorMin, "12", false),
			},
			values: map[string]string{testKeyPwdLen: "8"},
			wantResults: map[string]string{
				testKeyPwdLen + "@":    ComplianceResultUnmapped,
				testKeyLockout + "@":   ComplianceResultUnmapped,
				testKeyClipboard + "@": ComplianceResultUnmapped,
				testKeyTransport + "@": ComplianceResultUnmapped,
				testKeyOrphan + "@":    ComplianceResultUnmapped,
			},
			wantUnmapped: []string{
				testKeyPwdLen, testKeyLockout, testKeyClipboard, testKeyTransport, testKeyOrphan,
			},
		},
		{
			// 條文涉及這個鍵但沒有給值（「使用足夠強度之加密」這類語境式要求）：
			// 系統不替條文發明一個門檻，連同目前值交給稽核人員判讀
			name:   "條文涉及但未定值：待稽核判讀，不計入符合或偏離",
			groups: []model.PolicyGroup{testGroup("g1", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1-3", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1-3", testKeyTransport, model.PolicyControlComparatorReview, "", false),
			},
			values: map[string]string{testKeyTransport: "warn"},
			wantResults: map[string]string{
				testKeyTransport + "@g1": ComplianceResultAuditReview,
				testKeyPwdLen + "@":      ComplianceResultUnmapped,
				testKeyLockout + "@":     ComplianceResultUnmapped,
				testKeyClipboard + "@":   ComplianceResultUnmapped,
				testKeyOrphan + "@":      ComplianceResultUnmapped,
			},
			wantUnmapped: []string{
				testKeyPwdLen, testKeyLockout, testKeyClipboard, testKeyOrphan,
			},
		},
		{
			name:   "參考值已由機構確認：仍是待人工確認，附確認資訊",
			groups: []model.PolicyGroup{testGroup("g1", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1-2", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1-2", testKeyTransport, model.PolicyControlComparatorEquals, "warn", true),
			},
			annotations: []model.PolicyClauseAnnotation{{
				GroupCode: "g1", ClauseNo: "1-2", Note: "已評估",
				ConfirmedBy: "admin", ConfirmedAt: &confirmedAt,
			}},
			values: map[string]string{testKeyTransport: "off"},
			wantResults: map[string]string{
				testKeyTransport + "@g1": ComplianceResultNeedsReview,
				testKeyPwdLen + "@":      ComplianceResultUnmapped,
				testKeyLockout + "@":     ComplianceResultUnmapped,
				testKeyClipboard + "@":   ComplianceResultUnmapped,
				testKeyOrphan + "@":      ComplianceResultUnmapped,
			},
			wantUnmapped: []string{
				testKeyPwdLen, testKeyLockout, testKeyClipboard, testKeyOrphan,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			snap := BuildSnapshot(testComplianceDefs(), c.values, nil,
				c.groups, c.clauses, c.controls, c.annotations)

			if got := resultsByPair(snap); !equalStringMap(got, c.wantResults) {
				t.Errorf("判定結果 = %v\nwant %v", got, c.wantResults)
			}
			if got := snap.UnmappedKeys; !equalStringSets(got, c.wantUnmapped) {
				t.Errorf("未對照鍵 = %v, want %v", got, c.wantUnmapped)
			}
			if snap.BuiltAt.IsZero() {
				t.Error("建構時點為零值：合規對照頁無從標示這份結果是何時算的")
			}
			if snap.KeyCount != len(testComplianceDefs()) {
				t.Errorf("涵蓋鍵數 = %d, want %d", snap.KeyCount, len(testComplianceDefs()))
			}
			// 分母規則：未對照的鍵不得被算成符合，也不得進偏離數的分母
			for _, key := range c.wantUnmapped {
				for _, v := range snap.Verdicts {
					if v.Key == key && v.Result == ComplianceResultCompliant {
						t.Errorf("%s 未被任何生效組對照，卻被判成符合", key)
					}
				}
			}
			// 每一種結果都要帶目前值：待稽核判讀靠它才判讀得出設定是否合理
			for _, v := range snap.Verdicts {
				if want := expectedCurrent(c.values, v.Key); v.Current != want {
					t.Errorf("%s 的目前值 = %q, want %q", v.Key, v.Current, want)
				}
			}
			// 逐組五格合計恆等於涵蓋鍵數（少一格或多算一格都會在這裡現形）
			for _, g := range c.groups {
				if !g.Enabled {
					continue
				}
				s := snap.GroupSummary(g.Code)
				total := s.Compliant + s.Deviating + s.NeedsReview + s.AuditReview + s.Unmapped
				if total != snap.KeyCount {
					t.Errorf("組 %s 的摘要合計 %d, want %d", g.Code, total, snap.KeyCount)
				}
			}
		})
	}

	t.Run("參考值的確認資訊隨判定帶出", func(t *testing.T) {
		confirmed := time.Date(2026, 9, 1, 8, 30, 0, 0, time.UTC)
		snap := BuildSnapshot(testComplianceDefs(),
			map[string]string{testKeyTransport: "off"}, nil,
			[]model.PolicyGroup{testGroup("g1", true)},
			[]model.PolicyClause{testClause("g1", "1-2", model.PolicyClauseKindSetting, "")},
			[]model.PolicyClauseControl{
				testControl("g1", "1-2", testKeyTransport, model.PolicyControlComparatorEquals, "warn", true),
			},
			[]model.PolicyClauseAnnotation{{
				GroupCode: "g1", ClauseNo: "1-2",
				ConfirmedBy: "admin", ConfirmedAt: &confirmed,
			}})

		var found bool
		for _, v := range snap.Verdicts {
			if v.Key != testKeyTransport {
				continue
			}
			found = true
			if v.ConfirmedBy != "admin" || v.ConfirmedAt == nil || !v.ConfirmedAt.Equal(confirmed) {
				t.Errorf("確認資訊未帶出: by=%q at=%v", v.ConfirmedBy, v.ConfirmedAt)
			}
			if v.Reason != ComplianceReasonReferenceConfirmed {
				t.Errorf("理由 = %q, want %q", v.Reason, ComplianceReasonReferenceConfirmed)
			}
			if v.ClauseNo != "1-2" {
				t.Errorf("條號 = %q, want 1-2（合規頁要以條文分組呈現）", v.ClauseNo)
			}
		}
		if !found {
			t.Fatal("參考值的鍵沒有判定")
		}
	})

	t.Run("系統內建保護的條文不產判定，另計一格", func(t *testing.T) {
		snap := BuildSnapshot(testComplianceDefs(),
			map[string]string{testKeyPwdLen: "12"}, nil,
			[]model.PolicyGroup{testGroup("g1", true)},
			[]model.PolicyClause{
				testClause("g1", "2-1", model.PolicyClauseKindBuiltinProtection, ""),
				testClause("g1", "2-2", model.PolicyClauseKindBuiltinProtection, ""),
				// 已自規範消失者不計入：那一條產品仍做，但它不再是誰的要求
				testClause("g1", "2-3", model.PolicyClauseKindBuiltinProtection, "2.0"),
				testClause("g1", "1-1", model.PolicyClauseKindSetting, ""),
			},
			[]model.PolicyClauseControl{
				// 資料異常的殘留：內建保護的條文不該掛得住要求，掛了也不得被判定讀走
				testControl("g1", "2-1", testKeyLockout, model.PolicyControlComparatorMax, "5", false),
				testControl("g1", "1-1", testKeyPwdLen, model.PolicyControlComparatorMin, "8", false),
			}, nil)

		summary := snap.GroupSummary("g1")
		if summary.BuiltinProtection != 2 {
			t.Errorf("系統內建保護條文數 = %d, want 2（已移除的那一條不計入）", summary.BuiltinProtection)
		}
		if got := verdictResult(snap, testKeyLockout, "g1"); got != "" {
			t.Errorf("內建保護條文上的殘留要求被判定讀走了, got %q", got)
		}
		if got := verdictResult(snap, testKeyPwdLen, "g1"); got != ComplianceResultCompliant {
			t.Errorf("同組的設定要求型條文仍應判定, got %q", got)
		}
		// 第六格的單位是條文，不進鍵層五格的合計
		keyCells := summary.Compliant + summary.Deviating + summary.NeedsReview +
			summary.AuditReview + summary.Unmapped
		if keyCells != snap.KeyCount {
			t.Errorf("鍵層五格合計 = %d, want %d（條文層計數不得混入）", keyCells, snap.KeyCount)
		}
	})

	t.Run("草稿覆蓋現值後重建", func(t *testing.T) {
		svc, repo, compliance := newComplianceStack(t)
		seedCustomClause(t, repo, "house_rule", PolicyPasswordMinLength,
			model.PolicyControlComparatorMin, "14")

		saved, err := compliance.Snapshot("", nil)
		if err != nil {
			t.Fatalf("讀取判定: %v", err)
		}
		if got := verdictResult(saved, PolicyPasswordMinLength, "house_rule"); got != ComplianceResultDeviating {
			t.Fatalf("出廠 12 對要求 14 應偏離, got %q", got)
		}
		if saved.Draft {
			t.Error("未帶草稿的判定不得標成草稿")
		}

		draft, err := compliance.Snapshot("", map[string]string{PolicyPasswordMinLength: "14"})
		if err != nil {
			t.Fatalf("讀取草稿判定: %v", err)
		}
		if got := verdictResult(draft, PolicyPasswordMinLength, "house_rule"); got != ComplianceResultCompliant {
			t.Errorf("草稿 14 對要求 14 應符合, got %q", got)
		}
		if !draft.Draft {
			t.Error("帶草稿的判定必須標示為草稿，否則與已儲存的結果無從區分")
		}
		// 已儲存的值不受草稿影響
		if got := svc.Get(PolicyPasswordMinLength); got != "12" {
			t.Errorf("草稿不得寫入現值, got %q", got)
		}
	})
}

// TestSnapshotFailsWhenPolicyValuesUnreadable 現值讀不到時判定與預覽都停止建構。
//
// 反例：吞掉讀取錯誤改以出廠預設建構，會產出一份帶著新建構時點、看起來完全正常
// 的判定——管理者收緊過的設定在畫面上變回出廠值，且沒有任何訊號說讀取失敗過。
// 執行期強制用的那一支（List）維持退回可用值，兩者的失效方向刻意相反。
func TestSnapshotFailsWhenPolicyValuesUnreadable(t *testing.T) {
	svc, repo, compliance := newComplianceStack(t)
	seedCustomClause(t, repo, "house_rule", PolicyPasswordMinLength,
		model.PolicyControlComparatorMin, "14")
	if err := svc.db.Migrator().DropTable(&model.SecurityPolicy{}); err != nil {
		t.Fatalf("移除政策表: %v", err)
	}

	if _, err := compliance.Snapshot("", nil); err == nil {
		t.Error("現值讀取失敗時 Snapshot 必須回錯，否則畫面會顯示一份以出廠預設算出的判定")
	}
	if _, err := compliance.Snapshot("", map[string]string{PolicyPasswordMinLength: "16"}); err == nil {
		t.Error("草稿判定同樣不得以出廠預設頂替讀不到的現值")
	}
	if _, err := compliance.PreviewApply([]string{PolicyPasswordMinLength},
		ApplyModeStrictest, "", nil); err == nil {
		t.Error("套用預覽必須回錯：以出廠預設算出的變動表會被填進表單")
	}
	if _, err := svc.ListWithError(); err == nil {
		t.Error("ListWithError 必須把讀取失敗回給呼叫端")
	}
	// 執行期強制路徑不受影響：讀不到時仍給得出一份可用的值
	views := svc.List()
	if len(views) == 0 {
		t.Fatal("List 在讀取失敗時仍應回全部設定鍵（強制執行不得因讀取失敗而停擺）")
	}
}

// 三處投影同一份判定：分區偏離數、合規頁摘要與套用預覽的鍵集合互相一致。
//
// 這是判定契約的核心不變式——三處各自算一份的話，管理者與稽核人員會在同一時點
// 看到不同的答案，而沒有任何一處會報錯。
func TestSnapshotProjectionsAgree(t *testing.T) {
	defs := testComplianceDefs()
	values := map[string]string{
		testKeyPwdLen:    "8",    // 對兩組都偏離
		testKeyLockout:   "0",    // 停用，偏離
		testKeyClipboard: "true", // 兩組要求相反 → 衝突
		testKeyTransport: "warn", // 符合
		testKeyOrphan:    "5",    // 未對照
	}
	groups := []model.PolicyGroup{testGroup("g1", true), testGroup("g2", true)}
	clauses := []model.PolicyClause{
		testClause("g1", "1-1", model.PolicyClauseKindSetting, ""),
		testClause("g2", "2-1", model.PolicyClauseKindSetting, ""),
	}
	controls := []model.PolicyClauseControl{
		testControl("g1", "1-1", testKeyPwdLen, model.PolicyControlComparatorMin, "12", false),
		testControl("g1", "1-1", testKeyLockout, model.PolicyControlComparatorMax, "5", false),
		testControl("g1", "1-1", testKeyClipboard, model.PolicyControlComparatorEquals, "false", false),
		testControl("g1", "1-1", testKeyTransport, model.PolicyControlComparatorEquals, "warn", false),
		testControl("g2", "2-1", testKeyPwdLen, model.PolicyControlComparatorMin, "20", false),
		testControl("g2", "2-1", testKeyClipboard, model.PolicyControlComparatorEquals, "true", false),
		// 零值上界：g2 要求關閉、g1 要求至多 5（在這個鍵上隱含必須開著）。
		// 兩者沒有交集，而現值 0 只符合其中一條——判定說偏離，預覽就必須
		// 在變動或衝突裡看得到它
		testControl("g2", "2-1", testKeyLockout, model.PolicyControlComparatorMax, "0", false),
	}

	snap := BuildSnapshot(defs, values, nil, groups, clauses, controls, nil)
	scope := []string{testKeyPwdLen, testKeyLockout, testKeyClipboard, testKeyTransport, testKeyOrphan}

	// 投影一：設定頁分區偏離數
	sectionKeys := snap.DeviatingKeys(scope)
	if snap.DeviationCount(scope) != len(sectionKeys) {
		t.Fatalf("偏離數 %d 與偏離鍵數 %d 不一致", snap.DeviationCount(scope), len(sectionKeys))
	}

	// 投影二：合規對照頁摘要（逐組）
	summaryKeys := map[string]bool{}
	totalDeviating := 0
	for _, g := range groups {
		s := snap.GroupSummary(g.Code)
		totalDeviating += s.Deviating
		total := s.Compliant + s.Deviating + s.NeedsReview + s.AuditReview + s.Unmapped
		if total != snap.KeyCount {
			t.Errorf("組 %s 的五格摘要合計 %d，與涵蓋鍵數 %d 不符（有鍵被漏算或重複算）",
				g.Code, total, snap.KeyCount)
		}
	}
	for _, v := range snap.Verdicts {
		if v.Result == ComplianceResultDeviating {
			summaryKeys[v.Key] = true
		}
	}
	if len(summaryKeys) != len(sectionKeys) {
		t.Errorf("摘要偏離鍵集合 %v 與分區偏離鍵 %v 不一致", summaryKeys, sectionKeys)
	}
	if totalDeviating <= len(summaryKeys) {
		t.Fatalf("本案應有鍵同時偏離兩組（逐組合計 %d 應大於去重後 %d），案例失去鑑別力",
			totalDeviating, len(summaryKeys))
	}

	// 投影三：套用預覽
	preview := buildApplyPreview(defs, values, snap, scope, ApplyModeStrictest, "")
	previewKeys := map[string]bool{}
	for _, c := range preview.Changes {
		previewKeys[c.Key] = true
	}
	for _, c := range preview.Conflicts {
		previewKeys[c.Key] = true
	}
	if len(previewKeys) != len(summaryKeys) {
		t.Errorf("預覽觸及的鍵 %v 與偏離鍵 %v 不一致", previewKeys, summaryKeys)
	}
	for key := range summaryKeys {
		if !previewKeys[key] {
			t.Errorf("%s 判定為偏離，卻不在預覽的變動或衝突清單內", key)
		}
	}
	if len(preview.Conflicts) == 0 {
		t.Fatal("本案應含衝突鍵，否則「變動加衝突等於偏離」這個等式沒有被驗到")
	}
	// 底部兩個計數與清單合起來必須涵蓋範圍內每一個鍵
	total := len(preview.Changes) + len(preview.Conflicts) + preview.UnchangedCount + preview.UnmappedCount
	if total != len(scope) {
		t.Errorf("變動 %d ＋衝突 %d ＋不變動 %d ＋未對照 %d = %d, want %d（範圍內有鍵沒有去處）",
			len(preview.Changes), len(preview.Conflicts), preview.UnchangedCount,
			preview.UnmappedCount, total, len(scope))
	}
}

// ---- 測試助手 ----

// newComplianceStack 一個 sqlite 記憶體庫上的政策服務、政策組資料存取與合規服務。
func newComplianceStack(t *testing.T) (*SecurityPolicyService, *PolicyGroupRepository, *ComplianceService) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// :memory: 連線池陷阱：多條連線各自是一個空庫
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })

	if err := db.AutoMigrate(&model.SecurityPolicy{}, &model.PolicyGroup{},
		&model.PolicyClause{}, &model.PolicyClauseControl{},
		&model.PolicyClauseAnnotation{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	svc := NewSecurityPolicyService(db)
	repo := NewPolicyGroupRepository(db)
	return svc, repo, NewComplianceService(svc, repo)
}

// seedCustomClause 建一個自建組並掛一條帶單一要求的條文。
func seedCustomClause(t *testing.T, repo *PolicyGroupRepository, group, key, comparator, expected string) {
	t.Helper()
	if err := repo.CreateCustomGroup(group, group, "zh-TW"); err != nil {
		t.Fatalf("建組: %v", err)
	}
	_, _, err := repo.UpsertCustomClause(
		model.PolicyClause{GroupCode: group, ClauseNo: "1", Title: "條文", Kind: model.PolicyClauseKindSetting},
		[]model.PolicyClauseControl{{PolicyKey: key, Comparator: comparator, ExpectedValue: expected}})
	if err != nil {
		t.Fatalf("寫入條文: %v", err)
	}
}

// expectedCurrent 該鍵在判定裡應該帶的目前值（測試未給值者為出廠預設）。
func expectedCurrent(values map[string]string, key string) string {
	if v, ok := values[key]; ok {
		return v
	}
	for _, def := range testComplianceDefs() {
		if def.Key == key {
			return def.Default
		}
	}
	return ""
}

// verdictResult 取某（鍵，組）的判定結果；沒有判定回空字串。
func verdictResult(snap ComplianceSnapshot, key, group string) string {
	for _, v := range snap.Verdicts {
		if v.Key == key && v.GroupCode == group {
			return v.Result
		}
	}
	return ""
}

func equalStringMap(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func equalStringSets(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	a := append([]string(nil), got...)
	b := append([]string(nil), want...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestBuildSnapshotCarriesLastChange 判定結果每一筆都帶該鍵的最後變更。
//
// 缺了這兩個欄位，「這個設定何時被誰改的」就只剩管理端的設定列表答得出來，
// 而稽核角色讀不到那一支——追證的第二步在稽核視角下會斷在半路。
func TestBuildSnapshotCarriesLastChange(t *testing.T) {
	changedAt := time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC)
	changes := map[string]PolicyKeyChange{
		testKeyPwdLen:  {UpdatedBy: "admin", UpdatedAt: &changedAt},
		testKeyOrphan:  {UpdatedBy: "operator", UpdatedAt: &changedAt},
		testKeyLockout: {},
	}
	snap := BuildSnapshot(testComplianceDefs(),
		map[string]string{testKeyPwdLen: "8", testKeyLockout: "10"}, changes,
		[]model.PolicyGroup{testGroup("g1", true)},
		[]model.PolicyClause{testClause("g1", "1-1", model.PolicyClauseKindSetting, "")},
		[]model.PolicyClauseControl{
			testControl("g1", "1-1", testKeyPwdLen, model.PolicyControlComparatorMin, "12", false),
			testControl("g1", "1-1", testKeyLockout, model.PolicyControlComparatorMax, "5", false),
		}, nil)

	byKey := map[string]Verdict{}
	for _, v := range snap.Verdicts {
		byKey[v.Key] = v
	}

	// 被對照的鍵（判成偏離）帶得出時戳與操作者
	pwd := byKey[testKeyPwdLen]
	if pwd.Result != ComplianceResultDeviating {
		t.Fatalf("前提不成立：密碼長度應判偏離，got %q", pwd.Result)
	}
	if pwd.UpdatedBy != "admin" {
		t.Errorf("操作者 = %q, want admin", pwd.UpdatedBy)
	}
	if pwd.UpdatedAt == nil || !pwd.UpdatedAt.Equal(changedAt) {
		t.Errorf("最後變更時戳 = %v, want %v", pwd.UpdatedAt, changedAt)
	}

	// 未對照的鍵同樣要帶：追證問的是「這個設定誰改的」，與判定結果無關
	orphan := byKey[testKeyOrphan]
	if orphan.Result != ComplianceResultUnmapped {
		t.Fatalf("前提不成立：無人對照的鍵應判未對照，got %q", orphan.Result)
	}
	if orphan.UpdatedBy != "operator" || orphan.UpdatedAt == nil {
		t.Errorf("未對照的鍵沒帶最後變更: by=%q at=%v", orphan.UpdatedBy, orphan.UpdatedAt)
	}

	// 從未被改過的鍵兩者皆空：不得憑空生一個時戳，否則畫面會顯示一筆不存在的變更
	lockout := byKey[testKeyLockout]
	if lockout.UpdatedBy != "" || lockout.UpdatedAt != nil {
		t.Errorf("沒有變更記錄的鍵不得帶最後變更: by=%q at=%v",
			lockout.UpdatedBy, lockout.UpdatedAt)
	}
	// 判定沒收到任何變更資料時，全部的鍵都空
	bare := BuildSnapshot(testComplianceDefs(), map[string]string{}, nil,
		[]model.PolicyGroup{testGroup("g1", true)}, nil, nil, nil)
	for _, v := range bare.Verdicts {
		if v.UpdatedBy != "" || v.UpdatedAt != nil {
			t.Errorf("%s 無變更資料卻帶了最後變更: by=%q at=%v", v.Key, v.UpdatedBy, v.UpdatedAt)
		}
	}
}
