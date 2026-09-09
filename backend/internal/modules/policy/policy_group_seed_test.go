package policy

import (
	"fmt"
	"sort"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 內建種子的四件事：每一筆要求都指得到一個型別相容的設定鍵、與設定鍵定義的規範
// 欄位只在具名的幾格上刻意不同、兩組的分母不會被無聲改動、重複啟動冪等且升級
// 移除條文不動機構備註。

// seedExpectation 一筆種子控制的可比較投影。
type seedExpectation struct {
	ClauseNo      string
	Comparator    string
	ExpectedValue string
	ReferenceOnly bool
}

// controlsByKey 把某組的控制投影成「設定鍵 → 期望」。
func controlsByKey(t *testing.T, db *gorm.DB, groupCode string) map[string]seedExpectation {
	t.Helper()
	var rows []model.PolicyClauseControl
	if err := db.Where("group_code = ?", groupCode).Find(&rows).Error; err != nil {
		t.Fatalf("讀取 %s 的條文要求: %v", groupCode, err)
	}
	out := make(map[string]seedExpectation, len(rows))
	for _, r := range rows {
		if _, dup := out[r.PolicyKey]; dup {
			t.Fatalf("組 %s 對設定鍵 %s 有兩筆要求：唯一索引沒有生效", groupCode, r.PolicyKey)
		}
		out[r.PolicyKey] = seedExpectation{
			ClauseNo: r.ClauseNo, Comparator: r.Comparator,
			ExpectedValue: r.ExpectedValue, ReferenceOnly: r.ReferenceOnly,
		}
	}
	return out
}

// clausesByNo 把某組的條文投影成「條號 → 條文」。
func clausesByNo(t *testing.T, db *gorm.DB, groupCode string) map[string]model.PolicyClause {
	t.Helper()
	var rows []model.PolicyClause
	if err := db.Where("group_code = ?", groupCode).Find(&rows).Error; err != nil {
		t.Fatalf("讀取 %s 的條文: %v", groupCode, err)
	}
	out := make(map[string]model.PolicyClause, len(rows))
	for _, r := range rows {
		out[r.ClauseNo] = r
	}
	return out
}

// seedControlLiterals 兩個內建組每一筆要求的字面量副本，鍵為「組代號|設定鍵」，
// 值為「條號 比較方式 要求值 參考值旗標」。
//
// **這是機器可檢的權威副本**：種子的內容就是合規報告的內容，少一條、多一條或
// 值被改一格，畫面上不會有任何異狀。多一筆或少一筆都會紅——沒有列在這裡的要求
// 是漂移，不是決定。
func seedControlLiterals() map[string]string {
	return map[string]string{
		// PCI DSS 4.0.1
		pciGroupCode + "|" + PolicyAccessPolicyDefault:          "7.2 equals \"approval\" ref=false",
		pciGroupCode + "|" + PolicyAccessRevokeDisconnect:       "7.2 equals \"true\" ref=false",
		pciGroupCode + "|" + PolicyAssetSecretMaxAgeDays:        "8.6.3 max \"90\" ref=true",
		pciGroupCode + "|" + PolicyBreakGlassDurationMinutes:    "7.2 max \"60\" ref=false",
		pciGroupCode + "|" + PolicyBreakGlassEnabled:            "7.2 equals \"false\" ref=false",
		pciGroupCode + "|" + PolicyBreakGlassReviewTimeoutHours: "7.2 max \"24\" ref=false",
		pciGroupCode + "|" + PolicyDailyReviewEnabled:           "10.4.1 equals \"true\" ref=false",
		pciGroupCode + "|" + PolicyFailureAlertEnabled:          "10.7.2 equals \"true\" ref=false",
		pciGroupCode + "|" + PolicyForceChangeOnReset:           "8.3.5 equals \"true\" ref=false",
		pciGroupCode + "|" + PolicyInactiveDisableDays:          "8.2.6 max \"90\" ref=false",
		pciGroupCode + "|" + PolicyKeyCryptoperiodReminderDays:  "3.7.4 max \"365\" ref=false",
		pciGroupCode + "|" + PolicyLockoutDurationMinutes:       "8.3.4 min \"30\" ref=false",
		pciGroupCode + "|" + PolicyLockoutMaxAttempts:           "8.3.4 max \"10\" ref=false",
		pciGroupCode + "|" + PolicyMFARequired:                  "8.4.2 equals \"all\" ref=false",
		pciGroupCode + "|" + PolicyPasswordHistoryCount:         "8.3.7 min \"4\" ref=false",
		pciGroupCode + "|" + PolicyPasswordMaxAgeDays:           "8.3.9 max \"90\" ref=false",
		pciGroupCode + "|" + PolicyPasswordMinLength:            "8.3.6 min \"12\" ref=false",
		pciGroupCode + "|" + PolicyPasswordRequireAlnum:         "8.3.6 equals \"true\" ref=false",
		pciGroupCode + "|" + PolicyRecordingFailCloseEnabled:    "10.2 equals \"true\" ref=false",
		pciGroupCode + "|" + PolicyRetentionAlertDays:           "10.5.1 min \"365\" ref=false",
		pciGroupCode + "|" + PolicyRetentionAuditLogDays:        "10.5.1 min \"365\" ref=false",
		pciGroupCode + "|" + PolicyRetentionRecordingDays:       "10.5.1 min \"365\" ref=false",
		pciGroupCode + "|" + PolicyRetentionSessionCommandDays:  "10.5.1 min \"365\" ref=false",
		pciGroupCode + "|" + PolicySessionIdleMinutes:           "8.2.8 max \"15\" ref=false",
		pciGroupCode + "|" + PolicyTransportDBLevel:             "4.2.1 review \"\" ref=false",
		pciGroupCode + "|" + PolicyTransportLDAPLevel:           "4.2.1 review \"\" ref=false",
		pciGroupCode + "|" + PolicyTransportNotifyLevel:         "4.2.1 review \"\" ref=false",
		pciGroupCode + "|" + PolicyTransportRDPLevel:            "4.2.1 review \"\" ref=false",
		pciGroupCode + "|" + PolicyTransportSyslogLevel:         "4.2.1 review \"\" ref=false",
		pciGroupCode + "|" + PolicyTransportVNCLevel:            "4.2.1 review \"\" ref=false",
		pciGroupCode + "|" + PolicyWebIdleMinutes:               "8.2.8 max \"15\" ref=false",
		// 支付基準組
		ePaymentGroupCode + "|" + PolicyAccessPolicyDefault:         "15-3(三) equals \"approval\" ref=false",
		ePaymentGroupCode + "|" + PolicyAccessRevokeDisconnect:      "15-2 review \"\" ref=false",
		ePaymentGroupCode + "|" + PolicyAssetSecretMaxAgeDays:       "15-8 max \"90\" ref=false",
		ePaymentGroupCode + "|" + PolicyClipboardRecvEnabled:        "21-8(七)1 equals \"false\" ref=false",
		ePaymentGroupCode + "|" + PolicyClipboardSendEnabled:        "21-8(七)1 equals \"false\" ref=false",
		ePaymentGroupCode + "|" + PolicyDailyReviewEnabled:          "15-3(三) equals \"true\" ref=false",
		ePaymentGroupCode + "|" + PolicyFailureAlertEnabled:         "24-1 equals \"true\" ref=false",
		ePaymentGroupCode + "|" + PolicyFileDeleteEnabled:           "16-6 review \"\" ref=false",
		ePaymentGroupCode + "|" + PolicyFileDownloadEnabled:         "16-6 review \"\" ref=false",
		ePaymentGroupCode + "|" + PolicyFileUploadEnabled:           "16-6 review \"\" ref=false",
		ePaymentGroupCode + "|" + PolicyForceChangeOnReset:          "4-7(七) equals \"true\" ref=false",
		ePaymentGroupCode + "|" + PolicyLockoutMaxAttempts:          "4-7(五) max \"5\" ref=false",
		ePaymentGroupCode + "|" + PolicyMFARequired:                 "15-3(四) equals \"all\" ref=false",
		ePaymentGroupCode + "|" + PolicyPasswordHistoryCount:        "4-7(六) min \"1\" ref=false",
		ePaymentGroupCode + "|" + PolicyPasswordMaxAgeDays:          "15-8 max \"90\" ref=false",
		ePaymentGroupCode + "|" + PolicyPasswordMinLength:           "4-7(一) min \"6\" ref=false",
		ePaymentGroupCode + "|" + PolicyPasswordRequireAlnum:        "4-7(二) equals \"true\" ref=true",
		ePaymentGroupCode + "|" + PolicyRetentionAlertDays:          "24-1 min \"730\" ref=false",
		ePaymentGroupCode + "|" + PolicyRetentionAuditLogDays:       "24-1 min \"730\" ref=false",
		ePaymentGroupCode + "|" + PolicyRetentionRecordingDays:      "24-1 min \"730\" ref=false",
		ePaymentGroupCode + "|" + PolicyRetentionSessionCommandDays: "24-1 min \"730\" ref=false",
		ePaymentGroupCode + "|" + PolicyTransportDBLevel:            "21-6 review \"\" ref=false",
		ePaymentGroupCode + "|" + PolicyTransportLDAPLevel:          "17-1(二) review \"\" ref=false",
		ePaymentGroupCode + "|" + PolicyTransportNotifyLevel:        "17-1(二) review \"\" ref=false",
		ePaymentGroupCode + "|" + PolicyTransportRDPLevel:           "21-6 review \"\" ref=false",
		ePaymentGroupCode + "|" + PolicyTransportSyslogLevel:        "17-1(二) review \"\" ref=false",
		ePaymentGroupCode + "|" + PolicyTransportVNCLevel:           "21-6 review \"\" ref=false",
		ePaymentGroupCode + "|" + PolicyWebIdleMinutes:              "15-5 max \"10\" ref=false",
	}
}

// seedControlLiteral 一筆要求的可比較字面量。
func seedControlLiteral(exp seedExpectation) string {
	return fmt.Sprintf("%s %s %q ref=%v",
		exp.ClauseNo, exp.Comparator, exp.ExpectedValue, exp.ReferenceOnly)
}

// builtinSeedRequirements 兩個內建組對某個設定鍵的要求（組代號 → 要求）。
// 沒有任何一組對照該鍵時回空 map。
func builtinSeedRequirements(t *testing.T, key string) map[string]seedControl {
	t.Helper()
	out := map[string]seedControl{}
	for _, seed := range builtinPolicyGroupSeeds() {
		controls, err := buildSeedControls(seed)
		if err != nil {
			t.Fatalf("組 %s 的種子建不出來: %v", seed.Code, err)
		}
		for _, c := range controls {
			if c.PolicyKey == key {
				out[seed.Code] = c
			}
		}
	}
	return out
}

// TestPolicyGroupSeedMatchesPolicyDefs 種子與設定鍵定義的關係。
//
// 種子已自帶要求值，兩者不再是同一份資料的兩個副本；仍要比對，是因為設定鍵定義
// 上的規範欄位在被淘汰前仍有兩條讀路徑（既有的偏離計數走它、合規頁走種子），
// 兩邊無聲漂開時畫面上會出現兩個都說得通卻不一致的數字。
func TestPolicyGroupSeedMatchesPolicyDefs(t *testing.T) {
	db := newPolicyGroupSeedDB(t)
	if err := SeedBuiltinPolicyGroups(db); err != nil {
		t.Fatalf("種子寫入: %v", err)
	}

	t.Run("每一筆要求都指得到型別相容的設定鍵", func(t *testing.T) {
		for _, seed := range builtinPolicyGroupSeeds() {
			got := controlsByKey(t, db, seed.Code)
			clauses := clausesByNo(t, db, seed.Code)
			for key, exp := range got {
				def := findDef(key)
				if def == nil {
					t.Errorf("組 %s 收了未定義的設定鍵 %s", seed.Code, key)
					continue
				}
				if err := assertComparatorFitsType(def, exp.Comparator); err != nil {
					t.Errorf("組 %s 的設定鍵 %s: %v", seed.Code, key, err)
				}
				if exp.Comparator == model.PolicyControlComparatorReview {
					if exp.ExpectedValue != "" {
						t.Errorf("組 %s 的設定鍵 %s 宣告未定值卻帶值 %q",
							seed.Code, key, exp.ExpectedValue)
					}
				} else if err := validatePolicyValue(def, exp.ExpectedValue); err != nil {
					t.Errorf("組 %s 對設定鍵 %s 的要求值 %q 不在合法值域: %v",
						seed.Code, key, exp.ExpectedValue, err)
				}
				clause, ok := clauses[exp.ClauseNo]
				if !ok {
					t.Errorf("組 %s 的設定鍵 %s 掛在不存在的條文 %s", seed.Code, key, exp.ClauseNo)
					continue
				}
				if clause.Kind != model.PolicyClauseKindSetting {
					t.Errorf("組 %s 的條文 %s 型別為 %s，卻掛了設定要求",
						seed.Code, exp.ClauseNo, clause.Kind)
				}
			}
		}
	})

	t.Run("每一筆要求逐格對上字面量表", func(t *testing.T) {
		want := seedControlLiterals()
		got := map[string]string{}
		for _, seed := range builtinPolicyGroupSeeds() {
			for key, exp := range controlsByKey(t, db, seed.Code) {
				got[seed.Code+"|"+key] = seedControlLiteral(exp)
			}
		}
		for k, v := range got {
			switch w, listed := want[k]; {
			case !listed:
				t.Errorf("%s 的要求 %s 不在字面量表裡——新增要求須有意識地同步本表", k, v)
			case w != v:
				t.Errorf("%s 的要求 = %s, want %s", k, v, w)
			}
		}
		for k, w := range want {
			if _, in := got[k]; !in {
				t.Errorf("字面量表列了 %s（%s），但種子裡沒有這一筆：要求被刪掉了", k, w)
			}
		}
	})

	t.Run("找不到條文出處的鍵不進 PCI 組", func(t *testing.T) {
		// 顯式排除而非靜默略過：這兩個鍵是產品自訂的存取時窗旋鈕，PCI 沒有對應
		// 條文。哪天有人替它們找到出處而想納入，本斷言會紅並要求有人重新決定
		got := controlsByKey(t, db, pciGroupCode)
		for _, key := range []string{
			PolicyAccessRequestMaxDurationMinutes,
			PolicyAccessRequestPendingTimeoutHours,
		} {
			if findDef(key) == nil {
				t.Fatalf("設定鍵 %s 不存在", key)
			}
			if _, in := got[key]; in {
				t.Errorf("%s 出現在內建組裡，但它沒有條文出處——等於替它發明一個出處", key)
			}
		}
	})

	t.Run("PCI 組的分母", func(t *testing.T) {
		assertSeedShape(t, db, pciGroupCode, seedShape{
			Clauses:       map[string]int{model.PolicyClauseKindSetting: 16},
			Comparators:   map[string]int{"min": 7, "max": 9, "equals": 9, "review": 6},
			ReferenceOnly: 1,
		})
	})

	t.Run("電支組的分母", func(t *testing.T) {
		assertSeedShape(t, db, ePaymentGroupCode, seedShape{
			Clauses: map[string]int{
				model.PolicyClauseKindSetting:           15,
				model.PolicyClauseKindSelfAttested:      11,
				model.PolicyClauseKindBuiltinProtection: 14,
			},
			Comparators:   map[string]int{"min": 6, "max": 4, "equals": 8, "review": 10},
			ReferenceOnly: 1,
		})
	})

	t.Run("兩組皆為內建且出廠生效", func(t *testing.T) {
		for _, code := range []string{pciGroupCode, ePaymentGroupCode} {
			var g model.PolicyGroup
			if err := db.Where("code = ?", code).First(&g).Error; err != nil {
				t.Fatalf("讀取組 %s: %v", code, err)
			}
			if g.Source != model.PolicyGroupSourceBuiltin {
				t.Errorf("組 %s 的來源 = %s, want %s", code, g.Source, model.PolicyGroupSourceBuiltin)
			}
			if !g.Enabled {
				t.Errorf("組 %s 出廠應為生效", code)
			}
			if g.Version == "" {
				t.Errorf("組 %s 缺內容版本：條文被移除時沒有版本可標", code)
			}
		}
	})
}

// seedShape 一個內建組落庫後的形狀：條文依型別、控制依比較方式、參考值筆數。
type seedShape struct {
	Clauses       map[string]int
	Comparators   map[string]int
	ReferenceOnly int
}

// assertSeedShape 分母釘住。數字變動時必須是有意識的同步——內建組的條文與要求
// 是合規報告的內容，少一條沒有人會在畫面上看見。
func assertSeedShape(t *testing.T, db *gorm.DB, groupCode string, want seedShape) {
	t.Helper()

	gotClauses := map[string]int{}
	for _, c := range clausesByNo(t, db, groupCode) {
		if c.RemovedInVersion != "" {
			t.Errorf("組 %s 的條文 %s 一落庫就被標為已移除", groupCode, c.ClauseNo)
		}
		gotClauses[c.Kind]++
	}
	assertCountsEqual(t, groupCode+" 的條文依型別", want.Clauses, gotClauses)

	controls := controlsByKey(t, db, groupCode)
	gotComparators := map[string]int{}
	referenceOnly := 0
	for _, exp := range controls {
		gotComparators[exp.Comparator]++
		if exp.ReferenceOnly {
			referenceOnly++
		}
	}
	assertCountsEqual(t, groupCode+" 的控制依比較方式", want.Comparators, gotComparators)
	if referenceOnly != want.ReferenceOnly {
		t.Errorf("組 %s 標為參考值的要求數 = %d, want %d", groupCode, referenceOnly, want.ReferenceOnly)
	}
}

func assertCountsEqual(t *testing.T, label string, want, got map[string]int) {
	t.Helper()
	if fmtCounts(want) != fmtCounts(got) {
		t.Errorf("%s = %s, want %s", label, fmtCounts(got), fmtCounts(want))
	}
}

// fmtCounts 依鍵排序的可比較字串（map 的列印順序不穩定，直接比字串才讀得出差在哪）。
func fmtCounts(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k, v := range counts {
		if v != 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := ""
	for _, k := range keys {
		out += fmt.Sprintf("%s=%d ", k, counts[k])
	}
	return out
}

// TestPolicyGroupSeedIsIdempotent 重複啟動不改變結果，也不改機構決定的生效狀態。
func TestPolicyGroupSeedIsIdempotent(t *testing.T) {
	db := newPolicyGroupSeedDB(t)
	if err := SeedBuiltinPolicyGroups(db); err != nil {
		t.Fatalf("第一次種子: %v", err)
	}
	firstClauses := snapshotClauses(t, db)
	firstControls := controlsByKey(t, db, pciGroupCode)

	// 機構把電支組關掉，並在一條 PCI 條文上留了備註
	repo := NewPolicyGroupRepository(db)
	if err := repo.SetGroupEnabled(ePaymentGroupCode, false); err != nil {
		t.Fatalf("關閉電支組: %v", err)
	}
	if err := repo.UpsertAnnotation(pciGroupCode, "8.3.4", "本行以三次為準"); err != nil {
		t.Fatalf("寫備註: %v", err)
	}

	if err := SeedBuiltinPolicyGroups(db); err != nil {
		t.Fatalf("第二次種子: %v", err)
	}

	if got := snapshotClauses(t, db); !equalClauseSnapshots(firstClauses, got) {
		t.Errorf("重複啟動改變了條文集合\n  第一次 %v\n  第二次 %v", firstClauses, got)
	}
	if got := controlsByKey(t, db, pciGroupCode); len(got) != len(firstControls) {
		t.Errorf("重複啟動後 PCI 組的要求數 = %d, want %d", len(got), len(firstControls))
	} else {
		for key, want := range firstControls {
			if got[key] != want {
				t.Errorf("重複啟動改變了設定鍵 %s 的要求：%+v → %+v", key, want, got[key])
			}
		}
	}

	var ep model.PolicyGroup
	if err := db.Where("code = ?", ePaymentGroupCode).First(&ep).Error; err != nil {
		t.Fatalf("讀取電支組: %v", err)
	}
	if ep.Enabled {
		t.Error("種子把機構關掉的組重新打開了：生效與否由機構決定，升級不得改它")
	}

	notes, err := repo.ListAnnotations(pciGroupCode)
	if err != nil {
		t.Fatalf("讀備註: %v", err)
	}
	if len(notes) != 1 || notes[0].Note != "本行以三次為準" {
		t.Errorf("重複啟動動到了機構備註: %+v", notes)
	}
}

// TestPolicyGroupSeedKeepsAnnotationsOnRemovedClauses 升級移除條文只標記，備註原封不動。
func TestPolicyGroupSeedKeepsAnnotationsOnRemovedClauses(t *testing.T) {
	db := newPolicyGroupSeedDB(t)

	before := policyGroupSeed{
		Code: "demo_std", Name: "示範規範", Version: "1.0",
		Clauses: []policyClauseSeed{
			{ClauseNo: "A-1", Title: "留下來的條文",
				Controls: []policyControlSeed{atLeast(PolicyPasswordMinLength, "12")}},
			{ClauseNo: "A-2", Title: "下一版會消失的條文",
				Controls: []policyControlSeed{atLeast(PolicyPasswordHistoryCount, "4")}},
		},
	}
	if err := applyPolicyGroupSeeds(db, []policyGroupSeed{before}); err != nil {
		t.Fatalf("第一版種子: %v", err)
	}

	repo := NewPolicyGroupRepository(db)
	if err := repo.UpsertAnnotation("demo_std", "A-2", "機構對這一條的說明"); err != nil {
		t.Fatalf("寫備註: %v", err)
	}

	after := before
	after.Version = "2.0"
	after.Clauses = before.Clauses[:1]
	if err := applyPolicyGroupSeeds(db, []policyGroupSeed{after}); err != nil {
		t.Fatalf("第二版種子: %v", err)
	}

	var removed model.PolicyClause
	if err := db.Where("group_code = ? AND clause_no = ?", "demo_std", "A-2").
		First(&removed).Error; err != nil {
		t.Fatalf("已移除的條文列不得被刪除（備註會失去掛靠對象）: %v", err)
	}
	if removed.RemovedInVersion != "2.0" {
		t.Errorf("已移除條文的版本標記 = %q, want \"2.0\"", removed.RemovedInVersion)
	}

	var kept model.PolicyClause
	if err := db.Where("group_code = ? AND clause_no = ?", "demo_std", "A-1").
		First(&kept).Error; err != nil {
		t.Fatalf("留下來的條文不見了: %v", err)
	}
	if kept.RemovedInVersion != "" {
		t.Errorf("仍在的條文被誤標為已移除: %q", kept.RemovedInVersion)
	}

	notes, err := repo.ListAnnotations("demo_std")
	if err != nil {
		t.Fatalf("讀備註: %v", err)
	}
	if len(notes) != 1 || notes[0].ClauseNo != "A-2" || notes[0].Note != "機構對這一條的說明" {
		t.Fatalf("移除條文時動到了機構備註: %+v", notes)
	}

	// 已移除條文的要求一併退場：判定不再計入它
	got := controlsByKey(t, db, "demo_std")
	if _, still := got[PolicyPasswordHistoryCount]; still {
		t.Error("已移除條文的要求仍留在庫裡，判定會繼續計入一條規範裡已經不存在的要求")
	}
	if _, ok := got[PolicyPasswordMinLength]; !ok {
		t.Error("仍在的條文其要求被誤刪")
	}
}

// TestPolicyGroupSeedRejectsMalformedContent 種子自帶內容之後，寫錯的那幾種形態要在
// 建構時就擋下，而不是落庫後在合規頁上變成一條說不出出處的要求。
func TestPolicyGroupSeedRejectsMalformedContent(t *testing.T) {
	cases := []struct {
		name   string
		clause policyClauseSeed
	}{
		{"未定義的設定鍵", policyClauseSeed{ClauseNo: "X-1", Title: "指向不存在的鍵",
			Controls: []policyControlSeed{atLeast("no_such_policy_key", "1")}}},
		{"比較方式與鍵的方向相反", policyClauseSeed{ClauseNo: "X-2", Title: "至少型的鍵寫成至多",
			Controls: []policyControlSeed{atMost(PolicyPasswordMinLength, "12")}}},
		{"要求值不在合法值域", policyClauseSeed{ClauseNo: "X-3", Title: "枚舉外的值",
			Controls: []policyControlSeed{mustBe(PolicyMFARequired, "everyone")}}},
		{"設定要求型卻沒有任何要求", policyClauseSeed{ClauseNo: "X-4", Title: "空的設定要求"}},
		{"內建保護型卻掛了要求", policyClauseSeed{ClauseNo: "X-5", Title: "可調的內建保護",
			Kind:     model.PolicyClauseKindBuiltinProtection,
			Controls: []policyControlSeed{mustBe(PolicyDailyReviewEnabled, "true")}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seed := policyGroupSeed{Code: "demo_std", Name: "示範規範", Version: "1.0",
				Clauses: []policyClauseSeed{c.clause}}
			if _, err := buildSeedControls(seed); err == nil {
				t.Error("種子的這個形態應在建構時擋下，卻通過了")
			}
		})
	}

	t.Run("同一個鍵被兩條條文各掛一次", func(t *testing.T) {
		seed := policyGroupSeed{Code: "demo_std", Name: "示範規範", Version: "1.0",
			Clauses: []policyClauseSeed{
				{ClauseNo: "Y-1", Title: "第一條", Controls: []policyControlSeed{atLeast(PolicyPasswordMinLength, "12")}},
				{ClauseNo: "Y-2", Title: "第二條", Controls: []policyControlSeed{atLeast(PolicyPasswordMinLength, "6")}},
			}}
		if _, err := buildSeedControls(seed); err == nil {
			t.Error("同組內同一個鍵掛兩次應被擋下：該組對自己自相矛盾，判定結果會取決於讀取順序")
		}
	})
}

// snapshotClauses 條文集合的可比較投影（組代號＋條號 → 標題與移除標記）。
func snapshotClauses(t *testing.T, db *gorm.DB) map[string]string {
	t.Helper()
	var rows []model.PolicyClause
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("讀取條文: %v", err)
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.GroupCode+"|"+r.ClauseNo] = r.Title + "|" + r.Kind + "|" + r.RemovedInVersion
	}
	return out
}

func equalClauseSnapshots(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// newPolicyGroupSeedDB 種子測試用的四張表。
func newPolicyGroupSeedDB(t *testing.T) *gorm.DB {
	t.Helper()
	_, db := newPolicyGroupRepo(t)
	return db
}
