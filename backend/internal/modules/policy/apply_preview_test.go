package policy

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 套用計算的測試。預覽與套用是同一支計算，故本檔釘住的就是按下「套用政策建議值」
// 之後表單會被填成什麼——包括**哪些鍵刻意不動**。

func TestPreviewApply(t *testing.T) {
	defs := testComplianceDefs()

	cases := []struct {
		name          string
		groups        []model.PolicyGroup
		clauses       []model.PolicyClause
		controls      []model.PolicyClauseControl
		values        map[string]string
		scope         []string
		mode          string
		groupCode     string
		wantChanges   map[string]string // 鍵 → 改成的值
		wantSources   map[string]string // 鍵 → 依據的組
		wantConflicts []string
		wantUnchanged int
		wantUnmapped  int
	}{
		{
			name: "多組取最嚴：至少取最大",
			groups: []model.PolicyGroup{
				testGroup("g1", true), testGroup("g2", true), testGroup("g3", true),
			},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
				testClause("g2", "1", model.PolicyClauseKindSetting, ""),
				testClause("g3", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "12", false),
				testControl("g2", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "6", false),
				testControl("g3", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "14", false),
			},
			values:      map[string]string{testKeyPwdLen: "12"},
			scope:       []string{testKeyPwdLen},
			mode:        ApplyModeStrictest,
			wantChanges: map[string]string{testKeyPwdLen: "14"},
			wantSources: map[string]string{testKeyPwdLen: "g3"},
		},
		{
			name:   "不放寬：現值已嚴於所有要求就不列入",
			groups: []model.PolicyGroup{testGroup("g1", true), testGroup("g3", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
				testClause("g3", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "12", false),
				testControl("g3", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "14", false),
			},
			values:        map[string]string{testKeyPwdLen: "16"},
			scope:         []string{testKeyPwdLen},
			mode:          ApplyModeStrictest,
			wantChanges:   map[string]string{},
			wantUnchanged: 1,
		},
		{
			name:   "開關型兩組要求相反：視為衝突，不自動改",
			groups: []model.PolicyGroup{testGroup("g1", true), testGroup("g2", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
				testClause("g2", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyClipboard, model.PolicyControlComparatorEquals, "false", false),
				testControl("g2", "1", testKeyClipboard, model.PolicyControlComparatorEquals, "true", false),
			},
			values:        map[string]string{testKeyClipboard: "true"},
			scope:         []string{testKeyClipboard},
			mode:          ApplyModeStrictest,
			wantChanges:   map[string]string{},
			wantConflicts: []string{testKeyClipboard},
		},
		{
			name:   "只動範圍內的鍵",
			groups: []model.PolicyGroup{testGroup("g1", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "14", false),
				testControl("g1", "1", testKeyClipboard, model.PolicyControlComparatorEquals, "false", false),
			},
			values: map[string]string{testKeyPwdLen: "12", testKeyClipboard: "true"},
			// 剪貼簿鍵同樣偏離，但它不在本頁：不得出現在任何一個清單或計數裡
			scope:       []string{testKeyPwdLen},
			mode:        ApplyModeStrictest,
			wantChanges: map[string]string{testKeyPwdLen: "14"},
			wantSources: map[string]string{testKeyPwdLen: "g1"},
		},
		{
			name:   "零值代表停用：要求非零時不得留在零",
			groups: []model.PolicyGroup{testGroup("g1", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyLockout, model.PolicyControlComparatorMax, "5", false),
			},
			// 0 在數值上小於 5，但它的意思是「鎖定機制沒開」
			values:      map[string]string{testKeyLockout: "0"},
			scope:       []string{testKeyLockout},
			mode:        ApplyModeStrictest,
			wantChanges: map[string]string{testKeyLockout: "5"},
			wantSources: map[string]string{testKeyLockout: "g1"},
		},
		{
			name:   "零值代表停用：非零現值已達要求就不動",
			groups: []model.PolicyGroup{testGroup("g1", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyLockout, model.PolicyControlComparatorMax, "5", false),
			},
			values:        map[string]string{testKeyLockout: "3"},
			scope:         []string{testKeyLockout},
			mode:          ApplyModeStrictest,
			wantChanges:   map[string]string{},
			wantUnchanged: 1,
		},
		{
			// 一組要求關閉、另一組要求「至多 5」：後者在零值代表停用的鍵上
			// 隱含「必須開著」，故沒有任何值同時滿足兩者。現值 0 已違反其中一條，
			// 預覽不得回「不變動、無衝突」——那會讓一個偏離的鍵在畫面上消失
			name:   "零值上界與非零上界並存：現值 0 仍是衝突",
			groups: []model.PolicyGroup{testGroup("g1", true), testGroup("g2", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
				testClause("g2", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyLockout, model.PolicyControlComparatorMax, "0", false),
				testControl("g2", "1", testKeyLockout, model.PolicyControlComparatorMax, "5", false),
			},
			values:        map[string]string{testKeyLockout: "0"},
			scope:         []string{testKeyLockout},
			mode:          ApplyModeStrictest,
			wantChanges:   map[string]string{},
			wantConflicts: []string{testKeyLockout},
		},
		{
			// 同一對要求、現值 3：上界收斂到 0 之後不得提出 0——那會把原已符合的
			// 「至多 5」打掉，且 0 在這個鍵上的意思是把鎖定機制關掉
			name:   "零值上界與非零上界並存：現值 3 不得被提出改成 0",
			groups: []model.PolicyGroup{testGroup("g1", true), testGroup("g2", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
				testClause("g2", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyLockout, model.PolicyControlComparatorMax, "0", false),
				testControl("g2", "1", testKeyLockout, model.PolicyControlComparatorMax, "5", false),
			},
			values:        map[string]string{testKeyLockout: "3"},
			scope:         []string{testKeyLockout},
			mode:          ApplyModeStrictest,
			wantChanges:   map[string]string{},
			wantConflicts: []string{testKeyLockout},
		},
		{
			name:   "同鍵有至少與至多且交集為空：視為衝突",
			groups: []model.PolicyGroup{testGroup("g1", true), testGroup("g2", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
				testClause("g2", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "20", false),
				testControl("g2", "1", testKeyPwdLen, model.PolicyControlComparatorMax, "15", false),
			},
			values:        map[string]string{testKeyPwdLen: "12"},
			scope:         []string{testKeyPwdLen},
			mode:          ApplyModeStrictest,
			wantChanges:   map[string]string{},
			wantConflicts: []string{testKeyPwdLen},
		},
		{
			name:   "同鍵有至少與至多且交集非空：現值落在區間內就不動",
			groups: []model.PolicyGroup{testGroup("g1", true), testGroup("g2", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
				testClause("g2", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "12", false),
				testControl("g2", "1", testKeyPwdLen, model.PolicyControlComparatorMax, "20", false),
			},
			values:        map[string]string{testKeyPwdLen: "16"},
			scope:         []string{testKeyPwdLen},
			mode:          ApplyModeStrictest,
			wantChanges:   map[string]string{},
			wantUnchanged: 1,
		},
		{
			name:   "指定單組：取該組的要求",
			groups: []model.PolicyGroup{testGroup("g1", true), testGroup("g2", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
				testClause("g2", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "14", false),
				testControl("g2", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "6", false),
			},
			values:      map[string]string{testKeyPwdLen: "12"},
			scope:       []string{testKeyPwdLen},
			mode:        ApplyModeGroup,
			groupCode:   "g1",
			wantChanges: map[string]string{testKeyPwdLen: "14"},
			wantSources: map[string]string{testKeyPwdLen: "g1"},
		},
		{
			name:   "指定單組：現值已嚴於該組要求就不動",
			groups: []model.PolicyGroup{testGroup("g1", true), testGroup("g2", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
				testClause("g2", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "14", false),
				testControl("g2", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "6", false),
			},
			// 套用要求較寬的那一組，現值已符合較嚴的另一組：不得被改回 6
			values:        map[string]string{testKeyPwdLen: "16"},
			scope:         []string{testKeyPwdLen},
			mode:          ApplyModeGroup,
			groupCode:     "g2",
			wantChanges:   map[string]string{},
			wantUnchanged: 1,
		},
		{
			name:   "指定單組：套用它會放寬另一組已符合的值，視為衝突",
			groups: []model.PolicyGroup{testGroup("g1", true), testGroup("g2", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
				testClause("g2", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "14", false),
				testControl("g2", "1", testKeyPwdLen, model.PolicyControlComparatorMax, "10", false),
			},
			// 現值 16 符合 g1 的下界、違反 g2 的上界；照 g2 改成 10 會讓 g1 由符合翻成偏離
			values:        map[string]string{testKeyPwdLen: "16"},
			scope:         []string{testKeyPwdLen},
			mode:          ApplyModeGroup,
			groupCode:     "g2",
			wantChanges:   map[string]string{},
			wantConflicts: []string{testKeyPwdLen},
		},
		{
			name:   "參考值不自動套用",
			groups: []model.PolicyGroup{testGroup("g1", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyTransport, model.PolicyControlComparatorEquals, "strict", true),
			},
			// 參考值是待人工確認，不是固定要求：一鍵套用不得替機構決定它
			values:        map[string]string{testKeyTransport: "off"},
			scope:         []string{testKeyTransport},
			mode:          ApplyModeStrictest,
			wantChanges:   map[string]string{},
			wantUnchanged: 1,
		},
		{
			name:   "條文未定值：不動也不衝突",
			groups: []model.PolicyGroup{testGroup("g1", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
			},
			// 條文涉及這個鍵但沒有給值：一鍵套用沒有可套的東西，交給稽核判讀
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyTransport, model.PolicyControlComparatorReview, "", false),
			},
			values:        map[string]string{testKeyTransport: "off"},
			scope:         []string{testKeyTransport},
			mode:          ApplyModeStrictest,
			wantChanges:   map[string]string{},
			wantUnchanged: 1,
		},
		{
			name:   "不屬於任何生效組的鍵另計",
			groups: []model.PolicyGroup{testGroup("g1", true)},
			clauses: []model.PolicyClause{
				testClause("g1", "1", model.PolicyClauseKindSetting, ""),
			},
			controls: []model.PolicyClauseControl{
				testControl("g1", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "14", false),
			},
			values:       map[string]string{testKeyPwdLen: "12", testKeyOrphan: "5"},
			scope:        []string{testKeyPwdLen, testKeyOrphan},
			mode:         ApplyModeStrictest,
			wantChanges:  map[string]string{testKeyPwdLen: "14"},
			wantSources:  map[string]string{testKeyPwdLen: "g1"},
			wantUnmapped: 1,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			snap := BuildSnapshot(defs, c.values, nil, c.groups, c.clauses, c.controls, nil)
			got := buildApplyPreview(defs, c.values, snap, c.scope, c.mode, c.groupCode)

			changes := map[string]string{}
			sources := map[string]string{}
			for _, ch := range got.Changes {
				changes[ch.Key] = ch.Proposed
				sources[ch.Key] = ch.SourceGroup
				if ch.Current != c.values[ch.Key] {
					t.Errorf("%s 的目前值 = %q, want %q", ch.Key, ch.Current, c.values[ch.Key])
				}
			}
			if !equalStringMap(changes, c.wantChanges) {
				t.Errorf("變動清單 = %v, want %v", changes, c.wantChanges)
			}
			if c.wantSources != nil && !equalStringMap(sources, c.wantSources) {
				t.Errorf("依據的政策組 = %v, want %v", sources, c.wantSources)
			}
			var conflictKeys []string
			for _, cf := range got.Conflicts {
				conflictKeys = append(conflictKeys, cf.Key)
				if len(cf.Reasons) < 2 {
					t.Errorf("%s 的衝突只列了 %d 條規則來源：畫面無從說明是哪兩條規則對立",
						cf.Key, len(cf.Reasons))
				}
			}
			if !equalStringSets(conflictKeys, c.wantConflicts) {
				t.Errorf("衝突鍵 = %v, want %v", conflictKeys, c.wantConflicts)
			}
			if got.UnchangedCount != c.wantUnchanged {
				t.Errorf("已符合不變動 = %d, want %d", got.UnchangedCount, c.wantUnchanged)
			}
			if got.UnmappedCount != c.wantUnmapped {
				t.Errorf("不屬任何政策組 = %d, want %d", got.UnmappedCount, c.wantUnmapped)
			}
			// 範圍內每一個鍵都要有去處，否則預覽底部的計數對不上畫面上的鍵
			total := len(got.Changes) + len(got.Conflicts) + got.UnchangedCount + got.UnmappedCount
			if total != len(c.scope) {
				t.Errorf("四類合計 %d, want 範圍鍵數 %d", total, len(c.scope))
			}
		})
	}

	t.Run("衝突逐條列出來源組與其要求", func(t *testing.T) {
		groups := []model.PolicyGroup{testGroup("g1", true), testGroup("g2", true)}
		clauses := []model.PolicyClause{
			testClause("g1", "1", model.PolicyClauseKindSetting, ""),
			testClause("g2", "1", model.PolicyClauseKindSetting, ""),
		}
		controls := []model.PolicyClauseControl{
			testControl("g1", "1", testKeyClipboard, model.PolicyControlComparatorEquals, "false", false),
			testControl("g2", "1", testKeyClipboard, model.PolicyControlComparatorEquals, "true", false),
		}
		values := map[string]string{testKeyClipboard: "true"}
		snap := BuildSnapshot(defs, values, nil, groups, clauses, controls, nil)
		got := buildApplyPreview(defs, values, snap,
			[]string{testKeyClipboard}, ApplyModeStrictest, "")

		if len(got.Conflicts) != 1 {
			t.Fatalf("衝突數 = %d, want 1", len(got.Conflicts))
		}
		reasons := map[string]string{}
		for _, r := range got.Conflicts[0].Reasons {
			reasons[r.Group] = r.Expected
			if r.Comparator == "" {
				t.Error("衝突來源未帶比較方式：畫面無從說出是「須為」還是「至少」")
			}
		}
		if !equalStringMap(reasons, map[string]string{"g1": "false", "g2": "true"}) {
			t.Errorf("衝突來源 = %v, want g1=false、g2=true", reasons)
		}
	})

	t.Run("預覽依設定鍵的呈現順序輸出", func(t *testing.T) {
		groups := []model.PolicyGroup{testGroup("g1", true)}
		clauses := []model.PolicyClause{testClause("g1", "1", model.PolicyClauseKindSetting, "")}
		controls := []model.PolicyClauseControl{
			testControl("g1", "1", testKeyPwdLen, model.PolicyControlComparatorMin, "14", false),
			testControl("g1", "1", testKeyLockout, model.PolicyControlComparatorMax, "5", false),
		}
		values := map[string]string{testKeyPwdLen: "12", testKeyLockout: "10"}
		snap := BuildSnapshot(defs, values, nil, groups, clauses, controls, nil)
		// 範圍以相反順序給進去：輸出仍應照設定鍵的呈現順序，
		// 否則預覽表的列序會隨呼叫端與 map 迭代而跳動
		got := buildApplyPreview(defs, values, snap,
			[]string{testKeyLockout, testKeyPwdLen}, ApplyModeStrictest, "")

		var keys []string
		for _, ch := range got.Changes {
			keys = append(keys, ch.Key)
		}
		if len(keys) != 2 || keys[0] != testKeyPwdLen || keys[1] != testKeyLockout {
			t.Errorf("變動順序 = %v, want [%s %s]", keys, testKeyPwdLen, testKeyLockout)
		}
	})

	t.Run("套用預覽走服務層時的參數檢查", func(t *testing.T) {
		_, repo, compliance := newComplianceStack(t)
		seedCustomClause(t, repo, "house_rule", PolicyPasswordMinLength,
			model.PolicyControlComparatorMin, "14")

		got, err := compliance.PreviewApply([]string{PolicyPasswordMinLength},
			ApplyModeStrictest, "", nil)
		if err != nil {
			t.Fatalf("預覽: %v", err)
		}
		if len(got.Changes) != 1 || got.Changes[0].Proposed != "14" {
			t.Fatalf("預覽變動 = %+v, want 密碼最小長度改成 14", got.Changes)
		}

		// 草稿覆蓋現值：已在草稿裡改到要求值的鍵不再列入變動
		drafted, err := compliance.PreviewApply([]string{PolicyPasswordMinLength},
			ApplyModeStrictest, "", map[string]string{PolicyPasswordMinLength: "14"})
		if err != nil {
			t.Fatalf("草稿預覽: %v", err)
		}
		if len(drafted.Changes) != 0 || drafted.UnchangedCount != 1 {
			t.Errorf("草稿已達要求時 = %+v, want 無變動且不變動數為 1", drafted)
		}

		if _, err := compliance.PreviewApply(nil, "bogus", "", nil); err == nil {
			t.Error("未知的套用模式應被拒（否則呼叫端拼錯字會靜默拿到空預覽）")
		}
		if _, err := compliance.PreviewApply(nil, ApplyModeGroup, "no_such_group", nil); err == nil {
			t.Error("指定不存在的政策組應被拒")
		}
	})
}
