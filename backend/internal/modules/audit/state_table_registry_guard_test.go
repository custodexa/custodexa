package audit

import (
	"sort"
	"testing"
)

// 登記清單守衛（role-assignment-integrity 第 1 組）。
//
// # 守的是什麼
//
// 登記一張狀態表就是宣告「這張表的指紋進鏈、直寫改動抓得到」。那句宣告要成立，
// 必須有人證明過兩件事：快照函式對它是穩定且不含個資的（快照測試），
// 以及對它的直寫竄改真的會被指出（竄改矩陣列）。少了任一件，登記清單就成了
// 一份沒有人驗過的承諾，而承諾會被寫進驗證頁與對外文件。
//
// # 雙向
//
// 只查一個方向都會留下靜默失效的形態：
//
//   - 只查「登記表有沒有測試」：測試表多出一張沒登記的表時無人發現，
//     那張表的測試看起來在保護什麼，實際上封章根本不會碰它。
//   - 只查「測試有沒有對應登記」：新增登記卻沒補測試時無人發現，
//     那正是「宣稱涵蓋但沒有偵測力」的形態。
//
// 故兩個方向都比對。射程的事實源是**真的被 range 過的資料**
//（`stateSnapshotCases()` 與 `tamperScenarios()`），不是另寫一份表名清單。

// registryTableNames 登記清單的表名（升冪）
func registryTableNames() []string {
	reg := StateTableRegistry()
	names := make([]string, 0, len(reg))
	for _, st := range reg {
		names = append(names, st.Name)
	}
	sort.Strings(names)
	return names
}

// snapshotTestedTables 有快照測試的表名（由快照測試的案例表推導）
func snapshotTestedTables() []string {
	cases := stateSnapshotCases()
	names := make([]string, 0, len(cases))
	for _, c := range cases {
		names = append(names, c.table)
	}
	sort.Strings(names)
	return names
}

// tamperCoveredTables 在竄改矩陣內有專屬情境的表名（由矩陣本身推導）
func tamperCoveredTables() []string {
	seen := map[string]bool{}
	for _, sc := range tamperScenarios() {
		if sc.stateTable != "" {
			seen[sc.stateTable] = true
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// diffStrings 回傳 a 有而 b 無的元素
func diffStrings(a, b []string) []string {
	inB := make(map[string]bool, len(b))
	for _, s := range b {
		inB[s] = true
	}
	var out []string
	for _, s := range a {
		if !inB[s] {
			out = append(out, s)
		}
	}
	return out
}

func TestStateTableRegistryGuard(t *testing.T) {
	registered := registryTableNames()
	if len(registered) == 0 {
		t.Fatal("登記清單為空：本能力的封章不會涵蓋任何狀態表，" +
			"驗證頁與對外文件卻仍會宣稱角色指派受保護")
	}

	t.Run("登記表都有快照測試", func(t *testing.T) {
		tested := snapshotTestedTables()
		if miss := diffStrings(registered, tested); len(miss) > 0 {
			t.Fatalf("登記表 %v 沒有快照測試（stateSnapshotCases 未涵蓋）："+
				"未經證明的快照函式＝一份沒有偵測力的宣稱", miss)
		}
		if extra := diffStrings(tested, registered); len(extra) > 0 {
			t.Fatalf("快照測試涵蓋了未登記的表 %v："+
				"封章不會碰它，那些測試保護的是一個不存在的機制", extra)
		}
	})

	t.Run("登記表都有竄改矩陣列", func(t *testing.T) {
		covered := tamperCoveredTables()
		if miss := diffStrings(registered, covered); len(miss) > 0 {
			t.Fatalf("登記表 %v 在竄改矩陣內無情境（tamperScenarios 的 stateTable 未涵蓋）："+
				"沒有人證明過對它的直寫竄改會被指出", miss)
		}
		if extra := diffStrings(covered, registered); len(extra) > 0 {
			t.Fatalf("竄改矩陣有未登記表 %v 的情境："+
				"矩陣宣稱抓得到一張封章根本不會快照的表", extra)
		}
	})

	t.Run("登記項欄位齊備", func(t *testing.T) {
		for _, st := range StateTableRegistry() {
			if st.Name == "" {
				t.Errorf("登記項缺表名: %+v", st)
			}
			if st.Snapshot == nil {
				t.Errorf("登記表 %s 缺快照函式：封章時無從取指紋", st.Name)
			}
			if st.EventResource == "" {
				t.Errorf("登記表 %s 缺審計資源名：對帳篩不出它的合法變更，"+
					"每一次合法改動都會變成假警報", st.Name)
			}
		}
	})
}
