package managedapi

import (
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/middleware"
)

// 守衛的自檢：以壞資料餵入檢查函式，每一種違規都要被指出，證明檢查不是恆真。

func cloneResources() []Resource { return Resources() }

func findRow(rows []Resource, name string) int {
	for i, r := range rows {
		if r.Name == name {
			return i
		}
	}
	return -1
}

func expectProblem(t *testing.T, label string, probs []string, want string) {
	t.Helper()
	for _, p := range probs {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Errorf("%s：檢查沒有指出問題（預期含 %q），實得 %v", label, want, probs)
}

func TestCheckCellsDetectsViolations(t *testing.T) {
	if probs := checkCells(cloneResources(), ExceptionSpecs(), IsInitial); len(probs) != 0 {
		t.Fatalf("前提：現況應無問題：%v", probs)
	}
	later := func(string) bool { return false }

	t.Run("格子留空", func(t *testing.T) {
		rows := cloneResources()
		delete(rows[0].Cells, RuleTimeFields)
		expectProblem(t, "留空", checkCells(rows, ExceptionSpecs(), IsInitial), "格子留空")
	})
	t.Run("例外值不在列舉內", func(t *testing.T) {
		rows := cloneResources()
		rows[0].Cells[RuleTimeFields] = exc("made_up_exception", "x")
		expectProblem(t, "列舉外", checkCells(rows, ExceptionSpecs(), IsInitial), "不在封閉列舉內")
	})
	t.Run("例外掛錯規則", func(t *testing.T) {
		rows := cloneResources()
		rows[0].Cells[RuleTimeFields] = exc(ExcNoExactLookup, "x")
		expectProblem(t, "掛錯", checkCells(rows, ExceptionSpecs(), IsInitial), "屬於規則")
	})
	t.Run("初始名單以外引用僅限初始名單的例外", func(t *testing.T) {
		rows := []Resource{cloneResources()[findRow(cloneResources(), "asset_account")]}
		rows[0].Name = "new_resource"
		expectProblem(t, "新列引用例外", checkCells(rows, ExceptionSpecs(), later), "不得引用僅限初始名單的例外")
	})
	t.Run("初始名單以外使用待查", func(t *testing.T) {
		rows := []Resource{cloneResources()[findRow(cloneResources(), "authorization")]}
		rows[0].Name = "new_resource"
		expectProblem(t, "新列待查", checkCells(rows, ExceptionSpecs(), later), "不得使用待查")
	})
	t.Run("依賴存在卻填不適用", func(t *testing.T) {
		rows := cloneResources()
		i := findRow(rows, "asset")
		rows[i].Cells[RuleDelete204] = na("x")
		expectProblem(t, "不適用", checkCells(rows, ExceptionSpecs(), IsInitial), "不得填不適用")
	})
	t.Run("沒有單筆讀取卻未登錄例外", func(t *testing.T) {
		rows := cloneResources()
		i := findRow(rows, "asset")
		rows[i].Read = nil
		expectProblem(t, "無單筆", checkCells(rows, ExceptionSpecs(), IsInitial), "必須登錄例外 no_single_read")
	})
	t.Run("沒有查找參數卻未登錄例外", func(t *testing.T) {
		rows := cloneResources()
		i := findRow(rows, "asset")
		rows[i].Lookup = Lookup{}
		expectProblem(t, "無查找", checkCells(rows, ExceptionSpecs(), IsInitial), "必須登錄例外 no_exact_lookup")
	})
	t.Run("詳情投影不同卻沒有共同欄位", func(t *testing.T) {
		rows := cloneResources()
		i := findRow(rows, "credential")
		rows[i].CommonFields = nil
		expectProblem(t, "共同欄位", checkCells(rows, ExceptionSpecs(), IsInitial), "必須列出共同欄位")
	})
	t.Run("名稱重複", func(t *testing.T) {
		rows := cloneResources()
		rows = append(rows, rows[0])
		expectProblem(t, "重複", checkCells(rows, ExceptionSpecs(), IsInitial), "名稱重複")
	})
	t.Run("有查找參數卻既非符合也非查找不能唯一定位", func(t *testing.T) {
		rows := cloneResources()
		i := findRow(rows, "asset")
		rows[i].Cells[RuleExactLookup] = exc(ExcNoExactLookup, "x")
		expectProblem(t, "查找狀態", checkCells(rows, ExceptionSpecs(), IsInitial), "精確查找規則應為符合，或登錄例外 lookup_not_unique")
	})
	t.Run("登錄查找不能唯一定位卻沒有查找參數", func(t *testing.T) {
		rows := cloneResources()
		i := findRow(rows, "asset_node")
		rows[i].Lookup = Lookup{}
		expectProblem(t, "查找參數", checkCells(rows, ExceptionSpecs(), IsInitial), "登錄 lookup_not_unique 時必須列出查找參數")
	})
	t.Run("列表獨有欄位卻未登錄詳情投影不同", func(t *testing.T) {
		rows := cloneResources()
		i := findRow(rows, "user")
		rows[i].ListOnlyFields = []string{"x"}
		expectProblem(t, "列表獨有", checkCells(rows, ExceptionSpecs(), IsInitial), "必須列出共同欄位或列表獨有欄位")
	})
	t.Run("共同欄位與列表獨有欄位同時列出", func(t *testing.T) {
		rows := cloneResources()
		i := findRow(rows, "asset")
		rows[i].CommonFields = []string{"id"}
		expectProblem(t, "二擇一", checkCells(rows, ExceptionSpecs(), IsInitial), "只能二擇一")
	})
}

func TestCheckInitialOnlyFrozenDetectsViolations(t *testing.T) {
	if probs := checkInitialOnlyFrozen(ExceptionSpecs(), frozenInitialOnlyCopy); len(probs) != 0 {
		t.Fatalf("前提：現況應無問題：%v", probs)
	}
	t.Run("例外改成不限初始名單", func(t *testing.T) {
		specs := ExceptionSpecs()
		s := specs[ExcNoExactLookup]
		s.InitialOnly = false
		specs[ExcNoExactLookup] = s
		expectProblem(t, "旗標", checkInitialOnlyFrozen(specs, frozenInitialOnlyCopy), "改成不限初始名單")
	})
	t.Run("新增僅限初始名單的例外而未同步副本", func(t *testing.T) {
		specs := ExceptionSpecs()
		specs["made_up"] = ExceptionSpec{Rule: RuleTimeFields, InitialOnly: true, Description: "x"}
		expectProblem(t, "未同步", checkInitialOnlyFrozen(specs, frozenInitialOnlyCopy), "不在凍結副本內")
	})
}

func TestCheckAttributionDetectsViolations(t *testing.T) {
	open := openRoutes()
	managed := ManagedRouteOwners()
	attrs := Attributions()
	frozen := FrozenUnmanagedFamilies()
	if probs := checkAttribution(open, managed, attrs, frozen, natureOfRegistry); len(probs) != 0 {
		t.Fatalf("前提：現況應無問題：%v", probs)
	}

	t.Run("新開放的路由沒有歸屬", func(t *testing.T) {
		o := map[string]bool{"POST /api/v1/widgets": true}
		for k := range open {
			o[k] = true
		}
		expectProblem(t, "未歸屬", checkAttribution(o, managed, attrs, frozen, natureOfRegistry), "POST /api/v1/widgets：對 API token 開放但沒有歸屬")
	})
	t.Run("新家族不在凍結名單", func(t *testing.T) {
		o := map[string]bool{"POST /api/v1/widgets": true}
		for k := range open {
			o[k] = true
		}
		a := Attributions()
		a["POST /api/v1/widgets"] = unmanaged("widgets")
		expectProblem(t, "新家族", checkAttribution(o, managed, a, frozen, natureOfRegistry), "不在尚未納管家族的凍結名單內")
	})
	t.Run("可寫路由藏進唯讀家族", func(t *testing.T) {
		a := Attributions()
		a["POST /api/v1/alert-rules"] = readOnly("alert_rules_ro")
		expectProblem(t, "唯讀家族", checkAttribution(open, managed, a, frozen, natureOfRegistry), "路由性質不是讀")
	})
	t.Run("可寫路由歸到非資源", func(t *testing.T) {
		a := Attributions()
		a["POST /api/v1/alert-rules"] = nonRes()
		expectProblem(t, "非資源", checkAttribution(open, managed, a, frozen, natureOfRegistry), "歸在非資源類別，但路由性質不是讀")
	})
	t.Run("歸屬表登錄了未開放的路由", func(t *testing.T) {
		a := Attributions()
		a["POST /api/v1/keys"] = nonRes()
		expectProblem(t, "未開放", checkAttribution(open, managed, a, frozen, natureOfRegistry), "未開放或不存在的路由")
	})
	t.Run("同時屬於納管資源與歸屬表", func(t *testing.T) {
		a := Attributions()
		a["GET /api/v1/assets"] = nonRes()
		expectProblem(t, "雙重歸屬", checkAttribution(open, managed, a, frozen, natureOfRegistry), "同時屬於納管資源")
	})
	t.Run("凍結名單有過時的家族", func(t *testing.T) {
		f := FrozenUnmanagedFamilies()
		f["retired_family"] = "x"
		expectProblem(t, "過時家族", checkAttribution(open, managed, attrs, f, natureOfRegistry), "已沒有任何路由")
	})
}

func TestCheckRegistryRoutesDetectsViolations(t *testing.T) {
	routes := registeredRoutes(t)
	if probs := checkRegistryRoutes(Resources(), routes, middleware.APITokenRouteClassOf, middleware.LookupAPITokenRoute); len(probs) != 0 {
		t.Fatalf("前提：現況應無問題：%v", probs)
	}
	t.Run("引用不存在的路由", func(t *testing.T) {
		rows := cloneResources()
		rows[0].Read = append(rows[0].Read, "GET /api/v1/no-such-route/:id")
		expectProblem(t, "不存在", checkRegistryRoutes(rows, routes, middleware.APITokenRouteClassOf, middleware.LookupAPITokenRoute), "路由清冊沒有這條路由")
	})
	t.Run("引用未開放的路由", func(t *testing.T) {
		rows := cloneResources()
		rows[0].Update = append(rows[0].Update, "POST /api/v1/keys")
		probs := checkRegistryRoutes(rows, routes, middleware.APITokenRouteClassOf, middleware.LookupAPITokenRoute)
		expectProblem(t, "未開放", probs, "POST /api/v1/keys")
	})
	t.Run("寫入路由放在讀取操作", func(t *testing.T) {
		rows := cloneResources()
		i := findRow(rows, "asset")
		rows[i].List = append(rows[i].List, "POST /api/v1/assets/batch/tags")
		expectProblem(t, "性質", checkRegistryRoutes(rows, routes, middleware.APITokenRouteClassOf, middleware.LookupAPITokenRoute), "與操作不符")
	})
	t.Run("同一路由屬於兩處", func(t *testing.T) {
		rows := cloneResources()
		rows[1].List = append(rows[1].List, rows[0].List[0])
		expectProblem(t, "重複", checkRegistryRoutes(rows, routes, middleware.APITokenRouteClassOf, middleware.LookupAPITokenRoute), "同時屬於")
	})
}
