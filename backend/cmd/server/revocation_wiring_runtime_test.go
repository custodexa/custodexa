package main

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/modules/identity"
)

// 撤銷管道接線的**執行期** oracle（同源 oracle 盲區）。
//
// `internal/modules/keyvault/revocation_wiring_guard_test.go` 已以 AST 掃描
// `cmd/server/stage2.go`，要求六個 `Set*` 呼叫存在。那道守衛與掃描器共用一個
// 前提：**「呼叫寫在那裡」＝「管道已接上」**。下列**正常開發會做的**改動會讓
// 這個前提不成立，而掃描器全數照綠：
//
//   - `Set*(nil)`：依賴在該點尚未建構、或建構失敗後退成 nil，呼叫仍原封不動。
//   - `Set*(resolve(x))`：重構引入一層中性名稱的取值 helper，helper 在某條分支
//     回 nil。呼叫點的接收者與方法名完全沒變，AST 掃描看不出任何差別。
//   - 接線被旗標／條件包住，執行期從未走到。
//
// 後果與該守衛檔頭自陳的一致：停用／解綁／provider 撤銷**永久靜默失效**，
// 既不 panic 也不報錯，操作照回 200、審計照寫「已撤銷」——只有攻擊者會發現。
// 這是安全紅線（授權繞過），故補一條與名稱無關的軸。
//
// **本格的軸**：跑真的段 2（完整解封），再以反射檢查服務圖上實際存在的
// identity 服務實例，其**介面型欄位**是否全數非 nil。它不讀 stage2.go 的原始碼、
// 不看呼叫點形狀、不看接收者變數名——接線改寫成迴圈、搬到別的檔、改成建構子
// 參數，本格照樣成立；而上述三種「呼叫還在、效果沒發生」的形態一律轉紅。
//
// **誠實界定**：本格證的是「生產組裝完成後管道非 nil」，不證「管道接到正確的
// 對象」（接到一個非 nil 的 no-op 樁仍會綠）。後者屬登記項語義漂移的範圍，
// 不在本格射程。行為面由各模組既有的撤銷矩陣測試涵蓋——但那些測試
// **自己在 fixture 裡接線**，故它們證不了生產組裝有接（testing.md §5 形態 9）。

// revocationRuntimeTargetNames 需要「介面型欄位全數非 nil」的服務型別。
//
// 以型別（而非圖上的路徑）指名：handler 之間的持有關係重構時本格不需跟著改。
var revocationRuntimeTargets = []reflect.Type{
	reflect.TypeOf(&identity.UserService{}),
	reflect.TypeOf(&identity.OIDCProviderService{}),
}

// revocationRuntimeNilAllowed 生產組裝完成後**允許**留 nil 的介面欄位。
//
// key＝`型別#欄位名`。**空集合是目標態**：新增一列等於宣告「這條依賴生產不接」，
// SHALL 附理由並經安全審查——nil 容忍的欄位一律是「靜默失效」的候選。
var revocationRuntimeNilAllowed = map[string]string{}

// minRevocationIfaceFields 每個目標型別的介面欄位數下限。
//
// 三條撤銷管道各佔一個介面欄。若有人把管道從介面欄改成 func 欄或具體型別欄，
// 本格的 nil 檢查會掃到空集合而假綠——這條下限就是那個形態的 tripwire。
const minRevocationIfaceFields = 3

// TestRevocationChannelsWiredAtRuntime 生產組裝完成後，撤銷管道實際非 nil。
func TestRevocationChannelsWiredAtRuntime(t *testing.T) {
	env := newSealIntegrationEnv(t)

	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("初始化解封回 %d：%s\n　　段 2 沒跑起來，本格的接線斷言將無從談起",
			w.Code, w.Body.String())
	}
	snap := env.machine.Snapshot()
	graph, ok := snap.Services.(*appGraph)
	if !ok || graph == nil {
		t.Fatalf("解封後取不到 *appGraph（實得 %T）：服務圖不可觀測即等於沒有本守衛", snap.Services)
	}

	want := map[reflect.Type]bool{}
	for _, typ := range revocationRuntimeTargets {
		want[typ] = true
	}
	found := map[reflect.Type][]reflect.Value{}
	walkServiceGraph(reflect.ValueOf(graph), want, found, map[serviceVisitKey]bool{}, 0)

	for _, typ := range revocationRuntimeTargets {
		insts := found[typ]
		if len(insts) == 0 {
			t.Fatalf("服務圖上找不到 %s 的實例：本格的斷言會在空集合下假綠。"+
				"若該服務已不由段 2 建構或已改名，SHALL 顯式更新 revocationRuntimeTargets", typ)
		}
		ifaceFields := 0
		for _, inst := range insts {
			elem := inst.Elem()
			structType := elem.Type()
			for i := 0; i < elem.NumField(); i++ {
				field := elem.Field(i)
				if field.Kind() != reflect.Interface {
					continue
				}
				ifaceFields++
				key := typ.String() + "#" + structType.Field(i).Name
				if !field.IsNil() {
					continue
				}
				if reason, exempt := revocationRuntimeNilAllowed[key]; exempt {
					t.Logf("具名例外 %s 為 nil：%s", key, reason)
					continue
				}
				t.Errorf("生產組裝完成後 %s 仍為 nil：該依賴採 nil 容忍，"+
					"未接線時相關操作會靜默跳過而不報錯（撤銷管道即屬此類，"+
					"後果是停用／解綁後既有存取存活）。"+
					"SHALL 於段 2 接線；確為刻意不接時 SHALL 具名登記於 "+
					"revocationRuntimeNilAllowed 並寫明理由", key)
			}
		}
		perInstance := ifaceFields / len(insts)
		if perInstance < minRevocationIfaceFields {
			t.Errorf("%s 只有 %d 個介面型欄位（下限 %d）：撤銷管道可能已改為非介面載體，"+
				"本格的 nil 檢查將掃到空集合而假綠", typ, perInstance, minRevocationIfaceFields)
		}
		// 偵測器健康度留痕：實例數為 0 或介面欄位數塌陷時本格會假綠，
		// 故把「這一輪實際檢查了什麼」印出來，使綠燈可被人審。
		t.Logf("%s：服務圖上 %d 個實例、每個 %d 個介面型欄位全數非 nil",
			typ, len(insts), perInstance)
	}
}

// serviceVisitKey 走訪去重鍵（型別＋指標身分）。
type serviceVisitKey struct {
	typ reflect.Type
	ptr uintptr
}

// serviceGraphWalkDepth 走訪深度上限（服務圖現況遠淺於此；防環與病態結構）。
const serviceGraphWalkDepth = 16

// inBackendModule 型別是否屬本 module（含組裝根 main 與未具名複合型別）。
// 用來把 gorm／gin／標準庫的內部結構排除在走訪之外。
func inBackendModule(typ reflect.Type) bool {
	for typ.Kind() == reflect.Ptr || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	pkg := typ.PkgPath()
	return pkg == "" || pkg == "main" || pkg == "github.com/custodexa/backend" ||
		strings.HasPrefix(pkg, "github.com/custodexa/backend/")
}

// walkServiceGraph 自服務圖走訪，收集 want 中型別的全部實例。
//
// 只讀 Kind／IsNil／Pointer，不呼叫 Interface()，故未匯出欄位同樣可走訪——
// 這正是「不依賴匯出面」的關鍵：本格不需要為了觀測而新增任何匯出符號。
func walkServiceGraph(v reflect.Value, want map[reflect.Type]bool,
	found map[reflect.Type][]reflect.Value, seen map[serviceVisitKey]bool, depth int) {
	if !v.IsValid() || depth > serviceGraphWalkDepth {
		return
	}
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return
		}
		typ := v.Type()
		key := serviceVisitKey{typ: typ, ptr: v.Pointer()}
		if seen[key] {
			return
		}
		seen[key] = true
		if want[typ] {
			found[typ] = append(found[typ], v)
			return
		}
		if !inBackendModule(typ) {
			return
		}
		walkServiceGraph(v.Elem(), want, found, seen, depth+1)
	case reflect.Interface:
		if v.IsNil() {
			return
		}
		walkServiceGraph(v.Elem(), want, found, seen, depth+1)
	case reflect.Struct:
		if !inBackendModule(v.Type()) {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			walkServiceGraph(v.Field(i), want, found, seen, depth+1)
		}
	case reflect.Slice:
		if v.IsNil() || !inBackendModule(v.Type()) {
			return
		}
		for i := 0; i < v.Len(); i++ {
			walkServiceGraph(v.Index(i), want, found, seen, depth+1)
		}
	case reflect.Array:
		if !inBackendModule(v.Type()) {
			return
		}
		for i := 0; i < v.Len(); i++ {
			walkServiceGraph(v.Index(i), want, found, seen, depth+1)
		}
	case reflect.Map:
		if v.IsNil() || !inBackendModule(v.Type()) {
			return
		}
		for _, k := range v.MapKeys() {
			walkServiceGraph(v.MapIndex(k), want, found, seen, depth+1)
		}
	}
}
