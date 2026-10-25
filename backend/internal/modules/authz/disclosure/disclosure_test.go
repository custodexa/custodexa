package disclosure

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestCountProducesIntegerOnlyForCountingKinds 三條計數類例外輸出整數；
// 名稱衝突例外、登錄外的值與負數都得到不可序列化的零值。
func TestCountProducesIntegerOnlyForCountingKinds(t *testing.T) {
	for _, k := range []Kind{OutOfScopeAssetCount, OutOfScopeNodeCount, NodeDeleteScopeReferenced} {
		v := Count(k, 3)
		if !v.Valid() || v.Kind() != k {
			t.Fatalf("Count(%s, 3) 應為合法值，得到 valid=%v kind=%v", k, v.Valid(), v.Kind())
		}
		b, err := json.Marshal(v)
		if err != nil || string(b) != "3" {
			t.Fatalf("Count(%s, 3) 序列化應為 3，得到 %q（err=%v）", k, b, err)
		}
		if v.String() != "3" {
			t.Fatalf("Count(%s, 3).String() 應為 3，得到 %q", k, v.String())
		}
		if b, _ := json.Marshal(Count(k, 0)); string(b) != "0" {
			t.Fatalf("Count(%s, 0) 序列化應為 0，得到 %q", k, b)
		}
	}
	for name, v := range map[string]Value{
		"名稱衝突例外不輸出計數":   Count(GlobalNameConflict, 1),
		"登錄外的 Kind":     Count(Kind(0), 1),
		"登錄外的 Kind(99)": Count(Kind(99), 1),
		"負數":            Count(OutOfScopeNodeCount, -1),
		"零值":            {},
	} {
		if v.Valid() {
			t.Fatalf("%s：應為零值", name)
		}
		if _, err := json.Marshal(v); err == nil {
			t.Fatalf("%s：零值序列化應失敗", name)
		}
		if _, err := json.Marshal(map[string]any{FieldCount: v}); err == nil {
			t.Fatalf("%s：零值放進 map 序列化也應失敗", name)
		}
		if v.String() != "" {
			t.Fatalf("%s：零值 String() 應為空字串，得到 %q", name, v.String())
		}
	}
}

// TestCarrierFieldsFlattenWithRegistryNames 嵌入載體後，外層 JSON 出現的欄名
// 等於登錄常數，值為整數，且外層其他欄位不被吃掉。
func TestCarrierFieldsFlattenWithRegistryNames(t *testing.T) {
	type row struct {
		ID int `json:"id"`
		AssetCountField
		NodeCountField
	}
	b, err := json.Marshal(row{
		ID:              7,
		AssetCountField: AssetCountField{OutOfScopeAssetCount: AssetCountValue{Count(OutOfScopeAssetCount, 2)}},
		NodeCountField:  NodeCountField{OutOfScopeNodeCount: NodeCountValue{Count(OutOfScopeNodeCount, 5)}},
	})
	if err != nil {
		t.Fatalf("序列化失敗: %v", err)
	}
	want := `{"id":7,"out_of_scope_asset_count":2,"out_of_scope_node_count":5}`
	if string(b) != want {
		t.Fatalf("得到 %s，want %s", b, want)
	}
	if _, err := json.Marshal(row{ID: 1}); err == nil {
		t.Fatal("載體留零值時序列化應失敗（未經 Count 的計數不得默默送出）")
	}

	tags := map[string]string{}
	for _, c := range []any{AssetCountField{}, NodeCountField{}} {
		rt := reflect.TypeOf(c)
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if f.Type.Kind() != reflect.Struct || f.Type.NumField() != 1 ||
				!f.Type.Field(0).Anonymous || f.Type.Field(0).Type != reflect.TypeOf(Value{}) {
				t.Fatalf("%s.%s 的型別應為只嵌入 Value 的欄位型別，得到 %s", rt.Name(), f.Name, f.Type)
			}
			tags[rt.Name()] = strings.Split(f.Tag.Get("json"), ",")[0]
		}
	}
	if tags["AssetCountField"] != FieldOutOfScopeAssetCount || tags["NodeCountField"] != FieldOutOfScopeNodeCount {
		t.Fatalf("載體 JSON 欄名與登錄常數不一致：%v", tags)
	}
}

// TestCarrierFieldsRejectWrongKind 載體欄位裝了別種例外的計數時序列化失敗；
// 種類相符時照常輸出。單獨序列化欄位值與嵌入外層後序列化都要成立。
func TestCarrierFieldsRejectWrongKind(t *testing.T) {
	type row struct {
		ID int `json:"id"`
		AssetCountField
		NodeCountField
	}
	ok := row{
		AssetCountField: AssetCountField{OutOfScopeAssetCount: AssetCountValue{Count(OutOfScopeAssetCount, 1)}},
		NodeCountField:  NodeCountField{OutOfScopeNodeCount: NodeCountValue{Count(OutOfScopeNodeCount, 1)}},
	}
	if _, err := json.Marshal(ok); err != nil {
		t.Fatalf("種類相符應可序列化: %v", err)
	}
	for name, c := range map[string]struct {
		field any
		outer row
	}{
		"台數欄裝節點計數": {
			field: AssetCountValue{Count(OutOfScopeNodeCount, 7)},
			outer: row{AssetCountField: AssetCountField{OutOfScopeAssetCount: AssetCountValue{Count(OutOfScopeNodeCount, 7)}},
				NodeCountField: ok.NodeCountField},
		},
		"台數欄裝刪除引用數": {
			field: AssetCountValue{Count(NodeDeleteScopeReferenced, 7)},
			outer: row{AssetCountField: AssetCountField{OutOfScopeAssetCount: AssetCountValue{Count(NodeDeleteScopeReferenced, 7)}},
				NodeCountField: ok.NodeCountField},
		},
		"節點欄裝台數": {
			field: NodeCountValue{Count(OutOfScopeAssetCount, 7)},
			outer: row{AssetCountField: ok.AssetCountField,
				NodeCountField: NodeCountField{OutOfScopeNodeCount: NodeCountValue{Count(OutOfScopeAssetCount, 7)}}},
		},
		"節點欄裝刪除引用數": {
			field: NodeCountValue{Count(NodeDeleteScopeReferenced, 7)},
			outer: row{AssetCountField: ok.AssetCountField,
				NodeCountField: NodeCountField{OutOfScopeNodeCount: NodeCountValue{Count(NodeDeleteScopeReferenced, 7)}}},
		},
	} {
		if b, err := json.Marshal(c.field); !errors.Is(err, errWrongKind) {
			t.Errorf("%s：欄位值序列化應回種類不符錯誤，得到 %s（err=%v）", name, b, err)
		}
		if b, err := json.Marshal(c.outer); err == nil || !strings.Contains(err.Error(), errWrongKind.Error()) {
			t.Errorf("%s：嵌入外層後序列化應回種類不符錯誤，得到 %s（err=%v）", name, b, err)
		}
	}
	for name, v := range map[string]any{"台數欄零值": AssetCountValue{}, "節點欄零值": NodeCountValue{}} {
		if _, err := json.Marshal(v); !errors.Is(err, errUnbuilt) {
			t.Errorf("%s：序列化應回未建構錯誤，得到 err=%v", name, err)
		}
	}
}

// TestEntriesAreCopies 呼叫端改動回傳值不影響登錄。
func TestEntriesAreCopies(t *testing.T) {
	a := Entries()
	a[1].Fields[0] = "tampered"
	a[0].Name = "tampered"
	b := Entries()
	if b[1].Fields[0] != FieldOutOfScopeNodeCount || b[0].Name != "OutOfScopeAssetCount" {
		t.Fatal("Entries 回傳值被改動後影響了登錄本身")
	}
	if GlobalNameConflict.String() != "GlobalNameConflict" || Kind(42).String() != "Kind(42)" {
		t.Fatalf("Kind.String 不符：%s／%s", GlobalNameConflict, Kind(42))
	}
}
