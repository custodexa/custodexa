package keyvault_test

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// 重包回應形狀守衛：回應不得含任何 KEK 明文欄。
//
// 守衛做兩層：偵測器先以合成型別自證會抓（正向）、會放行乾淨型別（敏感度），
// 才拿去掃真正的 keyvault.KEKRewrapResult。缺了自證，「掃不到違規」等於什麼都沒證明。

// plaintextishFields 回報結構中疑似承載金鑰明文的 json 欄位。
//
// 判準：欄位名（json tag，無 tag 則用 Go 欄位名小寫）含 kek／material／secret／
// plaintext／password 任一，且**不是以 _id 結尾的識別欄**（指紋、ARN 等引用為
// 非機密，是刻意要回傳的）。
func plaintextishFields(v any) []string {
	var out []string
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.ToLower(f.Name)
		if tag := f.Tag.Get("json"); tag != "" && tag != "-" {
			name = strings.ToLower(strings.Split(tag, ",")[0])
		}
		if strings.HasSuffix(name, "_id") || strings.HasSuffix(name, "_ref") || strings.HasSuffix(name, "_mode") {
			continue
		}
		for _, needle := range []string{"kek", "material", "secret", "plaintext", "password"} {
			if strings.Contains(name, needle) {
				out = append(out, f.Name+"("+name+")")
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestPlaintextFieldDetectorSelfCheck 偵測器自證：抓得到明文欄、放得過引用欄
func TestPlaintextFieldDetectorSelfCheck(t *testing.T) {
	type withPlaintext struct {
		NewKEK   string `json:"new_kek"`
		NewKEKID string `json:"new_kek_id"`
	}
	if got := plaintextishFields(withPlaintext{}); len(got) != 1 || !strings.Contains(got[0], "new_kek)") {
		t.Fatalf("偵測器應且僅應抓到 new_kek，得 %v", got)
	}
	type cleanShape struct {
		TargetMode string `json:"target_mode"`
		NewKEKID   string `json:"new_kek_id"`
		KeyRef     string `json:"key_ref"`
		Rows       int    `json:"rewrapped_keys"`
	}
	if got := plaintextishFields(cleanShape{}); len(got) != 0 {
		t.Fatalf("引用欄不得被誤報為明文欄，得 %v", got)
	}
}

// TestRewrapResultHasNoPlaintextField keyvault.KEKRewrapResult 不得含明文欄，
// 且序列化後的鍵集恰為契約所定三鍵（多一個鍵就是回應形狀漂移）
func TestRewrapResultHasNoPlaintextField(t *testing.T) {
	if got := plaintextishFields(keyvault.KEKRewrapResult{}); len(got) != 0 {
		t.Fatalf("重包回應含 KEK 明文欄（禁止）: %v", got)
	}
	blob, err := json.Marshal(keyvault.KEKRewrapResult{TargetMode: keyvault.RewrapTargetModeLocal, NewKEKID: "abc", RewrappedKeys: 3})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"new_kek_id", "rewrapped_keys", "target_mode"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("重包回應鍵集 = %v，契約為 %v", keys, want)
	}
}
