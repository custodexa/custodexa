package policy

import (
	"errors"
	"strings"
	"testing"
)

// The DEK cache lifetime key is the first policy key with a three-state domain
// (empty = unlimited, 0 = no cache, N > 0 = fixed lifetime). These tests pin the
// new AllowEmpty column's guard and the key's own value domain.

// TestAllowEmptyGuardRejectsMisuse 「空值合法」欄的結構自檢：
// 只可用於 int 型、且該鍵出廠值必為空。兩個方向都要擋——非 int 型設了會被
// 靜默忽略，Default 非空則「未設定」不再是出廠態，本欄語義落空。
func TestAllowEmptyGuardRejectsMisuse(t *testing.T) {
	cases := []struct {
		name string
		def  PolicyDef
		want string
	}{
		{
			name: "非 int 型不得設 AllowEmpty",
			def:  PolicyDef{Key: "probe_bool", Type: PolicyTypeBool, Default: "false", AllowEmpty: true},
			want: "僅 int 型有空值語義",
		},
		{
			name: "AllowEmpty 的鍵出廠值必為空",
			def:  PolicyDef{Key: "probe_int", Type: PolicyTypeInt, Default: "30", AllowEmpty: true, Max: 100},
			want: "空值須為出廠態",
		},
		{
			// 突變方向：既有 int 鍵（未開 AllowEmpty）帶空值 Default 必須紅燈，
			// 否則新欄等於對所有 int 鍵默默放行空字串
			name: "未開 AllowEmpty 的 int 鍵不得以空值為出廠值",
			def:  PolicyDef{Key: "probe_plain_int", Type: PolicyTypeInt, Default: "", Max: 100},
			want: "須為非負整數",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateDefList([]PolicyDef{c.def})
			if err == nil {
				t.Fatalf("定義 %+v 通過自檢，預期紅燈", c.def)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("錯誤 = %v，預期含 %q", err, c.want)
			}
		})
	}
	// 正向：合法形狀（int＋空 Default）必須通過，否則上面三格可能是誤傷
	ok := PolicyDef{Key: "probe_ok", Type: PolicyTypeInt, Default: "", AllowEmpty: true, ZeroDisables: true, Max: 100}
	if err := validateDefList([]PolicyDef{ok}); err != nil {
		t.Errorf("合法定義被拒: %v", err)
	}
}

// TestDekCacheTTLValueDomain 三態值域與非法值：空值／0／正整數通過，
// 負數、非整數與超上界被拒且政策維持原值。
func TestDekCacheTTLValueDomain(t *testing.T) {
	def := mustDef(t, PolicyDekCacheTTLSeconds)
	if def.Default != "" {
		t.Fatalf("出廠預設 = %q, want 空值（不限期）", def.Default)
	}
	if def.Direction != "" {
		t.Errorf("Direction = %q, want 空（本鍵不做符合性評估）", def.Direction)
	}
	if !def.AllowEmpty || !def.ZeroDisables {
		t.Fatalf("AllowEmpty=%v ZeroDisables=%v, want 皆為 true", def.AllowEmpty, def.ZeroDisables)
	}
	if def.Max <= 0 {
		t.Errorf("Max = %d, want 有限上界", def.Max)
	}

	svc, _ := setupPolicyDB(t)
	for _, good := range []string{"", "0", "1", "300", "86400"} {
		if _, err := svc.UpdateBatch(map[string]string{PolicyDekCacheTTLSeconds: good}, "admin"); err != nil {
			t.Errorf("合法值 %q 被拒: %v", good, err)
			continue
		}
		if got := svc.Get(PolicyDekCacheTTLSeconds); got != good {
			t.Errorf("存 %q 讀回 %q", good, got)
		}
	}
	// 落在合法值上，用來確認非法值不會改動現值
	if _, err := svc.UpdateBatch(map[string]string{PolicyDekCacheTTLSeconds: "300"}, "admin"); err != nil {
		t.Fatalf("設定基準值失敗: %v", err)
	}
	for _, bad := range []string{"-1", "abc", "1.5", "86401", " "} {
		if _, err := svc.UpdateBatch(map[string]string{PolicyDekCacheTTLSeconds: bad}, "admin"); err == nil {
			t.Errorf("非法值 %q 被接受", bad)
		} else if !errors.Is(err, ErrPolicyInvalidValue) {
			t.Errorf("非法值 %q 的錯誤不可辨識: %v", bad, err)
		}
		if got := svc.Get(PolicyDekCacheTTLSeconds); got != "300" {
			t.Fatalf("非法值 %q 後現值變成 %q，應維持 300", bad, got)
		}
	}
}

// TestDekCacheTTLNotInAnyPolicyGroup 本鍵不進任何內建政策組：
// 它是機構自選的風險預算旋鈕，掛上建議值等同宣稱某個秒數為合規要求。
func TestDekCacheTTLNotInAnyPolicyGroup(t *testing.T) {
	for _, seed := range builtinPolicyGroupSeeds() {
		for _, clause := range seed.Clauses {
			for _, ctl := range clause.Controls {
				if ctl.Key == PolicyDekCacheTTLSeconds {
					t.Errorf("政策組 %s 的條文 %s 對照了本鍵", seed.Code, clause.ClauseNo)
				}
			}
		}
	}
}

// TestDekCacheTTLChangeIsReportedForAudit 變更須被回報為 PolicyChange（old→new）：
// handler 的審計迴圈只審計 UpdateBatch 回報的項，漏報＝該鍵被靜默改掉而審計軌跡上沒有這筆。
func TestDekCacheTTLChangeIsReportedForAudit(t *testing.T) {
	svc, _ := setupPolicyDB(t)
	changes, err := svc.UpdateBatch(map[string]string{PolicyDekCacheTTLSeconds: "0"}, "admin")
	if err != nil {
		t.Fatalf("更新失敗: %v", err)
	}
	if len(changes) != 1 || changes[0].Key != PolicyDekCacheTTLSeconds ||
		changes[0].OldValue != "" || changes[0].NewValue != "0" {
		t.Fatalf("變更回報 = %+v, want 單筆 \"\"→\"0\"", changes)
	}
	// 空值改回也要回報：由 0（不留快取）回到不限期是安全語義的鬆綁，最需要留痕
	back, err := svc.UpdateBatch(map[string]string{PolicyDekCacheTTLSeconds: ""}, "admin")
	if err != nil {
		t.Fatalf("改回空值失敗: %v", err)
	}
	if len(back) != 1 || back[0].OldValue != "0" || back[0].NewValue != "" {
		t.Fatalf("改回空值的變更回報 = %+v, want 單筆 \"0\"→\"\"", back)
	}
	again, err := svc.UpdateBatch(map[string]string{PolicyDekCacheTTLSeconds: ""}, "admin")
	if err != nil {
		t.Fatalf("重複更新失敗: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("無變動仍回報 %+v：審計中不應出現 X→X", again)
	}
}
