package main

import (
	"strings"
	"testing"
)

// 寫入回應對照守衛的比較器本身：該報錯的輸入確實報錯，該放行的確實放行。比較器若過寬，主線守衛
// 會在寫入回應真的出錯時照樣全綠，故以反例逐條固定。

func TestWriteResponseComparator(t *testing.T) {
	absentInRead := wrOmission{"only_write": {wrAbsentInRead, "測試用：讀取回應沒有這個鍵"}}
	absentInWrite := wrOmission{"only_read": {wrAbsentInWrite, "測試用：寫入回應沒有這個鍵"}}

	mustReport := []struct {
		name        string
		write, read map[string]any
		omit        wrOmission
		wantKey     string
	}{
		{"omitted_key_present_on_both_sides_with_different_values",
			map[string]any{"only_write": "a"}, map[string]any{"only_write": "b"}, absentInRead, "only_write"},
		{"omitted_as_absent_in_read_but_only_read_has_it",
			map[string]any{}, map[string]any{"only_write": "x"}, absentInRead, "only_write"},
		{"omitted_as_absent_in_write_but_write_has_it",
			map[string]any{"only_read": "x"}, map[string]any{}, absentInWrite, "only_read"},
		{"omitted_as_absent_in_write_present_on_both_sides_with_different_values",
			map[string]any{"only_read": 1.0}, map[string]any{"only_read": 2.0}, absentInWrite, "only_read"},
		{"empty_object_vs_empty_array",
			map[string]any{"member_sources": map[string]any{}}, map[string]any{"member_sources": []any{}}, nil, "member_sources"},
		{"empty_object_vs_missing",
			map[string]any{"member_sources": map[string]any{}}, map[string]any{}, nil, "member_sources"},
		{"empty_object_vs_null",
			map[string]any{"member_sources": map[string]any{}}, map[string]any{"member_sources": nil}, nil, "member_sources"},
		{"nested_empty_object_vs_missing_nested_key",
			map[string]any{"obj": map[string]any{"inner": map[string]any{}}}, map[string]any{"obj": map[string]any{}}, nil, "obj"},
		{"null_vs_false",
			map[string]any{"flag": nil}, map[string]any{"flag": false}, nil, "flag"},
		{"empty_array_vs_zero",
			map[string]any{"n": []any{}}, map[string]any{"n": 0.0}, nil, "n"},
		{"unlisted_key_only_in_write",
			map[string]any{"extra": "x"}, map[string]any{}, nil, "extra"},
		{"same_instant_timestamps_with_different_strings",
			map[string]any{"t": "2099-01-01T00:00:00.123456789Z"}, map[string]any{"t": "2099-01-01T00:00:00.123456Z"}, nil, "t"},
		{"same_instant_timestamps_in_different_zones",
			map[string]any{"t": "2099-01-01T08:00:00.123456+08:00"}, map[string]any{"t": "2099-01-01T00:00:00.123456Z"}, nil, "t"},
	}
	for _, tc := range mustReport {
		t.Run("reports_"+tc.name, func(t *testing.T) {
			d := wrDiff(tc.write, tc.read, tc.omit)
			if len(d) == 0 {
				t.Fatalf("應報出 %s，比較器卻放行", tc.wantKey)
			}
			found := false
			for _, line := range d {
				if strings.HasPrefix(line, tc.wantKey+" ") {
					found = true
				}
			}
			if !found {
				t.Fatalf("應報出 %s，實際 %v", tc.wantKey, d)
			}
		})
	}

	mustPass := []struct {
		name        string
		write, read map[string]any
		omit        wrOmission
	}{
		{"missing_null_and_empty_array_are_equivalent",
			map[string]any{"a": nil, "b": []any{}}, map[string]any{"b": nil, "c": []any{}}, nil},
		{"omitted_key_really_absent_in_read",
			map[string]any{"only_write": "x"}, map[string]any{}, absentInRead},
		{"omitted_key_really_absent_in_write",
			map[string]any{}, map[string]any{"only_read": "x"}, absentInWrite},
		{"omitted_key_present_on_both_sides_with_equal_values",
			map[string]any{"only_write": "x"}, map[string]any{"only_write": "x"}, absentInRead},
		{"identical_timestamp_strings",
			map[string]any{"t": "2099-01-01T00:00:00.123456Z"}, map[string]any{"t": "2099-01-01T00:00:00.123456Z"}, nil},
		{"nested_empty_array_vs_missing_nested_key",
			map[string]any{"obj": map[string]any{"inner": []any{}}}, map[string]any{"obj": map[string]any{}}, nil},
	}
	for _, tc := range mustPass {
		t.Run("passes_"+tc.name, func(t *testing.T) {
			if d := wrDiff(tc.write, tc.read, tc.omit); len(d) != 0 {
				t.Fatalf("不應報錯：%v", d)
			}
		})
	}

	t.Run("sub_microsecond_timestamps_are_reported", func(t *testing.T) {
		got := wrSubMicro(map[string]any{"a": "2099-01-01T00:00:00.1234567Z", "b": "2099-01-01T00:00:00.123456Z",
			"c": []any{map[string]any{"d": "2099-01-01T08:00:00.123456789+08:00"}}, "e": "not a time", "f": "2099-01-01T00:00:00Z"}, "")
		want := []string{"a：2099-01-01T00:00:00.1234567Z", "c[0].d：2099-01-01T08:00:00.123456789+08:00"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("微秒以下位數的時間戳：得 %v，應為 %v", got, want)
		}
	})

	t.Run("every_omission_names_a_side_and_a_reason", func(t *testing.T) {
		for _, set := range []wrOmission{wrOmitTimestampsWriteOnly, wrOmitWinrmCACert,
			wrOmitUserDetailProjections, wrOmitCredentialAggregateState} {
			for k, o := range set {
				if o.absent != wrAbsentInRead && o.absent != wrAbsentInWrite {
					t.Errorf("窄清單項目 %s 沒有指明哪一邊沒有", k)
				}
				if strings.TrimSpace(o.why) == "" {
					t.Errorf("窄清單項目 %s 沒有理由", k)
				}
			}
		}
	})
}
