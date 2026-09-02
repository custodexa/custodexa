package dbconsole

import (
	"math"
	"strings"
	"testing"
	"time"
)

// 值的文字化與型別分類。
//
// 這一層的失效**沒有症狀**：畫面上仍然是一個看起來正常的數字，只是它已經不是
// 目標端的那個數字了。故每一條都以逐字元相等斷言，不用「約等於」。

func TestTextifyPreservesExactText(t *testing.T) {
	cases := []struct {
		name string
		in   any
		kind Kind
		want string
	}{
		{"driver 文字原文", []byte("9223372036854775807"), KindInteger, "9223372036854775807"},
		{"30 位 decimal", []byte("123456789012345678901234567.890"), KindDecimal, "123456789012345678901234567.890"},
		{"微秒時戳原文", []byte("2026-09-02 13:45:06.123456"), KindDateTime, "2026-09-02 13:45:06.123456"},
		{"字串", "hello", KindText, "hello"},
		{"布林", true, KindBool, "true"},
		{"int64 最大值", int64(math.MaxInt64), KindInteger, "9223372036854775807"},
		{"int64 最小值", int64(math.MinInt64), KindInteger, "-9223372036854775808"},
		{"二進位以佔位呈現", []byte{0x00, 0x01, 0x02}, KindBinary, "<bytes 3>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := textify(tc.in, tc.kind)
			if got == nil {
				t.Fatal("值不得為 nil")
			}
			if *got != tc.want {
				t.Errorf("文字化 = %q, want %q", *got, tc.want)
			}
		})
	}

	if textify(nil, KindText) != nil {
		t.Error("SQL NULL 必須是 nil——與空字串合流之後，畫面與 CSV 都分不出這一格有沒有值")
	}
}

// TestFormatFloatSpecialValues 浮點特殊值走字面而非 null。
//
// 換成 null 就變成「這一格是 NULL」，那是另一件事：NaN 是目標端真實回傳的值。
func TestFormatFloatSpecialValues(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{math.NaN(), "NaN"},
		{math.Inf(1), "Infinity"},
		{math.Inf(-1), "-Infinity"},
		{0, "0"},
		{-0.5, "-0.5"},
	}
	for _, tc := range cases {
		if got := formatFloat(tc.in); got != tc.want {
			t.Errorf("formatFloat(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestTimeTextKeepsPrecisionAndZone 時間值不換算時區、不截精度。
func TestTimeTextKeepsPrecisionAndZone(t *testing.T) {
	loc := time.FixedZone("UTC+8", 8*3600)
	ts := time.Date(2026, 9, 2, 13, 45, 6, 123456000, loc)

	got := textify(ts, KindDateTime)
	if got == nil {
		t.Fatal("時間值不得為 nil")
	}
	if !strings.Contains(*got, "123456") {
		t.Errorf("微秒被截掉了：%s", *got)
	}
	if !strings.Contains(*got, "+08:00") {
		t.Errorf("時區被換算掉了：%s——一換算，同一筆資料在主控台與命令列上就長得不一樣", *got)
	}
}

func TestTruncateCell(t *testing.T) {
	short := strings.Repeat("a", 100)
	if got, cut := truncateCell(short); cut || got != short {
		t.Errorf("未逾上限的值不得被動：cut=%v", cut)
	}

	long := strings.Repeat("b", MaxCellBytes+500)
	got, cut := truncateCell(long)
	if !cut {
		t.Fatal("逾上限的值未被截斷")
	}
	if !strings.HasSuffix(got, "bytes]") {
		t.Errorf("截斷標記未附上：%.40s…", got)
	}
	if !strings.Contains(got, "500") {
		t.Errorf("標記未說明被丟掉多少位元組：%s", got[len(got)-40:])
	}

	// 多位元組字元不得被切成半個序列：半個 UTF-8 序列在 JSON 編碼後會變成
	// 替代字元，那看起來像資料本身有問題
	multi := strings.Repeat("中", MaxCellBytes) // 每字 3 bytes
	cutText, _ := truncateCell(multi)
	body := strings.Split(cutText, "…[")[0]
	for _, r := range body {
		if r == '�' {
			t.Fatal("截斷點落在字元中間，產生了替代字元")
		}
	}
}

func TestKindOf(t *testing.T) {
	cases := []struct {
		typeName string
		want     Kind
	}{
		{"VARCHAR(255)", KindText},
		{"TEXT", KindText},
		{"CHARACTER VARYING", KindText},
		{"BIGINT", KindInteger},
		{"int8", KindInteger},
		{"SERIAL", KindInteger},
		{"DECIMAL(18,4)", KindDecimal},
		{"NUMERIC", KindDecimal},
		{"MONEY", KindDecimal},
		{"DOUBLE PRECISION", KindFloat},
		{"float8", KindFloat},
		{"REAL", KindFloat},
		{"BOOL", KindBool},
		{"BIT", KindBool},
		{"TIMESTAMP WITH TIME ZONE", KindDateTime},
		{"datetime2", KindDateTime},
		{"DATE", KindDateTime},
		{"JSONB", KindJSON},
		{"BLOB", KindBinary},
		{"BYTEA", KindBinary},
		{"IMAGE", KindBinary},
		// VARBINARY 同時含 BINARY 與 CHAR 的片段：分類順序把二進位排在文字之前，
		// 順序一旦倒過來，一個二進位欄會被當成文字整份搬進畫面與 CSV
		{"VARBINARY(MAX)", KindBinary},
		{"", KindOther},
		{"GEOMETRY", KindOther},
	}
	for _, tc := range cases {
		if got := KindOf(tc.typeName); got != tc.want {
			t.Errorf("KindOf(%q) = %q, want %q", tc.typeName, got, tc.want)
		}
	}
}
