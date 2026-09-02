package dbconsole

import (
	"errors"
	"reflect"
	"testing"
)

// 執行單位的切分：只有 MSSQL 切，切點只認整行的 GO。
//
// 切錯的後果不是「多一個單位」而是「送出了一段被改寫過的 SQL」——
// 把 `SELECT 'GO'` 攔腰切開會產生兩個都不合法的批次，而使用者看到的錯誤訊息
// 完全指不到真正的原因。

func TestSplitUnitsNonMSSQLKeepsWholeText(t *testing.T) {
	text := "SELECT 1;\nGO\nSELECT 2;"
	for _, p := range []Protocol{ProtocolMySQL, ProtocolPostgres} {
		units, err := SplitUnits(p, text)
		if err != nil {
			t.Fatalf("%s 切分回錯: %v", p, err)
		}
		if len(units) != 1 || units[0] != text {
			t.Errorf("%s 的一次送出應為單一執行單位且逐位元組相同，實得 %#v", p, units)
		}
	}
}

func TestSplitUnitsMSSQL(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []string
	}{
		{"單一批次無 GO", "SELECT 1", []string{"SELECT 1"}},
		{"兩個批次", "SELECT 1\nGO\nSELECT 2", []string{"SELECT 1", "SELECT 2"}},
		{"小寫 go 同樣是終止符", "SELECT 1\ngo\nSELECT 2", []string{"SELECT 1", "SELECT 2"}},
		{"前後空白不影響判定", "SELECT 1\n   GO   \nSELECT 2", []string{"SELECT 1", "SELECT 2"}},
		{"CRLF 的行尾", "SELECT 1\r\nGO\r\nSELECT 2\r", []string{"SELECT 1\r", "SELECT 2\r"}},
		{"連續 GO 不產生空批次", "SELECT 1\nGO\nGO\nSELECT 2", []string{"SELECT 1", "SELECT 2"}},
		{"結尾的 GO 不產生空批次", "SELECT 1\nGO\n", []string{"SELECT 1"}},
		{"只有 GO", "GO", nil},
		{"全空白", "   \n\n  ", nil},
		// 以下三條是切分器最容易切錯的地方：GO 出現在行內或作為識別字的一部分
		{"行內的 GO 不是終止符", "SELECT 'GO'", []string{"SELECT 'GO'"}},
		{"GOTO 不是終止符", "GOTO label", []string{"GOTO label"}},
		{"GO 後接非數字不是終止符", "GO_SOMETHING", []string{"GO_SOMETHING"}},
		{"批次內保留原始換行", "SELECT 1\nFROM t\nGO\nSELECT 2", []string{"SELECT 1\nFROM t", "SELECT 2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			units, err := SplitUnits(ProtocolMSSQL, tc.text)
			if err != nil {
				t.Fatalf("切分回錯: %v", err)
			}
			if !reflect.DeepEqual(units, tc.want) {
				t.Errorf("切分結果 = %#v, want %#v", units, tc.want)
			}
		})
	}
}

// TestSplitUnitsRejectsGoCount `GO <n>` 明確拒絕，不靜默當成內容。
//
// 靜默送出去的話目標端會回一個語法錯誤，而使用者拿到的訊息不會告訴他
// 真正的原因是這裡不支援重複次數。
func TestSplitUnitsRejectsGoCount(t *testing.T) {
	for _, text := range []string{"SELECT 1\nGO 5", "SELECT 1\ngo 10\nSELECT 2", "SELECT 1\nGO 0"} {
		if _, err := SplitUnits(ProtocolMSSQL, text); !errors.Is(err, ErrGoCountUnsupported) {
			t.Errorf("%q 的錯誤 = %v, want ErrGoCountUnsupported", text, err)
		}
	}
	// 反向對照：非 MSSQL 方言不切分，`GO 5` 只是內容
	if _, err := SplitUnits(ProtocolMySQL, "SELECT 1\nGO 5"); err != nil {
		t.Errorf("MySQL 不切批次，GO 5 只是內容，卻回錯: %v", err)
	}
}

// TestQuoteIdentifier 識別字引用逐方言。
//
// 這不是通用的跳脫函式：它只用於系統自發的 `USE`，且傳入的名稱必須是目標端
// 目錄剛回傳的。它對付的是名稱裡合法出現的引用字元。
func TestQuoteIdentifier(t *testing.T) {
	cases := []struct {
		proto Protocol
		name  string
		want  string
	}{
		{ProtocolMySQL, "app", "`app`"},
		{ProtocolMySQL, "my db", "`my db`"},
		{ProtocolMySQL, "we`ird", "`we``ird`"},
		{ProtocolMSSQL, "app", "[app]"},
		{ProtocolMSSQL, "we]ird", "[we]]ird]"},
		{ProtocolPostgres, "app", `"app"`},
		{ProtocolPostgres, `we"ird`, `"we""ird"`},
	}
	for _, tc := range cases {
		if got := QuoteIdentifier(tc.proto, tc.name); got != tc.want {
			t.Errorf("%s 的 %q 引用為 %s, want %s", tc.proto, tc.name, got, tc.want)
		}
	}
}
