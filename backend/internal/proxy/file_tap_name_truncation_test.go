package proxy

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// === 檔名截斷必須落在 rune 邊界（guacamole-protocol-conformance 5.4 撈出）===
//
// 原實作 `name[:fileAuditMaxName]` 是**位元組**切片。`fileAuditMaxName = 512`，
// 而 512 % 3 == 2，故中文檔名恰好在第 171 個字的中間被切斷，產生無效 UTF-8。
//
// **後果不是顯示難看**：Postgres 直接拒收該筆
// （`invalid byte sequence for encoding "UTF8": 0xe6 0xb8`），
// 而檔案傳輸審計是 fail-open（寫入失敗只記 log、不回壓會話）——
// 於是**檔案照常轉發、那筆留痕靜默消失**。
// 客戶端用一個夠長的中文檔名即可規避檔案傳輸留痕。
//
// 實測復現（真 VNC 會話 + 真 WebSocket）：
// 604 bytes 的中文檔名 → 新增審計 0 筆，log 出現上述 SQLSTATE 22021。
// `0xe6 0xb8` 正是「測」（e6 b8 ac）的前兩個位元組。

// TestTruncateAuditNameAlwaysValidUTF8 截斷結果恆為合法 UTF-8。
func TestTruncateAuditNameAlwaysValidUTF8(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"純中文超長（實測復現的形態）", strings.Repeat("測試報告", 151)}, // 604 個字 = 1812 bytes
		{"中文恰好跨越上限", strings.Repeat("測", 171)},          // 513 bytes，斷點落在第 171 字中間
		{"中英混合超長", strings.Repeat("報告abc", 200)},
		{"emoji 超長（4 位元組字元）", strings.Repeat("😀", 200)},
		{"純 ASCII 超長（回歸）", strings.Repeat("a", 1000)},
		{"未達上限的中文", "報告,最終版;測試.txt"},
		{"空字串", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := truncateAuditName(c.input)

			if !utf8.ValidString(got) {
				t.Errorf("截斷結果不是合法 UTF-8——Postgres 會拒收，"+
					"而審計是 fail-open，該筆留痕會靜默消失。len=%d", len(got))
			}
			if len(got) > fileAuditMaxName {
				t.Errorf("截斷後 %d bytes 超過上限 %d", len(got), fileAuditMaxName)
			}
			// 未超過上限者不得被改動
			if len(c.input) <= fileAuditMaxName && got != c.input {
				t.Errorf("未超過上限的檔名被改動：%q → %q", c.input, got)
			}
			// 截斷結果必須是原字串的前綴（不得產生原本不存在的內容）
			if !strings.HasPrefix(c.input, got) {
				t.Errorf("截斷結果不是原檔名的前綴——審計文字被竄改了")
			}
		})
	}
}

// TestTruncateAuditNamePreservesAsMuchAsPossible 截斷不得過度保守。
//
// 退到 rune 邊界最多只該退幾個位元組（UTF-8 單字元上限 4 bytes），
// 若實作圖省事直接退到某個固定位置，會平白丟掉大量檔名內容。
func TestTruncateAuditNamePreservesAsMuchAsPossible(t *testing.T) {
	input := strings.Repeat("測", 300) // 900 bytes
	got := truncateAuditName(input)

	if len(got) > fileAuditMaxName {
		t.Fatalf("超過上限：%d", len(got))
	}
	// 512 / 3 = 170 個完整的「測」= 510 bytes，故只該少 2 bytes
	if fileAuditMaxName-len(got) >= utf8.UTFMax {
		t.Errorf("截斷後 %d bytes，較上限 %d 少了 %d bytes——"+
			"退到 rune 邊界最多只需退 %d bytes，實作過度保守會丟失檔名內容",
			len(got), fileAuditMaxName, fileAuditMaxName-len(got), utf8.UTFMax-1)
	}
}

// TestTruncateAuditNameBoundaryIsByteNotRuneCount 上限的語義是**位元組**不是字元數。
//
// 該欄位的限制來自 DB 欄寬，故上限必須以位元組計。
// 若誤改成以 rune 計，600 個中文字（1800 bytes）會通過檢查而撐爆欄位。
func TestTruncateAuditNameBoundaryIsByteNotRuneCount(t *testing.T) {
	// 600 個中文字 = 1800 bytes，遠超 512 位元組上限但只有 600 個 rune
	input := strings.Repeat("測", 600)
	got := truncateAuditName(input)

	if len(got) > fileAuditMaxName {
		t.Errorf("600 個中文字截斷後仍有 %d bytes（上限 %d）——"+
			"上限被誤解為字元數，會撐爆 DB 欄位", len(got), fileAuditMaxName)
	}
}
