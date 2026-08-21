package vtscreen

import "testing"

// fuzzSeeds 為模糊測試的種子語料。
// 前兩筆是行為基準內 legacy_panicked=true 的兩組輸入
// （testdata/behavior-baseline.json 的 synth/csi-truncated 與 synth/csi-truncated-params）——
// 被取代的實作在它們身上以負索引切片 panic。
var fuzzSeeds = []string{
	"ls -la\x1b[",
	"ls\x1b[12;",
	"ls -la\x1b",
	"\x1b]0;user@host: ~\x07prompt$ ls",
	"\x1b]0;title\x1b\\prompt$ ls",
	"55> \x1b[1Gab",
	"\x1b[1G55> SELECT name\x1b[0K\x1b[16G",
	"testuser@host:~$ echo hi\r\n",
	"abcdef\x1b[4D\x1b[2X\x1b[3@\x1b[2P",
	"l1\r\nl2\r\nl3\x1b[1Jtail",
	"中文測試\rX",
	"printf a\tb",
	"\x1b[?1049hvim\x1b[?1049l$ ",
	"\x1b[999;999H\x1b[9999@X",
	"\x1bPq;;\x1b\\ok",
}

// FuzzScreen 斷言三件事：
//  1. 任何位元組序列都不得使解析 panic；
//  2. 還原結果不得含任何控制位元組（否則控制序列的殘骸會進入審計文字）；
//  3. 分塊邊界不得改變結果——未完成的序列必須保留在狀態機內，而非被吐成文字。
func FuzzScreen(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		whole := Lines(data)
		assertNoControlBytes(t, "整段餵入", whole)

		// 逐位元組餵入（輸入較大時改用固定分塊，避免模糊測試變成效能測試）
		step := 1
		if len(data) > 512 {
			step = 64
		}
		s := New()
		for i := 0; i < len(data); i += step {
			end := i + step
			if end > len(data) {
				end = len(data)
			}
			s.Write(data[i:end])
		}
		chunked := s.Lines()
		assertNoControlBytes(t, "分塊餵入", chunked)

		if len(chunked) != len(whole) {
			t.Fatalf("分塊邊界改變了結果：行數 chunked=%d whole=%d", len(chunked), len(whole))
		}
		for i := range whole {
			if chunked[i] != whole[i] {
				t.Fatalf("分塊邊界改變了第 %d 行：chunked=%q whole=%q", i, chunked[i], whole[i])
			}
		}
	})
}

func assertNoControlBytes(t *testing.T, label string, lines []string) {
	t.Helper()
	for i, line := range lines {
		for _, r := range line {
			if r < 0x20 || r == 0x7F {
				t.Fatalf("%s：第 %d 行含控制位元組 %#U", label, i, r)
			}
		}
	}
}
