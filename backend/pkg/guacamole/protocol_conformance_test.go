package guacamole

import (
	"bufio"
	"strings"
	"testing"
)

// === Guacamole 協議長度前綴一致性（guacamole-protocol-conformance）===
//
// 缺陷：長度前綴原以 Go 的 `len()`（byte 數）產生與驗證，而規範規定是
// **Unicode codepoint 數**。中文一字三 byte，我方送出的前綴是規範值的三倍。
//
// **既有測試全綠證明不了任何事**——ASCII 下 byte == codepoint，缺陷完美隱形。
// 本檔的對照樣本全部由**官方實作實跑產生**（見下方 officialVectors 的取得方式），
// 不是我方自己算出來再拿來對自己：那只能證明自洽，不能證明符合規範。

// officialVectors 官方 guacamole-common-js 1.5.5 的 `Guacamole.Parser.toInstruction`
// 實跑輸出（2026-08-18，於 frontend 容器內以 node vm 沙箱載入
// `frontend/public/guacamole-1.5.5.min.js` 產生）。
//
// 該檔就是本產品前端實際載入、與後端對接的那一份，故它比 guacamole-server 的 C 端
// 更有直接效力——雙方訊框對不上時，使用者看到的就是黑畫面。
//
// 官方的長度定義見同檔 `Guacamole.Parser.codePointCount`：
// UTF-16 長度扣掉 surrogate pair 數 ＝ codepoint 數。故 emoji 算 1 而非 2。
var officialVectors = []struct {
	name     string
	opcode   string
	args     []string
	encoded  string
	whyItRun string
}{
	{
		name: "純 ASCII（回歸）", opcode: "select", args: []string{"rdp"},
		encoded:  "6.select,3.rdp;",
		whyItRun: "byte == codepoint，改動前後都必須相同",
	},
	{
		name: "中文帳密（握手 connect 走這條路）", opcode: "connect", args: []string{"使用者", "密碼123"},
		encoded:  "7.connect,3.使用者,5.密碼123;",
		whyItRun: "密碼政策明確允許中文密碼；前綴算成 byte 數會讓 guacd 依宣告長度等不到的字元而**靜默掛住**（實測非 PARSE_ERROR）",
	},
	{
		name: "值內含逗號的檔名", opcode: "put", args: []string{"1", "2", "報告,最終版.txt"},
		encoded:  "3.put,1.1,1.2,10.報告,最終版.txt;",
		whyItRun: "元素邊界只由長度前綴決定，值可合法含逗號——以 Split(\",\") 切分必錯",
	},
	{
		name: "值內含分號", opcode: "log", args: []string{"a;b"},
		encoded:  "3.log,3.a;b;",
		whyItRun: "同上，且 ReadString(';') 會在此提早截斷並使其後的串流全部失步",
	},
	{
		name: "中英混合", opcode: "blob", args: []string{"0", "混合abc中文"},
		encoded:  "4.blob,1.0,7.混合abc中文;",
		whyItRun: "混合輸入下 byte 數與 codepoint 數的差不是固定倍率",
	},
	{
		name: "emoji（4 byte／UTF-16 surrogate pair）", opcode: "clipboard", args: []string{"0", "emoji:😀"},
		encoded:  "9.clipboard,1.0,7.emoji:😀;",
		whyItRun: "釘死「codepoint 而非 UTF-16 code unit」：算 UTF-16 會得到 8，官方是 7",
	},
	{
		name: "無參數指令", opcode: "nop", args: nil,
		encoded:  "3.nop;",
		whyItRun: "邊界：只有 opcode",
	},
	{
		name: "空值參數", opcode: "x", args: []string{""},
		encoded:  "1.x,0.;",
		whyItRun: "邊界：長度 0 的元素，其後直接接終止符",
	},
}

// TestEncodeMatchesOfficialImplementation 我方 Encode 的輸出須逐位元組等同官方實作。
//
// **這是唯一能證明「符合規範」而非「自己跟自己一致」的測試。**
func TestEncodeMatchesOfficialImplementation(t *testing.T) {
	for _, v := range officialVectors {
		t.Run(v.name, func(t *testing.T) {
			got := NewInstruction(v.opcode, v.args...).Encode()
			if got != v.encoded {
				t.Errorf("Encode = %q\n官方   = %q\n（為什麼測這筆：%s）", got, v.encoded, v.whyItRun)
			}
		})
	}
}

// TestDecodeMatchesOfficialImplementation 官方編出來的位元組，我方須解得回原值。
func TestDecodeMatchesOfficialImplementation(t *testing.T) {
	for _, v := range officialVectors {
		t.Run(v.name, func(t *testing.T) {
			inst, err := DecodeInstruction(v.encoded)
			if err != nil {
				t.Fatalf("解碼官方樣本 %q 失敗: %v（為什麼測這筆：%s）", v.encoded, err, v.whyItRun)
			}
			if inst.Opcode != v.opcode {
				t.Errorf("Opcode = %q, want %q", inst.Opcode, v.opcode)
			}
			if len(inst.Args) != len(v.args) {
				t.Fatalf("Args = %q, want %q", inst.Args, v.args)
			}
			for i := range v.args {
				if inst.Args[i] != v.args[i] {
					t.Errorf("Args[%d] = %q, want %q", i, inst.Args[i], v.args[i])
				}
			}
		})
	}
}

// TestRoundTrip Decode(Encode(x)) == x。最能抓出兩側定義不一致。
func TestRoundTrip(t *testing.T) {
	for _, v := range officialVectors {
		t.Run(v.name, func(t *testing.T) {
			inst := NewInstruction(v.opcode, v.args...)
			back, err := DecodeInstruction(inst.Encode())
			if err != nil {
				t.Fatalf("往返解碼失敗: %v", err)
			}
			if back.Encode() != inst.Encode() {
				t.Errorf("往返後 = %q，原始 = %q", back.Encode(), inst.Encode())
			}
		})
	}
}

// TestReadInstructionStreamDoesNotDesync 串流失步：值內含 `;` 不得影響後續指令。
//
// 這條打的是 `client.go` 原先的 `reader.ReadString(';')`——它在值中間的分號處截斷，
// 殘渣留在 reader 裡，**其後每一個指令都錯位**。單看一個指令的解碼測不出來，
// 必須連讀兩個才會現形。
func TestReadInstructionStreamDoesNotDesync(t *testing.T) {
	stream := NewInstruction("log", "a;b").Encode() +
		NewInstruction("put", "1", "2", "報告,最終版.txt").Encode() +
		NewInstruction("select", "rdp").Encode()

	r := bufio.NewReader(strings.NewReader(stream))
	want := [][]string{
		{"log", "a;b"},
		{"put", "1", "2", "報告,最終版.txt"},
		{"select", "rdp"},
	}
	for i, w := range want {
		inst, err := ReadInstruction(r)
		if err != nil {
			t.Fatalf("第 %d 個指令讀取失敗: %v（串流已失步）", i+1, err)
		}
		got := append([]string{inst.Opcode}, inst.Args...)
		if strings.Join(got, "\x00") != strings.Join(w, "\x00") {
			t.Errorf("第 %d 個指令 = %q, want %q", i+1, got, w)
		}
	}
}

// TestDecodeFailsClosed 解析失敗仍須回 error 並丟棄，不得為了「盡量解析」而放寬。
func TestDecodeFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		data string
		why  string
	}{
		{"長度大於實際內容", "9.abc;", "宣告 9 個字元卻只有 3 個"},
		{"長度小於實際內容", "1.abc;", "讀滿 1 字元後該位置不是 ',' 或 ';'"},
		{"缺少長度前綴", "abc;", "沒有 '.' 分隔的長度"},
		{"長度非數字", "x.abc;", "長度欄含非數字"},
		{"缺少終止符", "3.abc", "讀完內容後沒有 ',' 或 ';'"},
		{"空字串", "", "沒有指令"},
		{"中文以 byte 數宣告（舊實作的產物）", "9.使用者;", "舊版會產生這種前綴，新版須拒絕"},
		{"指令後有殘留", "3.nop;3.nop;", "一則訊息只該有一個指令"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if inst, err := DecodeInstruction(c.data); err == nil {
				t.Errorf("解碼 %q 竟成功（= %+v），應 fail-closed：%s", c.data, inst, c.why)
			}
		})
	}
}

// TestReadInstructionRejectsOversizedElement 串流讀取的上界：長度前綴由對端宣告，
// 沒有上界等於讓對端指定我方配置多少記憶體。此上界是本次修法引入的新失敗面的封口。
func TestReadInstructionRejectsOversizedElement(t *testing.T) {
	oversized := "99999999.x;" // 遠超 maxElementRunes
	if _, err := DecodeInstruction(oversized); err == nil {
		t.Error("超長元素宣告竟被接受：對端可藉此指定我方配置任意記憶體")
	}
	tooManyDigits := strings.Repeat("9", maxLengthDigits+1) + ".x;"
	if _, err := DecodeInstruction(tooManyDigits); err == nil {
		t.Error("超長位數的長度前綴竟被接受")
	}
}
