package vtscreen

import (
	"strconv"
	"strings"
	"testing"
)

// 記憶體上限的可觀測性（design.md D14 第 11 條）。
//
// 上限本身是必要的阻斷（防惡意輸出把容器吃爆），但**靜默丟字是審計產品最不能有的失效形態**：
// 還原出的文字少了字，卻沒有任何人知道。故 Screen 必須能回答「我有沒有丟過東西」，
// 由呼叫端記一行降級日誌。

// TestScreenDroppedFalseOnNormalInput 釘死「正常輸入下恆為假」——
// 這條若鬆掉，降級日誌會在每條指令上噴一次，形同沒有訊號。
func TestScreenDroppedFalseOnNormalInput(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"單純指令", "ssh-test-server:~$ ls -la"},
		{"退格修正", "lss\b\x1b[K"},
		{"清行重繪", "rm -rf /tmp/x\r" + strings.Repeat("\x1b[C", 19) + "\x1b[K" + "echo safe"},
		{"多行輸出", "line1\r\nline2\r\nline3\r\n"},
		{"CJK 與 emoji", "echo 中文測試 \U0001F389 ok"},
		{"行內插入與刪除", "abcdef\x1b[3D\x1b[6@xy\x1b[1P"},
		{"清畫面", "\x1b[H\x1b[2Jprompt$ "},
		{"截斷的控制序列", "ls -la\x1b[12;"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := New()
			s.Write([]byte(c.input))
			if s.Dropped() {
				t.Errorf("正常輸入不得標記為丟棄：%q", c.input)
			}
		})
	}

	// Seed 過的螢幕同樣不得誤報
	s := New()
	s.Seed("ssh-test-server:~$ ", 19)
	s.Write([]byte("echo safe"))
	if s.Dropped() {
		t.Error("種入原點後的正常輸入不得標記為丟棄")
	}
}

// TestScreenDroppedTrueOnLimitHit 對三種上限各餵一次，斷言旗標為真。
func TestScreenDroppedTrueOnLimitHit(t *testing.T) {
	t.Run("maxCols：越過單列欄數上限的寫入", func(t *testing.T) {
		s := New()
		// CHA 到最大欄之後再右移，寫入時必然越界
		s.Write([]byte("\x1b[" + strconv.Itoa(maxCols-1) + "G\x1b[10CX"))
		if !s.Dropped() {
			t.Error("越過 maxCols 的寫入被靜默丟棄，卻沒有標記")
		}
	})

	t.Run("maxCells：累計配置超過全螢幕上限", func(t *testing.T) {
		s := New()
		var b strings.Builder
		// 每列都定位到極右欄再寫入，數列之後即撞上 cell 總數上限
		for row := 1; row <= 8; row++ {
			b.WriteString("\x1b[" + strconv.Itoa(row) + ";60000HX")
		}
		s.Write([]byte(b.String()))
		if !s.Dropped() {
			t.Error("撞上 maxCells 而放棄寫入，卻沒有標記")
		}
	})

	t.Run("maxRows：換行超過列數上限", func(t *testing.T) {
		s := New()
		s.Write([]byte(strings.Repeat("\n", maxRows+1)))
		if !s.Dropped() {
			t.Error("換行超過 maxRows 使其後內容與最後一列相疊，卻沒有標記")
		}
	})
}

// TestScreenDroppedResetBySeed 斷言 Seed 重置螢幕時一併重置丟棄狀態——
// 否則上一條指令的丟棄會被算到下一條頭上。
func TestScreenDroppedResetBySeed(t *testing.T) {
	s := New()
	s.Write([]byte("\x1b[" + strconv.Itoa(maxCols-1) + "G\x1b[10CX"))
	if !s.Dropped() {
		t.Fatal("前置條件未成立：這一段輸入本應觸發丟棄")
	}
	s.Seed("prompt$ ", 8)
	if s.Dropped() {
		t.Error("Seed 未重置丟棄狀態")
	}
}
