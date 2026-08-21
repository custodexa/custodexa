package sshproxy

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// B 層端到端重放（design.md D9 的 B 層協議、tasks 3.5）。
//
// 以真實錄製的 28 個情境重放 CommandParser：事件依錄製時的**原始 chunk 邊界**逐筆餵入，
// 最後斷言結算出的指令等於人工標註的 expected_command（標註依據為輸入方向的按鍵序列，
// 不是輸出反推）。
//
// 這一層守的是 A 層守不到的東西：A 層只看單次解析的螢幕還原，
// 而審計入庫的指令是「快照 prompt → 累積 echo → 剝除前綴 → 結算」整條鏈的產物；
// 偽證缺陷（使用者按 Ctrl-U 清掉的字仍入庫）正是在這條鏈上發生的。
//
// **接線前必有紅筆**：`ctrl-u-kill`／`bash-ctrl-u`／`psql-tab` 三筆在指令原點種入
// （tasks 4）完成前必定失敗，且失敗內容應為「入庫了使用者沒打過的指令」。
// 那是這組測試存在的理由，不是它的缺陷。

const (
	sshCaptureFile  = "../vtscreen/testdata/ssh-capture.json"
	psqlCaptureFile = "../vtscreen/testdata/psql-capture.json"

	// 情境數下限：與錄製當日一致，防止靠刪情境轉綠。
	sshCaptureScenarios  = 21
	psqlCaptureScenarios = 7
)

// captureEvent 為一筆錄製事件。dir 為 in（使用者按鍵）或 out（伺服器回顯）；
// data 是該次 read/write 的原始位元組，chunk 邊界即錄製當下的真實邊界。
type captureEvent struct {
	Dir  string `json:"dir"`
	MS   int    `json:"ms"`
	Data string `json:"data"`
}

// captureScenario 為一個錄製情境。
type captureScenario struct {
	Name                string         `json:"name"`
	Desc                string         `json:"desc"`
	Events              []captureEvent `json:"events"`
	ExpectedCommand     string         `json:"expected_command"`
	ExpectedCommandNote string         `json:"expected_command_note"`
}

// sessionTeardownInputs 為情境收尾用的按鍵序列（連同 Enter 一次送出）。
//
// expected_command 的標註判準是「該情境送出的最後一條**實質**指令，排除 session 收尾」，
// 因此比對前必須先把收尾那幾條扣掉。扣除的依據取自**輸入方向**——那是使用者真正按了什麼的
// 唯一事實源；若改以「結算出的字串是否等於 exit」來扣，收尾指令一旦被重組錯
// （實測 ctrl-c 情境即得到 `ssh-test-server:~$ exit`）就扣不掉，比對會拿實質指令去對收尾指令，
// 紅在錯的地方。
//
// 收尾指令本身有沒有被重組正確，由 TestCaptureReplayTeardownCommandIntact 單獨守住，
// 不會因為這裡扣掉而失去覆蓋。
var sessionTeardownInputs = [][]byte{
	[]byte("exit\r"),
	[]byte(`\q` + "\r"),
}

// trailingTeardownInputs 數出情境尾端連續有幾個收尾按鍵事件
// （bash 子 shell 的情境會有兩個 exit）。
func trailingTeardownInputs(sc captureScenario) []string {
	var ins [][]byte
	for _, ev := range sc.Events {
		if ev.Dir != "in" {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(ev.Data)
		if err != nil {
			return nil
		}
		ins = append(ins, data)
	}
	var teardown []string
	for i := len(ins) - 1; i >= 0; i-- {
		matched := ""
		for _, t := range sessionTeardownInputs {
			if string(ins[i]) == string(t) {
				matched = strings.TrimSuffix(string(t), "\r")
				break
			}
		}
		if matched == "" {
			break
		}
		teardown = append([]string{matched}, teardown...)
	}
	return teardown
}

func loadCapture(t *testing.T, path string) []captureScenario {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取錄製檔 %s 失敗：%v", path, err)
	}
	var scenarios []captureScenario
	if err := json.Unmarshal(raw, &scenarios); err != nil {
		t.Fatalf("解析錄製檔 %s 失敗：%v", path, err)
	}
	return scenarios
}

// replayScenario 以原始 chunk 邊界重放一個情境，回傳 CommandParser 發出的所有指令。
func replayScenario(t *testing.T, sc captureScenario, protocol string) []string {
	t.Helper()
	var emitted []string
	p := NewCommandParser(func(command string, _ time.Time) {
		emitted = append(emitted, command)
	}, protocol)

	for i, ev := range sc.Events {
		data, err := base64.StdEncoding.DecodeString(ev.Data)
		if err != nil {
			t.Fatalf("情境 %s 第 %d 筆事件的 data 解碼失敗：%v", sc.Name, i, err)
		}
		switch ev.Dir {
		case "in":
			p.WriteInput(data)
		case "out":
			p.WriteOutput(data)
		default:
			t.Fatalf("情境 %s 第 %d 筆事件的 dir 非法：%q", sc.Name, i, ev.Dir)
		}
	}
	p.Flush()
	return emitted
}

// assertScenarioCommand 斷言該情境結算出的最後一條實質指令等於標註值。
func assertScenarioCommand(t *testing.T, sc captureScenario, protocol string) {
	t.Helper()
	if sc.ExpectedCommand == "" {
		t.Fatalf("情境 %s 沒有 expected_command：沒有標註就沒有斷言，等於這個情境沒被測", sc.Name)
	}

	emitted := replayScenario(t, sc, protocol)
	teardown := trailingTeardownInputs(sc)
	if len(emitted) <= len(teardown) {
		t.Fatalf("情境 %s（%s）扣掉 %d 條收尾指令後一條實質指令都不剩\n"+
			"  期望：%q\n  發出的全部指令：%s",
			sc.Name, sc.Desc, len(teardown), sc.ExpectedCommand, formatCommands(emitted))
	}
	substantive := emitted[:len(emitted)-len(teardown)]

	got := substantive[len(substantive)-1]
	if got != sc.ExpectedCommand {
		t.Errorf("情境 %s（%s）入庫的指令與使用者實際送出的不符\n"+
			"  期望（依輸入方向按鍵序列標註）：%q\n"+
			"  實得（CommandParser 結算值）  ：%q\n"+
			"  發出的全部指令：%s\n"+
			"  標註依據：%s",
			sc.Name, sc.Desc, sc.ExpectedCommand, got,
			formatCommands(emitted), sc.ExpectedCommandNote)
	}
}

func formatCommands(cmds []string) string {
	if len(cmds) == 0 {
		return "（零條）"
	}
	parts := make([]string, 0, len(cmds))
	for _, c := range cmds {
		b, err := json.Marshal(c)
		if err != nil {
			parts = append(parts, c)
			continue
		}
		parts = append(parts, string(b))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// TestCaptureReplaySSHScenarios 重放 21 個真實 SSH 情境（protocol=ssh，逐行結算）。
func TestCaptureReplaySSHScenarios(t *testing.T) {
	scenarios := loadCapture(t, sshCaptureFile)
	t.Logf("SSH 錄製情境數：%d（下限 %d）", len(scenarios), sshCaptureScenarios)
	if len(scenarios) < sshCaptureScenarios {
		t.Fatalf("SSH 情境數 %d 低於下限 %d：情境只准增不准減", len(scenarios), sshCaptureScenarios)
	}
	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			assertScenarioCommand(t, sc, "ssh")
		})
	}
}

// TestCaptureReplayPsqlScenarios 重放 7 個真實 psql 情境（protocol=postgres，走 sqlMode 累積）。
func TestCaptureReplayPsqlScenarios(t *testing.T) {
	scenarios := loadCapture(t, psqlCaptureFile)
	t.Logf("psql 錄製情境數：%d（下限 %d）", len(scenarios), psqlCaptureScenarios)
	if len(scenarios) < psqlCaptureScenarios {
		t.Fatalf("psql 情境數 %d 低於下限 %d：情境只准增不准減", len(scenarios), psqlCaptureScenarios)
	}
	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			assertScenarioCommand(t, sc, "postgres")
		})
	}
}

// TestCaptureReplayTeardownCommandIntact 斷言收尾指令本身也要被正確重組。
//
// 收尾的 `exit`／`\q` 是使用者一次按完、連 Enter 一起送出的完整指令文字，
// 螢幕重組沒有任何理由把它變成別的東西。它之所以獨立成一條測試，是因為
// assertScenarioCommand 依輸入方向把尾端這幾條扣掉了——扣掉是為了讓實質指令的比對
// 不被收尾污染帶偏，但扣掉的部分必須另有人守，否則就成了測試的盲區。
func TestCaptureReplayTeardownCommandIntact(t *testing.T) {
	for _, tc := range []struct {
		file     string
		protocol string
	}{
		{sshCaptureFile, "ssh"},
		{psqlCaptureFile, "postgres"},
	} {
		for _, sc := range loadCapture(t, tc.file) {
			sc, protocol := sc, tc.protocol
			t.Run(sc.Name, func(t *testing.T) {
				teardown := trailingTeardownInputs(sc)
				if len(teardown) == 0 {
					t.Skipf("情境 %s 沒有以 exit／\\q 收尾", sc.Name)
				}
				emitted := replayScenario(t, sc, protocol)
				if len(emitted) < len(teardown) {
					t.Fatalf("情境 %s 送出 %d 條收尾指令，卻只結算出 %d 條指令：%s",
						sc.Name, len(teardown), len(emitted), formatCommands(emitted))
				}
				got := emitted[len(emitted)-len(teardown):]
				for i := range teardown {
					if got[i] == teardown[i] {
						continue
					}
					// 已知缺口棘輪（清單與移除條件見 command_parser_capture_replay_gap_test.go）：
					// 只有「情境名 + 實測結算值」兩者同時對上清單，這一筆才不算失敗。
					// 清單本身是否仍與實際失敗集合精確相等，由
					// TestCaptureReplayKnownTeardownGapsAreExact 逐輪把關——
					// 缺口被修好、缺口形態改變、或出現清單外的新失敗，那條測試都會轉紅。
					if gap, ok := knownTeardownGaps[sc.Name]; ok && gap.gotCommand == got[i] {
						t.Logf("情境 %s 命中已知缺口：入庫 %q（使用者按的是 %q）\n  成因：%s\n  依據：%s\n  移除條件：%s",
							sc.Name, got[i], teardown[i], gap.reason, gap.designRef, gap.removalCondition)
						continue
					}
					t.Errorf("情境 %s 的第 %d 條收尾指令被重組成別的文字\n"+
						"  使用者按的  ：%q\n"+
						"  入庫的      ：%q\n"+
						"  發出的全部指令：%s",
						sc.Name, i+1, teardown[i], got[i], formatCommands(emitted))
				}
			})
		}
	}
}

// TestCaptureReplayEveryScenarioIsAsserted 防假綠：每個情境都必須有 expected_command，
// 否則該情境雖被重放卻沒有任何斷言，看起來有覆蓋、實際上沒有。
func TestCaptureReplayEveryScenarioIsAsserted(t *testing.T) {
	total, named := 0, map[string]bool{}
	for _, path := range []string{sshCaptureFile, psqlCaptureFile} {
		for _, sc := range loadCapture(t, path) {
			total++
			if sc.Name == "" {
				t.Errorf("%s 內有情境缺少 name", path)
				continue
			}
			if named[sc.Name] {
				t.Errorf("情境名稱重複：%s（重複名稱會使情境數被灌水）", sc.Name)
			}
			named[sc.Name] = true
			if strings.TrimSpace(sc.ExpectedCommand) == "" {
				t.Errorf("情境 %s 缺少 expected_command", sc.Name)
			}
			if len(sc.Events) == 0 {
				t.Errorf("情境 %s 沒有任何事件", sc.Name)
			}
		}
	}
	t.Logf("B 層情境總數：%d（唯一名稱 %d）", total, len(named))
	if want := sshCaptureScenarios + psqlCaptureScenarios; total < want {
		t.Fatalf("B 層情境總數 %d 低於下限 %d", total, want)
	}
}

// TestCaptureReplayFabricatedCommandSamples 把三筆偽證樣本單獨釘死（design.md D4.4）。
//
// 它們與上面的逐情境斷言重疊是刻意的：D4.4 是本 change 的核心驗收面，
// 需要一個名字就說得出「這裡驗的是什麼」的測試，而不是淹沒在 21 個子測試裡。
// 除了「等於使用者實際送出的指令」，另外斷言「入庫文字不得含使用者已清除的片段」——
// 前者是正面條件，後者直接描述偽證的形態。
func TestCaptureReplayFabricatedCommandSamples(t *testing.T) {
	cases := []struct {
		file     string
		name     string
		protocol string
		// forbidden 是使用者按 Ctrl-U／補全後已從螢幕清除、絕不該入庫的片段。
		forbidden string
	}{
		{sshCaptureFile, "ctrl-u-kill", "ssh", "rm -rf"},
		{sshCaptureFile, "bash-ctrl-u", "ssh", "rm -rf"},
		{psqlCaptureFile, "psql-tab", "postgres", "FRO"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			sc, ok := findScenario(loadCapture(t, c.file), c.name)
			if !ok {
				t.Fatalf("找不到情境 %s：偽證樣本不得自錄製檔消失", c.name)
			}
			emitted := replayScenario(t, sc, c.protocol)
			for _, cmd := range emitted {
				if strings.Contains(cmd, c.forbidden) {
					t.Errorf("情境 %s 入庫了使用者已清除的片段 %q：\n  指令=%q\n  使用者實際送出的是 %q",
						c.name, c.forbidden, cmd, sc.ExpectedCommand)
				}
			}
			assertScenarioCommand(t, sc, c.protocol)
		})
	}
}

// TestCaptureReplayCorrectBehaviorSample 反面對照組：bash-tab-ambiguous 的現行行為本來就正確。
//
// 它的作用是把「重放方式」本身釘死——若這一筆也紅，代表重放路徑與產品實際路徑不符
// （測試有問題），而不是產品有問題。
func TestCaptureReplayCorrectBehaviorSample(t *testing.T) {
	sc, ok := findScenario(loadCapture(t, sshCaptureFile), "bash-tab-ambiguous")
	if !ok {
		t.Fatal("找不到情境 bash-tab-ambiguous：反面對照組不得消失")
	}
	assertScenarioCommand(t, sc, "ssh")
}

func findScenario(scenarios []captureScenario, name string) (captureScenario, bool) {
	for _, sc := range scenarios {
		if sc.Name == name {
			return sc, true
		}
	}
	return captureScenario{}, false
}
