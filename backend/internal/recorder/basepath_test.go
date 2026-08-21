package recorder

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// naiveGraphicsPath 修法前 internal/proxy/handler.go 的字串拼接寫法，逐字保留於此。
// 每個「Join 的結果 != 拼接的結果」前置條件都以它為對照組——少了這一條，
// 底下的相等斷言在任何實作下都會成立（恆真式假綠）。
func naiveGraphicsPath(basePath string, sessionID uint) string {
	return fmt.Sprintf("%s/session-%d.guac", basePath, sessionID)
}

func TestResolveBasePath(t *testing.T) {
	t.Run("注入值優先於環境變數", func(t *testing.T) {
		t.Setenv("RECORDING_PATH", "/from/env")
		if got := ResolveBasePath("/injected"); got != "/injected" {
			t.Fatalf("ResolveBasePath(\"/injected\") = %q，期望 /injected", got)
		}
	})

	t.Run("空字串退回環境變數", func(t *testing.T) {
		t.Setenv("RECORDING_PATH", "/from/env")
		if got := ResolveBasePath(""); got != "/from/env" {
			t.Fatalf("ResolveBasePath(\"\") = %q，期望 /from/env", got)
		}
	})

	t.Run("環境變數未設時退回出廠預設", func(t *testing.T) {
		os.Unsetenv("RECORDING_PATH")
		if got := ResolveBasePath(""); got != DefaultBasePath {
			t.Fatalf("ResolveBasePath(\"\") = %q，期望 %q", got, DefaultBasePath)
		}
	})

	// 運維把目錄路徑寫成帶尾斜線是再自然不過的事，而錄影根會被逐字存進
	// sessions.recording_path；未正規化就會與 filepath.Walk 的 clean 輸出對不上。
	t.Run("尾斜線與重複斜線一律正規化", func(t *testing.T) {
		const clean = "/var/lib/custodexa/recordings"
		// 需要正規化的輸入：每一筆的原字串都 != clean，故「結果等於 clean」
		// 只有在真的做了正規化時才成立
		for _, in := range []string{
			clean + "/",
			clean + "///",
			"/var/lib//custodexa/./recordings/",
			"/var/lib/custodexa/tmp/../recordings",
		} {
			if in == clean {
				t.Fatalf("前置條件不成立：輸入 %q 本來就是正規形態", in)
			}
			if got := ResolveBasePath(in); got != clean {
				t.Errorf("ResolveBasePath(%q) = %q，期望 %q", in, got, clean)
			}
		}
		// 已是正規形態者不得被亂動
		if got := ResolveBasePath(clean); got != clean {
			t.Errorf("ResolveBasePath(%q) = %q，期望原樣", clean, got)
		}
	})

	t.Run("環境變數帶尾斜線同樣被正規化", func(t *testing.T) {
		t.Setenv("RECORDING_PATH", "/var/lib/custodexa/recordings/")
		got := ResolveBasePath("")
		if got != "/var/lib/custodexa/recordings" {
			t.Fatalf("ResolveBasePath(\"\") = %q，期望 /var/lib/custodexa/recordings", got)
		}
	})
}

// TestGraphicsRecordingPath_MatchesWalkOutput 釘住本次修的缺陷本體：圖形錄影路徑
// 是寫進 sessions.recording_path 的字串，而清理端拿 filepath.Walk 的輸出做
// `WHERE recording_path = ?` 精確比對。兩者只要有一邊沒正規化，檔案刪得掉、DB 欄位
// 清不掉，UI 就留下「可回放」但檔案不存在的死列。
func TestGraphicsRecordingPath_MatchesWalkOutput(t *testing.T) {
	tmpDir := t.TempDir()
	rawBase := tmpDir + "/" // 運維在 RECORDING_PATH 尾端多打一條斜線
	const sessionID = uint(77)

	// 前置條件只用標準庫描述**夾具**：這個 rawBase 下，拼接與正規化必然分歧。
	// 刻意不拿受測函式的輸出當前置條件——那會讓「改回拼接」在前置條件處就中止，
	// 底下真正的斷言反而永遠跑不到。
	naive := naiveGraphicsPath(rawBase, sessionID)
	want := filepath.Join(filepath.Clean(rawBase), fmt.Sprintf("session-%d.guac", sessionID))
	if naive == want {
		t.Fatalf("前置條件不成立：此夾具下拼接與正規化同值（%q），測不到缺陷", naive)
	}

	got := GraphicsRecordingPath(rawBase, sessionID)
	if got != want {
		t.Fatalf("GraphicsRecordingPath = %q，期望 %q", got, want)
	}

	// 實際落檔後由 Walk 取回路徑——比對的是真正的檔案系統遍歷輸出，不是再算一次 Join
	if err := os.WriteFile(got, []byte("guac"), 0600); err != nil {
		t.Fatalf("建立測試錄影檔失敗: %v", err)
	}
	var walked []string
	err := filepath.Walk(rawBase, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			walked = append(walked, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk 失敗: %v", err)
	}
	if len(walked) != 1 {
		t.Fatalf("期望遍歷到 1 個檔案，實得 %v", walked)
	}
	if walked[0] != got {
		t.Fatalf("寫入端路徑 %q 與 Walk 產出 %q 不一致——clearRecordingInDB 將永遠命不中", got, walked[0])
	}
	// 反證：拼接版本確實對不上 Walk，證明上面的相等不是巧合
	if naive == walked[0] {
		t.Fatalf("夾具失效：拼接版本也對得上 Walk（%q）", naive)
	}
}

func TestGraphicsTempRecordingPath_Normalized(t *testing.T) {
	tmpDir := t.TempDir()
	rawBase := tmpDir + "/"
	got := GraphicsTempRecordingPath(rawBase, "rdp-1755123456789000000")
	want := filepath.Join(tmpDir, "rdp-1755123456789000000")
	if got != want {
		t.Fatalf("GraphicsTempRecordingPath = %q，期望 %q", got, want)
	}
	// 對照組＝修法前的拼接寫法 fmt.Sprintf("%s/%s", basePath, recordingName)
	if naive := fmt.Sprintf("%s/%s", rawBase, "rdp-1755123456789000000"); got == naive {
		t.Fatalf("前置條件不成立：此 base 下拼接與 Join 同值（%q），測不到正規化", naive)
	}
}

// TestAsciicastRecorder_HonorsInjectedBasePath 文字錄影端的對稱守衛：建構子曾把注入的
// basePath 整個丟棄、Start 一律重讀 RECORDING_PATH，注入形同裝飾。此處刻意讓 env 指向
// 另一個目錄，唯有真正採用注入值才會通過。
func TestAsciicastRecorder_HonorsInjectedBasePath(t *testing.T) {
	envDir := t.TempDir()
	injectedDir := t.TempDir()
	t.Setenv("RECORDING_PATH", envDir)

	start := time.Date(2025, 10, 20, 12, 0, 0, 0, time.UTC)
	rec := NewAsciicastRecorder(injectedDir + "/") // 注入值同樣帶尾斜線
	if err := rec.Start(RecordingMetadata{SessionID: 88, Protocol: "ssh", Width: 80, Height: 24, StartTime: start}); err != nil {
		t.Fatalf("Start 失敗: %v", err)
	}
	defer rec.Stop()

	want := filepath.Join(injectedDir, "2025-10-20", "session-88.cast")
	if got := rec.GetFilePath(); got != want {
		t.Fatalf("錄影落檔於 %q，期望 %q（注入的 basePath 未被採用或未正規化）", got, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("期望路徑上沒有檔案: %v", err)
	}
}
