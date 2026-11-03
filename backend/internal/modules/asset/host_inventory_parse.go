package asset

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/model"
)

// 結束原因碼的套件內別名。
const (
	inventoryReasonHostKeyMismatch    = model.InventoryHostKeyMismatch
	inventoryReasonHostKeyCheckFailed = model.InventoryHostKeyCheckFailed
	inventoryReasonLoginFailed        = model.InventoryLoginFailed
	inventoryReasonConnectionFailed   = model.InventoryConnectionFailed
	inventoryReasonTimeout            = model.InventoryTimeout
	inventoryReasonCommandFailed      = model.InventoryCommandFailed
	inventoryReasonOutputLimit        = model.InventoryOutputLimit
	inventoryReasonOutputMalformed    = model.InventoryOutputMalformed
)

// invAccountRow 合併後的一個主機帳號。
type invAccountRow struct {
	Name   string
	UID    string // 第一列的 uid
	GIDs   []uint64
	Shells []string
	UID0   bool // 任一列 uid 為 0
	// UIDConflict 同名各列 uid 不全相同
	UIDConflict bool
}

// invGroup 合併後的一個群組。
type invGroup struct {
	Name    string
	GIDs    []uint64
	Members map[string]bool
}

// invListStats 帳號或群組清單的計數。
type invListStats struct {
	Rows          int
	Invalid       int // 不合格而排除的列數
	DuplicateRows int // 同名多出的列數
}

// validInventoryName 帳號／群組名：合法 UTF-8、1–256 位元組、不含 `:`、換行、NUL 與其他 Cc。
// 格式字元（Cf）不排除：排除會讓名稱含零寬字元的特權帳號從結果中消失。
func validInventoryName(name string) bool {
	if name == "" || len(name) > inventoryMaxAccountNameSz || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r == ':' || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func parseUintField(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

// splitInventoryLines 依換行切列並檢查單行長度；結尾空列略過。
func splitInventoryLines(data []byte, sess inventorySessionID, maxRows int) ([]string, error) {
	if len(data) == 0 {
		return nil, nil
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxRows {
		return nil, invErr(inventoryReasonOutputLimit, sess, fmt.Sprintf("rows>%d", maxRows))
	}
	for i, l := range lines {
		if len(l) > inventoryMaxLineBytes {
			return nil, invErr(inventoryReasonOutputLimit, sess, fmt.Sprintf("line=%d length", i+1))
		}
	}
	return lines, nil
}

// parseInventoryAccounts 解析 getent passwd：7 欄；不合格列排除並計數；同名多列合併。
func parseInventoryAccounts(data []byte) ([]*invAccountRow, invListStats, error) {
	var st invListStats
	lines, err := splitInventoryLines(data, inventorySessionAccounts, inventoryMaxAccountRows)
	if err != nil {
		return nil, st, err
	}
	byName := map[string]*invAccountRow{}
	var order []*invAccountRow
	for _, l := range lines {
		if l == "" {
			continue
		}
		st.Rows++
		f := strings.Split(l, ":")
		if len(f) != 7 || !validInventoryName(f[0]) {
			st.Invalid++
			continue
		}
		uid, ok1 := parseUintField(f[2])
		gid, ok2 := parseUintField(f[3])
		if !ok1 || !ok2 {
			st.Invalid++
			continue
		}
		uidStr := strconv.FormatUint(uid, 10)
		row := byName[f[0]]
		if row == nil {
			row = &invAccountRow{Name: f[0], UID: uidStr}
			byName[f[0]] = row
			order = append(order, row)
		} else {
			st.DuplicateRows++
			if row.UID != uidStr {
				row.UIDConflict = true
			}
		}
		if uid == 0 {
			row.UID0 = true
		}
		row.GIDs = append(row.GIDs, gid)
		row.Shells = append(row.Shells, f[6])
	}
	return order, st, nil
}

// parseInventoryGroup 解析 getent group：4 欄，或成員為空時的 3 欄（部分 libc 在成員清單為空時
// 不輸出結尾冒號）；同名多列成員取聯集、gid 取集合。
func parseInventoryGroup(data []byte) (map[string]*invGroup, invListStats, error) {
	var st invListStats
	lines, err := splitInventoryLines(data, inventorySessionGroup, inventoryMaxGroupRows)
	if err != nil {
		return nil, st, err
	}
	out := map[string]*invGroup{}
	for _, l := range lines {
		if l == "" {
			continue
		}
		st.Rows++
		f := strings.Split(l, ":")
		if len(f) == 3 {
			f = append(f, "")
		}
		if len(f) != 4 || !validInventoryName(f[0]) {
			st.Invalid++
			continue
		}
		gid, ok := parseUintField(f[2])
		if !ok {
			st.Invalid++
			continue
		}
		g := out[f[0]]
		if g == nil {
			g = &invGroup{Name: f[0], Members: map[string]bool{}}
			out[f[0]] = g
		} else {
			st.DuplicateRows++
		}
		g.GIDs = append(g.GIDs, gid)
		if f[3] != "" {
			for _, m := range strings.Split(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					g.Members[m] = true
				}
			}
		}
	}
	return out, st, nil
}

// 檢查項狀態。
const (
	invStateChecked    = "checked"
	invStatePartial    = "partial"
	invStateUnreadable = "unreadable"
	invStateAbsent     = "absent"
	invStateFailed     = "failed"
	// invStateUndetermined 前提項目讀不到，這一項無從判斷（只用於 sudo 規則中無法解析的項目）。
	invStateUndetermined = "undetermined"
)

// invSudoFile 規則目錄中的一個檔。
type invSudoFile struct {
	Name     string
	Readable bool
	Content  []byte
}

// invSudoFrames sudo 段解碼後的內容。
type invSudoFrames struct {
	SudoPresent bool
	MainState   string // absent／unreadable／ok
	Main        []byte
	DirState    string
	Files       []invSudoFile

	// 提權讀取（專用帳號身分）併入後的標記。
	Escalated         bool // 內容改用提權讀取的快照
	EscDenied         bool // 提權讀取被拒，未提權讀取讀不到的項目原因改記 escalation_denied
	DirPartialUnknown bool // 規則目錄無從核對是否有檔被略過
	Unparsable        int  // 封存中無法解析的項目數
}

func decodeHexField(s string) ([]byte, bool) {
	if len(s)%2 != 0 {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}

// parseInventorySudoFrames 解析 sudo 段的列；不符文法即 INVENTORY_OUTPUT_MALFORMED。
func parseInventorySudoFrames(data []byte) (*invSudoFrames, error) {
	malformed := func(line int) error {
		return invErr(inventoryReasonOutputMalformed, inventorySessionSudo, fmt.Sprintf("line=%d", line))
	}
	fr := &invSudoFrames{}
	var gotP, gotM, gotD bool
	total := 0
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	for i, l := range lines {
		n := i + 1
		f := strings.Fields(l)
		if len(f) == 0 {
			return nil, malformed(n)
		}
		switch f[0] {
		case "P":
			if gotP || len(f) != 2 || (f[1] != "0" && f[1] != "1") {
				return nil, malformed(n)
			}
			gotP, fr.SudoPresent = true, f[1] == "1"
		case "M":
			if gotM || len(f) < 2 {
				return nil, malformed(n)
			}
			gotM = true
			switch {
			case f[1] == "ok" && len(f) <= 3:
				fr.MainState = "ok"
				if len(f) == 3 {
					b, ok := decodeHexField(f[2])
					if !ok {
						return nil, malformed(n)
					}
					fr.Main = b
				}
			case (f[1] == "absent" || f[1] == "unreadable") && len(f) == 2:
				fr.MainState = f[1]
			default:
				return nil, malformed(n)
			}
			total += len(fr.Main)
			if len(fr.Main) > inventoryMaxLineBytes*2 {
				return nil, invErr(inventoryReasonOutputLimit, inventorySessionSudo, "main_bytes")
			}
		case "D":
			if gotD || len(f) != 2 || (f[1] != "ok" && f[1] != "absent" && f[1] != "unreadable") {
				return nil, malformed(n)
			}
			gotD, fr.DirState = true, f[1]
		case "F":
			if !gotD || fr.DirState != "ok" || len(f) < 3 {
				return nil, malformed(n)
			}
			name, ok := decodeHexField(f[1])
			if !ok || len(name) == 0 {
				return nil, malformed(n)
			}
			file := invSudoFile{Name: string(name)}
			switch {
			case f[2] == "ok" && len(f) <= 4:
				file.Readable = true
				if len(f) == 4 {
					b, ok := decodeHexField(f[3])
					if !ok {
						return nil, malformed(n)
					}
					file.Content = b
				}
			case f[2] == "unreadable" && len(f) == 3:
			default:
				return nil, malformed(n)
			}
			fr.Files = append(fr.Files, file)
			if len(fr.Files) > inventoryMaxSudoFiles {
				return nil, invErr(inventoryReasonOutputLimit, inventorySessionSudo, "files")
			}
			total += len(file.Content)
		default:
			return nil, malformed(n)
		}
		if total > inventoryMaxSudoBytes {
			return nil, invErr(inventoryReasonOutputLimit, inventorySessionSudo, "sudo_bytes")
		}
	}
	if !gotP || !gotM || !gotD {
		return nil, malformed(len(lines))
	}
	// 解碼後的單行長度上限
	for _, c := range append([][]byte{fr.Main}, contents(fr.Files)...) {
		for _, l := range bytes.Split(c, []byte("\n")) {
			if len(l) > inventoryMaxLineBytes {
				return nil, invErr(inventoryReasonOutputLimit, inventorySessionSudo, "line_length")
			}
		}
	}
	return fr, nil
}

func contents(files []invSudoFile) [][]byte {
	out := make([][]byte, 0, len(files))
	for _, f := range files {
		out = append(out, f.Content)
	}
	return out
}

// parseInventoryUID 解析 uid 段的 id -u。
func parseInventoryUID(data []byte) (uint64, error) {
	v, ok := parseUintField(strings.TrimSpace(string(data)))
	if !ok {
		return 0, invErr(inventoryReasonOutputMalformed, inventorySessionUID, "uid")
	}
	return v, nil
}
