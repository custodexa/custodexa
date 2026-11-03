package asset

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

// 專用帳號身分的提權讀取：登入帳號不是 root 且 sudo 規則讀不到時，
// 以常數 tar 指令經 sudo 一次取回主規則檔與規則目錄。指令不經 sh -c、不拼接任何文字；
// 輸出邊界由 tar 格式界定，遠端無法偽造分段。

const inventorySessionEscalated inventorySessionID = "escalated"

// invFrameOK 是未提權讀取輸出的 M／D 列中的 ok 狀態字面值。
const invFrameOK = "ok"

const (
	// invReasonViaEscalation 該項內容經提權讀取取得。
	invReasonViaEscalation = "via_escalation"
	// invReasonEscalationDenied 該項原本讀不到，提權讀取也被拒。
	invReasonEscalationDenied = "escalation_denied"

	// 盤點結束審計 escalation 欄的值（只在專用帳號身分出現）。
	invEscalationNotNeeded = "not_needed"
	invEscalationUsed      = "used"
	invEscalationDenied    = "denied"
)

// 提權讀取的兩段常數指令。密碼只在第二段的 stdin，且是唯一一列。
const (
	inventoryEscalatedCmdNoPassword = `env LC_ALL=C sudo -n tar -cf - -C /etc sudoers sudoers.d`
	inventoryEscalatedCmdPassword   = `sudo -k -S -p '' tar -cf - -C /etc sudoers sudoers.d`

	inventoryMaxEscalatedBytes = 4 << 20
	// stderr 只用來選段，最多看前 4 KiB，不落地。
	inventoryEscalatedStderrCap = 4 << 10
	inventoryPasswordRequired   = "password is required"
)

type inventoryExecutorCtxKey struct{}

// withInventoryExecutor 標記這次盤點以專用帳號身分執行（collector 簽章不變，旗標走 ctx）。
func withInventoryExecutor(ctx context.Context) context.Context {
	return context.WithValue(ctx, inventoryExecutorCtxKey{}, true)
}

func inventoryExecutorFrom(ctx context.Context) bool {
	v, _ := ctx.Value(inventoryExecutorCtxKey{}).(bool)
	return v
}

// invEscArchive tar 封存解析後的內容。
type invEscArchive struct {
	Main       []byte
	HasMain    bool
	DirSeen    bool
	Files      []invSudoFile
	Unparsable int
}

// invEscalation 一次提權讀取的結果。Denied＝stdout 為空（sudo 拒絕或要求密碼）。
type invEscalation struct {
	Denied bool
	Exit   int
	Arch   *invEscArchive
}

// sudoFramesHaveUnreadable 未提權讀取中任一項讀不到才需要提權讀取。
func sudoFramesHaveUnreadable(fr *invSudoFrames) bool {
	if fr.MainState == invStateUnreadable || fr.DirState == invStateUnreadable {
		return true
	}
	for _, f := range fr.Files {
		if !f.Readable {
			return true
		}
	}
	return false
}

// parseEscalatedArchive 解析 tar 串流：只接受 sudoers（一般檔）、sudoers.d（目錄）與
// sudoers.d/<名>（一般檔，不再往下一層）；符號連結與其他型別計入無法解析的項目。
func parseEscalatedArchive(data []byte) (*invEscArchive, error) {
	malformed := func(detail string) error {
		return invErr(inventoryReasonOutputMalformed, inventorySessionEscalated, detail)
	}
	arch := &invEscArchive{}
	tr := tar.NewReader(bytes.NewReader(data))
	total := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, malformed("tar")
		}
		name := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
		isReg := h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA //nolint:staticcheck // 舊式一般檔旗標
		switch {
		case name == "sudoers":
			if !isReg {
				arch.Unparsable++
				continue
			}
			b, err := readEscalatedMember(tr, &total)
			if err != nil {
				return nil, err
			}
			arch.Main, arch.HasMain = b, true
		case name == "sudoers.d":
			if h.Typeflag == tar.TypeDir {
				arch.DirSeen = true
			} else {
				arch.Unparsable++
			}
		case strings.HasPrefix(name, "sudoers.d/"):
			rest := strings.TrimPrefix(name, "sudoers.d/")
			if rest == "" || strings.Contains(rest, "/") {
				continue
			}
			if h.Typeflag == tar.TypeDir {
				continue // 規則目錄裡的子目錄不遞迴
			}
			if !isReg {
				arch.Unparsable++
				continue
			}
			arch.DirSeen = true
			b, err := readEscalatedMember(tr, &total)
			if err != nil {
				return nil, err
			}
			arch.Files = append(arch.Files, invSudoFile{Name: rest, Readable: true, Content: b})
			if len(arch.Files) > inventoryMaxSudoFiles {
				return nil, invErr(inventoryReasonOutputLimit, inventorySessionEscalated, "files")
			}
		}
	}
	return arch, nil
}

func readEscalatedMember(tr *tar.Reader, total *int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(tr, inventoryMaxSudoBytes+1))
	if err != nil {
		return nil, invErr(inventoryReasonOutputMalformed, inventorySessionEscalated, "tar_body")
	}
	*total += len(b)
	if *total > inventoryMaxSudoBytes {
		return nil, invErr(inventoryReasonOutputLimit, inventorySessionEscalated, "sudo_bytes")
	}
	return b, nil
}

// classifyEscalatedOutput 以封存內容判定，不看退出碼：空＝被拒；合法且含 sudoers 一般檔＝成功；其餘＝格式不符。
func classifyEscalatedOutput(stdout []byte, exit int) (*invEscalation, error) {
	if len(stdout) == 0 {
		return &invEscalation{Denied: true, Exit: exit}, nil
	}
	arch, err := parseEscalatedArchive(stdout)
	if err != nil {
		return nil, err
	}
	if !arch.HasMain {
		return nil, invErr(inventoryReasonOutputMalformed, inventorySessionEscalated, "no_sudoers")
	}
	return &invEscalation{Exit: exit, Arch: arch}, nil
}

// applyEscalation 把提權讀取的結果併進未提權讀取的解碼內容，取一份一致的快照（不混用兩邊的內容）。
func applyEscalation(fr *invSudoFrames, esc *invEscalation) {
	if esc.Denied {
		fr.EscDenied = true
		return
	}
	s4Dir, s4Files := fr.DirState, fr.Files
	arch := esc.Arch
	fr.Escalated = true
	fr.MainState, fr.Main = invFrameOK, arch.Main
	fr.Unparsable = arch.Unparsable
	switch {
	case arch.DirSeen && esc.Exit == 0:
		fr.DirState, fr.Files = invFrameOK, arch.Files
	case arch.DirSeen && s4Dir == invFrameOK:
		// 退出碼非零：未提權讀取已列出的檔若封存中沒有，逐一記為讀不到
		have := map[string]bool{}
		for _, f := range arch.Files {
			have[f.Name] = true
		}
		files := append([]invSudoFile(nil), arch.Files...)
		for _, f := range s4Files {
			if !have[f.Name] {
				files = append(files, invSudoFile{Name: f.Name})
			}
		}
		fr.DirState, fr.Files = invFrameOK, files
	case arch.DirSeen:
		// 未提權讀取無從列出檔名：無從核對是否有檔被略過
		fr.DirState, fr.Files, fr.DirPartialUnknown = invFrameOK, arch.Files, true
	case esc.Exit == 0 || s4Dir == invStateAbsent:
		fr.DirState, fr.Files = invStateAbsent, nil
	default:
		fr.DirState, fr.Files = invStateUnreadable, nil
	}
}

// runEscalatedRead 在已建立的連線上跑提權讀取。password 為空＝金鑰型，只有第一段。
func runEscalatedRead(ctx context.Context, client *ssh.Client, password []byte) (*invEscalation, error) {
	budget := int64(inventoryMaxEscalatedBytes)
	out, exit, pwNeeded, err := runEscalatedSession(ctx, client, inventoryEscalatedCmdNoPassword, nil, &budget, nil)
	if err != nil {
		return nil, escalatedSessionError(ctx, err)
	}
	if len(out) == 0 && pwNeeded && len(password) > 0 {
		stdin := append(append([]byte(nil), password...), '\n')
		budget = int64(inventoryMaxEscalatedBytes)
		out, exit, _, err = runEscalatedSession(ctx, client, inventoryEscalatedCmdPassword, stdin, &budget, nil)
		for i := range stdin {
			stdin[i] = 0
		}
		if err != nil {
			return nil, escalatedSessionError(ctx, err)
		}
	}
	return classifyEscalatedOutput(out, exit)
}

// escalatedStreamResult 邊讀邊丟的判定結果：只有位元組數與「封存內有 sudoers 一般檔」兩個事實，不保留任何內容。
type escalatedStreamResult struct {
	Bytes   int64
	HasMain bool
}

// budgetReader 計數並套用同一個總量上限，超過回 INVENTORY_OUTPUT_LIMIT。
type budgetReader struct {
	r      io.Reader
	budget *int64
	n      *int64
}

func (b *budgetReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if n > 0 {
		if int64(n) > *b.budget {
			return 0, invErr(inventoryReasonOutputLimit, "", "total_bytes")
		}
		*b.budget -= int64(n)
		*b.n += int64(n)
	}
	return n, err
}

// streamEscalatedArchive 逐項走過 tar 串流，內容一律丟棄（記憶體用量與輸出大小無關），只記有沒有 sudoers 一般檔。
func streamEscalatedArchive(res *escalatedStreamResult) func(io.Reader, *int64) ([]byte, error) {
	return func(r io.Reader, budget *int64) ([]byte, error) {
		cr := &budgetReader{r: r, budget: budget, n: &res.Bytes}
		wrap := func(err error) error {
			var ie *inventoryError
			if errors.As(err, &ie) {
				return err
			}
			return invErr(inventoryReasonOutputMalformed, inventorySessionEscalated, "tar")
		}
		tr := tar.NewReader(cr)
		// 與盤點解封存（readEscalatedArchive）同一套計數：規則檔數與解出內容總量超過上限即
		// INVENTORY_OUTPUT_LIMIT，避免測試登入回可讀、實際盤點卻因上限失敗。
		files, contentBytes := 0, int64(0)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, wrap(err)
			}
			name := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
			isReg := h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA //nolint:staticcheck // 舊式一般檔旗標
			rest := strings.TrimPrefix(name, "sudoers.d/")
			counted := isReg && (name == "sudoers" ||
				(strings.HasPrefix(name, "sudoers.d/") && rest != "" && !strings.Contains(rest, "/")))
			if name == "sudoers" && isReg {
				res.HasMain = true
			}
			if counted && name != "sudoers" {
				files++
				if files > inventoryMaxSudoFiles {
					return nil, invErr(inventoryReasonOutputLimit, inventorySessionEscalated, "files")
				}
			}
			n, err := io.Copy(io.Discard, tr)
			if err != nil {
				return nil, wrap(err)
			}
			if counted {
				contentBytes += n
				if contentBytes > inventoryMaxSudoBytes {
					return nil, invErr(inventoryReasonOutputLimit, inventorySessionEscalated, "sudo_bytes")
				}
			}
		}
		if _, err := io.Copy(io.Discard, cr); err != nil {
			return nil, wrap(err)
		}
		return nil, nil
	}
}

// runEscalatedCheck 測試登入用的提權讀取：與 runEscalatedRead 同指令、同兩段式，
// 但輸出邊讀邊丟。回傳 denied＝stdout 為空；封存沒有 sudoers 一般檔視為格式錯誤。
func runEscalatedCheck(ctx context.Context, client *ssh.Client, password []byte) (denied bool, err error) {
	budget := int64(inventoryMaxEscalatedBytes)
	var res escalatedStreamResult
	_, _, pwNeeded, err := runEscalatedSession(ctx, client, inventoryEscalatedCmdNoPassword, nil, &budget, streamEscalatedArchive(&res))
	if err != nil {
		return false, escalatedSessionError(ctx, err)
	}
	if res.Bytes == 0 && pwNeeded && len(password) > 0 {
		stdin := append(append([]byte(nil), password...), '\n')
		budget = int64(inventoryMaxEscalatedBytes)
		res = escalatedStreamResult{}
		_, _, _, err = runEscalatedSession(ctx, client, inventoryEscalatedCmdPassword, stdin, &budget, streamEscalatedArchive(&res))
		for i := range stdin {
			stdin[i] = 0
		}
		if err != nil {
			return false, escalatedSessionError(ctx, err)
		}
	}
	if res.Bytes == 0 {
		return true, nil
	}
	if !res.HasMain {
		return false, invErr(inventoryReasonOutputMalformed, inventorySessionEscalated, "no_sudoers")
	}
	return false, nil
}

func escalatedSessionError(ctx context.Context, err error) error {
	var ie *inventoryError
	if errors.As(err, &ie) {
		ie.Session = inventorySessionEscalated
		return ie
	}
	if ctx.Err() != nil {
		return invErr(inventoryReasonTimeout, inventorySessionEscalated, "deadline")
	}
	return invErr(inventoryReasonCommandFailed, inventorySessionEscalated, "session_error")
}

// runEscalatedSession 一個 session：stdin 為 nil 時空；stdout 邊讀邊計；stderr 只看是否含「password is required」。
// consume 為 nil 時用 readCapped 收進記憶體；測試登入傳入邊讀邊丟的消費者。
func runEscalatedSession(ctx context.Context, client *ssh.Client, cmd string, stdin []byte, budget *int64, consume func(io.Reader, *int64) ([]byte, error)) (out []byte, exit int, pwNeeded bool, err error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, 0, false, err
	}
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return nil, 0, false, err
	}
	errBuf := &cappedBuffer{limit: inventoryEscalatedStderrCap}
	sess.Stderr = errBuf
	if len(stdin) > 0 {
		sess.Stdin = bytes.NewReader(stdin)
	}
	if err := sess.Start(cmd); err != nil {
		return nil, 0, false, err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-done:
		}
	}()
	if consume == nil {
		consume = readCapped
	}
	buf, err := consume(stdout, budget)
	if err != nil {
		_ = sess.Close()
		return nil, 0, false, err
	}
	if werr := sess.Wait(); werr != nil {
		var ee *ssh.ExitError
		if !errors.As(werr, &ee) {
			return nil, 0, false, werr
		}
		exit = ee.ExitStatus()
	}
	return buf, exit, strings.Contains(errBuf.String(), inventoryPasswordRequired), nil
}

// cappedBuffer 只留前 limit 位元組的寫入端（超出的丟棄，不回錯）。
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		c.buf.Write(p[:room])
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }

// escalationLabel 結束審計的 escalation 欄。
func escalationLabel(executor bool, esc *invEscalation) string {
	switch {
	case !executor:
		return ""
	case esc == nil:
		return invEscalationNotNeeded
	case esc.Denied:
		return invEscalationDenied
	default:
		return invEscalationUsed
	}
}
