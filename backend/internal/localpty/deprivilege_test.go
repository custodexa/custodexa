//go:build linux

package localpty

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// ptsPathOf 由 PTY 主端取得從屬端路徑（ioctl TIOCGPTN）。
//
// 不改由 `/proc/<pid>/fd/0` 的 symlink 取：容器內的 root **沒有** CAP_SYS_PTRACE，
// 跨 uid 讀不到降權子程序的 fd（實測 permission denied）；同 uid 則讀得到——
// 那正是本測試要防守的跨會話面。
func ptsPathOf(t *testing.T, c *Conn) string {
	t.Helper()
	const tiocGPTN = 0x80045430
	var ptn uint32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, c.ptmx.Fd(), tiocGPTN,
		uintptr(unsafe.Pointer(&ptn)))
	if errno != 0 {
		t.Fatalf("TIOCGPTN 取 PTY 從屬端編號失敗: %v", errno)
	}
	return fmt.Sprintf("/dev/pts/%d", ptn)
}

// 子程序執行身分的環境不變式（database-protocol「CLI 子程序執行環境降權」）。
//
// 這組測試是新方案的命脈：安全保證不再來自「看得懂使用者輸入什麼」，而是
// 「子程序即使收到任意輸入也讀不到、寫不了、逃不出任何有價值的東西」。
// 該保證只有在執行身分真的降權時才成立，故身分本身必須被機械斷言。

// procStatus 讀 /proc/<pid>/status 的欄位表（測試程序為 root，讀得到子程序的）
func procStatus(t *testing.T, pid int) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatalf("讀 /proc/%d/status 失敗（子程序可能已退出）: %v", pid, err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields[k] = strings.TrimSpace(v)
	}
	return fields
}

func TestStartWithOptionsRunsAsNonRoot(t *testing.T) {
	uid, gid, _, err := LookupUser(CLIUser)
	if err != nil {
		t.Fatalf("查不到 CLI 降權身分 %q（backend image 需重建）: %v", CLIUser, err)
	}
	if uid == 0 || gid == 0 {
		t.Fatalf("CLI 降權身分不得為 root: uid=%d gid=%d", uid, gid)
	}

	// busybox cat 是常駐子程序：PTY 開著就不會退出，可穩定查 /proc
	conn, err := StartWithOptions("/bin/busybox", []string{"cat"}, nil, 80, 24,
		Options{User: CLIUser})
	if err != nil {
		t.Fatalf("降權啟動失敗: %v", err)
	}
	defer conn.Close()

	st := procStatus(t, conn.Pid())

	// Uid/Gid 四欄（real/effective/saved/fs）皆須為降權身分——只有 effective
	// 降權會留下 saved uid，setuid(0) 可原路升回
	wantUID := fmt.Sprintf("%d\t%d\t%d\t%d", uid, uid, uid, uid)
	if st["Uid"] != wantUID {
		t.Errorf("子程序 Uid 欄位 = %q，期望 %q", st["Uid"], wantUID)
	}
	wantGID := fmt.Sprintf("%d\t%d\t%d\t%d", gid, gid, gid, gid)
	if st["Gid"] != wantGID {
		t.Errorf("子程序 Gid 欄位 = %q，期望 %q", st["Gid"], wantGID)
	}
	// 附屬群組須清空：後端程序（root）的群組若被繼承，group 位元就成了讀取面
	if st["Groups"] != "" {
		t.Errorf("子程序附屬群組未清空: %q", st["Groups"])
	}
	// 有效／可繼承／ambient capability 全為 0（非 root exec，且 image 內無 setuid 檔）
	for _, k := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb"} {
		if v := st[k]; v != "0000000000000000" {
			t.Errorf("子程序 %s = %q，期望全 0（不得帶任何 capability）", k, v)
		}
	}
}

func TestStartWithOptionsEnvIsIsolatedHome(t *testing.T) {
	_, _, home, err := LookupUser(CLIUser)
	if err != nil {
		t.Fatalf("查不到 CLI 降權身分: %v", err)
	}

	// 同時驗兩件事：降權子程序在 root 開的 PTY 上可正常讀寫（輸出讀得到），
	// 且 HOME/TMPDIR 指向該身分的獨立空目錄而非後端的 /root
	conn, err := StartWithOptions("/bin/busybox", []string{"env"}, nil, 80, 24,
		Options{User: CLIUser})
	if err != nil {
		t.Fatalf("降權啟動失敗: %v", err)
	}
	defer conn.Close()

	// 哨兵必須是**最後**那個斷言目標的完整字串：環境依 PATH/TERM/LANG/TMPDIR/HOME
	// 的順序輸出（conn.go StartWithOptions），舊版以 `TMPDIR=` 當哨兵會在 HOME 送出
	// 之前就返回而偶發假紅（-count=400 可穩定重現）。以 `HOME=<家目錄>` 當哨兵，
	// 讀到它即代表前面的 TMPDIR 整行已到齊。
	out := readUntil(t, conn, "HOME="+home, 3*time.Second)
	for _, want := range []string{"HOME=" + home, "TMPDIR=" + home} {
		if !strings.Contains(out, want) {
			t.Errorf("降權子程序環境缺 %q，實得: %q", want, out)
		}
	}
	if strings.Contains(out, "HOME=/root") {
		t.Errorf("降權子程序 HOME 仍指向後端家目錄: %q", out)
	}
}

// TestCLISessionPTYIsNotAccessibleToCLIUser 會話 PTY 從屬端（/dev/pts/N）不得對
// CLI 降權身分開放。
//
// 這條是跨會話面**真正**的守門人。各 DB 會話共用同一降權身分，故同 uid 的
// ptrace 檢查是通過的：以 dbcli 身分 `ls /proc/<其他會話 pid>/fd/` 會成功、
// `readlink fd/0` 也讀得到 `/dev/pts/N`（先前文件誤植為「fd/ 因無 CAP_SYS_PTRACE
// 而 Permission denied」，實測不成立）。擋下實際讀寫的是 pts 節點本身的
// `root:tty` 所有權與 `crw--w----` 權限位元——PTY 由後端（root）開啟，降權身分
// 對它沒有任何 DAC 權限。
//
// 一旦 pts 被 chown 給該身分或放寬 other 位元，跨會話面就從「讀得到 PATH」
// 升級成「讀他人擊鍵、寫入他人終端」。故以斷言釘住。
func TestCLISessionPTYIsNotAccessibleToCLIUser(t *testing.T) {
	uid, gid, _, err := LookupUser(CLIUser)
	if err != nil {
		t.Fatalf("查不到 CLI 降權身分: %v", err)
	}
	conn, err := StartWithOptions("/bin/busybox", []string{"cat"}, nil, 80, 24,
		Options{User: CLIUser})
	if err != nil {
		t.Fatalf("降權啟動失敗: %v", err)
	}
	defer conn.Close()

	pts := ptsPathOf(t, conn)
	st := statOf(t, pts)
	if st.Uid == uint32(uid) {
		t.Errorf("%s 的 owner 為 CLI 降權身分（uid=%d）——同身分的其他會話即可"+
			"讀取擊鍵與注入輸入", pts, uid)
	}
	if st.Uid != 0 {
		t.Errorf("%s 的 owner uid=%d，期望 0（PTY 由後端以 root 開啟）", pts, st.Uid)
	}
	if bits := modeBitsFor(st, uint32(uid), uint32(gid)); bits != 0 {
		t.Errorf("%s 對 CLI 降權身分有 rwx=%03b 的權限（mode=%o owner=%d:%d），期望完全無權",
			pts, bits, st.Mode&07777, st.Uid, st.Gid)
	}
}

func TestStartWithOptionsUnknownUserFailsClosed(t *testing.T) {
	// 查不到降權身分時必須開不了會話——退回以 root 起 CLI 是靜默失去全部保證
	conn, err := StartWithOptions("/bin/busybox", []string{"cat"}, nil, 80, 24,
		Options{User: "no-such-cli-user"})
	if err == nil {
		conn.Close()
		t.Fatal("查無降權身分時應回錯（fail-close），實際成功啟動")
	}
}

func TestDeprivilegedHomeIsNotWritable(t *testing.T) {
	uid, gid, home, err := LookupUser(CLIUser)
	if err != nil {
		t.Fatalf("查不到 CLI 降權身分: %v", err)
	}
	info, err := os.Stat(home)
	if err != nil {
		t.Fatalf("降權身分家目錄 %s 不存在: %v", home, err)
	}
	if !info.IsDir() {
		t.Fatalf("降權身分家目錄 %s 不是目錄", home)
	}
	if writableByUser(t, home, uid, gid) {
		t.Errorf("降權身分家目錄 %s 對該身分可寫（不應給任何可寫路徑）: mode=%v",
			home, info.Mode())
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatalf("讀取 %s 失敗: %v", home, err)
	}
	if len(entries) != 0 {
		t.Errorf("降權身分家目錄 %s 非空（共 %d 項），不得放置任何檔案", home, len(entries))
	}
}
