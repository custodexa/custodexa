//go:build linux

package localpty

import (
	"os"
	"syscall"
	"unsafe"
)

// lineState PTY 行紀律的兩個關鍵旗標（由主端 ioctl 讀取，主從共用同一組設定）
type lineState struct {
	canonical bool // ICANON：逐行讀取（client 未進入 readline 的原始狀態）
	echo      bool // ECHO：核心代為回顯
}

// ttyLineState 讀取 PTY 的行紀律狀態。
//
// 用途是「client 現在是不是正在讀密碼」的結構性判準：實測 psql 16.14 與 mariadb
// client 15.2 在讀密碼時為 ICANON=true／ECHO=false（關回顯但仍逐行讀），進入
// readline 互動後則為 ICANON=false——這兩態不可能混淆，比純文字比對可靠得多。
//
// 以 SyscallConn 取 fd 而非 os.File.Fd()：後者會把檔案切成阻塞模式並脫離 runtime
// poller，會讓 Close 無法中斷進行中的 Read。
func ttyLineState(f *os.File) (lineState, bool) {
	if f == nil {
		return lineState{}, false
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return lineState{}, false
	}
	var st lineState
	ok := false
	ctlErr := rc.Control(func(fd uintptr) {
		var t syscall.Termios
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd,
			uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t)))
		if errno != 0 {
			return
		}
		st = lineState{
			canonical: t.Lflag&syscall.ICANON != 0,
			echo:      t.Lflag&syscall.ECHO != 0,
		}
		ok = true
	})
	if ctlErr != nil {
		return lineState{}, false
	}
	return st, ok
}
