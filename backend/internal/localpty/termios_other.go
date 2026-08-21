//go:build !linux

package localpty

import "os"

// lineState 見 termios_linux.go；非 Linux 平台無對應 ioctl 常數
type lineState struct {
	canonical bool
	echo      bool
}

// ttyLineState 非 Linux 平台一律回報「讀不到」。產品執行環境是 Linux 容器；
// 此處存在只為讓 darwin 上的編輯器與 go vet 可用。讀不到時，需要 termios 判準的
// 提示注入會 fail-close（不注入），而非退化成純文字比對。
func ttyLineState(*os.File) (lineState, bool) {
	return lineState{}, false
}
