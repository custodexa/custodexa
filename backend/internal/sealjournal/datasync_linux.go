//go:build linux

package sealjournal

import (
	"os"
	"syscall"
)

// datasync 在 Linux 上使用 fdatasync：只保證資料（與必要的中繼資料）落地，
// 較 fsync 便宜。journal 為預配置定長檔，檔長不變，fdatasync 已足夠。
func datasync(f *os.File) error {
	return syscall.Fdatasync(int(f.Fd()))
}
