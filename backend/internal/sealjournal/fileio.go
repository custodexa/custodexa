package sealjournal

import (
	"io/fs"
	"os"
)

// fileIO 為 journal 對底層檔案的最小操作面。
// 抽出介面的唯一目的是讓測試能注入 I/O 故障與記錄操作定序
// （驗收要求「驗證未早於 header fdatasync」「單一 writer」需觀察真實 I/O 序列）。
// 產品路徑一律使用 osFile。
type fileIO interface {
	WriteAt(p []byte, off int64) (int, error)
	ReadAt(p []byte, off int64) (int, error)
	// Datasync 為資料同步（Linux 上為 fdatasync，其餘平台退回 fsync）。
	Datasync() error
	Stat() (fs.FileInfo, error)
	Close() error
}

// osFile 是 fileIO 的產品實作。
type osFile struct {
	f *os.File
}

func (o *osFile) WriteAt(p []byte, off int64) (int, error) { return o.f.WriteAt(p, off) }
func (o *osFile) ReadAt(p []byte, off int64) (int, error)  { return o.f.ReadAt(p, off) }
func (o *osFile) Datasync() error                          { return datasync(o.f) }
func (o *osFile) Stat() (fs.FileInfo, error)               { return o.f.Stat() }
func (o *osFile) Close() error                             { return o.f.Close() }

// syncDirFn 為 syncDir 的可置換入口，僅供測試斷言「首次建立確有同步目錄項」。
var syncDirFn = syncDir

// syncDir 同步父目錄項。首次建立 journal 後必須執行：
// 未同步目錄項時，崩潰後檔案本身可能不存在，下次啟動又走「檔案不存在」分支
// 而從零起算，單調計數器的意義即被抹除。
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
