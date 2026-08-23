package recorder

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ProbeWritable 探測錄影落地可寫性：
// 連線 token 簽發點的前置檢查。探測「當日子目錄」而非僅 base——文字路徑
// 實際寫入 {base}/{YYYY-MM-DD}/，只驗 base 會漏掉日期層被佔用/不可寫的
// 情境（建立子目錄本身也同時驗證了 base 可寫，涵蓋
// guacd 直寫 base 的圖形路徑）。寫入帶 fsync 迫使配額/磁碟滿早期現形。
// 限制（誠實記載）：backend 以 root 執行時權限類失敗探不到；小檔探測對
// 「近滿磁碟寫大檔」「不同 UID（guacd）的權限差異」無保證——由建線與
// 會後偵測兜底。
func ProbeWritable(basePath string) error {
	dateDir := filepath.Join(ResolveBasePath(basePath), time.Now().Format("2006-01-02"))
	if err := os.MkdirAll(dateDir, 0755); err != nil {
		return fmt.Errorf("錄影目錄不可用: %w", err)
	}
	f, err := os.CreateTemp(dateDir, ".probe-*")
	if err != nil {
		return fmt.Errorf("錄影目錄不可寫: %w", err)
	}
	name := f.Name()
	_, werr := f.Write([]byte("ok"))
	serr := f.Sync()
	cerr := f.Close()
	rerr := os.Remove(name)
	switch {
	case werr != nil:
		return fmt.Errorf("錄影目錄寫入失敗: %w", werr)
	case serr != nil:
		return fmt.Errorf("錄影探測檔落盤失敗: %w", serr)
	case cerr != nil:
		return fmt.Errorf("錄影探測檔關閉失敗: %w", cerr)
	case rerr != nil:
		return fmt.Errorf("錄影探測檔清除失敗: %w", rerr)
	}
	return nil
}
