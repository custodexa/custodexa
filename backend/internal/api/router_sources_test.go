package api

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// readRouterSources 遞迴讀取路由目錄下的所有 .js/.ts，串成一份來源。
// 排除 __tests__ 等測試目錄——那裡的假路由不是真實路由宣告
func readRouterSources(dir string) ([]byte, error) {
	var buf []byte
	found := false
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), "__") || d.Name() == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(d.Name())
		if ext != ".js" && ext != ".ts" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		buf = append(buf, b...)
		buf = append(buf, '\n')
		found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fs.ErrNotExist
	}
	return buf, nil
}
