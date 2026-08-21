package main

// openspec 下 manifest 檔的路徑解析（modular-architecture Phase C 歸檔時抽出）。
//
// # 為什麼需要這一層
//
// 兩份 manifest（審計產生點、lifecycle）是守衛的**單一事實源**，權威檔只有 repo 根
// `openspec/` 下那一份：docker 內由 docker-compose.dev.yml 的 `./openspec:/app/testdata/openspec:ro`
// 唯讀掛入 module 內（掛在 /app 內是必要的——go test 的結果快取只追蹤 module 內被開啟的
// 檔案，掛在 module 外時純改 manifest 不會使快取失效，守衛會回報 (cached) 綠而根本不執行），
// host 全 repo checkout 直跑則走 module 根的上一層。
//
// **change 歸檔會移動這個檔**（`openspec/changes/<name>/` → `openspec/changes/archive/<日期>-<name>/`）。
// 原本的作法是把歸檔後路徑寫死成 `changes/archive/<name>/…`——但本 repo 的歸檔慣例帶日期前綴
// （`2026-08-11-modular-architecture`），寫死的字串對不上，守衛會在歸檔當下轉紅；就算當場改成
// 正確字串，下一個 change 歸檔時仍會再踩一次。故改為**掃描解析**：未歸檔與已歸檔（任意日期前綴）
// 兩種佈局都認得，路徑不再是需要有人記得同步的常數。
//
// # 兩條刻意保留的 fail-close
//
//  1. **找不到即 t.Fatal，永不 Skip**：守衛讀不到 manifest 只剩「假綠」或「恆紅」兩種結局，
//     而跳過的守衛與通過的守衛在統計上無從區分——它守的是 fail-close 退化這種靜默失效。
//  2. **找到多份即 t.Fatal**：同一份 manifest 同時存在於未歸檔與已歸檔位置（或兩個歸檔目錄），
//     代表出現了複本；此時「守衛在驗哪一份」不確定，而複本會漂移。寧可當場紅。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// openspecChangeDirName 本批 manifest 所屬 change 的目錄名（不含歸檔日期前綴）。
const openspecChangeDirName = "modular-architecture"

// openspecManifestPath 解析 openspec 下某份 manifest 的絕對路徑。
//
// moduleRoot＝go.mod 所在目錄（由呼叫端以 module 身分錨點定位，非層數推算）；
// rel＝manifest 相對 change 目錄的路徑（例 "research/manifest-lifecycle.md"）。
func openspecManifestPath(t *testing.T, moduleRoot, changeDir, rel string) string {
	t.Helper()

	found, tried := findOpenSpecManifest(moduleRoot, changeDir, rel)
	switch len(found) {
	case 1:
		return found[0]
	case 0:
		t.Fatalf("openspec manifest 不可達：%s\n已試：\n  %s\n"+
			"docker 內須有 docker-compose.dev.yml 的 `./openspec:/app/testdata/openspec:ro` 掛載"+
			"（容器已在跑時需 `docker compose up -d --force-recreate backend` 才生效）；"+
			"host 直跑須在 repo 完整 checkout 下執行。"+
			"**本守衛不得因找不到 manifest 而跳過**——跳過的守衛與通過的守衛在統計上無從區分。",
			rel, joinLines(tried))
	default:
		t.Fatalf("openspec manifest 找到 %d 份複本（應恰為 1）：\n  %s\n"+
			"複本會各自漂移，守衛驗的是哪一份不確定。請確認 change 只存在於未歸檔或已歸檔其中一處。",
			len(found), joinLines(found))
	}
	return ""
}

// findOpenSpecManifest 回傳所有命中的路徑與嘗試過的位置（供錯誤訊息用）。
//
// 佈局一：`<openspec>/changes/<change>/<rel>`（未歸檔）
// 佈局二：`<openspec>/changes/archive/<任意前綴><change>/<rel>`（已歸檔，本 repo 慣例為日期前綴）
func findOpenSpecManifest(moduleRoot, changeDir, rel string) (found, tried []string) {
	roots := []string{
		filepath.Join(moduleRoot, "testdata", "openspec"),   // docker 唯讀掛載
		filepath.Join(filepath.Dir(moduleRoot), "openspec"), // host 全 repo checkout
	}
	seen := map[string]bool{}
	for _, root := range roots {
		live := filepath.Join(root, "changes", changeDir, rel)
		tried = append(tried, live)
		if _, err := os.Stat(live); err == nil && !seen[live] {
			seen[live] = true
			found = append(found, live)
		}

		pattern := filepath.Join(root, "changes", "archive", "*"+changeDir, rel)
		tried = append(tried, pattern)
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue // pattern 語法錯誤：changeDir 含 glob 元字元，交由 0 命中的 Fatal 呈現
		}
		for _, m := range matches {
			if info, statErr := os.Stat(m); statErr == nil && !info.IsDir() && !seen[m] {
				seen[m] = true
				found = append(found, m)
			}
		}
	}
	return found, tried
}

func joinLines(paths []string) string { return strings.Join(paths, "\n  ") }
