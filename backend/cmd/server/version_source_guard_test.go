package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 版本號單一事實源的守衛。
//
// 被防的缺陷是實際發生過的：main.go 的 Version 是手寫常數，停在開發初期的握手版字面值
// 而產品已發布 1.0.1——該值經 /health 對外揭露，任何人打健康檢查看到的版本都與
// CHANGELOG／GitHub Release 不符，且**沒有任何機制會發現**。
//
// 改成建置時注入之後，事實源變成專案根的 VERSION 檔（Dockerfile 讀它、compose 只是
// 覆寫口）。於是漂移的形態也跟著換一種：發版時改了 CHANGELOG 卻忘了改 VERSION，
// 映像照樣建得出來、照樣一路綠，只是自稱上一版。本檔的兩條守衛各堵一邊：
//
//	TestVersionFileMatchesChangelog   VERSION 檔 ⇄ CHANGELOG.md 最新版本節
//	TestServerVersionIsBuildInjected  main.go 的預設值不得回頭變成寫死的版本字面值
//
// 讀不到被驗證對象時一律 Fatal 而非 skip：skip 只會製造假綠（見 .env.example 守衛的
// 同一則教訓）。

const (
	// releaseFilesRODir 是專案根 VERSION 與 CHANGELOG.md 在測試容器內的唯讀掛載點
	// （docker-compose.dev.yml backend volumes）。
	//
	// 兩者都住在 repo 根，而 repo 根**不得**整個掛進容器（compose 內該段記載了實測後果：
	// host 的 .env 會對資料庫 CLI 的降權身分可讀），故逐檔掛入本目錄。
	// 位置在 module 內是必要條件：go test 的結果快取只追蹤 module 內被開啟的檔案。
	releaseFilesRODir = "testdata/release"

	// versionBuildDefault 是未注入建置時 Version 的值（main.go）。
	// 測試二進位一律以純 `go test` 建置、不帶 ldflags，故此處看到的必是原始碼裡的預設值。
	versionBuildDefault = "dev"
)

var (
	// changelogVersionHeading 取 CHANGELOG.md 的版本節標題首個 token。
	// 現行格式：`## 1.0.1 — dependency security updates (2026-08-21)`。
	// 只匹配兩個 `#`（`### Security` 之類的子節不會誤中）。
	changelogVersionHeading = regexp.MustCompile(`^##\s+(\S+)`)

	// releaseVersionFormat 是版本號的允許形狀：SemVer 主體 ＋ 可選預發布後綴。
	// **不接受 `v` 前綴**：VERSION 檔的內容會原樣進到 /health 的 version 欄位，
	// 前綴要不要加是 git tag／image tag 那一層的事。
	releaseVersionFormat = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
)

// TestVersionFileMatchesChangelog 斷言專案根 VERSION 檔的內容等於 CHANGELOG.md
// 最新版本節的版本號——兩者不一致即代表發版動作只做了一半。
func TestVersionFileMatchesChangelog(t *testing.T) {
	raw := readReleaseFile(t, "VERSION")

	// 單行純版本號是契約：Dockerfile 以 `tr -d ' \t\r\n'` 取值，多行檔案會被黏成
	// 一個沒人看得懂的字串注進 /health，而不是建置失敗。
	if body := strings.TrimRight(raw, "\r\n"); strings.ContainsAny(body, "\r\n") {
		t.Fatalf("VERSION 檔必須是單行純版本號，實得多行內容：%q", raw)
	}

	version := strings.TrimSpace(raw)
	if version == "" {
		t.Fatal("VERSION 檔為空——正式版建置會 fail-close，且守衛失去比對對象")
	}
	if !releaseVersionFormat.MatchString(version) {
		t.Fatalf("VERSION 檔內容 %q 不是可接受的版本號形狀（SemVer、無 v 前綴）；"+
			"它會原樣成為 /health 的 version 欄位值", version)
	}

	latest := latestChangelogVersion(t)
	if version != latest {
		t.Errorf("VERSION 檔為 %q，CHANGELOG.md 最新版本節為 %q——發版時兩者必須同時更新。"+
			"不一致的後果不是建置失敗而是靜默錯誤：映像照樣建得出來，只是 /health 對外自稱另一個版本",
			version, latest)
	}
}

// TestServerVersionIsBuildInjected 斷言 main.go 的 Version 預設值仍是注入前的佔位值。
//
// 這條擋的是回頭路：有人為了「讓開發環境也顯示正確版號」而把版本字面值寫回 Go 碼，
// 於是事實源又變成兩個，下一次發版照樣漂——而那正是本次要根治的缺陷本身。
// VERSION ⇄ CHANGELOG 的守衛看不到這種改動（改回去的當下值是對的）。
func TestServerVersionIsBuildInjected(t *testing.T) {
	if Version != versionBuildDefault {
		t.Errorf("main.Version 的值為 %q，期望注入前的預設值 %q：版本號必須由建置時注入"+
			"（正式版見 docker/backend/Dockerfile 的 -X main.Version，事實源為專案根 VERSION 檔），"+
			"不得在 Go 碼寫死；若這是刻意帶 -ldflags 跑測試造成的，請改用不注入的一般 go test",
			Version, versionBuildDefault)
	}
}

// latestChangelogVersion 取 CHANGELOG.md 由上而下第一個版本節的版本號。
func latestChangelogVersion(t *testing.T) string {
	t.Helper()
	body := readReleaseFile(t, "CHANGELOG.md")
	for _, line := range strings.Split(body, "\n") {
		m := changelogVersionHeading.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		got := m[1]
		if !releaseVersionFormat.MatchString(got) {
			// 例如改採 `## Unreleased` 的慣例。此時本守衛的比對前提已不成立，
			// 直接紅並要求回頭修守衛——靜默放行等於守衛從此不存在。
			t.Fatalf("CHANGELOG.md 最上方的版本節標題為 %q，不是版本號：本守衛假設最上方一節"+
				"即最新發布版本，該慣例若改變，守衛與 VERSION 檔的角色須一併重新檢視", got)
		}
		return got
	}
	t.Fatal("CHANGELOG.md 找不到任何 `## <版本>` 版本節標題——讀不到被驗證對象即等於沒有守衛")
	return ""
}

// readReleaseFile 讀取專案根的發版事實源檔案，雙路徑比照 apiSpecPath：
// 容器內走 releaseFilesRODir 的唯讀掛載點、host 直跑走 module 根上一層的專案根。
func readReleaseFile(t *testing.T, name string) string {
	t.Helper()
	candidates := []string{
		filepath.Join(cmdServerDir(t), releaseFilesRODir, name), // 容器唯讀掛載點（module 內）
		filepath.Join(filepath.Dir(guardModuleRoot(t)), name),   // host 專案根
	}
	for _, p := range candidates {
		body, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		// 掛載點存在但空檔＝容器建立的 mount 副產物被當成真檔（bind mount 未生效）。
		// 那會讓守衛拿著空內容去比對而必然紅得莫名其妙，故在此指名真因。
		if strings.TrimSpace(string(body)) == "" && p == candidates[0] {
			t.Fatalf("%s 為空——那是容器的單檔掛載副產物，代表 %s 沒被掛進來；"+
				"請 recreate backend（見 docker-compose.dev.yml backend volumes）", p, name)
		}
		return string(body)
	}
	t.Fatalf("找不到專案根 %s（容器內應唯讀掛於 cmd/server/%s；見 docker-compose.dev.yml "+
		"backend volumes）——讀不到被驗證對象即等於沒有守衛，故 fail 而非 skip", name, releaseFilesRODir)
	return ""
}
