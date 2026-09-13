package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// `.env.example` 的委託段守衛（任務 9.1）。
//
// 範本是部署者唯一會照著改的檔。退場鍵若留在裡面，它就是一句「請設定這個」的
// 邀請——而那個值自本版起不再生效，設了也不會有任何錯誤訊號，症狀是部署者以為
// 自己設好了保管處，實際上系統停在「拓撲尚未設定」。
//
// 本檔守兩件事：委託段只剩兩鍵；五個退場鍵在範本內**不以可設定的形態出現**。

// envKeyLine 可設定的形態：行首（可帶註解標記）＋鍵名＋等號。
// 散文裡提到鍵名不算——升級說明必須講得出「哪些鍵不再生效」。
func envKeyLine(key string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^\s*#?\s*` + regexp.QuoteMeta(key) + `\s*=`)
}

func envTemplateBody(t *testing.T) string {
	t.Helper()
	root := backendRoot(t)
	// 兩個候選沿 TestEnvExampleNoDrift 的同一組：容器內是唯讀掛載點，
	// host 上是專案根。找不到即 Fatal——讀不到被驗證對象等於沒有守衛。
	for _, path := range []string{
		filepath.Join(root, "config", "testdata", ".env.example"),
		filepath.Join(root, "..", ".env.example"),
	} {
		if raw, err := os.ReadFile(path); err == nil {
			return string(raw)
		}
	}
	t.Fatal("讀不到環境變數範本（守衛讀不到被驗證對象即等於沒有守衛）")
	return ""
}

// TestEnvTemplateDelegatedSectionKeepsTwoKeys 委託段只剩兩鍵。
func TestEnvTemplateDelegatedSectionKeepsTwoKeys(t *testing.T) {
	body := envTemplateBody(t)
	for _, key := range []string{EnvKeyKEKProvider, EnvKeyKMSProvider} {
		if !envKeyLine(key).MatchString(body) {
			t.Errorf("委託段應保留 %s，但範本裡沒有可設定的那一行", key)
		}
	}
}

// TestEnvTemplateRetiredDelegatedKeysAreGone 五個退場鍵不再以可設定的形態出現。
func TestEnvTemplateRetiredDelegatedKeysAreGone(t *testing.T) {
	body := envTemplateBody(t)
	for _, key := range []string{
		"KEK_KMS_KEY_ID", "KEK_KMS_REGION",
		"KEK_VAULT_ADDR", "KEK_VAULT_ROLE_ID", "KEK_VAULT_SECRET_ID",
	} {
		if envKeyLine(key).MatchString(body) {
			t.Errorf("退場鍵 %s 仍以可設定的形態留在範本裡——留著等於邀請部署者去設一個不生效的值", key)
		}
	}
}

// TestEnvTemplateStatesDelegatedRestartCost 範本講到委託部署不再無人值守。
//
// 這是本次最大的營運代價：主機重開、容器重建、自動擴縮都會停在已封存等人到場。
// 部署者若在升級之後才發現，發現的方式會是一次起不來的服務。
func TestEnvTemplateStatesDelegatedRestartCost(t *testing.T) {
	body := strings.ToLower(envTemplateBody(t))
	for _, phrase := range []string{"no longer unattended", "sealed"} {
		if !strings.Contains(body, phrase) {
			t.Errorf("範本未說明委託部署的重啟代價（缺 %q）", phrase)
		}
	}
	// 且不得把它寫成可自動恢復。
	for _, forbidden := range []string{"resumes automatically", "restarts unattended"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("範本主張了系統不具備的能力：%q", forbidden)
		}
	}
}
