package audit

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
)

// 原因碼與保留清除對象的三語完備性守衛（形態同 timeline_summary_completeness_test.go）。
//
// 三語鍵集合互相比對的守衛擋不住「後端新增一個碼、三語同時沒有」；本守衛從後端登記表
// 展開碼集合，要求三語都有譯文，反向也驗：locale 有而後端已無＝譯文腐爛

// minAuditReasonCodes 碼數下限（防登記表被清空或展開失真時的空集合假綠）。
// 2026-10-12 現況 72 個，門檻保留餘裕
const minAuditReasonCodes = 65

// minRetentionTargets 保留清除對象下限（三類表＋檢查點鏈＋錄影檔＝5）
const minRetentionTargets = 5

const retentionServiceRel = "retention_service.go"

// localeSubtree 讀 locale 的 dailyReview.<sub> 子樹並攤平
func localeSubtree(t *testing.T, dir, locale, sub string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, locale+".json"))
	if err != nil {
		t.Fatalf("讀 %s locale 失敗: %v", locale, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 %s locale 失敗: %v", locale, err)
	}
	dr, ok := doc["dailyReview"].(map[string]any)
	if !ok {
		t.Fatalf("%s 缺 dailyReview", locale)
	}
	node, ok := dr[sub].(map[string]any)
	if !ok {
		t.Fatalf("%s 缺 dailyReview.%s：原因欄會整段退回原始欄位", locale, sub)
	}
	out := map[string]string{}
	flattenSummary(node, "", out)
	return out
}

// TestAuditReasonCodesTranslated AuditReasonCodes ⇔ 三語 dailyReview.reason.* 雙向相等
func TestAuditReasonCodesTranslated(t *testing.T) {
	if len(AuditReasonCodes) < minAuditReasonCodes {
		t.Fatalf("只有 %d 個原因碼（現況至少 %d）：登記表展開失真，本守衛正在放行一切",
			len(AuditReasonCodes), minAuditReasonCodes)
	}
	codes := map[string]bool{}
	for _, c := range AuditReasonCodes {
		codes[c] = true
	}
	dir := summaryLocaleDir(t)
	for _, locale := range summaryLocales {
		missing, stale := diffSummaryCodes(codes, localeSubtree(t, dir, locale, "reason"), nil)
		for _, code := range missing {
			t.Errorf("%s 的 dailyReview.reason 缺 %q：該語系的原因欄會退回通用句型", locale, code)
		}
		for _, key := range stale {
			t.Errorf("%s 的 dailyReview.reason 登記了 %q 但後端已無此碼：譯文腐爛，請刪除", locale, key)
		}
	}
	if !t.Failed() {
		t.Logf("原因碼 %d 個，三語皆有譯文", len(codes))
	}
}

// retentionPurgeTargets 自 retention_service.go 展開保留清除列的 target 值域：
// PurgeResult{Target: <字面>} 直接收；Target: target.table 展開 retentionTargets 登記表
func retentionPurgeTargets(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, retentionServiceRel, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗: %v", retentionServiceRel, err)
	}
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if ident, ok := cl.Type.(*ast.Ident); !ok || ident.Name != "PurgeResult" {
			return true
		}
		for _, elt := range cl.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Target" {
				continue
			}
			switch v := kv.Value.(type) {
			case *ast.BasicLit:
				if s, err := strconv.Unquote(v.Value); err == nil && s != "" {
					out[s] = true
				}
			case *ast.SelectorExpr:
				if v.Sel.Name != "table" {
					t.Errorf("%s 的 PurgeResult.Target 取自未登記的欄位 %s：本守衛無法展開其值域", retentionServiceRel, v.Sel.Name)
				}
				for _, rt := range retentionTargets {
					out[rt.table] = true
				}
			default:
				t.Errorf("%s 的 PurgeResult.Target 既非字面也非 target.table（%T）：本守衛無法展開其值域", retentionServiceRel, kv.Value)
			}
		}
		return true
	})
	return out
}

// TestRetentionReasonTargetsTranslated 保留清除對象 ⇔ 三語 dailyReview.reasonTarget.* 雙向相等。
// 前端以這組鍵翻譯 retention_purge 的 target 參數；漏了就只看得到表名
func TestRetentionReasonTargetsTranslated(t *testing.T) {
	targets := retentionPurgeTargets(t)
	if len(targets) < minRetentionTargets {
		keys := make([]string, 0, len(targets))
		for k := range targets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Fatalf("只展開出 %d 個清除對象 %v（至少 %d）：AST 條件已失真", len(targets), keys, minRetentionTargets)
	}
	dir := summaryLocaleDir(t)
	for _, locale := range summaryLocales {
		missing, stale := diffSummaryCodes(targets, localeSubtree(t, dir, locale, "reasonTarget"), nil)
		for _, k := range missing {
			t.Errorf("%s 的 dailyReview.reasonTarget 缺 %q：保留清除的原因只顯示表名", locale, k)
		}
		for _, k := range stale {
			t.Errorf("%s 的 dailyReview.reasonTarget 登記了 %q 但保留清除已無此對象：請刪除", locale, k)
		}
	}
}
