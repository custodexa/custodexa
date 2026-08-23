package policy

import (
	"errors"
	"strconv"
	"testing"
)

// 鏈自動驗證三鍵的鍵層級守衛。
//
// **守的是什麼**：三鍵（近期窗口／全鏈週期／掃描速率）的值會直接寫進驗證頁
// 對稽核的陳述，故三者都不得被用來實質關閉驗證——
// 三鍵一律不開 ZeroDisables（0 被擋）、一律有 Max（極大值被擋），
// 速率鍵另有 Min: 10000（極小值被擋，它是唯一一顆「調小才危險」的旋鈕）。
//
// 在此之前這三條只是 policyDefs 裡的欄位宣稱，沒有任何鍵層級測試釘住：
// 日後有人為了方便拿掉 Min、或補上 ZeroDisables，不會有測試轉紅。
//
// **走的是真實裝配的路徑**：斷言一律經 `svc.Update`（＝政策頁 PUT 走的
// handler → UpdateBatch → validatePolicyValue → 落庫），不直接呼叫
// validatePolicyValue。管理員在政策頁改值是正常操作流程，這條路徑必須被釘住；
// 繞過政策層直改資料層屬信任邊界內，不在本檔射程（消費端另有 clamp 作為
// 防禦深度，見 chain_verify_service.go:192-204，那不是本檔要測的行為）。

// chainVerifyKeyBound 三鍵各自的值域宣稱。Min=0 表示該鍵不應有下界。
type chainVerifyKeyBound struct {
	key string
	min int // 0 = 無下界（最小合法值即 1）
	max int
	why string
}

var chainVerifyKeyBounds = []chainVerifyKeyBound{
	{
		key: PolicyAuditChainRecentVerifyDays, min: 0, max: 30,
		why: "上界 30：超過即與全鏈層繞行週期重疊，只多出成本；無下界是因最小合法值 1 天仍含鏈尾最新區間",
	},
	{
		key: PolicyAuditChainVerifyIntervalSeconds, min: 0, max: 604800,
		why: "上界 604800（7 天）：更長的間隔會使「本系統每 X 自動驗證整條鏈一次」這句陳述本身變成負面證據",
	},
	{
		key: PolicyAuditChainVerifyRowsPerHour, min: 10000, max: 5000000,
		why: "下界 10000：再低則舊區間在被合法清除前永遠輪不到重驗，內容層對那段歷史實質關閉而畫面上仍在推進",
	},
}

// TestChainVerifyKeysCannotBeUsedToDisableVerification 三鍵各自：0 被拒、
// 超上界被拒，且被拒後現值不動（整批回滾，不半套生效）。
//
// **拿掉任一鍵的 Max、或替任一鍵補上 ZeroDisables 即轉紅**
func TestChainVerifyKeysCannotBeUsedToDisableVerification(t *testing.T) {
	for _, b := range chainVerifyKeyBounds {
		t.Run(b.key, func(t *testing.T) {
			def := findDef(b.key)
			if def == nil {
				t.Fatalf("政策鍵 %s 未定義", b.key)
			}
			// 欄位宣稱：三鍵都不得開 ZeroDisables，且上界須恰為裁決值
			if def.ZeroDisables {
				t.Errorf("%s 不得開 ZeroDisables：0 會被解讀為停用＝自動驗證可被關閉（%s）", b.key, b.why)
			}
			if def.Max != b.max {
				t.Errorf("%s Max = %d, want %d：%s", b.key, def.Max, b.max, b.why)
			}
			if def.Min != b.min {
				t.Errorf("%s Min = %d, want %d：%s", b.key, def.Min, b.min, b.why)
			}

			svc, _ := setupPolicyDB(t)
			before := svc.GetInt(b.key)

			for _, bad := range []string{"0", strconv.Itoa(b.max + 1)} {
				_, err := svc.Update(b.key, bad, "admin")
				if !errors.Is(err, ErrPolicyInvalidValue) {
					t.Errorf("%s 接受了 %s（err=%v）——這正是「把值設成極端數字使驗證實質關閉，"+
						"而政策頁上看起來還在跑」的路徑", b.key, bad, err)
				}
				if got := svc.GetInt(b.key); got != before {
					t.Errorf("%s 被拒後現值變成 %d（原 %d）：拒絕的值不得落庫", b.key, got, before)
				}
			}
		})
	}
}

// TestChainVerifyKeysAcceptBoundaryValues 三鍵各自的邊界值本身可存並讀回。
//
// 與上一支互為對照：拒絕測試單獨存在時，把驗證改成「一律拒絕」也會全綠。
// 邊界值取最小合法值與上界本身（速率鍵的最小合法值即其 Min）
func TestChainVerifyKeysAcceptBoundaryValues(t *testing.T) {
	for _, b := range chainVerifyKeyBounds {
		t.Run(b.key, func(t *testing.T) {
			lowest := b.min
			if lowest == 0 {
				lowest = 1 // 無下界時最小合法值＝1（0 已由非 ZeroDisables 擋下）
			}
			for _, ok := range []int{lowest, b.max} {
				svc, _ := setupPolicyDB(t)
				if _, err := svc.Update(b.key, strconv.Itoa(ok), "admin"); err != nil {
					t.Fatalf("%s 拒絕了合法邊界值 %d: %v", b.key, ok, err)
				}
				if got := svc.GetInt(b.key); got != ok {
					t.Errorf("%s 存 %d 後讀回 %d：顯示值須等於生效值", b.key, ok, got)
				}
			}
			// 出廠預設必須自己落在值域內（政策頁載入即用此值）
			svc, _ := setupPolicyDB(t)
			if _, err := svc.Update(b.key, mustDef(t, b.key).Default, "admin"); err != nil {
				t.Errorf("%s 的出廠預設 %q 不合法: %v", b.key, mustDef(t, b.key).Default, err)
			}
		})
	}
}

// TestChainVerifyRowsPerHourRejectsBelowFloor 速率鍵是三鍵中唯一「調小才危險」者：
// 低於 10000 一律拒，10000 本身放行。
//
// **這是本檔的突變靶心**：把 policyDefs 的 `Min: 10000` 拿掉或改成 0 即轉紅。
// 具體攻擊值 1 與 9999 直接寫死在此，不由 def.Min 推導——推導式的測試在
// Min 被改小時會跟著一起放寬，等於自己失效
func TestChainVerifyRowsPerHourRejectsBelowFloor(t *testing.T) {
	svc, _ := setupPolicyDB(t)
	before := svc.GetInt(PolicyAuditChainVerifyRowsPerHour)

	for _, bad := range []string{"1", "9999"} {
		_, err := svc.Update(PolicyAuditChainVerifyRowsPerHour, bad, "admin")
		if !errors.Is(err, ErrPolicyInvalidValue) {
			t.Errorf("掃描速率接受了 %s 筆/小時（err=%v）——低於 10000 時舊區間在被合法清除前"+
				"永遠輪不到重驗，內容層對那段歷史實質關閉，而驗證頁上仍顯示掃描在推進", bad, err)
		}
		if got := svc.GetInt(PolicyAuditChainVerifyRowsPerHour); got != before {
			t.Errorf("掃描速率被拒後現值變成 %d（原 %d）", got, before)
		}
	}

	if _, err := svc.Update(PolicyAuditChainVerifyRowsPerHour, "10000", "admin"); err != nil {
		t.Fatalf("掃描速率拒絕了下界本身 10000: %v", err)
	}
	if got := svc.GetInt(PolicyAuditChainVerifyRowsPerHour); got != 10000 {
		t.Errorf("掃描速率存 10000 後讀回 %d", got)
	}
}

// TestChainVerifyKeyChangesAreReportedForAudit 三鍵的變更都須被回報為
// PolicyChange（old→new）——handler 的審計迴圈只審計 UpdateBatch 回報的項
// （`internal/api/security_policy_handler.go:104-107`，鍵無關的泛用迴圈），
// 故「三鍵的變更會不會進審計」在本包內的等價命題就是「會不會被回報」。
// 漏報＝該鍵被靜默改掉而審計軌跡上沒有這筆
func TestChainVerifyKeyChangesAreReportedForAudit(t *testing.T) {
	for _, b := range chainVerifyKeyBounds {
		t.Run(b.key, func(t *testing.T) {
			svc, _ := setupPolicyDB(t)
			d := mustDef(t, b.key)
			newValue := strconv.Itoa(b.max) // 與出廠預設必不相同（三鍵預設皆遠低於上界）
			if newValue == d.Default {
				t.Fatalf("%s 的上界與出廠預設相同，本測試構造不出變更", b.key)
			}

			changes, err := svc.UpdateBatch(map[string]string{b.key: newValue}, "admin")
			if err != nil {
				t.Fatalf("%s 更新失敗: %v", b.key, err)
			}
			if len(changes) != 1 || changes[0].Key != b.key ||
				changes[0].OldValue != d.Default || changes[0].NewValue != newValue {
				t.Fatalf("%s 的變更回報 = %+v, want 單筆 %s→%s（審計的 old→new 取自這裡）",
					b.key, changes, d.Default, newValue)
			}

			// 同值再存一次不得回報：審計裡不該出現 X→X 的空變更
			again, err := svc.UpdateBatch(map[string]string{b.key: newValue}, "admin")
			if err != nil {
				t.Fatalf("%s 重複更新失敗: %v", b.key, err)
			}
			if len(again) != 0 {
				t.Errorf("%s 無變動仍回報 %+v：審計中不應出現 X→X", b.key, again)
			}
		})
	}
}

// mustDef 取政策定義，缺鍵即中止（測試內慣用的取值助手）
func mustDef(t *testing.T, key string) *PolicyDef {
	t.Helper()
	d := findDef(key)
	if d == nil {
		t.Fatalf("政策鍵 %s 未定義", key)
	}
	return d
}
