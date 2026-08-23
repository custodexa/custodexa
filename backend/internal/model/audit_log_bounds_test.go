package model

// 審計列欄位長度收口的守衛（第一層）。
//
// # 突變自檢（互不掩蓋）
//
//	BoundAuditLogFields 整個改為 no-op
//	  → TestBoundAuditLogFieldsCapsOversizedPath 轉紅（path 仍為 616 字元）
//	BeforeCreate 拿掉 BoundAuditLogFields 呼叫
//	  → TestBeforeCreateBoundsBeforeStamping 轉紅（列存值超界）
//	截斷改為純砍尾（拿掉指紋標記）
//	  → TestBoundAuditStringStaysAttributable 轉紅（答不出原長度與指紋）
//	上界改為手寫常數 500 而不從標籤導出
//	  → TestAuditLogRuneLimitsComeFromStructTags 轉紅（標籤改了、常數沒跟上）

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestAuditLogRuneLimitsComeFromStructTags 上界的來源必須是結構標籤本身。
//
// 手寫對照表與 schema 必然漂移，而兩個方向的漂移都不會有其他測試轉紅：
// 表大於實際上界 → 收口放行超界值，寫入照樣失敗；表小於實際上界 → 合法值被
// 誤截，稽核平白損失資訊。
func TestAuditLogRuneLimitsComeFromStructTags(t *testing.T) {
	want := map[string]int{
		"Action":          20,
		"Resource":        20,
		"Status":          20,
		"Username":        100,
		"Method":          10,
		"Path":            500,
		"ClientIP":        50,
		"RequestID":       100,
		"IdempotencyUUID": 64, // 指標欄也必須被涵蓋
		"IntegrityHMAC":   64,
	}
	for field, limit := range want {
		if got := AuditLogRuneLimit(field); got != limit {
			t.Errorf("%s 的上界 = %d，應自標籤導出為 %d（標籤與收口漂移時，"+
				"超界值會照舊整批陪葬）", field, got, limit)
		}
	}
	// text 欄無上界，不得被誤收口——details 是聚合列的證據本體，截了就沒了
	for _, field := range []string{"Details", "RequestBody", "ErrorMsg"} {
		if got := AuditLogRuneLimit(field); got != 0 {
			t.Errorf("%s 是 text 欄，不應有上界，實得 %d", field, got)
		}
	}
	// 防空掃：反射失效時最可能的症狀是「一個欄位都沒導出」而全綠
	if len(auditLogRuneLimits()) < len(want) {
		t.Errorf("只導出 %d 個有上界的欄位（下界 %d）——導不出東西的收口"+
			"不是「沒有超界欄位」，是「沒在看」", len(auditLogRuneLimits()), len(want))
	}
}

// TestBoundAuditLogFieldsCapsOversizedPath 第一層收口的本體：
// `:id` 型路由可以吸收任意長度，匿名列原樣填 URL path，於是零憑證的請求就能
// 產出一列超出 varchar(500) 的審計列。
func TestBoundAuditLogFieldsCapsOversizedPath(t *testing.T) {
	raw := "/api/v1/assets/" + strings.Repeat("A", 600)
	row := &AuditLog{Path: raw, Method: "GET", ClientIP: "203.0.113.9"}

	BoundAuditLogFields(row)

	limit := AuditLogRuneLimit("Path")
	if n := utf8.RuneCountInString(row.Path); n > limit {
		t.Fatalf("收口後 path 仍有 %d 字元（上界 %d）——超界列寫入失敗，"+
			"且會讓同批其他合法審計列一併回滾", n, limit)
	}
	if !strings.HasPrefix(row.Path, "/api/v1/assets/AAAA") {
		t.Errorf("收口後 path = %q，前綴應保留（稽核要答得出他打的是哪一支端點）",
			row.Path[:40])
	}
	// 未超界的欄位不得被動到
	if row.Method != "GET" || row.ClientIP != "203.0.113.9" {
		t.Errorf("未超界欄位被改寫：method=%q client_ip=%q", row.Method, row.ClientIP)
	}
}

// TestBoundAuditStringStaysAttributable 截斷不得損失可歸屬性。
//
// 純砍尾之後，稽核在那一列上答不出「攻擊者到底打了什麼」——打了多長？是不是
// 同一發？兩次嘗試是同一條路徑還是不同條？故標記必須帶原始長度與指紋。
func TestBoundAuditStringStaysAttributable(t *testing.T) {
	raw := "/api/v1/assets/" + strings.Repeat("A", 600)
	got := BoundAuditString(raw, 500)

	if !strings.Contains(got, fmt.Sprintf("len=%d", utf8.RuneCountInString(raw))) {
		t.Errorf("截斷標記未帶原始長度：%q——「他打了多長」是判定探測或溢位攻擊的依據", got)
	}
	sum := sha256.Sum256([]byte(raw))
	fp := hex.EncodeToString(sum[:8])
	if !strings.Contains(got, "sha256="+fp) {
		t.Errorf("截斷標記未帶指紋：%q——沒有指紋就無法把同一條超長路徑的多次嘗試關聯計次", got)
	}

	// 指紋必須可鑑別：不同原值 → 不同指紋（否則「關聯計次」會把不同攻擊併成一筆）
	other := BoundAuditString("/api/v1/users/"+strings.Repeat("B", 600), 500)
	if strings.Contains(other, "sha256="+fp) {
		t.Errorf("不同原值得到相同指紋，指紋不可鑑別")
	}

	// 同一原值 → 同一指紋（可關聯）
	if again := BoundAuditString(raw, 500); again != got {
		t.Errorf("同一原值兩次收口結果不同：%q vs %q", got, again)
	}
}

// TestBoundAuditStringIsRuneSafe Postgres 的 varchar(N) 限的是**字元數**，
// 且從中間切斷 UTF-8 序列會產出亂碼（甚至讓 JSON 欄位解析失敗）。
func TestBoundAuditStringIsRuneSafe(t *testing.T) {
	// 全中文路徑：byte 數是 rune 數的三倍
	raw := "/api/v1/assets/" + strings.Repeat("測", 600)
	got := BoundAuditString(raw, 500)

	if n := utf8.RuneCountInString(got); n > 500 {
		t.Errorf("收口後 %d 字元，超過上界 500（以位元組計會誤判）", n)
	}
	if !utf8.ValidString(got) {
		t.Errorf("收口後不是合法 UTF-8——從中間切斷多位元組字元")
	}

	// 未超界的多位元組字串原樣不動
	short := strings.Repeat("測", 100)
	if BoundAuditString(short, 500) != short {
		t.Errorf("100 個中文字（300 位元組）被誤截——上界應以字元計")
	}
}

// TestBoundAuditStringShortFieldsFallBackToPlainTruncate 放不下標記的短欄位
// （method varchar(10)、status varchar(20)）仍須收口。
//
// 這些欄位的值不由請求決定，超界代表程式缺陷；純砍尾仍勝過整批陪葬。
func TestBoundAuditStringShortFieldsFallBackToPlainTruncate(t *testing.T) {
	got := BoundAuditString("PROPFINDPROPFIND", 10)
	if utf8.RuneCountInString(got) > 10 {
		t.Errorf("短欄位未收口：%q", got)
	}
	if got != "PROPFINDPR" {
		t.Errorf("短欄位應純砍尾為 %q，實得 %q", "PROPFINDPR", got)
	}
}

// TestBoundAuditLogFieldsCoversPointerField IdempotencyUUID 是 *string
// （唯一索引欄位需要 NULL 語義）。指標欄漏掉收口時，回灌路徑的超界值照樣毒化整批。
func TestBoundAuditLogFieldsCoversPointerField(t *testing.T) {
	long := strings.Repeat("u", 200)
	row := &AuditLog{IdempotencyUUID: &long}

	BoundAuditLogFields(row)

	if row.IdempotencyUUID == nil {
		t.Fatal("收口把指標欄清成 nil——NULL 與「有值但過長」是兩回事")
	}
	if n := utf8.RuneCountInString(*row.IdempotencyUUID); n > AuditLogRuneLimit("IdempotencyUUID") {
		t.Errorf("指標欄未收口：%d 字元", n)
	}

	// nil 指標不得 panic
	BoundAuditLogFields(&AuditLog{})
}

// TestBeforeCreateBoundsBeforeStamping 收口必須發生在**蓋章之前**。
//
// HMAC 涵蓋 path 等欄位；先蓋章後截斷會讓存入的值與章不符，鏈驗證當場報竄改
// ——那是把一個寫入缺陷升級成「審計被竄改」的假警報。
func TestBeforeCreateBoundsBeforeStamping(t *testing.T) {
	var stampedPath string
	SetAuditCreateHooks(func(l *AuditLog) { stampedPath = l.Path }, nil)
	t.Cleanup(func() { SetAuditCreateHooks(nil, nil) })

	row := &AuditLog{Path: "/api/v1/assets/" + strings.Repeat("A", 600)}
	if err := row.BeforeCreate(nil); err != nil {
		t.Fatalf("BeforeCreate: %v", err)
	}

	if n := utf8.RuneCountInString(row.Path); n > AuditLogRuneLimit("Path") {
		t.Fatalf("BeforeCreate 未收口 path（%d 字元）——收口不在唯一匯流點上時，"+
			"每條入庫路徑都要自己記得，那是必漏的模式", n)
	}
	if stampedPath != row.Path {
		t.Errorf("蓋章看到的 path 與存入值不同（章 %q 位元組 vs 存 %q 位元組）——"+
			"順序倒置會讓鏈驗證把正常寫入報成竄改",
			fmt.Sprint(len(stampedPath)), fmt.Sprint(len(row.Path)))
	}
}
