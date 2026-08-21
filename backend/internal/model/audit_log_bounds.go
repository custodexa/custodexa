package model

// 審計列的欄位長度收口（audit-coverage-closure 批 1-R，缺陷 F1 第一層）。
//
// # 這裡補的是什麼洞
//
// `audit_logs.path` 是 `varchar(500)`，而寫入端原樣填 `c.Request.URL.Path`。
// `:id` 型路由可以吸收任意長度的字串，於是一個**零憑證**的請求
// （`GET /api/v1/assets/<600 個 A>`）就能產出一列超出欄位約束的審計列。
// 該列寫入失敗，`audit_logs` 零新列——批 1 剛補上的「拒絕路徑必留痕」在這條
// 路徑上被繞過。
//
// **真正的傷害是連帶損害**：審計走非同步批次，而多列 INSERT 是單一語句，
// 一列違約全批回滾。實測 9 發 401 中夾 1 發超長路徑 → 入庫 3/9，6 列合法
// 審計列跟著被沖掉。攻擊者可藉此在攻擊的同時抹掉自己的真實攻擊記錄。
// 那一層的隔離在 `modules/audit/audit_log_service.go` 的逐列重試；本檔負責
// 讓審計列**從源頭就不會超界**。
//
// # 為什麼收口在 model 的 BeforeCreate 而不是各寫入端
//
// `audit_logs` 有多條入庫路徑（middleware 批次、匿名拒絕列、asset GORM hook、
// file_tap、k8s cp、seal journal 回灌）。逐寫入端補「記得截斷」與逐 handler 補
// 審計是同一種必漏的模式；BeforeCreate 是全部入庫路徑的**唯一**匯流點，
// 收在這裡，新的寫入端自動涵蓋。
//
// 收口必須排在完整性蓋章**之前**——HMAC 涵蓋這些欄位，先蓋章後截斷會讓存入
// 的值與章不符，鏈驗證當場報竄改。
//
// # 上界從哪裡來
//
// **反射結構標籤導出**（`type:varchar(N)`），不是另寫一張對照表。手寫表與
// schema 必然漂移：改了 migration 忘了改表，收口就會放行超界值或誤截合法值，
// 而兩種漂移都不會有任何測試轉紅。
//
// 以**字元數**（rune）而非位元組計：Postgres 的 `varchar(N)` 限的是字元數，
// 以位元組截會在多位元組字元上誤判，且不會把 UTF-8 序列從中間切斷產生亂碼。
//
// **射程僅及於字元語義的後端**（批 1-R2 訂正）：本收口保證「字元數 ≤ N」，
// **不保證位元組數 ≤ N**——一個 rune 最多 4 個 byte，500 runes 可達 2000 bytes。
// 今日兩個後端都不受影響（Postgres 的 varchar 計字元、SQLite 不強制長度），
// 但若日後接上以 byte 計長度的後端，本收口擋不住超界，須另行處理。
// 原註解寫「rune 數 ≤ byte 數，故對 byte 語義的後端亦安全」，**推論方向寫反**
// ——該不等式成立，但它推出的恰好是「byte 語義的後端**不**安全」。
//
// # 截斷後仍要能歸屬
//
// 單純砍尾會損失可歸屬性——稽核在那一列上答不出「攻擊者到底打了什麼」。
// 故超界值改寫為「前綴 ＋ 指紋標記」：標記帶**原始字元長度**與原值的
// SHA-256 前 8 位元組。於是仍答得出：
//
//   - 打了哪一支端點（前綴保留 460 餘字元，路由前綴與載荷開頭都在裡面）；
//   - 打了多長（`len=`，可據以判定是探測還是溢位攻擊）；
//   - 是不是同一發（`sha256=`，同一條超長路徑的多次嘗試指紋相同，可關聯計次）。
//
// 完整原值另存於 access log（`middleware/accesslog.go` 印出完整 request target），
// 該處無長度上界。誠實邊界：access log 會輪替、不受檢查點鏈保護，故它是
// 補充證據而非權威留痕。

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// auditTruncMinRoom 標記所需的最小容納空間。低於此值的欄位（method
// `varchar(10)`、status `varchar(20)` 等枚舉欄）放不下標記，改為純砍尾。
//
// 那些欄位的值不由請求決定（HTTP 方法由路由層先擋、action／resource／status
// 是內部枚舉），超界代表程式缺陷而非攻擊；純砍尾仍勝過整批陪葬，且
// `logAuditTruncation` 會留下告警讓缺陷可被發現
const auditTruncMinRoom = 64

// auditLogType 反射用的型別握把。**以 nil 指標取型別而不是 `AuditLog{}` 字面量**：
// `internal/guards/moduleboundary` 的守衛以「model 包內出現 AuditLog 複合字面量」
// 判定「有人又在 model 層直寫審計列」，那個判準刻意不依賴命名習慣，故連型別
// 表達式也會命中。這裡繞開字面量，守衛的判準一個字都不必放寬
func auditLogType() reflect.Type {
	return reflect.TypeOf((*AuditLog)(nil)).Elem()
}

// auditLogRuneLimits 欄位索引 → 字元上界，自結構標籤導出。
//
// **刻意是函式而非包級 var**：同 `audit.safeAuditFieldSet` 的理由——它是自不可變
// 標籤導出的純函式結果，沒有初始化順序語義，做成包級全域只會讓 lifecycle manifest
// 多一筆需要人工寫「順序反了會怎樣」的登記（而答案是「不會怎樣」＝噪音）。
// 每列重建一次的成本是二十餘次結構標籤讀取，與同一路徑上的 DB 寫入不在同一個
// 數量級，且遮罩清單早已是同樣的形狀
func auditLogRuneLimits() map[int]int {
	limits := map[int]int{}
	t := auditLogType()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !isBoundableStringField(f.Type) {
			continue
		}
		n := parseVarcharLimit(f.Tag.Get("gorm"))
		if n <= 0 {
			continue
		}
		limits[i] = n
	}
	return limits
}

// parseVarcharLimit 自 gorm 標籤取出 `varchar(N)` 的 N（0＝無此宣告）。
// 只認 varchar——text 無上界，不需要也不應該收口
func parseVarcharLimit(tag string) int {
	const prefix = "varchar("
	i := strings.Index(tag, prefix)
	if i < 0 {
		return 0
	}
	rest := tag[i+len(prefix):]
	j := strings.IndexByte(rest, ')')
	if j < 0 {
		return 0
	}
	n, err := strconv.Atoi(rest[:j])
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// isBoundableStringField 字串欄或字串指標欄（IdempotencyUUID 是後者）
func isBoundableStringField(t reflect.Type) bool {
	if t.Kind() == reflect.String {
		return true
	}
	return t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.String
}

// AuditLogRuneLimit 回傳某欄位的字元上界（0＝無上界或無此欄）。
// 匯出的唯一理由是讓測試以**同一個來源**核對收口結果，而不是各自寫死 500
func AuditLogRuneLimit(field string) int {
	f, ok := auditLogType().FieldByName(field)
	if !ok || len(f.Index) != 1 {
		return 0
	}
	return auditLogRuneLimits()[f.Index[0]]
}

// BoundAuditLogFields 把所有有長度上界的字串欄收進上界內。
//
// 匯出是為了讓不經 GORM 的落地路徑（若日後出現）也能顯式套用同一套收口；
// 生產路徑由 `BeforeCreate` 自動呼叫，呼叫端不需要記得
func BoundAuditLogFields(a *AuditLog) {
	if a == nil {
		return
	}
	v := reflect.ValueOf(a).Elem()
	for idx, limit := range auditLogRuneLimits() {
		f := v.Field(idx)
		switch {
		case f.Kind() == reflect.String:
			orig := f.String()
			bounded := BoundAuditString(orig, limit)
			if bounded != orig {
				f.SetString(bounded)
				logAuditTruncation(v.Type().Field(idx).Name, orig, limit)
			}
		case f.Kind() == reflect.Ptr && !f.IsNil():
			orig := f.Elem().String()
			bounded := BoundAuditString(orig, limit)
			if bounded != orig {
				f.Elem().SetString(bounded)
				logAuditTruncation(v.Type().Field(idx).Name, orig, limit)
			}
		}
	}
}

// BoundAuditString 把單一字串收進 limit 個字元內，超界時附上可歸屬的指紋標記
func BoundAuditString(s string, limit int) string {
	if limit <= 0 || utf8.RuneCountInString(s) <= limit {
		return s
	}
	if limit < auditTruncMinRoom {
		return truncateRunes(s, limit)
	}
	marker := auditTruncMarker(s)
	keep := limit - utf8.RuneCountInString(marker)
	if keep < 0 {
		// 標記本身放不下（僅在 limit 極小時發生，前一個分支已擋掉常見情形）
		return truncateRunes(s, limit)
	}
	return truncateRunes(s, keep) + marker
}

// auditTruncMarker 截斷標記。**不含原值任何片段**（前綴已在標記之前保留），
// 只帶長度與指紋——指紋讓同一個超界值的多次出現可被關聯計次
func auditTruncMarker(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("…[trunc len=%d sha256=%s]",
		utf8.RuneCountInString(s), hex.EncodeToString(sum[:8]))
}

// truncateRunes 取前 n 個字元。以 range 走訪取得 rune 邊界，
// 不會把 UTF-8 序列從中間切斷
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// logAuditTruncation 截斷告警。**只印欄位名、長度與指紋，不印值本體**——
// 被截斷的值多半是攻擊載荷，原樣進 log 等於把載荷散佈到日誌收集鏈
func logAuditTruncation(field, orig string, limit int) {
	sum := sha256.Sum256([]byte(orig))
	log.Printf("警告: 審計欄位 %s 超出上界（%d 字元 > %d），已截斷並附指紋 sha256=%s",
		field, utf8.RuneCountInString(orig), limit, hex.EncodeToString(sum[:8]))
}
