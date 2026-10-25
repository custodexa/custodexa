package asset

// 標籤比對與正規化的對外入口：授權選擇器在範圍內候選資產上重用資產列表的標籤語義
// （NFC＋小寫折疊、整詞比對），避免兩處的標籤相等規則分岔。

// TagMatchCondition 整詞比對條件（欄位為 assets.tags）；搭配 TagMatchPattern 的參數。
const TagMatchCondition = tagWholeWordCondition

// TagMatchPattern 單一標籤的整詞比對參數。
func TagMatchPattern(tag string) string { return tagWholeWordPattern(tag) }

// NormalizeTagList 逗號字串切成正規化標籤序列（切分、NFC、去空、canonical 去重）。
func NormalizeTagList(raw string) []string { return normalizeTagList(raw) }

// CanonicalTagKey 標籤的 canonical 相等鍵。
func CanonicalTagKey(tag string) string { return canonicalTag(tag) }
