package reviewcal

import (
	"sort"
	"strings"
	"time"
)

// DateFormat 所屬日的日期格式
const DateFormat = "2006-01-02"

// SettleGrace 日終後的落庫寬限：告警聚合與操作日誌批次寫入會讓該日最後幾秒的
// 事件晚幾秒入庫，寬限結束前該日列入待簽但不能簽
const SettleGrace = 30 * time.Minute

// 歷史列來源中屬於「初值」的兩種：它們描述的是起點而不是一次變更，
// 所以之前的日子也以它們的值切
const (
	sourceSeed             = "seed"
	sourceMigrationUpgrade = "migration_upgrade"
)

// 推定來源與對應的 enabled_basis
var presumedBasisBySource = map[string]string{
	"migration_presumed_purged": "presumed_purged",
	"migration_presumed_gap":    "presumed_gap",
	"migration_presumed_tail":   "presumed_tail",
}

// inferredStartSources 連續啟用起點落在這些來源的區段時，起點本身是推定的
var inferredStartSources = map[string]bool{
	"migration_presumed_purged": true,
	"migration_presumed_gap":    true,
	"migration_presumed_tail":   true,
	"migration_policy_row":      true,
}

// BasisRecorded 有紀錄證明當天開著
const BasisRecorded = "recorded"

// Change 一筆政策變更歷史（依時刻遞增排列；同時刻依寫入順序）
type Change struct {
	At     time.Time
	Old    string
	New    string
	Source string
}

// Inputs 行事曆的輸入
type Inputs struct {
	// TZ 業務時區鍵的變更歷史
	TZ []Change
	// Enabled 功能開關鍵的變更歷史
	Enabled []Change
	// CurrentTZ 政策現值；沒有任何時區歷史時以它切每一天
	CurrentTZ string
}

// Day 一個所屬日
type Day struct {
	Date string
	TZ   string
	// TZInferred 該日的時區是升級時推定的（整天落在升級之前）
	TZInferred bool
	Start      time.Time
	End        time.Time
	DueAt      time.Time
	SignableAt time.Time
	InScope    bool
	// Basis 在啟用範圍內的依據（不在範圍內為空）
	Basis string
	// Source 決定該日依據的那一段歷史的來源（不在範圍內為空）
	Source string
}

// Ended 該日在 now 是否已結束
func (d Day) Ended(now time.Time) bool { return !now.Before(d.End) }

// Signable 該日在 now 是否已過落庫寬限
func (d Day) Signable(now time.Time) bool { return !now.Before(d.SignableAt) }

// Overdue 該日在 now 是否已過準時期限
func (d Day) Overdue(now time.Time) bool { return !now.Before(d.DueAt) }

// Pending 待生效的時區變更
type Pending struct {
	Value         string
	EffectiveDate string
	EffectiveAt   time.Time
}

type segment struct {
	start, end time.Time
	source     string
}

// Calendar 由歷史算出的行事曆：自最早一筆歷史所在的日子起，到今天（含）為止
type Calendar struct {
	now     time.Time
	days    []Day
	index   map[string]int
	tz0     string
	tzOrder []Change
	latest  string
	segs    []segment
	pending *Pending
}

// Build 由歷史與現在時刻算出行事曆
func Build(in Inputs, now time.Time) *Calendar {
	c := &Calendar{now: now, index: map[string]int{}}

	tzChanges := append([]Change(nil), in.TZ...)
	sortChanges(tzChanges)
	enabled := append([]Change(nil), in.Enabled...)
	sortChanges(enabled)

	// 初值：第一筆若是播種或升級寫入的初值，它就是起點的值；否則起點是它的舊值
	tz0 := in.CurrentTZ
	var migrationAt *time.Time
	if len(tzChanges) > 0 {
		first := tzChanges[0]
		if first.Source == sourceSeed || first.Source == sourceMigrationUpgrade {
			tz0 = first.New
			if first.Source == sourceMigrationUpgrade {
				at := first.At
				migrationAt = &at
			}
			tzChanges = tzChanges[1:]
		} else if first.Old != "" {
			tz0 = first.Old
		}
	}
	if _, ok := LoadTimezone(tz0); !ok {
		tz0 = DefaultTimezone
	}
	c.tz0 = tz0
	c.tzOrder = tzChanges
	c.segs = buildSegments(enabled)

	// 起點：最早一筆歷史所在的日子（與 now 無關，同一天任何時候算都一樣）
	startAt := now
	for _, list := range [][]Change{in.TZ, in.Enabled} {
		for _, ch := range list {
			if ch.At.Before(startAt) {
				startAt = ch.At
			}
		}
	}
	loc0 := mustLocation(tz0)
	startLocal := startAt.In(loc0)
	date := civil(startLocal.Year(), startLocal.Month(), startLocal.Day())
	day := Day{Date: date.format(), TZ: tz0, Start: midnight(date, loc0), End: midnight(date.add(1), loc0)}

	latest := tz0
	ptr := 0
	appliedChange := false
	for {
		c.finishDay(&day, migrationAt, appliedChange)
		c.index[day.Date] = len(c.days)
		c.days = append(c.days, day)
		if now.Before(day.End) {
			break
		}
		// 下一天的時區：該日結束前儲存的最後一個值
		for ptr < len(tzChanges) && tzChanges[ptr].At.Before(day.End) {
			latest = tzChanges[ptr].New
			ptr++
		}
		if latest != day.TZ {
			appliedChange = true
		}
		day = nextDay(day, latest)
	}

	// 待生效：至今最後儲存的值與今天的切日時區不同
	cur := latest
	for _, ch := range tzChanges[ptr:] {
		if !ch.At.After(now) {
			cur = ch.New
		}
	}
	today := c.days[len(c.days)-1]
	if cur != today.TZ {
		next := nextDay(today, cur)
		c.pending = &Pending{Value: cur, EffectiveDate: next.Date, EffectiveAt: today.End}
	}
	c.latest = cur
	return c
}

// nextDay 由前一天推下一天：起點接在前一天的結束時刻，終點是該日期在新時區的結束；
// 兩時區差過大使長度 ≤ 0 時順延一個日期，被跳過的日期不列入
func nextDay(prev Day, tz string) Day {
	loc := mustLocation(tz)
	date := parseCivil(prev.Date).add(1)
	end := midnight(date.add(1), loc)
	for !end.After(prev.End) {
		date = date.add(1)
		end = midnight(date.add(1), loc)
	}
	return Day{Date: date.format(), TZ: tz, Start: prev.End, End: end}
}

func (c *Calendar) finishDay(d *Day, migrationAt *time.Time, appliedChange bool) {
	loc := mustLocation(d.TZ)
	d.DueAt = midnight(parseCivil(d.Date).add(2), loc)
	d.SignableAt = d.End.Add(SettleGrace)
	d.TZInferred = migrationAt != nil && !appliedChange && !d.End.After(*migrationAt)
	d.InScope, d.Basis, d.Source = c.scopeOf(d.Start, d.End)
}

// scopeOf 啟用期間任一時刻落在 [start, end) 內即在範圍內；有任何有證據的區段
// 依據即為 recorded，只與推定區段相交時取最早一段的成因
func (c *Calendar) scopeOf(start, end time.Time) (bool, string, string) {
	var presumed *segment
	for i := range c.segs {
		s := &c.segs[i]
		if !s.start.Before(end) || !s.end.After(start) {
			continue
		}
		if _, isPresumed := presumedBasisBySource[s.source]; !isPresumed {
			return true, BasisRecorded, s.source
		}
		if presumed == nil {
			presumed = s
		}
	}
	if presumed == nil {
		return false, "", ""
	}
	return true, presumedBasisBySource[presumed.source], presumed.source
}

// buildSegments 重播開關歷史，得出開著的區段（同值但來源不同的列切出新區段）
func buildSegments(changes []Change) []segment {
	if len(changes) == 0 {
		return nil
	}
	far := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	var out []segment
	var open *segment
	if changes[0].Old == "true" {
		open = &segment{start: time.Time{}, source: ""}
	}
	for _, ch := range changes {
		on := ch.New == "true"
		if open != nil && (!on || open.source != ch.Source) {
			open.end = ch.At
			if open.end.After(open.start) {
				out = append(out, *open)
			}
			open = nil
		}
		if on && open == nil {
			open = &segment{start: ch.At, source: ch.Source}
		}
	}
	if open != nil {
		open.end = far
		out = append(out, *open)
	}
	return out
}

func sortChanges(list []Change) {
	sort.SliceStable(list, func(i, j int) bool { return list[i].At.Before(list[j].At) })
}

// Days 自起點到今天（含）的所屬日，依時間排列
func (c *Calendar) Days() []Day { return c.days }

// Today 現在時刻所屬的所屬日（尚未結束）
func (c *Calendar) Today() Day { return c.days[len(c.days)-1] }

// Yesterday 今天的前一個所屬日；行事曆只有今天一天時 ok=false
func (c *Calendar) Yesterday() (Day, bool) {
	if len(c.days) < 2 {
		return c.Lookup(parseCivil(c.Today().Date).add(-1).format())
	}
	return c.days[len(c.days)-2], true
}

// Pending 待生效的時區變更；沒有則 nil
func (c *Calendar) Pending() *Pending { return c.pending }

// Active 目前生效的時區（今天的切日時區）
func (c *Calendar) Active() string { return c.Today().TZ }

// Lookup 依日期查所屬日。早於行事曆起點的日子以初值時區切、不在範圍內；
// 晚於今天的日子尚未結束（以至今最後儲存的時區估算起訖）；被跳過的日期 ok=false
func (c *Calendar) Lookup(date string) (Day, bool) {
	if i, ok := c.index[date]; ok {
		return c.days[i], true
	}
	if _, ok := ParseDate(date); !ok {
		return Day{}, false
	}
	first := c.days[0]
	if date < first.Date {
		loc := mustLocation(c.tz0)
		cd := parseCivil(date)
		d := Day{Date: date, TZ: c.tz0, Start: midnight(cd, loc), End: midnight(cd.add(1), loc)}
		d.DueAt = midnight(cd.add(2), loc)
		d.SignableAt = d.End.Add(SettleGrace)
		d.InScope, d.Basis, d.Source = c.scopeOf(d.Start, d.End)
		return d, true
	}
	today := c.Today()
	if date > today.Date {
		// 直接計算，不逐日推進（日期來自請求，逐日走到 9999-12-31 是數百萬次迭代）：
		// 今天之後只有「明天」可能是轉換日（起點接在今天結束、可能跳過日期），
		// 再之後全部以至今最後儲存的時區整日切
		next := nextDay(today, c.latest)
		var d Day
		switch {
		case date < next.Date:
			return Day{}, false // 轉換時被跳過的日期
		case date == next.Date:
			d = next
		default:
			loc := mustLocation(c.latest)
			cd := parseCivil(date)
			d = Day{Date: date, TZ: c.latest, Start: midnight(cd, loc), End: midnight(cd.add(1), loc)}
		}
		loc := mustLocation(d.TZ)
		d.DueAt = midnight(parseCivil(d.Date).add(2), loc)
		d.SignableAt = d.End.Add(SettleGrace)
		d.InScope, d.Basis, d.Source = c.scopeOf(d.Start, d.End)
		return d, true
	}
	// 落在行事曆範圍內卻查無：改時區時被跳過的日期
	return Day{}, false
}

// EnabledSince 目前這段連續啟用的起點（推定區段與相鄰的有證據區段視為連續）、
// 起點是否為推定；目前未啟用時 ok=false
func (c *Calendar) EnabledSince() (since time.Time, inferred bool, ok bool) {
	idx := -1
	for i := range c.segs {
		if !c.segs[i].start.After(c.now) && c.segs[i].end.After(c.now) {
			idx = i
		}
	}
	if idx < 0 {
		return time.Time{}, false, false
	}
	for idx > 0 && !c.segs[idx-1].end.Before(c.segs[idx].start) {
		idx--
	}
	s := c.segs[idx]
	return s.start, inferredStartSources[s.source] || s.source == "", true
}

// DayOf 某時刻所屬的所屬日（行事曆範圍內）
func (c *Calendar) DayOf(t time.Time) (Day, bool) {
	for i := len(c.days) - 1; i >= 0; i-- {
		if !t.Before(c.days[i].Start) && t.Before(c.days[i].End) {
			return c.days[i], true
		}
	}
	return Day{}, false
}

// IsPresumedBasis basis 是否為推定
func IsPresumedBasis(basis string) bool { return strings.HasPrefix(basis, "presumed_") }

// ParseDate 解析 YYYY-MM-DD；格式或日期不合法回 ok=false
func ParseDate(s string) (time.Time, bool) {
	if len(s) != len(DateFormat) {
		return time.Time{}, false
	}
	t, err := time.Parse(DateFormat, s)
	if err != nil || t.Format(DateFormat) != s {
		return time.Time{}, false
	}
	return t, true
}

// DueAt 準時期限：所屬日加兩個日曆日在該時區的 00:00（日曆加日，不是固定 48 小時）
func DueAt(date string, tz string) time.Time {
	return midnight(parseCivil(date).add(2), mustLocation(tz))
}

// DayWindow 以單一時區切的所屬日起訖（沒有改時區時的一般情形）
func DayWindow(date string, tz string) (time.Time, time.Time) {
	loc := mustLocation(tz)
	cd := parseCivil(date)
	return midnight(cd, loc), midnight(cd.add(1), loc)
}

// LateDays 遲簽晚幾天：簽核時刻在該時區的日期減去所屬日隔天
func LateDays(date, tz string, signedAt time.Time) int {
	local := signedAt.In(mustLocation(tz))
	signed := civil(local.Year(), local.Month(), local.Day())
	return signed.daysSince(parseCivil(date).add(1))
}

// AddDays 日期加減
func AddDays(date string, n int) string { return parseCivil(date).add(n).format() }

// civilDate 不含時區的日曆日期
type civilDate struct{ t time.Time }

func civil(y int, m time.Month, d int) civilDate {
	return civilDate{time.Date(y, m, d, 0, 0, 0, 0, time.UTC)}
}

func parseCivil(s string) civilDate {
	t, _ := time.Parse(DateFormat, s)
	return civilDate{t}
}

func (c civilDate) add(n int) civilDate { return civilDate{c.t.AddDate(0, 0, n)} }
func (c civilDate) format() string      { return c.t.Format(DateFormat) }
func (c civilDate) daysSince(o civilDate) int {
	return int(c.t.Sub(o.t).Hours() / 24)
}

func midnight(c civilDate, loc *time.Location) time.Time {
	return time.Date(c.t.Year(), c.t.Month(), c.t.Day(), 0, 0, 0, 0, loc)
}
