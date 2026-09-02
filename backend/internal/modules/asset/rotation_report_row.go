package asset

import (
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 逐帳號的計算：涵蓋計劃、適用天數、剩餘天數與狀態桶。

// coveringPlan 一個已啟用計劃在報告中用得到的部分。
type coveringPlan struct {
	id         uint
	name       string
	assets     map[uint]bool
	names      []string // nil＝該計劃涵蓋資產上的全部帳號
	maxAgeDays int
	// next 本計劃於截止時點之後的下一次觸發；零值＝無排程
	next time.Time
}

// planCoverage 已啟用計劃的預解析結果。
//
// cron 於此一次解析：對每個帳號各解析一次會把一次報告產出變成上萬次
// 字串剖析，而結果對同一個計劃恆等。
type planCoverage struct {
	plans []coveringPlan
}

func newPlanCoverage(plans []model.ChangeSecretPlan, asOf time.Time) *planCoverage {
	out := &planCoverage{}
	for i := range plans {
		p := &plans[i]
		// 停用計劃不算涵蓋。它的歷史記錄仍計入最後改密時刻——那是發生過的事實，
		// 與「今後誰負責改這個帳號」是兩件事
		if !p.Enabled {
			continue
		}
		cp := coveringPlan{id: p.ID, name: p.Name, maxAgeDays: p.MaxAgeDays,
			assets: map[uint]bool{}}
		for _, id := range AssetIDList(p) {
			cp.assets[id] = true
		}
		cp.names = explicitAccountNames(PlanAccountScope(p))
		if p.Cron != "" {
			if sched, err := cronParser.Parse(p.Cron); err == nil {
				cp.next = sched.Next(asOf)
			}
		}
		out.plans = append(out.plans, cp)
	}
	return out
}

// covers 該計劃是否涵蓋此帳號。
func (c *coveringPlan) covers(acc *model.AssetAccount) bool {
	if !c.assets[acc.AssetID] {
		return false
	}
	if c.names == nil {
		return true
	}
	for _, n := range c.names {
		if n == acc.Username {
			return true
		}
	}
	return false
}

// buildRow 單一帳號的完整推導。
func (b *RotationReportBuilder) buildRow(acc *model.AssetAccount, asset *model.Asset,
	cov *planCoverage, globalMaxAge int, lastSuccess map[uint]time.Time,
	lastRecord map[uint]string, candidates map[uint]string, asOf time.Time) AccountRow {

	row := AccountRow{
		AccountID: acc.ID, AssetID: acc.AssetID, Username: acc.Username,
		CredentialType: credentialType(acc), Privileged: acc.Privileged,
		SharedCredential: acc.CredentialGroup != "",
		LastRecordStatus: lastRecord[acc.ID],
		CandidateState:   CandidateNone,
	}
	if asset != nil {
		row.AssetName = asset.Name
		row.AssetAddress = addressOf(asset)
		row.Protocol = string(asset.Protocol)
	}
	if st, ok := candidates[acc.ID]; ok {
		row.CandidateState = st
	}

	var names []string
	var next time.Time
	planDays, planName := 0, ""
	for i := range cov.plans {
		p := &cov.plans[i]
		if !p.covers(acc) {
			continue
		}
		names = append(names, p.name)
		// 多計劃取最嚴：天數最小、排程最近
		if p.maxAgeDays > 0 && (planDays == 0 || p.maxAgeDays < planDays) {
			planDays, planName = p.maxAgeDays, p.name
		}
		if !p.next.IsZero() && (next.IsZero() || p.next.Before(next)) {
			next = p.next
		}
	}
	row.Plans = sortedNames(names)
	row.MultiPlan = len(names) > 1

	switch {
	case planDays > 0:
		row.MaxAgeDays, row.MaxAgeSource = planDays, MaxAgeSourcePlanPrefix+planName
	case globalMaxAge > 0:
		row.MaxAgeDays, row.MaxAgeSource = globalMaxAge, MaxAgeSourceGlobal
	}

	if ts, ok := lastSuccess[acc.ID]; ok {
		// 一律換算到截止時點的時區：同一份報告裡兩種位移並存，讀者無從判斷
		// 兩個時刻孰先孰後
		t := ts.In(asOf.Location())
		row.LastSuccessAt = &t
		if row.MaxAgeDays > 0 {
			a := row.MaxAgeDays - wholeDaysBetween(ts, asOf)
			row.RemainingDaysA = &a
		}
	}
	if !next.IsZero() {
		t := next.In(asOf.Location())
		row.NextScheduleAt = &t
		bDays := wholeDaysBetween(asOf, next)
		row.RemainingDaysB = &bDays
	}
	row.Bucket = bucketOf(&row)
	return row
}

// bucketOf 狀態桶的互斥判定，順序即語義優先序。
//
// 未驗證排最前：那是本系統對遠端狀態不可知的窗口，任何以「最後成功改密」
// 為基礎的判定在此期間都可能是錯的。無政策次之：沒有適用天數就沒有逾期可言，
// 把它算成合規或逾期都是編造。
func bucketOf(row *AccountRow) string {
	switch {
	case row.CandidateState != CandidateNone && row.CandidateState != "":
		return BucketUnverified
	case row.MaxAgeDays == 0:
		return BucketNoPolicy
	case row.LastSuccessAt == nil || row.RemainingDaysA == nil:
		return BucketNoRecord
	case *row.RemainingDaysA < 0:
		return BucketOverdue
	case *row.RemainingDaysA <= dueSoonWindowDays:
		return BucketDueSoon
	default:
		return BucketCompliant
	}
}

// wholeDaysBetween 由 from 到 to 的整日數（不足一日捨去；to 早於 from 時為負）。
func wholeDaysBetween(from, to time.Time) int {
	d := to.Sub(from)
	days := int(d / (24 * time.Hour))
	// Go 的整數除法對負值朝零捨入，而「差了 25 小時」不論方向都應是一整日
	if d < 0 && d%(24*time.Hour) != 0 {
		days--
	}
	return days
}

// credentialType 帳號持有的憑證型別。只說型別，不透露任何憑證內容。
func credentialType(acc *model.AssetAccount) string {
	switch {
	case acc.PasswordEnc != "":
		return CredentialTypePassword
	case acc.PrivateKeyEnc != "":
		return CredentialTypeSSHKey
	default:
		return CredentialTypeNone
	}
}

func addressOf(a *model.Asset) string {
	if a.Port == 0 {
		return a.Host
	}
	return a.Host + ":" + strconv.Itoa(a.Port)
}
