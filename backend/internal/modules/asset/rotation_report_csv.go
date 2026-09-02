package asset

import (
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/csvsafe"
	"github.com/custodexa/backend/internal/notifycat"
)

// 報告的兩個 CSV 檔。
//
// 讀者是試算表：帶 BOM（否則繁中與日文在 Excel 直開是亂碼）、CRLF、
// 每個儲存格套公式注入轉義。欄名依報告語言。

// phraseFn 取本報告語言的一則短語。
type phraseFn func(key string) string

func phraseFor(lang string) phraseFn {
	return func(key string) string {
		return notifycat.Phrase(lang, notifycat.LexiconRotationReport, key)
	}
}

// accountColumnKeys 帳號檔的欄名鍵，順序即欄序。
//
// PDF 的附表 A 用同一份清單與同一支列轉換：兩處各寫一遍即等於允許
// 「CSV 與 PDF 的同一欄放的不是同一件事」。
var accountColumnKeys = []string{
	"col_asset", "col_address", "col_protocol", "col_account",
	"col_credential_type", "col_privileged", "col_shared",
	"col_plans", "col_multi_plan", "col_max_age_days", "col_max_age_source",
	"col_last_success", "col_last_status", "col_remaining_a",
	"col_next_schedule", "col_remaining_b", "col_candidate", "col_bucket",
}

// recordColumnKeys 記錄檔的欄名鍵，順序即欄序。
var recordColumnKeys = []string{
	"col_record_id", "col_executed_at", "col_plan", "col_asset", "col_account",
	"col_account_deleted", "col_secret_type", "col_result", "col_reason_code",
}

// csvAsOfPrefix CSV 首行註解列的前綴；其後接 RFC3339 的截止時點（含時區位移）。
// 兩個 CSV 都以它開頭：CSV 是最常被單獨抽出來丟進試算表的那一份，
// 「剩餘天數」離開截止時點就不可解釋，也無法重算。
const csvAsOfPrefix = "# as_of="

// writeAsOfRow 寫入截止時點註解列（單一儲存格，以 # 起頭）。
func writeAsOfRow(cw *csvsafe.Writer, rep *RotationReport) error {
	return cw.Write([]string{csvAsOfPrefix + rep.Meta.AsOf.Format(time.RFC3339)})
}

// WriteAccountsCSV 帳號明細檔。
func WriteAccountsCSV(w io.Writer, rep *RotationReport) error {
	ph := phraseFor(rep.Meta.Language)
	cw, err := csvsafe.NewWriter(w, csvsafe.Options{BOM: true, CRLF: true, Escape: true})
	if err != nil {
		return err
	}
	if err := writeAsOfRow(cw, rep); err != nil {
		return err
	}
	if err := cw.Write(headerRow(ph, accountColumnKeys)); err != nil {
		return err
	}
	for i := range rep.Rows {
		if err := cw.Write(accountValues(&rep.Rows[i], ph, timeValue)); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteRecordsCSV 區間記錄明細檔。
func WriteRecordsCSV(w io.Writer, rep *RotationReport) error {
	ph := phraseFor(rep.Meta.Language)
	cw, err := csvsafe.NewWriter(w, csvsafe.Options{BOM: true, CRLF: true, Escape: true})
	if err != nil {
		return err
	}
	if err := writeAsOfRow(cw, rep); err != nil {
		return err
	}
	if err := cw.Write(headerRow(ph, recordColumnKeys)); err != nil {
		return err
	}
	for i := range rep.Records {
		if err := cw.Write(recordValues(&rep.Records[i], ph, timeValue)); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func headerRow(ph phraseFn, keys []string) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = ph(k)
	}
	return out
}

// timeFmt 時刻的呈現方式。CSV 給完整到秒，PDF 表格給到分鐘（欄寬所限，
// 詳見 PDF 側的說明）。
type timeFmt func(*time.Time) string

// accountValues 一個帳號的欄值（CSV 與 PDF 附表 A 共用）。
func accountValues(row *AccountRow, ph phraseFn, tf timeFmt) []string {
	return []string{
		row.AssetName,
		row.AssetAddress,
		row.Protocol,
		row.Username,
		ph("credential_" + row.CredentialType),
		boolPhrase(row.Privileged, ph),
		boolPhrase(row.SharedCredential, ph),
		strings.Join(row.Plans, " / "),
		boolPhrase(row.MultiPlan, ph),
		daysValue(row.MaxAgeDays),
		maxAgeSourceLabel(row.MaxAgeSource, ph),
		tf(row.LastSuccessAt),
		statusLabel(row.LastRecordStatus, ph),
		intPtrValue(row.RemainingDaysA),
		tf(row.NextScheduleAt),
		intPtrValue(row.RemainingDaysB),
		ph("candidate_" + row.CandidateState),
		ph("bucket_" + row.Bucket),
	}
}

// recordValues 一筆記錄的欄值。
func recordValues(rec *RecordRow, ph phraseFn, tf timeFmt) []string {
	return []string{
		strconv.FormatUint(uint64(rec.RecordID), 10),
		tf(&rec.ExecutedAt),
		rec.PlanName,
		rec.AssetName,
		rec.AccountUsername,
		boolPhrase(rec.AccountDeleted, ph),
		rec.SecretType,
		statusLabel(rec.Status, ph),
		rec.ReasonCode,
	}
}

func boolPhrase(v bool, ph phraseFn) string {
	if v {
		return ph("value_yes")
	}
	return ph("value_no")
}

// daysValue 適用天數；0 意為未設定，輸出「未設定」而非 0——
// 0 天會被讀成「要求每天更換」。
func daysValue(days int) string {
	if days <= 0 {
		return ""
	}
	return strconv.Itoa(days)
}

func intPtrValue(v *int) string {
	if v == nil {
		return ""
	}
	return strconv.Itoa(*v)
}

func timeValue(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

func statusLabel(status string, ph phraseFn) string {
	if status == "" {
		return ""
	}
	return ph("status_" + status)
}

// maxAgeSourceLabel 天數出處：全域或某個計劃。
func maxAgeSourceLabel(source string, ph phraseFn) string {
	switch {
	case source == MaxAgeSourceGlobal:
		return ph("source_global")
	case strings.HasPrefix(source, MaxAgeSourcePlanPrefix):
		return ph("source_plan") + ": " + strings.TrimPrefix(source, MaxAgeSourcePlanPrefix)
	default:
		return ""
	}
}
