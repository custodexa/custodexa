package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 合規對照報告的資料集。
//
// 一份報告對應一個生效政策組、一個時點（打包當下，不回推）。PDF 與 CSV 都只讀
// 這份資料集：摘要數字由逐列結果數出來，而不是另取判定快照的摘要——兩處各算
// 一次，摘要與明細就可能對不起來，而沒有任何一處會報錯。
//
// 本檔不依賴 audit 模組（模組依賴矩陣禁止 policy→audit）；打包與清單檔在
// audit 的 ComplianceReportPackager。

// 保留天數的值域與缺省（值域沿輪替報告排程）。
const (
	ComplianceReportRetentionMinDays     = 1
	ComplianceReportRetentionMaxDays     = 3650
	ComplianceReportRetentionDefaultDays = 90
)

var (
	// ErrComplianceReportGroupInactive 政策組未生效：未生效組的判定快照不含該組
	// 任何一列，產出來會是一份「全部不在對照範圍」的報告
	ErrComplianceReportGroupInactive = errors.New("政策組未生效，無法產出報告")
	// ErrComplianceReportBadRetention 保留天數越界
	ErrComplianceReportBadRetention = errors.New("保留天數超出允許範圍")
)

// ComplianceReportMeta 報告的後設資訊（封面與頁尾）。
type ComplianceReportMeta struct {
	GroupCode    string
	GroupName    string
	GroupVersion string
	GroupSource  string
	GroupLocale  string
	// AsOf 資料時點＝判定快照的建構時點
	AsOf time.Time
	// GeneratedAt 產出時刻（打包當下）；GeneratedBy 發起者名
	GeneratedAt time.Time
	GeneratedBy string
	Language    string
	// JobRef 工作單識別（印在每頁頁尾）
	JobRef string
}

// ComplianceReportRow 一個（條文，設定鍵）判定；設定要求型條文沒有任何要求時
// 仍留一列（結果空白），使條文數與明細對得起來。
type ComplianceReportRow struct {
	ClauseNo    string
	ClauseTitle string
	Kind        string
	Key         string
	Result      string
	Reason      string
	Current     string
	Expected    string
	Comparator  string
	UnitKey     string
	// ZeroDisables 該鍵的 0 代表機制停用或永久保留（呈現層據此說出 0 的意義）
	ZeroDisables     bool
	ConfirmedBy      string
	ConfirmedAt      *time.Time
	ConfirmationNote string
	Note             string
	UpdatedBy        string
	UpdatedAt        *time.Time
}

// ComplianceReportClause 不產生鍵層判定的條文（由機構自行確認、由產品承擔）。
type ComplianceReportClause struct {
	ClauseNo string
	Title    string
	Note     string
}

// ComplianceReport 一份報告的完整資料集。
type ComplianceReport struct {
	Meta ComplianceReportMeta
	// Summary 由 Rows 數出的鍵層計數，Unmapped 取自判定快照，BuiltinProtection
	// 為 Builtin 的條數
	Summary GroupSummary
	// ClauseCount 本組仍在規範內的條文數（三型合計）
	ClauseCount  int
	Rows         []ComplianceReportRow
	SelfAttested []ComplianceReportClause
	Builtin      []ComplianceReportClause
}

// BuildComplianceReport 由判定快照與該組條文建構資料集（純函式）。
func BuildComplianceReport(snap ComplianceSnapshot, group model.PolicyGroup,
	clauses []model.PolicyClause, annotations []model.PolicyClauseAnnotation,
	meta ComplianceReportMeta) *ComplianceReport {

	meta.GroupCode = group.Code
	meta.GroupName = group.Name
	meta.GroupVersion = group.Version
	meta.GroupSource = group.Source
	meta.GroupLocale = group.Locale
	meta.AsOf = snap.BuiltAt

	notes := map[string]model.PolicyClauseAnnotation{}
	for _, a := range annotations {
		if a.GroupCode == group.Code {
			notes[a.ClauseNo] = a
		}
	}
	byClause := map[string][]Verdict{}
	for _, v := range snap.Verdicts {
		if v.GroupCode == group.Code {
			byClause[v.ClauseNo] = append(byClause[v.ClauseNo], v)
		}
	}

	rep := &ComplianceReport{Meta: meta}
	for _, c := range clauses {
		if c.GroupCode != group.Code || c.RemovedInVersion != "" {
			continue
		}
		rep.ClauseCount++
		ann := notes[c.ClauseNo]
		switch c.Kind {
		case model.PolicyClauseKindBuiltinProtection:
			rep.Builtin = append(rep.Builtin, ComplianceReportClause{ClauseNo: c.ClauseNo, Title: c.Title, Note: ann.Note})
		case model.PolicyClauseKindSelfAttested:
			rep.SelfAttested = append(rep.SelfAttested, ComplianceReportClause{ClauseNo: c.ClauseNo, Title: c.Title, Note: ann.Note})
		default:
			verdicts := byClause[c.ClauseNo]
			if len(verdicts) == 0 {
				rep.Rows = append(rep.Rows, ComplianceReportRow{ClauseNo: c.ClauseNo, ClauseTitle: c.Title,
					Kind: model.PolicyClauseKindSetting, Note: ann.Note})
				continue
			}
			for _, v := range verdicts {
				rep.Rows = append(rep.Rows, reportRowFrom(c, v, ann))
			}
		}
	}

	rep.Summary = GroupSummary{GroupCode: group.Code, BuiltinProtection: len(rep.Builtin),
		Unmapped: snap.GroupSummary(group.Code).Unmapped}
	for _, r := range rep.Rows {
		switch r.Result {
		case ComplianceResultCompliant:
			rep.Summary.Compliant++
		case ComplianceResultDeviating:
			rep.Summary.Deviating++
		case ComplianceResultNeedsReview:
			rep.Summary.NeedsReview++
		case ComplianceResultAuditReview:
			rep.Summary.AuditReview++
		}
	}
	return rep
}

func reportRowFrom(c model.PolicyClause, v Verdict, ann model.PolicyClauseAnnotation) ComplianceReportRow {
	row := ComplianceReportRow{
		ClauseNo: c.ClauseNo, ClauseTitle: c.Title, Kind: model.PolicyClauseKindSetting,
		Key: v.Key, Result: v.Result, Reason: v.Reason, Current: v.Current,
		Expected: v.Expected, Comparator: v.Comparator, UnitKey: v.UnitKey,
		ZeroDisables: v.ZeroDisables, ConfirmedBy: v.ConfirmedBy, ConfirmedAt: v.ConfirmedAt,
		Note: ann.Note, UpdatedBy: v.UpdatedBy, UpdatedAt: v.UpdatedAt,
	}
	if v.ConfirmedBy != "" {
		row.ConfirmationNote = ann.ConfirmationNote
	}
	return row
}

// BuildReport 以現值建構某一生效政策組的報告資料集。
//
// 政策現值、條文、要求與備註各讀一次，判定與報告明細出自同一批輸入——分兩次讀
// 的話，其間一次寫入會讓報告裡的條文與它的判定來自不同時點。
func (s *ComplianceService) BuildReport(groupCode string, meta ComplianceReportMeta) (*ComplianceReport, error) {
	group, err := s.groups.GetGroup(groupCode)
	if err != nil {
		return nil, err
	}
	if !group.Enabled {
		return nil, ErrComplianceReportGroupInactive
	}
	views, err := s.policies.ListWithError()
	if err != nil {
		return nil, err
	}
	clauses, err := s.groups.ListClauses(groupCode)
	if err != nil {
		return nil, err
	}
	controls, err := s.groups.ListControls(groupCode)
	if err != nil {
		return nil, err
	}
	annotations, err := s.groups.ListAnnotations(groupCode)
	if err != nil {
		return nil, err
	}
	values, changes := policyStateFromViews(views)
	snap := BuildSnapshot(policyDefs, values, changes, []model.PolicyGroup{*group},
		clauses, controls, annotations)
	return BuildComplianceReport(snap, *group, clauses, annotations, meta), nil
}

// ---- 工作單的參數快照 ----

// ComplianceReportJobFilter 合規報告工作單的參數快照：受理時存入、打包時讀回，
// 是發起與打包之間唯一的傳遞面。
type ComplianceReportJobFilter struct {
	Group string `json:"group"`
	// GroupName 受理當下的組名，只供下載中心顯示；報告封面以打包當下的組名為準
	GroupName     string `json:"group_name,omitempty"`
	Language      string `json:"language"`
	RetentionDays int    `json:"retention_days"`
	// GeneratedBy 發起者名，印在封面與清單檔；不進去重鍵
	GeneratedBy string `json:"generated_by,omitempty"`
}

// Marshal 序列化為工作單快照。
func (f ComplianceReportJobFilter) Marshal() (string, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return "", fmt.Errorf("序列化合規報告參數失敗: %w", err)
	}
	return string(data), nil
}

// DedupeKey 去重鍵：清掉不影響產物內容的欄位（發起者、顯示用組名）。
// 兩個人同時要同一份報告時拿到同一張工作單。
func (f ComplianceReportJobFilter) DedupeKey() (string, error) {
	f.GeneratedBy = ""
	f.GroupName = ""
	return f.Marshal()
}

// ValidateRetention 保留天數值域。
func (f ComplianceReportJobFilter) ValidateRetention() error {
	if f.RetentionDays < ComplianceReportRetentionMinDays || f.RetentionDays > ComplianceReportRetentionMaxDays {
		return ErrComplianceReportBadRetention
	}
	return nil
}

// ParseComplianceReportJobFilter 讀回快照。
func ParseComplianceReportJobFilter(snapshot string) (*ComplianceReportJobFilter, error) {
	var f ComplianceReportJobFilter
	if err := json.Unmarshal([]byte(snapshot), &f); err != nil {
		return nil, fmt.Errorf("解析合規報告參數失敗: %w", err)
	}
	return &f, nil
}

// ComplianceReportJobDisplay 下載中心列表的顯示投影（解析失敗回空 map：清單少
// 一段摘要，好過整份清單變成錯誤）。
func ComplianceReportJobDisplay(snapshot string) map[string]string {
	out := map[string]string{}
	f, err := ParseComplianceReportJobFilter(snapshot)
	if err != nil {
		return out
	}
	out["group"] = f.Group
	if f.GroupName != "" {
		out["group_name"] = f.GroupName
	}
	out["language"] = f.Language
	if f.RetentionDays != 0 {
		out["retention_days"] = strconv.Itoa(f.RetentionDays)
	}
	if f.GeneratedBy != "" {
		out["generated_by"] = f.GeneratedBy
	}
	return out
}
