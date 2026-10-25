package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 權限附證。
//
// 附證是掛在既有檢查點上的一組可空欄（model.AuditCheckpoint.Perm*）：權限快照本體、
// 事件鏈界標、對帳結果與起點旗標。第四版載荷的 `perm` 鍵由這組欄位重建（快照摘要由本體現算），
// 附證因此在檢查點自己的簽章與鏈接雜湊之內，沒有另一把附證簽章：清空、部分清空或改動任一欄，
// 都使該點自己驗不過（鏈尾那一點與其他點同等）。起點判定見 permission_coverage.go。

// StateTablePermission 權限狀態在失效事件通道與報表中的項名。
const StateTablePermission = "permission_state"

// 擴充項的簽章載體種類。
const (
	CarrierBaseSnapshot = "base_snapshot" // 既有基礎快照欄（僅基礎三項）
	CarrierAttestation  = "attestation"   // 權限附證
)

// PermissionExtension 登記清單的權限擴充項：指明載體與事件來源。
type PermissionExtension struct {
	Name        string
	Carrier     string
	EventSource string
}

// PermissionExtensionRegistry 權限擴充登記清單（回傳新 slice，呼叫端不得就地改寫）。
func PermissionExtensionRegistry() []PermissionExtension {
	return []PermissionExtension{{Name: StateTablePermission, Carrier: CarrierAttestation, EventSource: "permission_state_events"}}
}

// 附證驗證狀態。
const (
	PermAttestNotCovered = "not_covered" // 啟用界標之前的歷史檢查點，或尚未啟用
	PermAttestValid      = "valid"
	PermAttestInvalid    = "invalid" // 缺必要附證、簽章不符、格式未知、快照被改
)

// permissionSigner 附證簽驗所需的最小能力（checkpointSigner 的子集）。
type permissionSigner interface {
	Sign(data []byte) (int, string)
	Verify(version int, data []byte, sigBase64 string) (bool, error)
}

// PermissionAttestStatus 一個檢查點的附證驗證結果。
type PermissionAttestStatus struct {
	State  string
	Reason string
}

// VerifyPermissionAttestation 單點附證狀態：第四版且帶附證者驗其簽章（附證在檢查點簽章之內）；
// 第四版不帶附證者在鏈上已有更早的附證點時為 invalid（啟用後不該再有無附證的點），否則 not_covered；
// 第四版之前的點帶附證欄為 invalid（那些欄不在其簽章內），不帶為 not_covered。
func VerifyPermissionAttestation(db *gorm.DB, cp *model.AuditCheckpoint, signer permissionSigner) PermissionAttestStatus {
	var earlier bool
	if err := db.Raw(`SELECT EXISTS (SELECT 1 FROM audit_checkpoints WHERE seq < ? AND (`+permAttestAnyColumn+`))`, cp.Seq).Scan(&earlier).Error; err != nil {
		return PermissionAttestStatus{PermAttestInvalid, fmt.Sprintf("讀取權限附證失敗: %v", err)}
	}
	return permissionAttestationStatus(cp, signer, earlier)
}

func permissionAttestationStatus(cp *model.AuditCheckpoint, signer permissionSigner, sawAttestation bool) PermissionAttestStatus {
	has := checkpointHasAnyPermColumn(cp)
	if cp.AggScheme != model.AggSchemeV4 {
		if has {
			return PermissionAttestStatus{PermAttestInvalid, "第四版之前的檢查點帶權限附證欄（不在其簽章內）"}
		}
		if res, ok := checkpointPointSignature(cp, signer); !ok {
			// 只有真的舊點才是「尚未涵蓋」：第四版改標成舊版的點以舊形狀重建後驗不過
			return PermissionAttestStatus{PermAttestInvalid, res.Detail}
		}
		return PermissionAttestStatus{State: PermAttestNotCovered}
	}
	if !has {
		if res, ok := checkpointPointSignature(cp, signer); !ok {
			// 附證在第四版簽章之內：清空附證的點自己驗不過，不能當作「尚未涵蓋」
			return PermissionAttestStatus{PermAttestInvalid, res.Detail}
		}
		if sawAttestation {
			return PermissionAttestStatus{PermAttestInvalid, "啟用後的第四版檢查點不帶權限附證"}
		}
		return PermissionAttestStatus{State: PermAttestNotCovered}
	}
	if res, ok := checkpointPointSignature(cp, signer); !ok {
		return PermissionAttestStatus{PermAttestInvalid, res.Detail}
	}
	return PermissionAttestStatus{State: PermAttestValid}
}

// PermissionReport 權限狀態對帳結果。
type PermissionReport struct {
	State        string // match／mismatch／unknown／not_covered
	SinceSeq     uint
	ExpectedHash string
	ActualHash   string
	Missing      []string // 預期有、現況無：[<首個數字 ID>,"<集合>"]
	Extra        []string // 現況有、預期無
	Error        string
	// 起算點（內部）：重放自哪一筆事件之後、是否自超管重設起算。確認入口據此驗證重設已被採用。
	startEventSeq int64
	fromRebase    bool
}

func typedID(set, row string) string {
	var fields []json.RawMessage
	_ = json.Unmarshal([]byte(row), &fields)
	for _, f := range fields {
		var n uint64
		if json.Unmarshal(f, &n) == nil {
			return fmt.Sprintf("[%d,%q]", n, set)
		}
	}
	return fmt.Sprintf("[0,%q]", set)
}

func typedIDs(d map[string][]string) []string {
	var out []string
	for set, rows := range d {
		for _, r := range rows {
			out = append(out, typedID(set, r))
		}
	}
	sort.Strings(out)
	return out
}

// repeatableRead 回傳在 PG 上取一致性視圖用的交易選項（sqlite 單連線已序列化）。
func repeatableRead(db *gorm.DB) []*sql.TxOptions {
	if db.Dialector.Name() == "postgres" {
		return []*sql.TxOptions{{Isolation: sql.LevelRepeatableRead, ReadOnly: false}}
	}
	return nil
}

// permissionStart 對帳的起算點。
type permissionStart struct {
	notCovered bool
	state      *PermissionState
	seq        int64  // 重放 seq 大於此值的事件
	digest     string // 起算事件的摘要
	sinceSeq   uint   // 作為基準的附證所在檢查點序號（0＝無）
	fromRebase bool
	// fromAttestation 自附證的快照起算：附證所錨定的那一筆事件必須仍在、摘要相同，
	// 否則事件鏈被刪動過，不能只拿快照與現況比（全刪事件後的比較沒有意義）。
	fromAttestation bool
}

// resolvePermissionStart 依驗章通過的事實決定起算點：尚未涵蓋、或可信基準
// （驗章通過且相符或為起點的附證、超管重設）。找不到可信基準回 ErrPermissionEventChain。
//
// 起點附證與其他附證一樣自檢查點內的快照與界標起算（啟用事件與起點同交易寫入、內容相同），
// 錨定事件必須是 seq=1 且摘要相同：事件被刪再重建的啟用事件摘要必不同。
func resolvePermissionStart(tx *gorm.DB, signer permissionSigner) (*permissionStart, error) {
	lin, err := readPermissionLineage(tx, signer)
	if err != nil {
		return nil, err
	}
	if lin.clean() {
		return &permissionStart{notCovered: true}, nil
	}
	base := lin.base()
	rebase, rebaseState, rebaseAfterCp, err := latestTrustedRebase(tx)
	if err != nil {
		return nil, err
	}
	st := &permissionStart{}
	switch {
	case rebase != nil && (base == nil || int64(base.cp.Seq) <= rebaseAfterCp):
		// 超管重設不早於最後可用附證所在的檢查點：自重設事件的事後狀態起算
		st.state, st.seq, st.digest, st.fromRebase = rebaseState, rebase.Seq, rebase.Digest, true
		if base != nil {
			st.sinceSeq = base.cp.Seq
		}
	case base != nil:
		if st.state, err = DecodePermissionState([]byte(*base.cp.PermStateSnapshot)); err != nil {
			return nil, err
		}
		st.seq, st.digest, st.sinceSeq, st.fromAttestation = base.perm.EventSeq, base.perm.EventHead, base.cp.Seq, true
	default:
		return nil, fmt.Errorf("%w: %s", ErrPermissionEventChain, lin.noBaseReason())
	}
	return st, nil
}

// ReconcilePermissionState 從可信基準出發，重放其後完整連續事件，與現況比較。
// 可信基準＝驗章通過且封章當下相符或為起點的附證、驗證碼有效的超管重設
// （見 permission_coverage.go）。缺事件、錯序、驗證失敗、找不到基準回 unknown；不自動修正任何資料。
func ReconcilePermissionState(ctx context.Context, db *gorm.DB, signer permissionSigner) PermissionReport {
	rep := PermissionReport{State: "unknown"}
	err := db.Transaction(func(tx *gorm.DB) error {
		start, err := resolvePermissionStart(tx, signer)
		if err != nil {
			return err
		}
		if start.notCovered {
			rep.State = "not_covered"
			return nil
		}
		rep.SinceSeq, rep.startEventSeq, rep.fromRebase = start.sinceSeq, start.seq, start.fromRebase
		if start.fromAttestation {
			var anchor model.PermissionStateEvent
			if err := tx.Where("seq = ?", start.seq).Limit(1).Find(&anchor).Error; err != nil {
				return fmt.Errorf("讀取附證錨定事件失敗: %w", err)
			}
			if anchor.ID == 0 || anchor.Digest != start.digest {
				return fmt.Errorf("%w: 附證錨定的事件 seq=%d 不存在或摘要不符", ErrPermissionEventChain, start.seq)
			}
		}
		startState, startSeq, startDigest := start.state, start.seq, start.digest
		expected, untraced, err := replayPermissionEvents(tx, startState, startSeq, startDigest)
		if err != nil {
			return err
		}
		actual, err := ReadPermissionState(ctx, tx)
		if err != nil {
			return err
		}
		if rep.ExpectedHash, err = expected.Digest(); err != nil {
			return err
		}
		if actual.Meta.FormatVersion > expected.Meta.FormatVersion {
			// 基準與其後事件都停在較舊格式（沒有任何新格式事件）：在舊格式下比較，
			// 不把「新格式多出的集合」當成差異。
			actual = actual.ProjectTo(expected.Meta.FormatVersion)
		}
		if rep.ActualHash, err = actual.Digest(); err != nil {
			return err
		}
		rep.State = "match"
		if rep.ExpectedHash != rep.ActualHash {
			rep.State = "mismatch"
			d := DiffPermissionState(expected, actual)
			rep.Missing, rep.Extra = typedIDs(d.Del), typedIDs(d.Add)
			if expected.Meta != actual.Meta {
				rep.Extra = append(rep.Extra, `[0,"meta"]`)
			}
		} else if len(untraced) > 0 {
			// 重放相符，但鏈上有無來源變動事件：資料曾被繞過應用層改過。如實回報不符，
			// 差集取自那些事件（Del→預期有而被拿掉、Add→被加進來），經既有失效事件通道告警。
			rep.State = "mismatch"
			rep.ExpectedHash = untraced[0].BeforeDigest
			rep.ActualHash = untraced[len(untraced)-1].AfterDigest
			del, add := map[string][]string{}, map[string][]string{}
			for i := range untraced {
				var ed permissionEventDelta
				if err := json.Unmarshal([]byte(untraced[i].Delta), &ed); err != nil {
					return fmt.Errorf("%w: seq=%d 的差集無法解析", ErrPermissionEventChain, untraced[i].Seq)
				}
				for k, v := range ed.Del {
					del[k] = append(del[k], v...)
				}
				for k, v := range ed.Add {
					add[k] = append(add[k], v...)
				}
			}
			rep.Missing, rep.Extra = typedIDs(del), typedIDs(add)
			if len(rep.Missing)+len(rep.Extra) == 0 {
				rep.Extra = []string{`[0,"meta"]`}
			}
		}
		return nil
	}, repeatableRead(db)...)
	if err != nil {
		rep.State, rep.Error = "unknown", err.Error()
	}
	return rep
}

// ReconcilePermission 對帳並經既有失效事件通道回報（識別含項名與差異的具型別 ID）。
func (r *RoleStateReconciler) ReconcilePermission(ctx context.Context) PermissionReport {
	rep := ReconcilePermissionState(ctx, r.db, r.permSigner)
	tr := StateTableReport{Table: StateTablePermission, SinceSeq: rep.SinceSeq, ExpectedHash: rep.ExpectedHash,
		ActualHash: rep.ActualHash, Missing: rep.Missing, Extra: rep.Extra, Error: rep.Error}
	switch rep.State {
	case "match":
		tr.Covered, tr.State = true, RoleStateMatch
	case "mismatch":
		tr.Covered, tr.State = true, RoleStateMismatch
	case "not_covered":
		tr.State = RoleStateNotCovered
	default:
		// 啟用後（或已有附證）比對做不成：開固定識別的單，使「偵測停擺」可見，
		// 並讓超管能經確認入口重設基準（not_covered 不會走到這裡）。
		tr.State = StateTableUnknown
		r.reportPermissionUnknown()
		return rep
	}
	r.settleTable(tr)
	return rep
}

// permissionUnknownParams 附證啟用後對帳無法判定的失效事件識別（固定值，不帶錯誤全文）：
// 整段無法判定期間只開一張單；恢復相符時由 settleTable 結案，轉為不符時由新單取代。
func permissionUnknownParams() map[string]string {
	return map[string]string{"table": StateTablePermission, "since_seq": "0", "actual_hash": "unknown", "missing": "", "extra": ""}
}

// reportPermissionUnknown 每次對帳都經持久通道回報：去重以資料庫中同識別且未結案的列為準
// （ReportStateMismatch 對同識別為 no-op），單被刪除或被填上結案時間，下一次對帳就重建並重新通知。
func (r *RoleStateReconciler) reportPermissionUnknown() {
	if r == nil || r.stateFailure == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.stateFailure.ReportStateMismatch(StateTablePermission, permissionUnknownParams()); err != nil {
		log.Printf("[PrincipalState] permission unknown report failed: %v", err)
	}
}

// permissionReadFailureParams 附證啟用前讀取權限狀態失敗的失效事件識別（固定值，不帶錯誤全文）。
// since_seq 固定 0、actual_hash 固定標記，使整段失敗期間只開一張單，不隨封章反覆重開。
func permissionReadFailureParams() map[string]string {
	return map[string]string{"table": StateTablePermission, "since_seq": "0", "actual_hash": "read_failed", "missing": "", "extra": ""}
}

// ReportPermissionReadFailure 附證啟用前讀取權限狀態失敗：沿 principal_state_integrity 通道、
// 項名 permission_state 開單（失效事件列即審計留痕）。nil 接收者／未接通道＝只留 log。
func (r *RoleStateReconciler) ReportPermissionReadFailure(cause error) {
	if r == nil || r.stateFailure == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.stateFailure.ReportStateMismatch(StateTablePermission, permissionReadFailureParams()); err != nil {
		log.Printf("[PrincipalState] permission read-failure report failed: %v", err)
		return
	}
	r.permReadFailing = true
}

// ResolvePermissionReadFailure 讀取恢復後結案（僅在本行程曾開單時；重啟後的殘單由下一次對帳相符結案）。
func (r *RoleStateReconciler) ResolvePermissionReadFailure() {
	if r == nil || r.stateFailure == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.permReadFailing {
		return
	}
	if err := r.stateFailure.ResolveStateMismatch(StateTablePermission); err != nil {
		log.Printf("[PrincipalState] permission read-failure resolve failed: %v", err)
		return
	}
	r.permReadFailing = false
}

// SetPermissionAttestSigner 注入附證驗證用的簽章驗證能力（組裝根呼叫；nil＝只能對帳不能驗章，
// 此時任何附證都視為不可用基準，對帳回 unknown）。
func (r *RoleStateReconciler) SetPermissionAttestSigner(s permissionSigner) { r.permSigner = s }

var errPermissionAttestStatus = errors.New("權限附證驗證未通過")

// PermissionAttestationSummary 彙整給內部驗證結果與備份還原核對報告的新維度（不進既有 HTTP DTO）。
type PermissionAttestationSummary struct {
	Covered   bool
	Valid     int
	Invalid   int
	NotCover  int
	FirstFail string
}

// SummarizePermissionAttestations 逐檢查點驗附證並彙整；舊封章的簽章另由既有驗證負責。
func SummarizePermissionAttestations(db *gorm.DB, signer permissionSigner) (PermissionAttestationSummary, error) {
	var cps []model.AuditCheckpoint
	if err := db.Order("seq ASC").Find(&cps).Error; err != nil {
		return PermissionAttestationSummary{}, err
	}
	var sum PermissionAttestationSummary
	saw := false
	for i := range cps {
		switch st := permissionAttestationStatus(&cps[i], signer, saw); st.State {
		case PermAttestValid:
			sum.Valid++
			sum.Covered = true
		case PermAttestInvalid:
			sum.Invalid++
			if sum.FirstFail == "" {
				sum.FirstFail = fmt.Sprintf("seq=%d: %s", cps[i].Seq, st.Reason)
			}
		default:
			sum.NotCover++
		}
		saw = saw || checkpointHasAnyPermColumn(&cps[i])
	}
	if sum.Invalid > 0 {
		return sum, fmt.Errorf("%w: %s", errPermissionAttestStatus, strings.TrimSpace(sum.FirstFail))
	}
	return sum, nil
}
