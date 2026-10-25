package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// 超管確認「無來源變動」，或在比對無法完成時重設比對基準。
//
// 權限狀態被偵測到「兩次合法事件之間有人繞過應用層改庫」後，對帳告警會一直持續。
// 本服務讓超管確認並留下「已接受此風險」：同一個交易內寫一筆 accept 事件（以目前實際狀態為
// 新基準）和一筆強制審計列（確認人、原因、差集摘要）。不改任何角色、binding、映射或其他
// 權限資料，也不阻擋任何其他操作；確認後的對帳以 accept 之後的事件為準。
//
// 比對無法完成（事件鏈缺漏、摘要或驗證碼不符、找不到可用基準）時，之後的直接修改都無從
// 判定。此時確認是「重設比對基準」：寫一筆帶重設標記的 accept 事件，重放自它的事後狀態
// 重新起算，審計列另記無法判定的原因摘要。重設不修復也不掩蓋鏈本身：被破壞的那一段
// 仍在資料庫與審計列上，只是不再阻止之後的偵測。重設事件記下寫入當下鏈上最新的檢查點序號
// （在驗證碼涵蓋內），與附證的先後以它判定；提交後重跑對帳，未以這次重設起算即回錯，不假成功。

// PermissionAcceptReasonMaxRunes 確認原因的字數上限。
const PermissionAcceptReasonMaxRunes = 500

// permissionRebaseCauseMaxRunes 重設基準時審計列記下的無法判定原因摘要上限（不帶個資）。
const permissionRebaseCauseMaxRunes = 200

// permissionAcceptListCap 審計摘要內列出的具型別 ID 上限（其餘只計數）。
const permissionAcceptListCap = 20

// ErrPermissionAcceptReason 確認原因缺少、過長或含控制字元。
var ErrPermissionAcceptReason = errors.New("確認原因須為 1 至 500 字且不含控制字元")

// PermissionNotAcceptableError 目前沒有可確認的差異（相符、尚未涵蓋）。
type PermissionNotAcceptableError struct{ State string }

func (e *PermissionNotAcceptableError) Error() string {
	return "權限狀態目前不可確認（對帳狀態 " + e.State + "）"
}

// PermissionAcceptActor 確認人與請求來源。
type PermissionAcceptActor struct {
	Actor   gatewayapi.Actor
	Request gatewayapi.RequestMeta
}

// PermissionAcceptResult 確認結果（不含自由文字以外的敏感內容）。
// 重設基準時，差集取自「最後可信參考點」（相符附證的快照或先前重設的事後狀態）對現況，
// 讓被接受的內容留在審計列與回應上；沒有任何可信參考點時參考欄留空、計數為 0。
type PermissionAcceptResult struct {
	OpID              string   `json:"op_id"`
	EventSeq          int64    `json:"event_seq"`
	MissingCount      int      `json:"missing_count"`
	ExtraCount        int      `json:"extra_count"`
	Missing           []string `json:"missing,omitempty"`
	Extra             []string `json:"extra,omitempty"`
	ReferenceCpSeq    *uint    `json:"reference_cp_seq,omitempty"`
	ReferenceEventSeq *int64   `json:"reference_event_seq,omitempty"`
}

// ErrPermissionRebaseNotAdopted 重設已提交，但重跑對帳時起算點不是這次重設（或仍無法判定）。
// 確認入口據此回失敗而不是假成功；已提交的事件與審計列照實保留。
var ErrPermissionRebaseNotAdopted = errors.New("權限狀態重設已記錄，但對帳未採用此重設")

// PermissionAcceptService 確認服務。
type PermissionAcceptService struct {
	db         *gorm.DB
	sink       port.TxSink
	reconciler *RoleStateReconciler
}

// NewPermissionAcceptService reconciler 提供附證驗章能力，並於確認後重跑對帳以結案告警。
func NewPermissionAcceptService(db *gorm.DB, sink port.TxSink, reconciler *RoleStateReconciler) *PermissionAcceptService {
	return &PermissionAcceptService{db: db, sink: sink, reconciler: reconciler}
}

func validPermissionAcceptReason(raw string) (string, bool) {
	reason := strings.TrimSpace(raw)
	n := utf8.RuneCountInString(reason)
	if n < 1 || n > PermissionAcceptReasonMaxRunes {
		return "", false
	}
	for _, r := range reason {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return reason, true
}

func capIDs(ids []string) []string {
	if len(ids) > permissionAcceptListCap {
		return ids[:permissionAcceptListCap]
	}
	return ids
}

// Accept 確認目前對帳的「不符」並以目前狀態為新基準；對帳無法判定時改為重設比對基準。
// 相符與尚未涵蓋時不成立。事件、審計列同一交易，審計寫不進去則整筆回滾。
func (s *PermissionAcceptService) Accept(ctx context.Context, who PermissionAcceptActor, rawReason string) (*PermissionAcceptResult, error) {
	reason, ok := validPermissionAcceptReason(rawReason)
	if !ok {
		return nil, ErrPermissionAcceptReason
	}
	if s == nil || s.db == nil || s.reconciler == nil || !PermissionSourcesWired() {
		return nil, &PermissionNotAcceptableError{State: "not_covered"}
	}
	var (
		res     *PermissionAcceptResult
		rebase  bool
		afterCp int64
	)
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		rep := ReconcilePermissionState(ctx, tx, s.reconciler.permSigner)
		rebase = rep.State == "unknown"
		if rep.State != "mismatch" && !rebase {
			return &PermissionNotAcceptableError{State: rep.State}
		}
		head, err := latestPermissionEvent(tx)
		if err != nil {
			return err
		}
		if head == nil && !rebase {
			return &PermissionNotAcceptableError{State: "not_covered"}
		}
		if head == nil {
			// 事件表為空（全刪事件後重設）：與封章的首次啟用路徑取同一把 authz_state 列鎖，
			// 兩者都要寫 seq 1，序列化後由先到者寫入、後到者回錯重試，不並存
			if err := lockPermissionActivation(ctx, tx); err != nil {
				return err
			}
		}
		var before *PermissionState
		if head != nil {
			if before, err = DecodePermissionState([]byte(head.AfterBody)); err != nil && !rebase {
				return fmt.Errorf("%w: 鏈頭快照無法解碼: %v", ErrPermissionEventChain, err)
			}
		}
		now, err := ReadPermissionState(ctx, tx)
		if err != nil {
			return err
		}
		missing, extra := rep.Missing, rep.Extra
		var mark permissionRebase
		var ref *permissionStart
		if rebase {
			if mark.AfterCpSeq, err = latestCheckpointSeq(tx); err != nil {
				return err
			}
			mark.On, afterCp = true, mark.AfterCpSeq
			// 參考點讀不到（找不到任何可信基準）時略過差集，不擋確認
			if st, rerr := resolvePermissionStart(tx, s.reconciler.permSigner); rerr == nil && !st.notCovered {
				ref = st
				d := DiffPermissionState(st.state, now)
				missing, extra = typedIDs(d.Del), typedIDs(d.Add)
				if st.state.Meta != now.Meta {
					extra = append(extra, `[0,"meta"]`)
				}
			}
		}
		opID, err := NewPermissionOpID()
		if err != nil {
			return err
		}
		ev, err := insertPermissionEvent(tx, head, model.PermEventAccept, opID, before, now, nil, mark)
		if err != nil {
			return err
		}
		if ev.IntegrityHMAC == "" {
			// 沒蓋上驗證碼的確認在重放時不被採信，提交了也不會結案，不如明說失敗
			return errors.New("權限狀態確認未能取得完整性密鑰")
		}
		res = &PermissionAcceptResult{OpID: opID, EventSeq: ev.Seq, MissingCount: len(missing), ExtraCount: len(extra),
			Missing: capIDs(missing), Extra: capIDs(extra)}
		summary := map[string]any{
			"event": "permission_state_accepted", "reason": reason, "op_id": opID, "event_seq": ev.Seq,
			"since_seq": rep.SinceSeq, "expected_hash": shortHash(rep.ExpectedHash), "actual_hash": shortHash(rep.ActualHash),
			"missing_count": res.MissingCount, "extra_count": res.ExtraCount, "missing": res.Missing, "extra": res.Extra,
		}
		if rebase {
			summary["mode"], summary["state"], summary["cause"] = "rebase", rep.State, capRunes(rep.Error, permissionRebaseCauseMaxRunes)
			summary["after_cp_seq"] = mark.AfterCpSeq
			if ref != nil {
				refSeq := ref.seq
				res.ReferenceEventSeq = &refSeq
				summary["reference_event_seq"] = refSeq
				if ref.sinceSeq > 0 && !ref.fromRebase {
					cpSeq := ref.sinceSeq
					res.ReferenceCpSeq = &cpSeq
					summary["reference_cp_seq"] = cpSeq
				}
			}
		}
		details, err := json.Marshal(summary)
		if err != nil {
			return err
		}
		id := uint(ev.Seq)
		if err := port.WriteInTx(s.sink, tx, port.AuditEvent{
			Action: string(model.ActionPermissionStateAccepted), Resource: string(model.ResourceAuditFailure), ResourceID: &id,
			Status: string(model.StatusSuccess), Actor: who.Actor, Request: who.Request, Details: string(details),
			ErrorMsg: "permission_state_accepted",
		}); err != nil {
			return fmt.Errorf("權限狀態確認稽核失敗: %w", err)
		}
		return nil
	}, repeatableRead(s.db)...)
	if err != nil {
		return nil, err
	}
	// 交易已提交：重跑對帳，相符即經既有失效事件通道結案告警。
	after := s.reconciler.ReconcilePermission(ctx)
	if rebase && !permissionRebaseAdopted(after, res.EventSeq, afterCp) {
		// 重設寫進去了卻沒被採用（例如先後判定錯誤）：不回成功，避免超管以為告警會結案
		log.Printf("[PermissionState] 重設事件 seq=%d 已提交但未被對帳採用（狀態 %s）", res.EventSeq, after.State)
		return nil, ErrPermissionRebaseNotAdopted
	}
	return res, nil
}

// permissionRebaseAdopted 重跑的對帳是否以這次（或更晚的）重設起算，或以重設之後才封出的相符附證起算。
func permissionRebaseAdopted(rep PermissionReport, eventSeq, afterCp int64) bool {
	if rep.State == "unknown" || rep.State == "not_covered" {
		return false
	}
	if rep.fromRebase {
		return rep.startEventSeq >= eventSeq
	}
	return int64(rep.SinceSeq) > afterCp
}

// latestCheckpointSeq 鏈上最新的檢查點序號（無檢查點為 0）。
func latestCheckpointSeq(tx *gorm.DB) (int64, error) {
	var cp model.AuditCheckpoint
	if err := tx.Order("seq DESC").Limit(1).Find(&cp).Error; err != nil {
		return 0, fmt.Errorf("讀取最新檢查點失敗: %w", err)
	}
	return int64(cp.Seq), nil
}

func capRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
