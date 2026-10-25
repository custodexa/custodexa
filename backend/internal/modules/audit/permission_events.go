package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

// 權限狀態事件鏈。
//
// 事件與每次權限版本推進同交易寫入（authz.AdvanceVersion 呼叫 RecordPermissionStateEvent），
// 寫入失敗則整個交易（資料變更＋版本）一併回滾。事件鏈是 append-only 的雜湊鏈，
// 每列另帶與審計列同一組完整性密鑰算出的驗證碼（permission_event_integrity.go），
// 鏈頭錨定進下一個檢查點的附證，附證在檢查點自己的簽章載荷之內（checkpoint_canonical_v4.go）。
// 雜湊鏈證明「序列沒被抽換」，驗證碼證明「這一列是持有密鑰的應用程式寫的」：
// 驗證碼不符或缺失的列，重放時計為無來源變動。
//
// 附證啟用之前不寫事件（沒有基準，也不回填偽造歷史）：第一個附證封章時在同一個封章交易內
// 寫入 activate 事件，之後的每次推進才有事件。來源未注入（單元測試夾具）視為未受管狀態，不寫事件，
// 封章也不產生附證；正式組裝一律注入。

// ErrPermissionEventChain 事件鏈結構不合（缺序、斷鏈、摘要不符、差集無法套用）。
var ErrPermissionEventChain = errors.New("權限狀態事件鏈不完整或被竄改")

// NewPermissionOpID 產生 128-bit 隨機操作識別（事件與恢復交易共用格式）。
func NewPermissionOpID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("產生操作識別失敗: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

type permissionEventDelta struct {
	PermissionDelta
	Meta *PermissionMeta `json:"meta,omitempty"`
	// Rebase 超管在對帳無法判定時重設比對基準：重放自此事件的事後狀態重新起算（只認驗證碼有效者）
	Rebase bool `json:"rebase,omitempty"`
	// AfterCpSeq 重設寫入當下鏈上最新的檢查點序號（只在重設時寫；在摘要與驗證碼涵蓋內）。
	// 重設與附證的先後以它對附證所在的檢查點序號判定，不比可能因整鏈被刪而歸零的事件序號。
	AfterCpSeq int64 `json:"after_cp_seq,omitempty"`
}

// permissionRebase 重設標記與其所在位置（非重設事件為零值）。
type permissionRebase struct {
	On         bool
	AfterCpSeq int64
}

// permissionActivation 啟用事件的附帶事實：界標（同交易封出的檢查點序號）。
type permissionActivation struct {
	Seq int64
}

// permissionEventDigest 事件摘要：以長度前綴雜湊綁定序號、種類、操作、版本、前後摘要與差集。
func permissionEventDigest(e *model.PermissionStateEvent) string {
	return stateHash([]byte(PermissionRow(e.Seq, e.Kind, e.OpID, e.Version, e.PrevDigest,
		e.BeforeDigest, e.AfterDigest, e.Delta)))
}

// permissionEventsTableExists 事件表是否存在。遷移前的資料庫（以及只建部分表的測試夾具）沒有它，
// 視同「附證尚未啟用」；正式庫在遷移後恆有此表。
func permissionEventsTableExists(tx *gorm.DB) bool {
	return tx.Migrator().HasTable(&model.PermissionStateEvent{})
}

func latestPermissionEvent(tx *gorm.DB) (*model.PermissionStateEvent, error) {
	if !permissionEventsTableExists(tx) {
		return nil, nil
	}
	var e model.PermissionStateEvent
	err := tx.Order("seq DESC").Limit(1).Find(&e).Error
	if err != nil {
		return nil, fmt.Errorf("讀取權限狀態事件鏈頭失敗: %w", err)
	}
	if e.ID == 0 {
		return nil, nil
	}
	return &e, nil
}

func insertPermissionEvent(tx *gorm.DB, head *model.PermissionStateEvent, kind, opID string,
	before, after *PermissionState, activation *permissionActivation, rebase permissionRebase) (*model.PermissionStateEvent, error) {
	afterBody, err := after.Encode()
	if err != nil {
		return nil, err
	}
	afterDigest := stateHash(afterBody)
	beforeDigest := afterDigest
	var delta PermissionDelta
	if before != nil {
		if beforeDigest, err = before.Digest(); err != nil {
			return nil, err
		}
		delta = DiffPermissionState(before, after)
	}
	meta := after.Meta
	ed := permissionEventDelta{PermissionDelta: delta, Meta: &meta, Rebase: rebase.On, AfterCpSeq: rebase.AfterCpSeq}
	var activatedSeq *int64
	if activation != nil {
		seq := activation.Seq
		activatedSeq = &seq
	}
	deltaJSON, err := json.Marshal(ed)
	if err != nil {
		return nil, err
	}
	e := &model.PermissionStateEvent{
		Seq: 1, Version: after.Meta.Version, Kind: kind, OpID: opID,
		BeforeDigest: beforeDigest, AfterDigest: afterDigest,
		Delta: string(deltaJSON), AfterBody: string(afterBody),
		ActivatedSeq: activatedSeq, CreatedAt: time.Now().UTC(),
	}
	if head != nil {
		e.Seq = head.Seq + 1
		e.PrevDigest = head.Digest
	}
	e.Digest = permissionEventDigest(e)
	stampPermissionEvent(e)
	if err := tx.Create(e).Error; err != nil {
		return nil, fmt.Errorf("寫入權限狀態事件失敗: %w", err)
	}
	return e, nil
}

// PermissionAttestationEnabled 權限附證事件鏈是否已啟用（已有鏈頭）。來源未注入時為 false。
// 只讀；供啟動資料步驟的報告標示，不用於任何放行判斷。
func PermissionAttestationEnabled(ctx context.Context, db *gorm.DB) (bool, error) {
	if !PermissionSourcesWired() {
		return false, nil
	}
	head, err := latestPermissionEvent(db.WithContext(ctx))
	if err != nil {
		return false, err
	}
	return head != nil, nil
}

// RecordPermissionStateEvent 於呼叫端交易 tx 內記錄一次權限狀態推進。
// 附證尚未啟用（無鏈頭）或來源未注入時不做事；其餘任何失敗都回傳錯誤，使呼叫端交易回滾。
func RecordPermissionStateEvent(ctx context.Context, tx *gorm.DB, kind, opID string) error {
	if !PermissionSourcesWired() {
		return nil
	}
	head, err := latestPermissionEvent(tx)
	if err != nil {
		return err
	}
	if head == nil {
		return nil
	}
	before, err := DecodePermissionState([]byte(head.AfterBody))
	if err != nil {
		return fmt.Errorf("%w: 鏈頭快照無法解碼: %v", ErrPermissionEventChain, err)
	}
	after, err := ReadPermissionState(ctx, tx)
	if err != nil {
		return err
	}
	if opID == "" {
		if opID, err = NewPermissionOpID(); err != nil {
			return err
		}
	}
	_, err = insertPermissionEvent(tx, head, kind, opID, before, after, nil, permissionRebase{})
	return err
}

// SettlePermissionStateEvent 於已記過事件的同一交易、其後仍有權限寫入時呼叫：
// 目前狀態與鏈頭事後狀態不同才再記一筆 change 事件（不推進版本），使交易提交時的鏈頭
// 等於實際狀態；相同則不寫。附證尚未啟用或來源未注入時為 no-op。
func SettlePermissionStateEvent(ctx context.Context, tx *gorm.DB) error {
	if !PermissionSourcesWired() {
		return nil
	}
	head, err := latestPermissionEvent(tx)
	if err != nil || head == nil {
		return err
	}
	before, err := DecodePermissionState([]byte(head.AfterBody))
	if err != nil {
		return fmt.Errorf("%w: 鏈頭快照無法解碼: %v", ErrPermissionEventChain, err)
	}
	now, err := ReadPermissionState(ctx, tx)
	if err != nil {
		return err
	}
	same, err := permissionStatesEqual(before, now)
	if err != nil {
		return err
	}
	if same {
		return nil
	}
	opID, err := NewPermissionOpID()
	if err != nil {
		return err
	}
	_, err = insertPermissionEvent(tx, head, model.PermEventChange, opID, before, now, nil, permissionRebase{})
	return err
}

// 無來源變動事件寫入流程的測試掛點，生產恆為 nil，只由本包的測試檔設定。
var (
	untracedAfterCompare  func(attempt int, headSeq int64)
	untracedAfterInsert   func(attempt int)
	untracedAfterConflict func(attempt int)
	untracedSavepointStep func(step string) error
)

// ErrPermissionEventContention 無來源變動事件的序號競爭在重試次數內仍未解決。
// 回傳的錯誤同時包住最後一次的資料庫原始錯誤，呼叫端交易應整筆回滾。
var ErrPermissionEventContention = errors.New("權限狀態事件序號競爭未能解決")

const (
	untracedMaxAttempts = 2
)

// isUntracedSeqConflict 只認事件序號唯一索引上的唯一衝突；其他約束與錯誤都不重試。
func isUntracedSeqConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "uq_permission_state_events_seq"
}

// untracedUsesSavepoint 只有 PostgreSQL 且 tx 確為交易時才以 savepoint 包住每次嘗試。
func untracedUsesSavepoint(tx *gorm.DB) bool {
	if tx.Dialector.Name() != "postgres" {
		return false
	}
	_, ok := tx.Statement.ConnPool.(gorm.TxCommitter)
	return ok
}

func untracedSavepointExec(tx *gorm.DB, step string) error {
	if untracedSavepointStep != nil {
		if err := untracedSavepointStep(step); err != nil {
			return err
		}
	}
	switch step {
	case "savepoint":
		return tx.Exec("SAVEPOINT perm_untraced").Error
	case "rollback_to":
		return tx.Exec("ROLLBACK TO SAVEPOINT perm_untraced").Error
	case "release":
		return tx.Exec("RELEASE SAVEPOINT perm_untraced").Error
	}
	return fmt.Errorf("未知的 savepoint 步驟: %s", step)
}

// untracedRollbackRelease 回到 savepoint 並釋放它（ROLLBACK TO 之後 savepoint 仍存在，必須再釋放）。
func untracedRollbackRelease(tx *gorm.DB) error {
	if err := untracedSavepointExec(tx, "rollback_to"); err != nil {
		return fmt.Errorf("回到 savepoint 失敗: %w", err)
	}
	if err := untracedSavepointExec(tx, "release"); err != nil {
		return fmt.Errorf("釋放 savepoint 失敗: %w", err)
	}
	return nil
}

func untracedRelease(tx *gorm.DB) error {
	if err := untracedSavepointExec(tx, "release"); err != nil {
		return fmt.Errorf("釋放 savepoint 失敗: %w", err)
	}
	return nil
}

// untracedFail 收尾一次失敗的嘗試：回滾並釋放 savepoint 後回傳原錯誤；收尾本身失敗時兩者並陳。
func untracedFail(tx *gorm.DB, cause error) error {
	if err := untracedRollbackRelease(tx); err != nil {
		return fmt.Errorf("%w（原始錯誤: %w）", err, cause)
	}
	return cause
}

// RecordUntracedPermissionDrift 在合法權限變更「動手之前」呼叫（同一交易）：比對目前權限狀態與
// 上一筆事件的事後狀態，不一致時先寫一筆獨立的 untraced 事件（記差集），使隨後的合法事件
// 差集只含合法變更，不把兩次合法事件之間的資料庫直寫洗進去。
// 不阻擋合法寫入；告警由對帳經既有失效事件通道發出（重放遇 untraced 事件即回報不符）。
// 附證尚未啟用、來源未注入時為 no-op。回傳是否寫了 untraced 事件。
//
// 在 PostgreSQL 交易內，兩筆並發寫入看見同一個鏈頭時會在序號唯一索引上相撞，後到者的交易
// 因此進入失敗狀態。這裡以 savepoint 包住「讀鏈頭、讀現況、比較、建事件、插入」整段，
// 只在撞到序號唯一索引時回到 savepoint 重算並再試一次（共兩次嘗試）；重算包含重新讀取
// 鏈頭，因此勝者已記下同一筆差異時，重試會發現現況與新鏈頭一致而不再寫入。
// 重試後仍相撞，或隔離級別使重讀看不到新鏈頭，回傳 ErrPermissionEventContention，由外層交易整筆回滾。
// 其他錯誤（含死結與序列化失敗）一律原樣回傳，不在此重試。
func RecordUntracedPermissionDrift(ctx context.Context, tx *gorm.DB) (bool, error) {
	if !PermissionSourcesWired() {
		return false, nil
	}
	if !untracedUsesSavepoint(tx) {
		return recordUntracedPermissionDriftOnce(ctx, tx)
	}
	var prevHeadSeq int64
	var firstErr error
	for attempt := 1; attempt <= untracedMaxAttempts; attempt++ {
		if err := untracedSavepointExec(tx, "savepoint"); err != nil {
			return false, fmt.Errorf("建立 savepoint 失敗: %w", err)
		}
		head, err := latestPermissionEvent(tx)
		if err != nil {
			return false, untracedFail(tx, err)
		}
		if head == nil {
			if attempt == 1 {
				return false, untracedRelease(tx)
			}
			return false, untracedFail(tx, fmt.Errorf("%w: 重試時鏈頭已不存在", ErrPermissionEventChain))
		}
		if attempt > 1 && head.Seq <= prevHeadSeq {
			return false, untracedFail(tx, fmt.Errorf("%w: 重讀的鏈頭沒有前進: %w", ErrPermissionEventContention, firstErr))
		}
		before, err := DecodePermissionState([]byte(head.AfterBody))
		if err != nil {
			return false, untracedFail(tx, fmt.Errorf("%w: 鏈頭快照無法解碼: %v", ErrPermissionEventChain, err))
		}
		now, err := ReadPermissionState(ctx, tx)
		if err != nil {
			return false, untracedFail(tx, err)
		}
		same, err := permissionStatesEqual(before, now)
		if err != nil {
			return false, untracedFail(tx, err)
		}
		if same {
			return false, untracedRelease(tx)
		}
		opID, err := NewPermissionOpID()
		if err != nil {
			return false, untracedFail(tx, err)
		}
		if untracedAfterCompare != nil {
			untracedAfterCompare(attempt, head.Seq)
		}
		if _, err := insertPermissionEvent(tx, head, model.PermEventUntraced, opID, before, now, nil, permissionRebase{}); err != nil {
			if untracedAfterConflict != nil {
				untracedAfterConflict(attempt)
			}
			if !isUntracedSeqConflict(err) {
				return false, untracedFail(tx, err)
			}
			if attempt == untracedMaxAttempts {
				return false, untracedFail(tx, fmt.Errorf("%w: %w", ErrPermissionEventContention, err))
			}
			if rerr := untracedRollbackRelease(tx); rerr != nil {
				return false, fmt.Errorf("%w（原始錯誤: %w）", rerr, err)
			}
			firstErr, prevHeadSeq = err, head.Seq
			continue
		}
		if untracedAfterInsert != nil {
			untracedAfterInsert(attempt)
		}
		return true, untracedRelease(tx)
	}
	return false, ErrPermissionEventContention // 不可達：迴圈內每條路徑都已回傳
}

// recordUntracedPermissionDriftOnce 單次嘗試版本：SQLite 與非交易 handle 使用，不開 savepoint。
func recordUntracedPermissionDriftOnce(ctx context.Context, tx *gorm.DB) (bool, error) {
	head, err := latestPermissionEvent(tx)
	if err != nil || head == nil {
		return false, err
	}
	before, err := DecodePermissionState([]byte(head.AfterBody))
	if err != nil {
		return false, fmt.Errorf("%w: 鏈頭快照無法解碼: %v", ErrPermissionEventChain, err)
	}
	now, err := ReadPermissionState(ctx, tx)
	if err != nil {
		return false, err
	}
	same, err := permissionStatesEqual(before, now)
	if err != nil {
		return false, err
	}
	if same {
		return false, nil
	}
	opID, err := NewPermissionOpID()
	if err != nil {
		return false, err
	}
	if untracedAfterCompare != nil {
		untracedAfterCompare(1, head.Seq)
	}
	if _, err := insertPermissionEvent(tx, head, model.PermEventUntraced, opID, before, now, nil, permissionRebase{}); err != nil {
		if untracedAfterConflict != nil {
			untracedAfterConflict(1)
		}
		return false, err
	}
	if untracedAfterInsert != nil {
		untracedAfterInsert(1)
	}
	return true, nil
}

// EnsurePermissionActivation 於封章交易 tx 內確保啟用界標存在。已啟用則回傳鏈頭；
// 否則以目前狀態寫入 activate 事件（activatedSeq＝同交易封出的檢查點序號）。
// 啟用事件與該檢查點同交易提交；這筆啟用是不是可信起點，由檢查點簽章內的起點旗標決定，
// 不寫在事件裡。
func EnsurePermissionActivation(ctx context.Context, tx *gorm.DB, state *PermissionState, activatedSeq int64) (*model.PermissionStateEvent, error) {
	head, err := latestPermissionEvent(tx)
	if err != nil {
		return nil, err
	}
	if head != nil {
		return head, nil
	}
	opID, err := NewPermissionOpID()
	if err != nil {
		return nil, err
	}
	return insertPermissionEvent(tx, nil, model.PermEventActivate, opID, nil, state,
		&permissionActivation{Seq: activatedSeq}, permissionRebase{})
}

// replayPermissionEvents 從附證快照（或重設基準事件）base 出發重放 seq > afterSeq 的完整連續事件。
// 回傳重放後的狀態與其中的無來源變動：untraced 事件，以及驗證碼不符或缺失的任何事件
// （不可信列帶來的狀態一律當作無來源變動；不可信的 accept 不清掉先前的無來源變動）。
// 任何缺序、斷鏈、摘要或差集問題都回 ErrPermissionEventChain，呼叫端據此回報 unknown，不默認相符。
func replayPermissionEvents(tx *gorm.DB, base *PermissionState, afterSeq int64, headDigest string) (*PermissionState, []model.PermissionStateEvent, error) {
	var events []model.PermissionStateEvent
	if err := tx.Where("seq > ?", afterSeq).Order("seq ASC").Find(&events).Error; err != nil {
		return nil, nil, fmt.Errorf("讀取權限狀態事件失敗: %w", err)
	}
	state := base
	prevSeq, prevDigest := afterSeq, headDigest
	var untraced []model.PermissionStateEvent
	for i := range events {
		e := &events[i]
		if e.Seq != prevSeq+1 {
			return nil, nil, fmt.Errorf("%w: 序號 %d 之後缺漏（下一筆為 %d）", ErrPermissionEventChain, prevSeq, e.Seq)
		}
		if e.PrevDigest != prevDigest {
			return nil, nil, fmt.Errorf("%w: seq=%d 的前一摘要不符", ErrPermissionEventChain, e.Seq)
		}
		if permissionEventDigest(e) != e.Digest {
			return nil, nil, fmt.Errorf("%w: seq=%d 的事件摘要不符", ErrPermissionEventChain, e.Seq)
		}
		var d permissionEventDelta
		if err := json.Unmarshal([]byte(e.Delta), &d); err != nil || d.Meta == nil {
			return nil, nil, fmt.Errorf("%w: seq=%d 的差集無法解析", ErrPermissionEventChain, e.Seq)
		}
		next, err := state.Apply(d.PermissionDelta)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: seq=%d %v", ErrPermissionEventChain, e.Seq, err)
		}
		next.Meta = *d.Meta
		next.Meta.FormatVersion = PermissionStateFormatVersion
		got, err := next.Digest()
		if err != nil || got != e.AfterDigest {
			return nil, nil, fmt.Errorf("%w: seq=%d 重放後摘要與事件記載不符", ErrPermissionEventChain, e.Seq)
		}
		switch {
		case !permissionEventTrusted(e):
			// 雜湊鏈接得上不代表是應用程式寫的：只持資料庫帳密者也算得出摘要
			untraced = append(untraced, *e)
		case e.Kind == model.PermEventUntraced:
			untraced = append(untraced, *e)
		case e.Kind == model.PermEventRestore && !d.PermissionDelta.Empty():
			// 恢復交易本身只改版本、世代指紋與操作識別；restore 事件裡的任何集合差異都不是
			// 恢復造成的，不因寫在帶驗證碼的 restore 事件內就變可信，照無來源變動回報。
			untraced = append(untraced, *e)
		case e.Kind == model.PermEventAccept:
			// 超管已確認：其前的無來源變動不再使對帳判不符（accept 事件本身的差集已套用）
			untraced = nil
		}
		state, prevSeq, prevDigest = next, e.Seq, e.Digest
	}
	return state, untraced, nil
}

// latestTrustedRebase 最近一筆驗證碼有效、且自身事後狀態可解的重設基準事件；沒有回 nil。
// 驗證碼不符的重設事件不被採信（只持資料庫帳密者不得自行重設基準）。
// 另回傳重設寫入當下鏈上最新的檢查點序號（在驗證碼涵蓋內）。
func latestTrustedRebase(tx *gorm.DB) (*model.PermissionStateEvent, *PermissionState, int64, error) {
	if !permissionEventsTableExists(tx) {
		return nil, nil, 0, nil
	}
	var evs []model.PermissionStateEvent
	if err := tx.Where("kind = ?", model.PermEventAccept).Order("seq DESC").Find(&evs).Error; err != nil {
		return nil, nil, 0, fmt.Errorf("讀取權限狀態確認事件失敗: %w", err)
	}
	for i := range evs {
		e := &evs[i]
		var d permissionEventDelta
		if json.Unmarshal([]byte(e.Delta), &d) != nil || !d.Rebase {
			continue
		}
		if permissionEventDigest(e) != e.Digest || stateHash([]byte(e.AfterBody)) != e.AfterDigest || !permissionEventTrusted(e) {
			continue
		}
		st, err := DecodePermissionState([]byte(e.AfterBody))
		if err != nil {
			continue
		}
		return e, st, d.AfterCpSeq, nil
	}
	return nil, nil, 0, nil
}
