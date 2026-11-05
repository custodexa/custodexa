package session

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/custodexa/backend/internal/keystroke"
	"github.com/custodexa/backend/internal/keystroke/format"
	"github.com/custodexa/backend/internal/keystroke/writer"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
)

// 鍵盤紀錄服務：每個涵蓋的會話一份加密檔案加一列中繼資料。
//
// 啟動順序：產生檔案金鑰 → 以欄位信封封存 → insert recording 列（含封存後的金鑰）→ 開檔寫標頭。
// 封存失敗與開檔失敗各自留下 failed 列；只有 insert 本身失敗（資料庫不可寫）會沒有紀錄列，
// 此時告警照發。失敗一律不斷線：呼叫端拿到 nil 即沒有鍵盤紀錄，轉發照常。
//
// 明文按鍵內容不進任何 log、錯誤訊息或審計欄位。

const (
	// keystrokeHeartbeat 寫入端活著的心跳間隔：更新 last_write_at 供對帳判斷
	keystrokeHeartbeat = 60 * time.Second
	// keystrokeReconcileEvery 對帳週期
	keystrokeReconcileEvery = 10 * time.Minute
	// keystrokeStaleAfter 超過此時間沒有心跳且非本行程活躍者視為異常中止
	keystrokeStaleAfter = 5 * time.Minute
	keystrokeDBTimeout  = 5 * time.Second
)

// KeystrokeFailureReporter 審計失敗告警鏈的出口（組裝根以 audit.AuditFailureService 滿足）。
type KeystrokeFailureReporter interface {
	Report(mechanism, causeCode string, params map[string]string)
	ResolveFailure(mechanism string)
}

// KeystrokeService 鍵盤紀錄的建立、收尾與對帳。
type KeystrokeService struct {
	db       *gorm.DB
	codec    material.BytesColumnCodec
	root     string
	instance string

	reporter  KeystrokeFailureReporter
	heartbeat time.Duration
	// writerHook 讓測試調整寫入器設定（注入慢速或失敗的檔案）
	writerHook func(*writer.Config)

	mu     sync.Mutex
	active map[uint]struct{} // 本行程正在寫入的紀錄列 id
}

// NewKeystrokeService 建立服務。root 為鍵盤紀錄根目錄（審計資料根下的 keystrokes）。
// reporter 可為 nil（不通報，僅測試或未組裝時）。
func NewKeystrokeService(db *gorm.DB, codec material.BytesColumnCodec, root string,
	reporter KeystrokeFailureReporter) *KeystrokeService {
	host, _ := os.Hostname()
	if len(host) > 40 {
		host = host[:40]
	}
	return &KeystrokeService{
		db: db, codec: codec, root: root, reporter: reporter,
		instance:  fmt.Sprintf("%s:%d", host, os.Getpid()),
		heartbeat: keystrokeHeartbeat,
		active:    map[uint]struct{}{},
	}
}

// SetWriterConfigHook 注入寫入器設定的調整函式（測試用：慢速、停住或失敗的檔案）。
// 組裝根不呼叫；僅供啟動前設定，執行中不可變更。
func (s *KeystrokeService) SetWriterConfigHook(fn func(*writer.Config)) { s.writerHook = fn }

// SetRoot 改變鍵盤紀錄根目錄（測試用：不可寫目錄）。僅供啟動前設定。
func (s *KeystrokeService) SetRoot(root string) { s.root = root }

// Root 回傳鍵盤紀錄根目錄。
func (s *KeystrokeService) Root() string { return s.root }

// ProbeRoot 簽發點目錄可寫探測。
func (s *KeystrokeService) ProbeRoot() error { return keystroke.Probe(s.root) }

// newFileKey 產生一把 256-bit 隨機檔案金鑰。
func newFileKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := crand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

func dbCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), keystrokeDBTimeout)
}

func (s *KeystrokeService) reportFailure(sessionID uint, cause string, err error) {
	params := map[string]string{"session_id": strconv.FormatUint(uint64(sessionID), 10)}
	if err != nil {
		params[model.CauseParamDetail] = err.Error()
	}
	log.Printf("[Keystroke] 鍵盤紀錄失敗: session=%d cause=%s", sessionID, cause)
	if s.reporter != nil {
		s.reporter.Report(model.MechanismKeystrokeRecord, cause, params)
	}
}

// KeystrokeRecorder 一個會話的鍵盤紀錄寫入句柄。
type KeystrokeRecorder struct {
	svc       *KeystrokeService
	recID     uint
	sessionID uint
	w         *writer.Writer
	stopHB    chan struct{}
	hbDone    chan struct{}

	failMu    sync.Mutex
	failCause string
	closeOnce sync.Once
}

// Start 為會話啟動鍵盤紀錄。任何失敗都已留下 failed 列（能寫入時）並通報，
// 回傳 nil 表示此會話沒有鍵盤紀錄，呼叫端照常轉發。
func (s *KeystrokeService) Start(sess *model.Session, protocol string) (*KeystrokeRecorder, error) {
	if sess == nil {
		return nil, errors.New("keystroke: nil session")
	}
	startedAt := time.Now()
	recUUID := uuid.NewString()

	fek, err := newFileKey()
	if err != nil {
		s.insertFailed(sess.ID, recUUID, protocol, startedAt, model.CauseKeystrokeKeySealFailed)
		s.reportFailure(sess.ID, model.CauseKeystrokeKeySealFailed, err)
		return nil, err
	}
	secret := material.Adopt(fek)

	var enc string
	sealErr := errors.New("keystroke: key codec unavailable")
	if s.codec != nil {
		sealErr = secret.Borrow(func(b []byte) error {
			ctx, cancel := dbCtx()
			defer cancel()
			var e error
			enc, e = s.codec.EncryptBytesFor(ctx, keyvault.RefKeystrokeFileKey, b)
			return e
		})
	}
	if sealErr != nil {
		secret.Destroy()
		s.insertFailed(sess.ID, recUUID, protocol, startedAt, model.CauseKeystrokeKeySealFailed)
		s.reportFailure(sess.ID, model.CauseKeystrokeKeySealFailed, sealErr)
		return nil, sealErr
	}

	row := &model.KeystrokeRecord{
		RecordUUID: recUUID, SessionID: sess.ID, Protocol: protocol,
		Status: model.KeystrokeStatusRecording, FileKeyEnc: enc,
		FilePath: keystroke.RelPath(recUUID, startedAt), WriterInstance: s.instance,
		StartedAt: startedAt,
	}
	ctx, cancel := dbCtx()
	err = s.db.WithContext(ctx).Create(row).Error
	cancel()
	if err != nil {
		secret.Destroy()
		// 資料庫不可寫：沒有紀錄列，告警照發
		s.reportFailure(sess.ID, model.CauseKeystrokeFileCreateFailed, err)
		return nil, err
	}

	rec := &KeystrokeRecorder{svc: s, recID: row.ID, sessionID: sess.ID,
		stopHB: make(chan struct{}), hbDone: make(chan struct{})}
	cfg := writer.Config{
		Root: s.root, RecordUUID: recUUID, SessionID: uint64(sess.ID), Protocol: protocol,
		Start: startedAt, Key: secret,
		OnFail: rec.onWriterFail,
	}
	if s.writerHook != nil {
		s.writerHook(&cfg)
	}
	w, err := writer.Open(cfg) // 失敗時 Key 已清除
	if err != nil {
		cause := model.CauseKeystrokeFileCreateFailed
		var oe *writer.OpenError
		if errors.As(err, &oe) {
			cause = oe.Cause
		}
		s.markOpenFailed(row.ID, cause)
		s.reportFailure(sess.ID, cause, err)
		return nil, err
	}
	rec.w = w

	s.mu.Lock()
	s.active[row.ID] = struct{}{}
	s.mu.Unlock()
	go rec.heartbeatLoop()

	if s.reporter != nil {
		s.reporter.ResolveFailure(model.MechanismKeystrokeRecord)
	}
	return rec, nil
}

// insertFailed 為封存失敗留下一筆 failed 列（無檔案、無金鑰）。
func (s *KeystrokeService) insertFailed(sessionID uint, recUUID, protocol string, startedAt time.Time, cause string) {
	now := time.Now()
	row := &model.KeystrokeRecord{
		RecordUUID: recUUID, SessionID: sessionID, Protocol: protocol,
		Status: model.KeystrokeStatusFailed, FailureCause: cause, WriterInstance: s.instance,
		StartedAt: startedAt, EndedAt: &now,
	}
	ctx, cancel := dbCtx()
	defer cancel()
	if err := s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(row).Error; err != nil {
		log.Printf("[Keystroke] 失敗列寫入失敗: session=%d", sessionID)
	}
}

// markOpenFailed 開檔失敗：剛建的列改為 failed 並清空檔案金鑰與路徑（檔案不存在）。
func (s *KeystrokeService) markOpenFailed(recID uint, cause string) {
	now := time.Now()
	ctx, cancel := dbCtx()
	defer cancel()
	if err := s.db.WithContext(ctx).Model(&model.KeystrokeRecord{}).Where("id = ?", recID).
		Updates(map[string]interface{}{
			"status": model.KeystrokeStatusFailed, "failure_cause": cause,
			"file_key_enc": "", "file_path": "", "ended_at": now,
		}).Error; err != nil {
		log.Printf("[Keystroke] 標記開檔失敗未成功: record=%d", recID)
	}
}

// RecordNotCovered 為不涵蓋的會話類型寫一筆判定列（無檔案、無金鑰）。重複呼叫安全。
func (s *KeystrokeService) RecordNotCovered(sessionID uint, protocol, reason string) error {
	now := time.Now()
	row := &model.KeystrokeRecord{
		RecordUUID: uuid.NewString(), SessionID: sessionID, Protocol: protocol,
		Status: model.KeystrokeStatusNotCovered, CoverageReason: reason,
		WriterInstance: s.instance, StartedAt: now, EndedAt: &now,
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(row).Error
}

// Append 追加事件（呼叫端為輸入泵；佇列滿時同步等待）。已失敗者立即返回。
func (r *KeystrokeRecorder) Append(kind, flags byte, payload []byte) {
	if r == nil || r.w == nil {
		return
	}
	// 失敗已由 onWriterFail 通報並標記；此處不重複處理，也不影響轉發
	_ = r.w.Append(kind, flags, payload)
}

// 便利方法：位元組流事件的三種來源。
func (r *KeystrokeRecorder) AppendInput(p []byte) { r.Append(format.KindBytes, 0, p) }
func (r *KeystrokeRecorder) AppendBlocked(p []byte) {
	r.Append(format.KindBytes, format.FlagBlocked, p)
}
func (r *KeystrokeRecorder) AppendPlatform(p []byte) {
	r.Append(format.KindBytes, format.FlagPlatform, p)
}

// AppendMarker 寫入一筆平台標記事件（kind 0x10，碼見 keystroke.Marker*）。
// 空碼忽略；已失敗者立即返回。
func (r *KeystrokeRecorder) AppendMarker(code string) {
	if code == "" {
		return
	}
	r.Append(format.KindMarker, format.FlagPlatform, []byte(code))
}

func (r *KeystrokeRecorder) onWriterFail(cause string, err error) {
	r.failMu.Lock()
	r.failCause = cause
	r.failMu.Unlock()
	r.svc.reportFailure(r.sessionID, cause, err)
	go r.persistFailure(cause)
}

func (r *KeystrokeRecorder) persistFailure(cause string) {
	st := r.w.Stats()
	upd := map[string]interface{}{
		"status": model.KeystrokeStatusFailed, "failure_cause": cause,
		"event_count": st.Events, "byte_size": st.Bytes, "segment_count": st.Segments,
	}
	if !st.LastAt.IsZero() {
		upd["last_write_at"] = st.LastAt
	}
	ctx, cancel := dbCtx()
	defer cancel()
	if err := r.svc.db.WithContext(ctx).Model(&model.KeystrokeRecord{}).
		Where("id = ? AND status = ?", r.recID, model.KeystrokeStatusRecording).
		Updates(upd).Error; err != nil {
		log.Printf("[Keystroke] 標記失敗未成功: record=%d", r.recID)
	}
}

func (r *KeystrokeRecorder) heartbeatLoop() {
	defer close(r.hbDone)
	t := time.NewTicker(r.svc.heartbeat)
	defer t.Stop()
	for {
		select {
		case <-r.stopHB:
			return
		case now := <-t.C:
			st := r.w.Stats()
			ctx, cancel := dbCtx()
			err := r.svc.db.WithContext(ctx).Model(&model.KeystrokeRecord{}).
				Where("id = ? AND status = ?", r.recID, model.KeystrokeStatusRecording).
				Updates(map[string]interface{}{
					"last_write_at": now, "event_count": st.Events,
					"byte_size": st.Bytes, "segment_count": st.Segments,
				}).Error
			cancel()
			if err != nil {
				log.Printf("[Keystroke] 心跳寫入失敗: record=%d", r.recID)
			}
		}
	}
}

// Close 會話結束：排空佇列、封結束段並標記完成（或失敗）。重複呼叫安全。
func (r *KeystrokeRecorder) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		close(r.stopHB)
		<-r.hbDone
		st, werr := r.w.Close()
		now := time.Now()
		status := model.KeystrokeStatusComplete
		upd := map[string]interface{}{
			"event_count": st.Events, "byte_size": st.Bytes, "segment_count": st.Segments,
			"ended_at": now,
		}
		if !st.LastAt.IsZero() {
			upd["last_write_at"] = st.LastAt
		}
		if werr != nil {
			status = model.KeystrokeStatusFailed
			if c := r.w.FailCause(); c != "" {
				upd["failure_cause"] = c
			}
		}
		upd["status"] = status
		ctx, cancel := dbCtx()
		err := r.svc.db.WithContext(ctx).Model(&model.KeystrokeRecord{}).
			Where("id = ? AND status IN ?", r.recID,
				[]string{model.KeystrokeStatusRecording, model.KeystrokeStatusFailed}).
			Updates(upd).Error
		cancel()
		if err != nil {
			log.Printf("[Keystroke] 收尾寫入失敗: record=%d", r.recID)
		}
		r.svc.mu.Lock()
		delete(r.svc.active, r.recID)
		r.svc.mu.Unlock()
	})
}

// ReconcileStale 把「錄製中」卻無人在寫的紀錄標為 incomplete：
// 不在本行程活躍集合、且 last_write_at（無值取 started_at）早於門檻。
// 另一個仍在運作的實例有心跳，不會被誤標。回傳標記筆數。
func (s *KeystrokeService) ReconcileStale(now time.Time) (int64, error) {
	s.mu.Lock()
	ids := make([]uint, 0, len(s.active))
	for id := range s.active {
		ids = append(ids, id)
	}
	s.mu.Unlock()

	cutoff := now.Add(-keystrokeStaleAfter)
	ctx, cancel := dbCtx()
	defer cancel()
	q := s.db.WithContext(ctx).Model(&model.KeystrokeRecord{}).
		Where("status = ? AND COALESCE(last_write_at, started_at) < ?", model.KeystrokeStatusRecording, cutoff)
	if len(ids) > 0 {
		q = q.Where("id NOT IN ?", ids)
	}
	res := q.Updates(map[string]interface{}{
		"status":   model.KeystrokeStatusIncomplete,
		"ended_at": gorm.Expr("COALESCE(last_write_at, started_at)"),
	})
	return res.RowsAffected, res.Error
}

// StartReconciler 啟動時對帳一次，之後每 10 分鐘一次，直到 ctx 結束。
func (s *KeystrokeService) StartReconciler(ctx context.Context) {
	run := func() {
		if n, err := s.ReconcileStale(time.Now()); err != nil {
			log.Printf("[Keystroke] 對帳失敗: %v", err)
		} else if n > 0 {
			log.Printf("[Keystroke] 對帳：%d 份紀錄標為未正常結束", n)
		}
	}
	run()
	go func() {
		t := time.NewTicker(keystrokeReconcileEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				run()
			}
		}
	}()
}
