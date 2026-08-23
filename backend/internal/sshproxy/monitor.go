package sshproxy

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/custodexa/backend/internal/apierror"
)

// replayBufferMax 中途加入觀察者的尾端回放緩衝上限：
// 足以讓 xterm.js 重建可讀畫面，不維護虛擬螢幕
const replayBufferMax = 64 * 1024

// monitorWriteTimeout 單次廣播寫入單一觀察者的上限。
//
// 為什麼需要：room 的廣播在持有 r.mu 時同步呼叫 ws.WriteMessage，慢速或半死的
// 觀察者（TCP 視窗塞滿、拔網路線的稽核員）會把整個 room 卡住，而 broadcastOutput
// 由 bridge 的輸出路徑呼叫——監看者反過來拖住被監看會話，與「監看絕不阻塞或影響
// 會話主路徑」的契約直接矛盾。
//
// 取捨：逾時即踢掉該觀察者並關其連線（監看是可重連的唯讀職能，掉線是可接受的降級；
// 會話主路徑被拖慢則不可接受）。有界佇列＋非同步 writer 是更平順的解法，但屬並發
// 結構重構，不在本次範圍。
//
// var 而非 const：測試以極短逾時驗證「慢速觀察者被移除且不阻塞」。
var monitorWriteTimeout = 5 * time.Second

// writeToObserver 帶寫入逾時送出單則已編碼幀（所有對觀察者的寫入都必須經此，
// 否則就是一條沒有 deadline 的阻塞路徑）
func writeToObserver(ws *websocket.Conn, raw []byte) error {
	if err := ws.SetWriteDeadline(time.Now().Add(monitorWriteTimeout)); err != nil {
		return err
	}
	return ws.WriteMessage(websocket.TextMessage, raw)
}

// ObserverContext 觀察者的認證脈絡。
//
// 監看訂閱是一種**長效能力**：它不建 session 列、不經連線授權，
// 純靠一次角色檢查就一直存活。缺了脈絡，provider 停用或帳號停用時
// 完全無從得知「哪些正在監看的人該被收線」——按 session 掃描掃不到它們，
// 因為被監看的會話可能是別人（甚至是本地帳號）建立的。
type ObserverContext struct {
	UserID uint
	// ProviderID 0＝本地/LDAP 登入的觀察者。按 provider 收線掃不到這種，
	// 故必須另有「按 user」的收線途徑（帳號停用/刪除時用）
	ProviderID uint
	AuthEpoch  int
	CredEpoch  int
}

// MonitorHub 全進程的會話監看註冊表：sessionID → room
type MonitorHub struct {
	mu    sync.Mutex
	rooms map[uint]*monitorRoom
}

// NewMonitorHub 建立監看 hub
func NewMonitorHub() *MonitorHub {
	return &MonitorHub{rooms: make(map[uint]*monitorRoom)}
}

// OpenRoom 為會話開啟監看 room（會話建立時呼叫），回傳掛上 bridge 的 tap
func (h *MonitorHub) OpenRoom(sessionID uint, cols, rows int) *monitorTap {
	h.mu.Lock()
	defer h.mu.Unlock()

	room := newMonitorRoom(cols, rows)
	h.rooms[sessionID] = room
	return &monitorTap{room: room}
}

// CloseRoom 會話結束：通知觀察者並移除 room
func (h *MonitorHub) CloseRoom(sessionID uint) {
	h.mu.Lock()
	room, ok := h.rooms[sessionID]
	delete(h.rooms, sessionID)
	h.mu.Unlock()

	if ok {
		room.close()
	}
}

// Join 觀察者加入會話監看；會話不存在（未開 room 或已結束）回傳 false。
//
// obs 為觀察者**自身**的認證脈絡（不是被監看會話的）——收線判定依觀察者是誰、
// 經哪個 provider 認證，與被監看會話的來源無關
func (h *MonitorHub) Join(sessionID uint, ws *websocket.Conn, obs ObserverContext) bool {
	h.mu.Lock()
	room, ok := h.rooms[sessionID]
	h.mu.Unlock()

	if !ok {
		return false
	}
	return room.join(ws, obs)
}

// DisconnectByProvider 收線經指定 provider 認證的全部觀察者（provider 停用/刪除/輪替密鑰）
func (h *MonitorHub) DisconnectByProvider(providerID uint) int {
	if providerID == 0 {
		return 0 // 0 是「本地登入」的語義，不是萬用字元
	}
	return h.disconnectMatching(func(o ObserverContext) bool {
		return o.ProviderID == providerID
	})
}

// DisconnectByUserAndProvider 收線特定使用者經特定 provider 建立的觀察（解綁單一身分）
func (h *MonitorHub) DisconnectByUserAndProvider(userID, providerID uint) int {
	if userID == 0 || providerID == 0 {
		return 0
	}
	return h.disconnectMatching(func(o ObserverContext) bool {
		return o.UserID == userID && o.ProviderID == providerID
	})
}

// DisconnectByUser 收線特定使用者的全部觀察（帳號停用/刪除/外部化/解綁）。
//
// **本地 admin 的監看 providerID=0**，前兩個方法掃不到；缺這一個，
// 停用一個本地管理員帳號時他正在進行的監看會繼續存活。
// **自動鎖定不得呼叫本方法**——鎖定可由未認證第三方觸發，那會使收線成為遠端斷線武器
func (h *MonitorHub) DisconnectByUser(userID uint) int {
	if userID == 0 {
		return 0
	}
	return h.disconnectMatching(func(o ObserverContext) bool {
		return o.UserID == userID
	})
}

// disconnectMatching 依述詞收線觀察者。
//
// **關閉連線在鎖外**：持鎖期間只做集合判定與移除，實際 Close 可能阻塞
// （對端已死但 TCP 尚未察覺），在鎖內做會拖住整個 hub 與所有會話的廣播路徑
func (h *MonitorHub) disconnectMatching(match func(ObserverContext) bool) int {
	h.mu.Lock()
	rooms := make([]*monitorRoom, 0, len(h.rooms))
	for _, r := range h.rooms {
		rooms = append(rooms, r)
	}
	h.mu.Unlock()

	var doomed []*websocket.Conn
	for _, r := range rooms {
		doomed = append(doomed, r.evict(match)...)
	}
	for _, ws := range doomed {
		if raw, err := EncodeCodedErrorMessage(apierror.CodeMonitorRevoked); err == nil {
			_ = writeToObserver(ws, raw)
		}
		ws.Close()
	}
	if len(doomed) > 0 {
		log.Printf("[Monitor] 已收線 %d 個觀察者（憑證撤銷）", len(doomed))
	}
	return len(doomed)
}

// Leave 觀察者離開
func (h *MonitorHub) Leave(sessionID uint, ws *websocket.Conn) {
	h.mu.Lock()
	room, ok := h.rooms[sessionID]
	h.mu.Unlock()

	if ok {
		room.leave(ws)
	}
}

// monitorRoom 單一會話的觀察者集合與回放緩衝
type monitorRoom struct {
	mu        sync.Mutex
	observers map[*websocket.Conn]ObserverContext
	replay    []byte
	cols      int
	rows      int
	closed    bool
}

func newMonitorRoom(cols, rows int) *monitorRoom {
	return &monitorRoom{
		observers: make(map[*websocket.Conn]ObserverContext),
		cols:      cols,
		rows:      rows,
	}
}

// join 加入觀察者：先送會話尺寸與回放緩衝，再進入即時流
func (r *monitorRoom) join(ws *websocket.Conn, obs ObserverContext) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return false
	}

	if err := writeMonitorResize(ws, r.cols, r.rows); err != nil {
		return false
	}
	if len(r.replay) > 0 {
		raw, err := EncodeMessage(MsgData, string(r.replay))
		if err == nil {
			if err := writeToObserver(ws, raw); err != nil {
				return false
			}
		}
	}

	r.observers[ws] = obs
	return true
}

// evict 移除符合述詞的觀察者並回傳其連線（**由呼叫端在鎖外關閉**）
func (r *monitorRoom) evict(match func(ObserverContext) bool) []*websocket.Conn {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []*websocket.Conn
	for ws, obs := range r.observers {
		if match(obs) {
			delete(r.observers, ws)
			out = append(out, ws)
		}
	}
	return out
}

func (r *monitorRoom) leave(ws *websocket.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.observers, ws)
}

// broadcastOutput 廣播輸出並更新回放緩衝。
// 寫入失敗或逾時（monitorWriteTimeout）的觀察者直接踢出並關連線——
// 監看絕不阻塞或影響會話主路徑
func (r *monitorRoom) broadcastOutput(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}

	r.replay = append(r.replay, p...)
	if len(r.replay) > replayBufferMax {
		trimmed := make([]byte, replayBufferMax)
		copy(trimmed, r.replay[len(r.replay)-replayBufferMax:])
		r.replay = trimmed
	}

	raw, err := EncodeMessage(MsgData, string(p))
	if err != nil {
		return
	}
	for ws := range r.observers {
		if err := writeToObserver(ws, raw); err != nil {
			log.Printf("[Monitor] 觀察者寫入失敗或逾時，已移除: %v", err)
			delete(r.observers, ws)
			ws.Close()
		}
	}
}

// broadcastResize 同步會話端尺寸給觀察者
func (r *monitorRoom) broadcastResize(cols, rows int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}

	r.cols = cols
	r.rows = rows
	for ws := range r.observers {
		if err := writeMonitorResize(ws, cols, rows); err != nil {
			delete(r.observers, ws)
			ws.Close()
		}
	}
}

// close 會話結束：通知並關閉所有觀察者
func (r *monitorRoom) close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.closed = true
	for ws := range r.observers {
		if raw, err := EncodeCodedErrorMessage(apierror.CodeSessionEnded); err == nil {
			if werr := writeToObserver(ws, raw); werr != nil {
				log.Printf("[Monitor] 結束通知送出失敗: %v", werr)
			}
		}
		ws.Close()
	}
	r.observers = make(map[*websocket.Conn]ObserverContext)
}

func writeMonitorResize(ws *websocket.Conn, cols, rows int) error {
	payload, err := EncodeMessage(MsgResize, fmt.Sprintf(`{"cols":%d,"rows":%d}`, cols, rows))
	if err != nil {
		return err
	}
	return writeToObserver(ws, payload)
}

// monitorTap 掛上 bridge 旁路的監看 sink
type monitorTap struct {
	room *monitorRoom
}

func (t *monitorTap) WriteOutput(p []byte) {
	t.room.broadcastOutput(p)
}

func (t *monitorTap) Resize(cols, rows int) {
	t.room.broadcastResize(cols, rows)
}
