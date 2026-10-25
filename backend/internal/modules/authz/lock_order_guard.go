package authz

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	"gorm.io/gorm"
)

// 測試期動態鎖序守衛。
//
// 同一交易內的鎖依「使用者層（編號升冪，同一位先憑證互斥鎖再帳號列鎖）→ 拓撲序列化鎖 → 業務列」
// 的全序取得。守衛在各鎖點取鎖之前收到通知，逐交易記下已持有的鎖，違反下列規則即回報：
//
//   - topology_then_user：交易已持拓撲鎖之後，再取一把尚未持有的群組列鎖或使用者層鎖。
//   - user_id_descending：取一位尚未持有的使用者的鎖，而其編號小於本交易已持有的最大使用者編號。
//   - ua_not_followed_by_ur：PostgreSQL 上某位使用者的憑證互斥鎖之後，下一個使用者層鎖不是同一位的帳號列鎖
//     （SQLite 沒有帳號列鎖，不檢查）。
//
// 已持有者重入不計。已知例外只在登記處放行：預取之後才出現的成員（late joiner）由補取點登記
// 那一位使用者；映射撤銷由撤銷入口標記整筆交易。登記不放行 ua_not_followed_by_ur。
//
// 生產路徑不安裝守衛：各掛點的載入函式回 nil，呼叫點以 `if hook != nil { hook(...) }` 跳過；
// 不讀任何設定或環境變數，只有測試經下方的安裝函式安裝。

// LockLayer 鎖的層別。
type LockLayer string

const (
	LockLayerGroup          LockLayer = "group"           // 群組列鎖（user_groups）
	LockLayerUserCredential LockLayer = "user_credential" // 使用者憑證互斥鎖（advisory；SQLite 為行程內互斥）
	LockLayerUserRow        LockLayer = "user_row"        // 帳號列鎖（users）
	LockLayerTopology       LockLayer = "topology"        // 拓撲序列化鎖
)

// 守衛規則名。
const (
	LockRuleTopologyThenUser  = "topology_then_user"
	LockRuleUserIDDescending  = "user_id_descending"
	LockRuleUaNotFollowedByUr = "ua_not_followed_by_ur"
)

// LateJoinerSite 預取之後才出現的成員的補取點。
type LateJoinerSite string

const (
	// LateJoinerGroupRoleReplace 群組角色替換推進版本之後的補取：只放行編號規則；
	// 交易已持拓撲鎖時同一登記另放行拓撲規則（帶範圍的群組角色指派）。
	LateJoinerGroupRoleReplace LateJoinerSite = "group_role_replace"
	// LateJoinerGroupDelete 群組刪除逐人迴圈內的補取：只放行編號規則，持拓撲鎖照常回報。
	LateJoinerGroupDelete LateJoinerSite = "group_delete"
)

// LockOrderViolation 一筆鎖序違規。Stack 是取鎖呼叫的位置（由內而外）。
type LockOrderViolation struct {
	Rule    string
	Layer   LockLayer
	IDs     []uint
	Dialect string
	Conn    gorm.ConnPool
	Stack   []string
}

func (v LockOrderViolation) String() string {
	return fmt.Sprintf("rule=%s layer=%s ids=%v dialect=%s at:\n\t%s",
		v.Rule, v.Layer, v.IDs, v.Dialect, strings.Join(v.Stack, "\n\t"))
}

// LockOrderProbeFunc 取鎖前呼叫的探針。
type LockOrderProbeFunc func(tx *gorm.DB, layer LockLayer, ids ...uint)

// LockOrderLateJoinerFunc late joiner 豁免登記。
type LockOrderLateJoinerFunc func(tx *gorm.DB, site LateJoinerSite, groupID, userID uint)

// LockOrderMappingRevocationFunc 映射撤銷豁免標記。
type LockOrderMappingRevocationFunc func(tx *gorm.DB)

type lateJoinerMark struct {
	site    LateJoinerSite
	groupID uint
}

// txLockOrder 一筆交易已持有的鎖與豁免登記。
type txLockOrder struct {
	topology      bool
	groups        map[uint]bool
	users         map[uint]map[LockLayer]bool
	maxUser       uint
	pendingUa     uint
	hasPendingUa  bool
	lateJoiners   map[uint]lateJoinerMark
	mappingExempt bool
}

type lockOrderGuard struct {
	mu          sync.Mutex
	onViolation func(LockOrderViolation)
	txs         map[gorm.ConnPool]*txLockOrder
}

// lockOrderGuardState 目前安裝的守衛；seq 用來驗證還原順序。生產恆為 nil。
var lockOrderGuardState struct {
	mu    sync.RWMutex
	guard *lockOrderGuard
	seq   uint64
}

func loadLockOrderGuard() *lockOrderGuard {
	lockOrderGuardState.mu.RLock()
	defer lockOrderGuardState.mu.RUnlock()
	return lockOrderGuardState.guard
}

// LockOrderProbeHook 回傳取鎖前的探針；未安裝守衛（生產）回 nil。
func LockOrderProbeHook() LockOrderProbeFunc {
	g := loadLockOrderGuard()
	if g == nil {
		return nil
	}
	return g.probe
}

// LockOrderExemptLateJoinerHook 回傳 late joiner 豁免登記；未安裝守衛（生產）回 nil。
// 補取點在警告行之後、同一分支內呼叫，只對登記的那一位使用者放行。
func LockOrderExemptLateJoinerHook() LockOrderLateJoinerFunc {
	g := loadLockOrderGuard()
	if g == nil {
		return nil
	}
	return g.exemptLateJoiner
}

// LockOrderExemptMappingRevocationHook 回傳映射撤銷豁免標記；未安裝守衛（生產）回 nil。
// 撤銷入口在取使用者鎖之前呼叫，只放行編號規則。
func LockOrderExemptMappingRevocationHook() LockOrderMappingRevocationFunc {
	g := loadLockOrderGuard()
	if g == nil {
		return nil
	}
	return g.exemptMappingRevocation
}

// 安裝鎖序守衛並回傳還原函式（測試用）；onViolation 為 nil 表示不安裝。
// 每次安裝都是一份新的交易登錄。還原必須依安裝的相反順序；順序不符或重複還原會 panic。
func SetLockOrderGuardForTest(onViolation func(LockOrderViolation)) (restore func()) {
	var g *lockOrderGuard
	if onViolation != nil {
		g = &lockOrderGuard{onViolation: onViolation, txs: map[gorm.ConnPool]*txLockOrder{}}
	}
	st := &lockOrderGuardState
	st.mu.Lock()
	prev, prevSeq := st.guard, st.seq
	st.seq++
	mine := st.seq
	st.guard = g
	st.mu.Unlock()
	done := false
	return func() {
		st.mu.Lock()
		defer st.mu.Unlock()
		if done {
			panic("lock order guard: restore called twice")
		}
		if st.seq != mine {
			panic("lock order guard: restore out of order")
		}
		done = true
		st.guard, st.seq = prev, prevSeq
	}
}

// txConn 交易識別：只有交易內的句柄才登記；交易外的鎖在語句結束即釋放，不屬鎖序問題。
func txConn(tx *gorm.DB) gorm.ConnPool {
	if tx == nil || tx.Statement == nil || tx.Statement.ConnPool == nil {
		return nil
	}
	if _, ok := tx.Statement.ConnPool.(gorm.TxCommitter); !ok {
		return nil
	}
	return tx.Statement.ConnPool
}

func dialectOf(tx *gorm.DB) string {
	if tx == nil || tx.Config == nil || tx.Dialector == nil {
		return ""
	}
	return tx.Dialector.Name()
}

func (g *lockOrderGuard) stateLocked(conn gorm.ConnPool) *txLockOrder {
	st, ok := g.txs[conn]
	if !ok {
		st = &txLockOrder{
			groups:      map[uint]bool{},
			users:       map[uint]map[LockLayer]bool{},
			lateJoiners: map[uint]lateJoinerMark{},
		}
		g.txs[conn] = st
	}
	return st
}

func sortedUnique(ids []uint) []uint {
	out := append([]uint(nil), ids...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	n := 0
	for i, id := range out {
		if i > 0 && out[i-1] == id {
			continue
		}
		out[n] = id
		n++
	}
	return out[:n]
}

func (g *lockOrderGuard) probe(tx *gorm.DB, layer LockLayer, ids ...uint) {
	conn := txConn(tx)
	if conn == nil {
		return
	}
	dialect := dialectOf(tx)
	var found []LockOrderViolation
	report := func(rule string, vids []uint) {
		found = append(found, LockOrderViolation{Rule: rule, Layer: layer, IDs: vids, Dialect: dialect, Conn: conn})
	}

	g.mu.Lock()
	st := g.stateLocked(conn)
	switch layer {
	case LockLayerTopology:
		st.topology = true
	case LockLayerGroup:
		var fresh []uint
		for _, id := range sortedUnique(ids) {
			if !st.groups[id] {
				fresh = append(fresh, id)
				st.groups[id] = true
			}
		}
		if st.topology && len(fresh) > 0 {
			report(LockRuleTopologyThenUser, fresh)
		}
	case LockLayerUserCredential, LockLayerUserRow:
		ids = sortedUnique(ids)
		if dialect == "postgres" {
			if st.hasPendingUa && (layer != LockLayerUserRow || len(ids) != 1 || ids[0] != st.pendingUa) {
				report(LockRuleUaNotFollowedByUr, ids)
			}
			st.hasPendingUa = false
			if layer == LockLayerUserCredential && len(ids) == 1 {
				st.pendingUa, st.hasPendingUa = ids[0], true
			}
		}
		var topo, desc []uint
		for _, id := range ids {
			held := st.users[id]
			mark, joined := st.lateJoiners[id]
			if st.topology && !held[layer] && !(joined && mark.site == LateJoinerGroupRoleReplace) {
				topo = append(topo, id)
			}
			if len(held) == 0 && len(st.users) > 0 && id < st.maxUser && !joined && !st.mappingExempt {
				desc = append(desc, id)
			}
			if held == nil {
				held = map[LockLayer]bool{}
				st.users[id] = held
			}
			held[layer] = true
			if id > st.maxUser {
				st.maxUser = id
			}
		}
		if len(topo) > 0 {
			report(LockRuleTopologyThenUser, topo)
		}
		if len(desc) > 0 {
			report(LockRuleUserIDDescending, desc)
		}
	}
	g.mu.Unlock()

	if len(found) == 0 {
		return
	}
	stack := callerStack()
	for _, v := range found {
		v.Stack = stack
		g.onViolation(v)
	}
}

func (g *lockOrderGuard) exemptLateJoiner(tx *gorm.DB, site LateJoinerSite, groupID, userID uint) {
	conn := txConn(tx)
	if conn == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stateLocked(conn).lateJoiners[userID] = lateJoinerMark{site: site, groupID: groupID}
}

func (g *lockOrderGuard) exemptMappingRevocation(tx *gorm.DB) {
	conn := txConn(tx)
	if conn == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stateLocked(conn).mappingExempt = true
}

// callerStack 取鎖呼叫的位置：略過守衛本身，最多十層。
func callerStack() []string {
	pcs := make([]uintptr, 24)
	n := runtime.Callers(3, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	var out []string
	for {
		f, more := frames.Next()
		if !strings.HasSuffix(f.File, "/lock_order_guard.go") && f.File != "<autogenerated>" {
			out = append(out, fmt.Sprintf("%s (%s:%d)", f.Function, f.File, f.Line))
		}
		if !more || len(out) >= 10 {
			break
		}
	}
	return out
}

// topologyLockAcquiredHookState 拓撲鎖取得之後、交易下一個語句之前的停點；seq 驗證還原順序。生產恆為 nil。
var topologyLockAcquiredHookState struct {
	mu  sync.RWMutex
	fn  func(tx *gorm.DB)
	seq uint64
}

func loadTopologyLockAcquiredHook() func(tx *gorm.DB) {
	topologyLockAcquiredHookState.mu.RLock()
	defer topologyLockAcquiredHookState.mu.RUnlock()
	return topologyLockAcquiredHookState.fn
}

// 設定拓撲鎖取得後的停點並回傳還原函式（測試用）；傳 nil 表示不掛。
// 還原必須依設定的相反順序；順序不符或重複還原會 panic。
func SetTopologyLockAcquiredHookForTest(fn func(tx *gorm.DB)) (restore func()) {
	st := &topologyLockAcquiredHookState
	st.mu.Lock()
	prev, prevSeq := st.fn, st.seq
	st.seq++
	mine := st.seq
	st.fn = fn
	st.mu.Unlock()
	done := false
	return func() {
		st.mu.Lock()
		defer st.mu.Unlock()
		if done {
			panic("topology lock hook: restore called twice")
		}
		if st.seq != mine {
			panic("topology lock hook: restore out of order")
		}
		done = true
		st.fn, st.seq = prev, prevSeq
	}
}
