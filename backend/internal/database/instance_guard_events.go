package database

import (
	"log"
	"sync"
)

// 守衛事件的 sink 與啟動前緩衝。
//
// overridden 事件發生在段 1，審計服務在段 2 才存在（B 模式甚至要等解封）。
// 守衛以**有界環形緩衝**暫存 sink 注入前的事件，SetEventSink 時依序 flush；
// 超過上限丟最舊並記 log（已知邊界：只有 B 模式長期封印且反覆失鎖才會碰到）。

// guardEventBuffer sink 與緩衝，獨立於狀態鎖（sink 呼叫不在狀態鎖內執行）。
type guardEventBuffer struct {
	mu       sync.Mutex
	sink     func(GuardEvent)
	limit    int
	buffered []GuardEvent
	dropped  int
}

// SetEventSink 注入事件 sink；注入當下依序 flush 緩衝。
//
// 傳入 nil 為解除（之後的事件回到緩衝）。
func (g *InstanceGuard) SetEventSink(fn func(GuardEvent)) {
	g.events.mu.Lock()
	g.events.sink = fn
	pending := g.events.buffered
	g.events.buffered = nil
	dropped := g.events.dropped
	g.events.dropped = 0
	g.events.mu.Unlock()

	if fn == nil {
		// 解除 sink：把未 flush 的事件放回緩衝，不遺失
		g.events.mu.Lock()
		g.events.buffered = append(pending, g.events.buffered...)
		g.events.dropped = dropped
		g.events.mu.Unlock()
		return
	}
	if dropped > 0 {
		log.Printf("[InstanceGuard] 事件 sink 注入前緩衝溢出，已丟棄最舊的 %d 筆守衛事件（上限 %d）", dropped, g.events.limit)
	}
	for _, ev := range pending {
		fn(ev)
	}
}

// emit 發送事件：有 sink 直接送；無 sink 進緩衝（滿則丟最舊）。
func (g *InstanceGuard) emit(ev GuardEvent) {
	g.events.mu.Lock()
	sink := g.events.sink
	if sink == nil {
		if len(g.events.buffered) >= g.events.limit {
			g.events.buffered = g.events.buffered[1:]
			g.events.dropped++
			log.Printf("[InstanceGuard] 事件緩衝已滿（上限 %d），丟棄最舊一筆以容納 %s 事件", g.events.limit, ev.Event)
		}
		g.events.buffered = append(g.events.buffered, ev)
		g.events.mu.Unlock()
		return
	}
	g.events.mu.Unlock()
	sink(ev)
}
