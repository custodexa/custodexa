package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 投遞步驟：依目的地輪流取到期紀錄、認領前的不計次判斷、認領計次、送出與判讀。
//
// 目的地的鍵是（來源通道, 是否帶快照, 目的地版本, 收件對象）。不帶快照的紀錄目的地版本恆為 0，代表通道當下的設定；
// 帶快照的紀錄是產生當下通道的目的地版本。通道的版本也從 0 起算，所以只看版本時，改址前排入的快照（版本 0）
// 會和改址後送往新設定的紀錄撞在同一個鍵；「是否帶快照」把兩者分開，使指向舊目的地的快照不影響使用新設定的紀錄。
// 收件對象為個人的紀錄（個人訊息）在同一通道合為一個目的地，與該通道的頻道紀錄分開取件、分開計算目的地層級失敗、
// 限流暫停與送出節流。
//
// 失敗分三類：
//   - 目的地層級（連線錯誤、逾時、HTTP 5xx）：該目的地本輪不再送出，此刻所有到期、未被認領的紀錄各計一次。
//   - 限流（HTTP 429）：只計被拒的一筆；目的地在記憶體暫停到 Retry-After 之後，同目的地其他到期紀錄延後、
//     不計次並補上第一次延後的時刻（throttled_since）。
//   - 單筆（其他回應、平台錯誤碼、不跟隨轉址的 3xx、轉址不符政策或次數過多）：只計這一筆，本輪繼續下一筆。
//
// 型別宣告每秒上限的目的地另有送出節流：每輪名額依距上次送出的秒數計算（takeQuota），同一目的地兩次送出之間
// 至少間隔 1/上限 秒。需要等待的紀錄移到本輪其他目的地都處理完之後再依序等待送出（輪到時重新做認領前的判斷），
// 所以等待不會延遲其他目的地；
// 一輪的累計等待以一個輪詢週期為限，超過的留到下一輪（尚未認領，不計次）。

// 收件對象：通道本身與個人（個人訊息只用於系統事件）。
const (
	deliveryAudienceChannel = model.NotificationAudienceChannel
	deliveryAudienceUser    = model.NotificationAudienceUser
)

// audienceOfRow 紀錄的收件對象；欄位為空（資料表預設值之前建立的記憶體物件）視為通道。
func audienceOfRow(row model.NotificationDelivery) string {
	if row.Audience == deliveryAudienceUser {
		return deliveryAudienceUser
	}
	return deliveryAudienceChannel
}

// deliveryDestKey 一個目的地的鍵。Snapshot 為真＝帶目的地快照的紀錄（系統安全告警）；零值代表送出時讀通道現值的紀錄。
type deliveryDestKey struct {
	ChannelID uint
	Snapshot  bool
	Version   int
	Audience  string
}

// rowCarriesSnapshot 紀錄是否帶目的地快照：系統安全告警帶快照，其餘類別送出時讀通道現值（資料表的約束保證兩者互斥）。
func rowCarriesSnapshot(row model.NotificationDelivery) bool {
	return row.Category == model.NotificationCategorySystemSecurityAlert
}

func destKeyOf(row model.NotificationDelivery) deliveryDestKey {
	return deliveryDestKey{ChannelID: derefUint(row.SourceChannelID), Snapshot: rowCarriesSnapshot(row),
		Version: row.DestVersion, Audience: audienceOfRow(row)}
}

// where 把鍵套到查詢條件。
func (k deliveryDestKey) where(q *gorm.DB) *gorm.DB {
	if k.ChannelID == 0 {
		q = q.Where("source_channel_id IS NULL")
	} else {
		q = q.Where("source_channel_id = ?", k.ChannelID)
	}
	if k.Snapshot {
		q = q.Where("category = ?", model.NotificationCategorySystemSecurityAlert)
	} else {
		q = q.Where("category <> ?", model.NotificationCategorySystemSecurityAlert)
	}
	audience := k.Audience
	if audience == "" {
		audience = deliveryAudienceChannel
	}
	return q.Where("dest_version = ? AND audience = ?", k.Version, audience)
}

// destRuntime 目的地的記憶體狀態。
type destRuntime struct {
	pausedUntil time.Time
	lastSentAt  time.Time
}

// maxPerSecondFor 型別對某個收件對象宣告的每秒上限（沒有分別宣告時沿用通道的上限）。
func (d ChannelTypeDescriptor) maxPerSecondFor(audience string) float64 {
	if v, ok := d.MaxPerSecondByAudience[audience]; ok {
		return v
	}
	return d.MaxPerSecond
}

// ---- 送出前檢查（依事件鍵登錄） ----

// DeliveryPrecheckStage 送出前檢查被呼叫的時點。
type DeliveryPrecheckStage string

const (
	// PrecheckBeforeClaim 認領之前（本版唯一的呼叫點）；取消時不計次。
	PrecheckBeforeClaim DeliveryPrecheckStage = "before_claim"
	// PrecheckAfterClaim 認領之後（個人訊息在外部查詢之後再呼叫一次）；取消時已計的次數不回減。
	PrecheckAfterClaim DeliveryPrecheckStage = "after_claim"
)

// DeliveryPrecheckInput 送出前檢查的輸入。Channel 是認領前讀到、之後送出也會使用的通道列（明文）。
type DeliveryPrecheckInput struct {
	Stage    DeliveryPrecheckStage
	Delivery model.NotificationDelivery
	Message  model.NotificationMessage
	Channel  model.NotificationChannel
}

// DeliveryPrecheckResult 送出前檢查的結果：Cancel 為真時取消並以 Reason 為結束原因（空字串＝precheck_canceled；
// 其他值須在待投遞表結束原因的值域內）。Err 非空表示檢查本身無法完成（例如資料庫錯誤），處置與 panic 相同：
// 認領並計一次失敗，不送出。
type DeliveryPrecheckResult struct {
	Cancel bool
	Reason string
	Err    error
}

// DeliveryPrecheck 送出前檢查函式。
type DeliveryPrecheck func(in DeliveryPrecheckInput) DeliveryPrecheckResult

var (
	precheckMu       sync.RWMutex
	precheckRegistry = map[notifycat.Event]DeliveryPrecheck{}
)

// RegisterDeliveryPrecheck 為事件鍵登錄送出前檢查；fn 為 nil 時移除。定向通知的四個事件由投遞程序的
// UseTargetedJudge 登錄同一個檢查。
func RegisterDeliveryPrecheck(event notifycat.Event, fn DeliveryPrecheck) {
	precheckMu.Lock()
	defer precheckMu.Unlock()
	if fn == nil {
		delete(precheckRegistry, event)
		return
	}
	precheckRegistry[event] = fn
}

func deliveryPrecheckFor(event notifycat.Event) DeliveryPrecheck {
	precheckMu.RLock()
	defer precheckMu.RUnlock()
	return precheckRegistry[event]
}

// runDeliveryPrecheck 以 recover 包住呼叫檢查；panic 時 panicked 為真。
func runDeliveryPrecheck(fn DeliveryPrecheck, in DeliveryPrecheckInput) (res DeliveryPrecheckResult, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[NotificationOutbox] 送出前檢查發生 panic (outbox_id=%d): %v", in.Delivery.ID, r)
			res, panicked = DeliveryPrecheckResult{}, true
		}
	}()
	return fn(in), false
}

// ---- 位址解析（通道目的地在此；個人訊息的解析在 notification_dm_address.go） ----

// AddressOutcome 位址解析的結果種類。
type AddressOutcome int

const (
	// AddressResolved 取得位址。
	AddressResolved AddressOutcome = iota
	// AddressNotFound 明確查無或資料不足（不可能成功）。
	AddressNotFound
	// AddressRetryable 可重試的單筆失敗。
	AddressRetryable
	// AddressDestinationFailure 目的地層級失敗。
	AddressDestinationFailure
	// AddressRateLimited 限流，附建議等待時間。
	AddressRateLimited
)

// AddressResolution 位址解析的結果。
type AddressResolution struct {
	Outcome    AddressOutcome
	Address    string
	Reason     string
	RetryAfter time.Duration
}

// resolveDeliveryAddress 解析收件對象為通道時的位址：通道的目標（可為空）。個人訊息走 resolveUserAddress。
func resolveDeliveryAddress(dest ChannelDestination, audience string) AddressResolution {
	if audience == deliveryAudienceChannel {
		return AddressResolution{Outcome: AddressResolved, Address: dest.Target}
	}
	return AddressResolution{Outcome: AddressNotFound, Reason: "unsupported_audience"}
}

// ---- 取件 ----

// notifyReservedNonCommandSlots 每個目的地每輪的名額中，保留給指令告警以外類別的筆數（有這類到期紀錄時）。
const notifyReservedNonCommandSlots = 5

// dueCandidate 取件查詢的一列。
type dueCandidate struct {
	ID        uint
	ChannelID *uint
	Snapshot  int
	Version   int
	Audience  string
	SevRank   int
	IsCommand int
	Rn        int
}

// dueCandidateIDs 依目的地輪流取到期、未被認領的紀錄編號。
//
// 每個目的地依「是否為指令告警」分兩組，各組依分級與編號編序、各取至多 perDestBatch 筆；在記憶體中為每個
// 目的地排出至多 perDestBatch 筆：先放至多 notifyReservedNonCommandSlots 筆指令告警以外的紀錄（固定排在
// 目的地內的最前面），其餘名額再依分級與編號從兩組剩下的紀錄補滿。外層依「在目的地內的序位、分級、編號」取 batch 筆。
// 指令告警爆量時，連線申請、破窗這類系統事件不必排在同一目的地的大量高分級指令告警之後。
func (w *SystemAlertOutboxWorker) dueCandidateIDs(now time.Time) ([]uint, error) {
	// 目的地的鍵（source_channel_id, 是否帶快照, dest_version, audience）同時出現在這句的 PARTITION BY、
	// pickDueCandidates 與 deliveryDestKey.where；三處一起改。
	const query = `SELECT id, channel_id, snapshot, version, audience, sev_rank, is_command, rn FROM (
		SELECT id, source_channel_id AS channel_id,
			CASE WHEN category = 'system_security_alert' THEN 1 ELSE 0 END AS snapshot,
			dest_version AS version, audience,
			CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END AS sev_rank,
			CASE WHEN category = 'command_alert' THEN 1 ELSE 0 END AS is_command,
			ROW_NUMBER() OVER (PARTITION BY source_channel_id,
				CASE WHEN category = 'system_security_alert' THEN 1 ELSE 0 END, dest_version, audience,
				CASE WHEN category = 'command_alert' THEN 1 ELSE 0 END
				ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, id) AS rn
		FROM system_alert_outbox
		WHERE state IN ? AND next_attempt_at <= ? AND (lease_until IS NULL OR lease_until < ?)
	) due WHERE rn <= ?`
	var rows []dueCandidate
	if err := w.db.Raw(query, activeOutboxStates(), now, now, w.perDestBatch).Scan(&rows).Error; err != nil {
		return nil, err
	}
	return pickDueCandidates(rows, w.perDestBatch, notifyReservedNonCommandSlots, w.batch), nil
}

// pickDueCandidates 依 dueCandidateIDs 的規則從兩組候選排出本輪的紀錄編號。
func pickDueCandidates(rows []dueCandidate, perDest, reserved, batch int) []uint {
	type key struct {
		ch       uint
		snapshot int
		ver      int
		audience string
	}
	less := func(a, b dueCandidate) bool {
		if a.SevRank != b.SevRank {
			return a.SevRank < b.SevRank
		}
		return a.ID < b.ID
	}
	groups := map[key][2][]dueCandidate{}
	for _, r := range rows {
		k := key{derefUint(r.ChannelID), r.Snapshot, r.Version, r.Audience}
		g := groups[k]
		g[r.IsCommand] = append(g[r.IsCommand], r)
		groups[k] = g
	}
	type placed struct {
		c   dueCandidate
		pos int
	}
	var all []placed
	for _, g := range groups {
		other, cmd := g[0], g[1]
		sort.Slice(other, func(i, j int) bool { return less(other[i], other[j]) })
		sort.Slice(cmd, func(i, j int) bool { return less(cmd[i], cmd[j]) })
		take := reserved
		if take > len(other) {
			take = len(other)
		}
		if take > perDest {
			take = perDest
		}
		chosen := append([]dueCandidate{}, other[:take]...)
		restOther, restCmd := other[take:], cmd
		for len(chosen) < perDest && (len(restOther) > 0 || len(restCmd) > 0) {
			if len(restCmd) == 0 || (len(restOther) > 0 && less(restOther[0], restCmd[0])) {
				chosen = append(chosen, restOther[0])
				restOther = restOther[1:]
			} else {
				chosen = append(chosen, restCmd[0])
				restCmd = restCmd[1:]
			}
		}
		// 預留的紀錄固定排在目的地最前面，不再依分級與其餘紀錄重排：每秒上限低的目的地一輪只送得出
		// 前幾筆，重排會讓 medium 系統事件永遠排在 high 指令告警之後。其餘名額維持分級、編號的先後。
		for i, c := range chosen {
			all = append(all, placed{c: c, pos: i})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].pos != all[j].pos {
			return all[i].pos < all[j].pos
		}
		return less(all[i].c, all[j].c)
	})
	if len(all) > batch {
		all = all[:batch]
	}
	ids := make([]uint, len(all))
	for i, p := range all {
		ids[i] = p.c.ID
	}
	return ids
}

// ---- 認領前的讀取與判斷 ----

type preReadOutcome int

const (
	preReadSend preReadOutcome = iota
	preReadTerminal
	preReadSkip
)

// preRead 認領前的讀取結果。
type preRead struct {
	outcome    preReadOutcome
	state      string
	reason     string
	dest       ChannelDestination
	readErr    string
	msg        model.NotificationMessage
	channel    model.NotificationChannel
	perSecond  float64
	checkPanic bool
}

// channelUnreadableText 通道設定解不開時記錄的原因。
const channelUnreadableText = "通道設定無法讀取"

// preReadDelivery 認領前、以不改變次數的讀取判斷：型別是否登錄、（不帶快照者）來源通道是否仍啟用、
// 送出前檢查。結果為取消或不可能成功時由呼叫端直接轉為終態。
func (w *SystemAlertOutboxWorker) preReadDelivery(row model.NotificationDelivery) preRead {
	if row.Category == model.NotificationCategorySystemSecurityAlert {
		desc, ok := ChannelType(row.DestType)
		if !ok {
			return preRead{outcome: preReadTerminal, state: model.NotificationDeliveryAbandoned, reason: model.NotificationEndTypeUnregistered}
		}
		dest, err := w.snapshotDestination(row)
		if err != nil {
			return preRead{outcome: preReadTerminal, state: model.NotificationDeliveryAbandoned, reason: model.NotificationEndSnapshotUnreadable}
		}
		return preRead{outcome: preReadSend, dest: dest, perSecond: desc.maxPerSecondFor(deliveryAudienceChannel)}
	}

	if row.SourceChannelID == nil {
		return preRead{outcome: preReadTerminal, state: model.NotificationDeliveryCanceled, reason: model.NotificationEndChannelDeleted}
	}
	var chs []model.NotificationChannel
	if err := w.db.Where("id = ?", *row.SourceChannelID).Limit(1).Find(&chs).Error; err != nil {
		log.Printf("[NotificationOutbox] 讀取來源通道失敗 (outbox_id=%d): %v", row.ID, err)
		return preRead{outcome: preReadSkip}
	}
	if len(chs) == 0 {
		return preRead{outcome: preReadTerminal, state: model.NotificationDeliveryCanceled, reason: model.NotificationEndChannelDeleted}
	}
	ch := chs[0]
	if !ch.Enabled {
		return preRead{outcome: preReadTerminal, state: model.NotificationDeliveryCanceled, reason: model.NotificationEndChannelDisabled}
	}
	dest := destinationFromChannel(&ch)
	desc, ok := ChannelType(dest.Type)
	if !ok {
		return preRead{outcome: preReadTerminal, state: model.NotificationDeliveryAbandoned, reason: model.NotificationEndTypeUnregistered}
	}
	out := preRead{outcome: preReadSend, perSecond: desc.maxPerSecondFor(audienceOfRow(row))}
	plainURL, uerr := readChannelValue(w.codec, keyvault.RefChannelURL, ch.URL)
	plainSecret, serr := readChannelValue(w.codec, keyvault.RefChannelSecret, ch.Secret)
	if uerr != nil || serr != nil {
		out.readErr = channelUnreadableText
	} else {
		dest.URL, dest.Secret = plainURL, plainSecret
		ch.URL, ch.Secret = plainURL, plainSecret
	}
	out.dest = dest
	out.channel = ch

	var msgs []model.NotificationMessage
	if row.MessageID != nil {
		if err := w.db.Where("id = ?", *row.MessageID).Limit(1).Find(&msgs).Error; err != nil {
			log.Printf("[NotificationOutbox] 讀取通知內容失敗 (outbox_id=%d): %v", row.ID, err)
			return preRead{outcome: preReadSkip}
		}
	}
	if len(msgs) == 1 {
		out.msg = msgs[0]
	}
	if fn := deliveryPrecheckFor(notifycat.Event(out.msg.EventKey)); fn != nil {
		res, panicked := runDeliveryPrecheck(fn, DeliveryPrecheckInput{Stage: PrecheckBeforeClaim, Delivery: row, Message: out.msg, Channel: ch})
		if panicked || res.Err != nil {
			if res.Err != nil {
				log.Printf("[NotificationOutbox] 送出前檢查無法完成 (outbox_id=%d): %v", row.ID, res.Err)
			}
			out.checkPanic = true
		} else if res.Cancel {
			reason := res.Reason
			if reason == "" {
				reason = model.NotificationEndPrecheckCanceled
			}
			return preRead{outcome: preReadTerminal, state: model.NotificationDeliveryCanceled, reason: reason}
		}
	}
	return out
}

// cancelClaimed 認領之後的取消（個人訊息在外部查詢之後的第二次檢查）：轉為已取消，已計的次數不回減。
func (w *SystemAlertOutboxWorker) cancelClaimed(row model.NotificationDelivery, reason string) bool {
	if reason == "" {
		reason = model.NotificationEndPrecheckCanceled
	}
	return w.terminate(row, model.NotificationDeliveryCanceled, reason, w.now(), false)
}

// ---- 一輪的投遞 ----

type sendKind int

const (
	sendDelivered sendKind = iota
	sendSingleFailure
	sendDestinationFailure
	sendRateLimited
	sendNotAttempted
	// sendImpossible 不可能成功（個人訊息沒有電子郵件、電子郵件不唯一、查無對應帳號）：立即放棄，結束原因為 endReason。
	sendImpossible
	// sendCanceled 認領之後的檢查判定取消：轉為已取消，結束原因為 endReason，已計的次數不回減。
	sendCanceled
)

type sendResult struct {
	kind       sendKind
	text       string
	retryAfter time.Duration
	hasRetry   bool
	requested  bool
	endReason  string
}

// deliveryRound 一輪內各目的地的狀態。
type deliveryRound struct {
	stopped  map[deliveryDestKey]bool
	quota    map[deliveryDestKey]int
	deferred map[deliveryDestKey]bool
}

// deliverDue 依目的地輪流取到期紀錄並逐筆處理。回傳送達的筆數。
func (w *SystemAlertOutboxWorker) deliverDue() int {
	now := w.now()
	ids, err := w.dueCandidateIDs(now)
	if err != nil {
		log.Printf("[NotificationOutbox] 讀取到期投遞列失敗: %v", err)
		return 0
	}
	if len(ids) == 0 {
		return 0
	}
	var rows []model.NotificationDelivery
	if err := w.db.Where("id IN ?", ids).Find(&rows).Error; err != nil {
		log.Printf("[NotificationOutbox] 讀取投遞列失敗: %v", err)
		return 0
	}
	byID := make(map[uint]model.NotificationDelivery, len(rows))
	for _, r := range rows {
		byID[r.ID] = r
	}
	round := &deliveryRound{stopped: map[deliveryDestKey]bool{}, quota: map[deliveryDestKey]int{}, deferred: map[deliveryDestKey]bool{}}
	delivered := 0
	var spaced []spacedSend
	for _, id := range ids {
		if w.stopped() {
			break
		}
		row, ok := byID[id]
		if !ok {
			continue
		}
		key := destKeyOf(row)
		if round.stopped[key] {
			continue
		}
		if w.pausedUntil(key).After(now) {
			round.deferred[key] = true
			continue
		}
		pre := w.preReadDelivery(row)
		if w.hooks.afterPreRead != nil {
			w.hooks.afterPreRead(id)
		}
		switch pre.outcome {
		case preReadSkip:
			continue
		case preReadTerminal:
			w.terminate(row, pre.state, pre.reason, now, true)
			continue
		}
		if !w.takeQuota(round, key, pre.perSecond, now) {
			round.deferred[key] = true
			continue
		}
		if w.spacingWait(key, pre.perSecond) > 0 {
			// 限速目的地距上次送出未滿 1/上限 秒：移到本輪最後再送，不讓等待延遲其他目的地。
			spaced = append(spaced, spacedSend{row: row, pre: pre, key: key})
			continue
		}
		if w.processClaimable(round, row, pre, key, now) {
			delivered++
		}
	}
	// 限速目的地的後送：依序等到間隔滿 1/上限 秒再送；本輪累計等待不超過一個輪詢週期，超過的留到下一輪（未認領、不計次）。
	var waited time.Duration
	for _, sp := range spaced {
		if w.stopped() {
			break
		}
		if round.stopped[sp.key] || w.pausedUntil(sp.key).After(w.now()) {
			round.deferred[sp.key] = true
			continue
		}
		if wait := w.spacingWait(sp.key, sp.pre.perSecond); wait > 0 {
			if waited+wait > w.interval {
				round.deferred[sp.key] = true
				continue
			}
			w.sleep(wait)
			waited += wait
		}
		pre, ok := w.rereadSpaced(sp)
		if !ok {
			continue
		}
		if w.processClaimable(round, sp.row, pre, sp.key, now) {
			delivered++
		}
	}
	for key := range round.deferred {
		w.markThrottled(key, now)
	}
	return delivered
}

// spacedSend 等待送出間隔而移到本輪最後的紀錄。pre 只用來估算等待；實際送出前由 rereadSpaced 重新判定。
type spacedSend struct {
	row model.NotificationDelivery
	pre preRead
	key deliveryDestKey
}

// rereadSpaced 後送的紀錄輪到送出時重新做一次認領前的讀取與判斷（通道現值、送出前檢查與收件資格）：
// 從排入後送到實際送出之間隔著其他目的地的送出，先前的判定可能已不成立。判定為取消或不可能成功時轉為終態，
// 讀取失敗時留到下一輪（未認領、不計次）；兩者都回 ok=false。
func (w *SystemAlertOutboxWorker) rereadSpaced(sp spacedSend) (preRead, bool) {
	pre := w.preReadDelivery(sp.row)
	switch pre.outcome {
	case preReadSkip:
		return pre, false
	case preReadTerminal:
		w.terminate(sp.row, pre.state, pre.reason, w.now(), true)
		return pre, false
	}
	return pre, true
}

// spacingWait 限速目的地距上次送出還差多久才滿 1/上限 秒；不限速或已滿時回 0。
func (w *SystemAlertOutboxWorker) spacingWait(key deliveryDestKey, perSecond float64) time.Duration {
	if perSecond <= 0 {
		return 0
	}
	w.destMu.Lock()
	last := w.runtime(key).lastSentAt
	w.destMu.Unlock()
	if last.IsZero() {
		return 0
	}
	gap := time.Duration(float64(time.Second) / perSecond)
	if d := gap - w.now().Sub(last); d > 0 {
		return d
	}
	return 0
}

// processClaimable 認領、送出並登記一筆已通過認領前判斷的紀錄；回傳是否送達。
func (w *SystemAlertOutboxWorker) processClaimable(round *deliveryRound, row model.NotificationDelivery, pre preRead, key deliveryDestKey, now time.Time) bool {
	if !w.claim(row.ID, now) {
		return false
	}
	row.Attempts++
	if w.hooks.afterClaim != nil && w.hooks.afterClaim(row.ID) {
		return false
	}
	res := w.sendClaimed(row, pre, now)
	if res.requested {
		w.markSent(key, w.now())
	}
	switch res.kind {
	case sendDelivered:
		return true
	case sendDestinationFailure:
		round.stopped[key] = true
		w.failDestination(key, res.text, now)
	case sendRateLimited:
		w.pauseDestination(key, row.Attempts, res, now)
		round.deferred[key] = true
	}
	return false
}

func (w *SystemAlertOutboxWorker) runtime(key deliveryDestKey) *destRuntime {
	rt, ok := w.dests[key]
	if !ok {
		rt = &destRuntime{}
		w.dests[key] = rt
	}
	return rt
}

func (w *SystemAlertOutboxWorker) pausedUntil(key deliveryDestKey) time.Time {
	w.destMu.Lock()
	defer w.destMu.Unlock()
	return w.runtime(key).pausedUntil
}

func (w *SystemAlertOutboxWorker) markSent(key deliveryDestKey, now time.Time) {
	w.destMu.Lock()
	w.runtime(key).lastSentAt = now
	w.destMu.Unlock()
}

// takeQuota 送出節流：型別宣告每秒上限時，目的地本輪的名額為 min(perDestBatch, floor(上限 × 距上次送出的秒數))，
// 從未送出過時為 max(1, floor(上限))；名額用完回 false。沒有宣告上限時不節流。
func (w *SystemAlertOutboxWorker) takeQuota(round *deliveryRound, key deliveryDestKey, perSecond float64, now time.Time) bool {
	if perSecond <= 0 {
		return true
	}
	q, ok := round.quota[key]
	if !ok {
		w.destMu.Lock()
		last := w.runtime(key).lastSentAt
		w.destMu.Unlock()
		if last.IsZero() {
			q = int(math.Max(1, math.Floor(perSecond)))
		} else {
			q = int(math.Floor(perSecond * now.Sub(last).Seconds()))
		}
		if q > w.perDestBatch {
			q = w.perDestBatch
		}
	}
	if q <= 0 {
		round.quota[key] = 0
		return false
	}
	round.quota[key] = q - 1
	return true
}

// claim 以條件更新認領一筆紀錄並同時把嘗試次數加一。
func (w *SystemAlertOutboxWorker) claim(id uint, now time.Time) bool {
	res := w.db.Model(&model.NotificationDelivery{}).
		Where("id = ? AND state IN ? AND attempts < ? AND (lease_until IS NULL OR lease_until < ?)",
			id, activeOutboxStates(), w.maxAttempts, now).
		Updates(map[string]any{"lease_until": now.Add(w.lease), "attempts": gorm.Expr("attempts + 1")})
	return res.Error == nil && res.RowsAffected == 1
}

// sendClaimed 送出已認領的紀錄並登記結果；渲染、送出與判讀以 recover 包住，panic 轉成一次單筆失敗。
func (w *SystemAlertOutboxWorker) sendClaimed(row model.NotificationDelivery, pre preRead, now time.Time) (res sendResult) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[NotificationOutbox] 送出時發生 panic (outbox_id=%d): %v", row.ID, r)
			res = sendResult{kind: sendSingleFailure, text: "送出時發生內部錯誤", requested: res.requested}
			w.recordFailure(row, res, now)
		}
	}()
	res = w.attemptSend(row, pre)
	switch res.kind {
	case sendDelivered:
		w.markDelivered(row)
	case sendImpossible:
		w.abandonImpossible(row, res, now)
	case sendCanceled:
		w.cancelClaimed(row, res.endReason)
	default:
		w.recordFailure(row, res, now)
	}
	return res
}

// attemptSend 渲染並送出，回傳判讀結果（不寫資料庫）。
func (w *SystemAlertOutboxWorker) attemptSend(row model.NotificationDelivery, pre preRead) sendResult {
	if pre.checkPanic {
		return sendResult{kind: sendSingleFailure, text: "送出前檢查失敗"}
	}
	if pre.readErr != "" {
		return sendResult{kind: sendSingleFailure, text: pre.readErr}
	}
	if w.hooks.beforeSend != nil {
		w.hooks.beforeSend(row.ID)
	}
	dest := pre.dest
	if audienceOfRow(row) == deliveryAudienceUser {
		return w.attemptSendToUser(row, pre)
	}
	addr := resolveDeliveryAddress(dest, deliveryAudienceChannel)
	switch addr.Outcome {
	case AddressResolved:
		dest.Target = addr.Address
	case AddressDestinationFailure:
		return sendResult{kind: sendDestinationFailure, text: addr.Reason}
	case AddressRateLimited:
		return sendResult{kind: sendRateLimited, text: addr.Reason, retryAfter: addr.RetryAfter, hasRetry: addr.RetryAfter > 0}
	default:
		return sendResult{kind: sendSingleFailure, text: addr.Reason}
	}
	return w.postRendered(row, pre, dest)
}

// postRendered 渲染並以 dest 送出（通道目的地與已解析的個人訊息共用），回傳判讀結果。
func (w *SystemAlertOutboxWorker) postRendered(row model.NotificationDelivery, pre preRead, dest ChannelDestination) sendResult {
	var body []byte
	var err error
	if row.Category == model.NotificationCategorySystemSecurityAlert {
		body, err = w.renderSnapshot(row, dest)
	} else {
		body, err = w.renderLive(row, pre.msg, dest)
	}
	if err != nil {
		return sendResult{kind: sendSingleFailure, text: truncateRunes(ScrubChannelTokens(err.Error(), dest.Secret), systemAlertErrMax)}
	}
	desc, ok := ChannelType(dest.Type)
	if !ok {
		return sendResult{kind: sendSingleFailure, text: fmt.Sprintf("通道型別 %q 不在登錄中", dest.Type)}
	}
	req, err := desc.NewRequest(dest, body)
	if err != nil {
		return sendResult{kind: sendSingleFailure, text: SanitizeChannelError(err, dest.URL, dest.Secret)}
	}
	client := newNotificationHTTPClient(dest.Type, dest.URL, w.httpTimeout, w.risks, w.transport)
	resp, err := client.Do(req)
	if err != nil {
		if text := redirectFailureText(err); text != "" {
			return sendResult{kind: sendSingleFailure, text: text, requested: true}
		}
		return sendResult{kind: sendDestinationFailure, text: SanitizeChannelError(err, dest.URL, dest.Secret), requested: true}
	}
	result := desc.ReadResult(resp)
	_ = resp.Body.Close()
	return classifyDeliveryResult(desc, result, w.now())
}

// classifyDeliveryResult 把回應判讀成三類失敗之一或成功。
func classifyDeliveryResult(desc ChannelTypeDescriptor, r DeliveryResult, now time.Time) sendResult {
	switch {
	case r.Status == http.StatusTooManyRequests:
		res := sendResult{kind: sendRateLimited, text: "HTTP 429", requested: true}
		res.retryAfter, res.hasRetry = parseRetryAfterHeader(r.RetryAfter, now)
		return res
	case r.Status >= 500:
		return sendResult{kind: sendDestinationFailure, text: fmt.Sprintf("HTTP %d", r.Status), requested: true}
	case r.Status >= 300 && r.Status < 400 && !desc.FollowRedirects:
		return sendResult{kind: sendSingleFailure, text: notifyRedirectNotFollowedText, requested: true}
	case r.OK():
		return sendResult{kind: sendDelivered, requested: true}
	case r.PlatformError != "" && r.Status >= 200 && r.Status < 300:
		return sendResult{kind: sendSingleFailure, text: "platform error: " + r.PlatformError, requested: true}
	case r.PlatformError != "":
		return sendResult{kind: sendSingleFailure, text: fmt.Sprintf("HTTP %d, platform error: %s", r.Status, r.PlatformError), requested: true}
	default:
		return sendResult{kind: sendSingleFailure, text: fmt.Sprintf("HTTP %d", r.Status), requested: true}
	}
}

// parseRetryAfterHeader 解析 Retry-After（整數秒或 HTTP 日期）；負值、無法解析或日期不晚於 now 時回 false。
func parseRetryAfterHeader(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n < 0 {
			return 0, false
		}
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d, true
		}
	}
	return 0, false
}

// backoffFor 第 n 次失敗後的等待：base 起倍增，上限 backoffMax。
func (w *SystemAlertOutboxWorker) backoffFor(attempts int) time.Duration {
	d := w.backoffBase
	for i := 1; i < attempts && d < w.backoffMax; i++ {
		d *= 2
	}
	if d > w.backoffMax {
		d = w.backoffMax
	}
	return d
}

// markDelivered 登記送達（持有租約者收尾）。
//
// 最近一次失敗的時間與錯誤文字保留：送達之後仍看得出這一筆曾經失敗的原因，通道健康欄位的「最近失敗」也不會因為
// 那一筆後來送達而失去原因。是否仍在失敗由狀態判斷，不由錯誤文字判斷。
func (w *SystemAlertOutboxWorker) markDelivered(row model.NotificationDelivery) {
	if err := w.db.Model(&model.NotificationDelivery{}).Where("id = ? AND state IN ?", row.ID, activeOutboxStates()).
		Updates(map[string]any{"state": model.NotificationDeliveryDelivered, "delivered_at": w.now(),
			"lease_until": nil}).Error; err != nil {
		log.Printf("[NotificationOutbox] 標記已送達失敗 (id=%d): %v", row.ID, err)
	}
}

// recordFailure 登記一次失敗（次數已在認領時加過）：達上限即放棄，否則依退避排下次。
// 限流時等待為 min(max(退避, Retry-After), backoffMax)。
func (w *SystemAlertOutboxWorker) recordFailure(row model.NotificationDelivery, res sendResult, now time.Time) {
	msg := truncateRunes(ScrubChannelTokens(res.text), systemAlertErrMax)
	if row.Attempts >= w.maxAttempts {
		if err := w.db.Model(&model.NotificationDelivery{}).Where("id = ?", row.ID).
			Updates(map[string]any{"last_error": msg, "last_failed_at": now}).Error; err != nil {
			log.Printf("[NotificationOutbox] 登記失敗原因失敗 (id=%d): %v", row.ID, err)
		}
		w.abandon(row, model.NotificationEndMaxAttempts, now, false)
		return
	}
	wait := w.backoffFor(row.Attempts)
	if res.kind == sendRateLimited && res.hasRetry {
		if res.retryAfter > wait {
			wait = res.retryAfter
		}
		if wait > w.backoffMax {
			wait = w.backoffMax
		}
	}
	upd := map[string]any{"state": model.NotificationDeliveryRetrying, "lease_until": nil,
		"last_error": msg, "last_failed_at": now, "next_attempt_at": now.Add(wait)}
	if res.kind == sendRateLimited && row.ThrottledSince == nil {
		// 被拒的這一筆同樣因限流而延後：補上第一次延後的時刻，讓「因限流延後」的時窗也涵蓋它。
		upd["throttled_since"] = now
	}
	if err := w.db.Model(&model.NotificationDelivery{}).Where("id = ? AND state IN ?", row.ID, activeOutboxStates()).
		Updates(upd).Error; err != nil {
		log.Printf("[NotificationOutbox] 登記失敗狀態失敗 (id=%d): %v", row.ID, err)
	}
	log.Printf("[NotificationOutbox] 投遞失敗將重試 (outbox_id=%d, category=%s, 第 %d 次): %s", row.ID, row.Category, row.Attempts, msg)
}

// dueUnclaimed 目的地此刻到期、未被認領的進行中紀錄。
func (w *SystemAlertOutboxWorker) dueUnclaimed(key deliveryDestKey, now time.Time) *gorm.DB {
	return key.where(w.db.Model(&model.NotificationDelivery{})).
		Where("state IN ? AND next_attempt_at <= ? AND (lease_until IS NULL OR lease_until < ?)", activeOutboxStates(), now, now)
}

// failDestination 目的地層級失敗：該目的地此刻所有到期、未被認領的紀錄各計一次失敗，依各自的次數排下次時間。
// 依編號逐筆條件更新（取鎖順序一致）；達上限的紀錄由下一輪的掃描放棄。
func (w *SystemAlertOutboxWorker) failDestination(key deliveryDestKey, text string, now time.Time) {
	var rows []struct {
		ID       uint
		Attempts int
	}
	if err := w.dueUnclaimed(key, now).Select("id, attempts").Order("id").Find(&rows).Error; err != nil {
		log.Printf("[NotificationOutbox] 讀取同目的地的到期紀錄失敗: %v", err)
		return
	}
	msg := truncateRunes(ScrubChannelTokens(text), systemAlertErrMax)
	for _, r := range rows {
		next := now.Add(w.backoffFor(r.Attempts + 1))
		if err := w.dueUnclaimed(key, now).Where("id = ?", r.ID).
			Updates(map[string]any{"attempts": gorm.Expr("attempts + 1"), "state": model.NotificationDeliveryRetrying,
				"last_error": msg, "last_failed_at": now, "next_attempt_at": next}).Error; err != nil {
			log.Printf("[NotificationOutbox] 同目的地計次失敗 (id=%d): %v", r.ID, err)
		}
	}
	if len(rows) > 0 {
		log.Printf("[NotificationOutbox] 目的地層級失敗，同目的地 %d 筆到期紀錄各計一次: %s", len(rows), msg)
	}
}

// pauseDestination 限流：目的地在記憶體暫停到 Retry-After 之後（沒有或無法解析時為被拒那一筆的退避值，上限
// notifyPauseMax）；同目的地此刻到期、未被認領的其他紀錄延到暫停截止、不計次，並補上第一次延後的時刻。
func (w *SystemAlertOutboxWorker) pauseDestination(key deliveryDestKey, attempts int, res sendResult, now time.Time) {
	pause := w.backoffFor(attempts)
	if res.hasRetry {
		pause = res.retryAfter
	}
	if pause > notifyPauseMax {
		pause = notifyPauseMax
	}
	until := now.Add(pause)
	w.destMu.Lock()
	w.runtime(key).pausedUntil = until
	w.destMu.Unlock()
	w.markThrottled(key, now)
	if err := w.dueUnclaimed(key, now).Where("next_attempt_at < ?", until).
		Update("next_attempt_at", until).Error; err != nil {
		log.Printf("[NotificationOutbox] 延後同目的地紀錄失敗: %v", err)
	}
}

// markThrottled 為目的地此刻到期、未被認領、尚未標記的紀錄補上第一次因限流或節流被延後的時刻。
func (w *SystemAlertOutboxWorker) markThrottled(key deliveryDestKey, now time.Time) {
	if err := w.dueUnclaimed(key, now).Where("throttled_since IS NULL").
		Update("throttled_since", now).Error; err != nil {
		log.Printf("[NotificationOutbox] 標記限流延後失敗: %v", err)
	}
}

// ---- 不帶快照紀錄的渲染 ----

// renderLive 組出指令告警或系統事件紀錄送往 dest 的本文（內容取自分派後的內容列）。
func (w *SystemAlertOutboxWorker) renderLive(row model.NotificationDelivery, msg model.NotificationMessage, dest ChannelDestination) ([]byte, error) {
	if msg.ID == 0 {
		return nil, errors.New("通知內容不存在")
	}
	params := map[string]string{}
	if msg.Params != "" {
		if err := json.Unmarshal([]byte(msg.Params), &params); err != nil {
			params = map[string]string{}
		}
	}
	switch msg.Category {
	case model.NotificationCategoryCommandAlert:
		var alert model.CommandAlert
		if err := w.db.First(&alert, derefUint(msg.AlertID)).Error; err != nil {
			return nil, fmt.Errorf("讀取告警列失敗: %w", err)
		}
		names := alertSubjectNames{User: msg.ActorName, Asset: msg.TargetName,
			ClientIP: params[messageParamClientIP], DegradeReason: params[messageParamDegradeReason]}
		ch := &model.NotificationChannel{Type: dest.Type, URL: dest.URL, Secret: dest.Secret, Target: dest.Target, Language: dest.Language}
		return buildChannelBody(ch, alertEventCommandAlert, alert, names, commandAlertObject(alert, names, row.DeliveryKey, w.now()))
	case model.NotificationCategorySystemEvent:
		return renderSystemEventBodyFor(msg, params, dest, row.DeliveryKey, w.now(), targetedTitleKeyFor(row, msg))
	default:
		return nil, fmt.Errorf("不支援的通知類別 %q", msg.Category)
	}
}

// systemEventSymbolSeverity 決定系統事件開頭符號的等級：事件規格宣告的分級優先；沿用類型目錄的事件
// 改用分派時寫入內容列的有效分級。只影響開頭符號，第一行的分級標籤仍依 eventSeverity。
func systemEventSymbolSeverity(event notifycat.Event, msg model.NotificationMessage) string {
	if sev := eventSeverity(event); sev != "" {
		return sev
	}
	return msg.Severity
}

// renderSystemEventBody 系統事件本文的共用渲染（投遞程序與稽核失效退路共用）：webhook 送
// {event, params, degraded?, sent_at, notification}；渲染文字的型別依通道語系組字。
func renderSystemEventBody(msg model.NotificationMessage, params map[string]string, dest ChannelDestination, deliveryID string, now time.Time) ([]byte, error) {
	return renderSystemEventBodyFor(msg, params, dest, deliveryID, now, "")
}

// renderSystemEventBodyFor 同 renderSystemEventBody；dmTitleKey 非空時（個人訊息）第一行的標題前加上定向標題
// （詞庫 dm_title 的該鍵，接「 · 」與原標題）。內文與連結不變。
func renderSystemEventBodyFor(msg model.NotificationMessage, params map[string]string, dest ChannelDestination, deliveryID string, now time.Time, dmTitleKey string) ([]byte, error) {
	event := notifycat.Event(msg.EventKey)
	desc, ok := ChannelType(dest.Type)
	if !ok {
		return nil, fmt.Errorf("通道型別 %q 不在登錄中", dest.Type)
	}
	degraded := msg.Degraded
	clean := params
	if !degraded {
		if c, err := notifycat.Validate(event, params); err == nil {
			clean = c
		} else {
			degraded = true
			clean, _ = notifycat.FilterDeclared(event, params)
		}
	}
	if desc.Caps.RendersText {
		link := ""
		if !degraded && desc.Caps.SupportsLinks && msg.LinkPath != "" {
			link = composeNotificationLink(msg.LinkPath)
		}
		var title, text string
		if degraded {
			title, text = notifycat.RenderDegraded(dest.Language, event, clean)
		} else {
			title, text = notifycat.RenderLinked(dest.Language, event, clean, link != "")
		}
		if dmTitleKey != "" {
			title = notifycat.Phrase(dest.Language, notifycat.LexiconDMTitle, dmTitleKey) + " · " + title
		}
		return desc.BuildBody(dest, OutboundMessage{Text: notifycat.ComposeSlack(dest.Language, notifycat.SlackMessage{
			Prefix: notifycat.SeveritySymbol(systemEventSymbolSeverity(event, msg)), Title: title, Severity: eventSeverity(event), Body: text,
			Occurred: msg.OccurredAt, Link: link, LinkLabel: notifycat.LinkLabelOf(event),
		})})
	}
	raw, err := json.Marshal(notifyEventPayload{
		Event:        string(event),
		Params:       notifycat.WireParams(event, clean),
		Degraded:     degraded,
		SentAt:       now.In(time.Local).Format(time.RFC3339),
		Notification: systemEventObject(msg, clean, degraded, deliveryID, now),
	})
	if err != nil {
		return nil, err
	}
	return desc.BuildBody(dest, OutboundMessage{JSON: raw})
}
