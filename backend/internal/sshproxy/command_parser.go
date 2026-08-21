package sshproxy

import (
	"bytes"
	"log"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/vtscreen"
)

// 緩衝上限：審計旁路不可無限制吃記憶體（design D3 degrade 原則）
const (
	// typingBufMax 指令 echo 緩衝上限：單行指令遠小於此，超出代表異常輸出
	typingBufMax = 64 * 1024
	// tailBufMax 指令間輸出的尾端緩衝：只為擷取 prompt，保留尾端即可
	tailBufMax = 8 * 1024
	// pendingFlushMax Enter 後等待回顯換行的上限：超出即強制結算
	pendingFlushMax = 4 * 1024

	// === 重放佇列上界（command-audit-pending-queue）===
	// 結算期間抵達的輸入改為排隊重放而非丟棄，這引入一個新的失敗面：
	// 對端**正是不受信的納管主機**，它若永不回顯，結算就永不完成、佇列無限增長。
	// 三個上界都是為此存在，且以常數而非註解表達（goal-charter §7：誠實邊界要機器可見）。

	// replayQueueMax 重放佇列的容量上界。滿載即停止入列並記錄可觀測訊號，
	// 不靜默丟棄——那只是把一個已知缺陷換成另一個同型缺陷。
	replayQueueMax = 64 * 1024
	// replayScanMax 重放輪以輸入錨定位自身 echo 時，掃描輸出的位元組上限
	replayScanMax = 32 * 1024
	// replayScanLines 同上的換行數上限。每個換行都要重算一次候選指令，
	// 用行數封頂避免前一條指令輸出極長時退化成逐行重算整個緩衝。
	replayScanLines = 256
)

// alternate screen 進出標記：vim/less 等全螢幕程式期間暫停指令解析（畫面重繪不是指令）
var (
	altScreenEnterMarks = [][]byte{
		[]byte("\x1b[?1049h"),
		[]byte("\x1b[?1048h"),
		[]byte("\x1b[?1047h"),
		[]byte("\x1b[?47h"),
	}
	altScreenExitMarks = [][]byte{
		[]byte("\x1b[?1049l"),
		[]byte("\x1b[?1048l"),
		[]byte("\x1b[?1047l"),
		[]byte("\x1b[?47l"),
	}
)

// interruptKeys 中斷鍵集合：在輸入行尚未送出時收到，即中止當輪輸入（design.md D4.2）。
//
// 目前只有 Ctrl-C（0x03）——它是**唯一有實錄佐證**的一個（ssh-capture 的 ctrl-c 情境，
// 逐事件追過：0x03 不含 \r，開啟的那輪 typing 永不結算）。Ctrl-D（0x04）／Ctrl-Z（0x1a）／
// Ctrl-\（0x1c）是否同形態尚無實錄亦未實測，依「宣稱強度不得超過證據」不憑猜加入；
// 觸發點＝錄到含該鍵的情境、或實測出同型的 typing 黏住行為時再擴充本集合。
//
// Ctrl-U（0x15）刻意**不**在此列：它清的是行內容、輸入行本身仍在繼續，
// 該輪的原點快照依然有效（ctrl-u-kill 情境現行即為正確結果），
// 中止那一輪反而會讓使用者接著重打的指令漏記。
//
// 全為 ASCII 控制碼，故可直接交給 bytes.ContainsAny 逐 code point 比對。
const interruptKeys = "\x03"

// CommandFunc 指令結算回呼：command 為虛擬螢幕還原後的完整指令行
type CommandFunc func(command string, executedAt time.Time)

// CommandRecordFunc 「非乾淨」審計紀錄的回呼（command-audit-altscreen-bypass C）。
//
//   - degraded=true  → 該輪**沒有可信的指令文字**，command 恆為空字串。
//     降級紀錄 SHALL NOT 包含推測的指令文字：捏造比漏記更嚴重。
//   - degraded=false → 文字已重組但**可能不等於實際執行的指令**，reason 說明限定的性質。
//     兩者刻意不共用旗標（design §6.6）——合併會讓「未標記 ⇒ 文字可信」變成假話。
//
// 未掛載（nil）時：降級紀錄無處可去故不發，限定紀錄退回 onCommand
// ——後者的文字本來就會入庫，落地形式不該因為觀測管道缺席而改變。
type CommandRecordFunc func(command string, degraded bool, reason string, executedAt time.Time)

// CommandParser 以虛擬終端螢幕重組 SSH 會話指令（design D3）
//
// 原理：指令文字不取自使用者按鍵，而取自伺服器的 echo 回顯——
// 退格、tab 補全、歷史鍵的最終結果都會反映在回顯流中，
// 將回顯餵進虛擬螢幕（internal/vtscreen）即可還原使用者實際送出的指令行。
//
// 狀態機：
//   - 閒置：輸出進 tailBuf（截尾保留，用於擷取 prompt 與指令原點）
//   - 輸入中（首個輸入 byte 觸發）：快照 prompt 與原點、重置緩衝，輸出 echo 進 typingBuf
//   - Enter 後（pending）：繼續收 echo 直到換行回顯到達才結算，避免輸入快於回顯的競態
//   - 中斷鍵（輸入中收到 Ctrl-C）：中止當輪、丟棄 echo、回到閒置，下一次按鍵重新取原點
//   - alternate screen 期間：完全抑制（不解析、不累積）
//
// 非併發安全：呼叫端（bridge）的 input/output 旁路須以同一把鎖序列化。
type CommandParser struct {
	onCommand CommandFunc
	// onRecord 降級／限定紀錄的落地入口（見 CommandRecordFunc）。
	onRecord CommandRecordFunc
	// sqlMode：DB CLI（mysql/postgres/mssql）逐行回顯屬同一條 SQL 的續行，
	// 累積到語句結束符才結算為單一指令——使審計記錄完整、且告警比對看得到
	// 完整語句（堵住「關鍵字拆行送出以規避 SQL 危險規則」的繞過）。redis 為逐行不啟用。
	sqlMode bool
	// tsqlMode：mssql 專屬，額外承認獨立一行的 GO 為批次終止符（D4）。
	// 對其餘協議恆為 false，故它們的切分行為與本欄位加入前逐位元組相同。
	tsqlMode bool

	// altScreenMarked 對端印出過 alternate screen 進入標記且尚未印出離開標記。
	// **它是汙染源不是抑制器**（design §6.1）：命中期間輸入輸出照常流經狀態機，
	// 只是每一輪都被標成「這段回顯不是 shell 的指令回顯」。見 scanAltScreen。
	altScreenMarked bool
	typing          bool
	pending         bool

	promptText string
	// learnedPrompt：本連線曾經**成功錨定過**一條指令的提示符（trim 後）。
	//
	// 為什麼需要它：promptText 是每一輪從 tailBuf 重新快照的「螢幕最後一個非空白行」，
	// 全螢幕重繪之後那一行可能是 pager 的狀態列（實測 busybox less 取到 `/etc/services`），
	// 於是當輪失去可用的錨。提示符本身是連線內穩定的字串，
	// 記住上一次真的用來剝除成功的那個，重繪之後仍能把指令行認出來。
	learnedPrompt string
	// originText／originX：輸入起始那一刻「游標所在列的原文（未 trim）」與「游標顯示欄」。
	// 這是 shell／readline 欄位算術的原點——指令回顯緩衝不含提示符，
	// 不把原點種回螢幕，清行重繪就會從錯誤的欄位切開，
	// 使審計得到一條使用者從未輸入過的指令（design.md D4.2）。
	originText string
	originX    int

	typingBuf  bytes.Buffer
	tailBuf    bytes.Buffer
	pendingLen int

	// === 重放佇列（command-audit-pending-queue）===
	// pending 期間抵達的輸入排隊、結算後重放，取代原先的整段丟棄。
	// 存原始位元組而非解析結果：重放走的是與真實輸入完全相同的路徑。
	replayQueue bytes.Buffer
	// replayRound 當前 pending 輪來自重放，其 echo 須定位（見 appendReplayPending）。
	replayRound bool
	// replayAnchor 該輪的輸入錨（使用者確實送出的那一行的可見形式）。
	// **可為空**：歷史鍵／補全這類輸入的可見文字只存在於 echo 中，
	// 輸入位元組裡沒有——那時改以提示符定位（見 replayCandidate）。
	replayAnchor   string
	replayScanned  int
	replayScanLine int
	// inReplay 僅在 drainReplay 餵入佇列內容期間為真，供 beginTyping 沿用上一輪原點。
	inReplay bool
	// 兩個降級終態的可觀測旗標（測試直接斷言，不靠讀日誌）
	replayOverflowed bool
	replayFellBack   bool
	overflowLogged   bool
	overflowRecorded bool
	fallbackLogged   bool

	stmtBuf strings.Builder // sqlMode：累積中的多行語句
	stmtLen int

	// === 全螢幕重繪的兩個新狀態（command-audit-altscreen-bypass 原型 D）===
	//
	// roundTainted 當輪的回顯緩衝出現過整螢幕層級的定位／清除（vtscreen.Redrawn）。
	// 為真代表「這段位元組不是一次行編輯」，故**以輸入位元組結算的兩條退路
	// （重放錨 fallback、會話結束 flush）不得動用**——那些按鍵是餵給全螢幕程式的，
	// 不是 shell 指令。與 scanAltScreen 清空佇列的理由同一條，但不依賴標記本身。
	roundTainted bool
	// roundAltScreen 當輪落在 alternate screen 標記區間內。
	//
	// **與 roundTainted 的差別是「拒發的強度」**：roundTainted 只在錨全部落空時
	// 拒發，roundAltScreen **無條件**拒發。兩者不能合併——實測
	// （TestCommandParserAltScreenSuppressed）顯示 vim 內按 Enter 那一輪的
	// **原點錨會命中**：beginTyping 從 tailBuf 取到的原點正是 vim 畫面上那一列，
	// 而 vim 把使用者打進檔案的字接在它後面，`raw` 於是真的以原點為前綴。
	// 只靠 `anchorNone && roundTainted`（design §6.1 的原文）會把
	// **使用者打進檔案的內文當成指令發出**＝捏造，且既有 Scenario
	// 「Alternate screen suppressed」當場轉紅。
	roundAltScreen bool
	// roundHasInput 當輪的輸入方向收到過 `\r` 以外的位元組。
	//
	// 用來把兩種「結算文字為空」分開：只按 Enter 是正常的空輸入（不記），
	// 打了字卻重組不出任何文字則是**對端關掉了回顯**（記降級，見 noteNoEcho）。
	roundHasInput bool
	// 兩個新降級終態的可觀測旗標（測試直接斷言，不靠讀日誌）
	unanchored     bool
	taintedDropped bool
	noEcho         bool
	altScreenRound bool
	unanchorLogged bool
	taintedLogged  bool
	noEchoLogged   bool
	altScreenLog   bool
	// pendingCaveat 下一筆入庫文字的限定碼（見 noteReplayFallback），由 emit 消費。
	// 以欄位而非參數傳遞：標注點與發出點之間隔著 finalizeReplay／accumulateSQL
	// 兩層，改簽章要動的呼叫點比它值得的多；單執行緒（auditTap 以單鎖序列化）故無競態。
	pendingCaveat string

	// 降級可觀測（design.md D7.4）：兩類降級各自最多記一行，
	// 避免持續出錯時灌爆日誌，也讓「解析出事」不再無聲。
	degradeLogged bool
	dropLogged    bool

	// render 為虛擬螢幕還原入口。抽成欄位只為了讓降級路徑可被測試——
	// 新解析器以「不 panic」為設計目標，正常輸入無從觸發 recover。
	render screenRenderFunc
}

// NewCommandParser 建立指令重組器。模式由協議推導（單一事實源）：
//   - mysql／postgres／mssql：sqlMode（多行語句累積）
//   - mssql：另啟 tsqlMode（GO 批次終止符）
//   - 其餘（ssh／k8s／redis）：逐行結算，行為與協議感知加入前完全相同
func NewCommandParser(onCommand CommandFunc, protocol string) *CommandParser {
	return &CommandParser{
		onCommand: onCommand,
		sqlMode:   protocol == "mysql" || protocol == "postgres" || protocol == "mssql",
		tsqlMode:  protocol == "mssql",
		render:    renderWithVTScreen,
	}
}

// SetRecordSink 掛上降級／限定紀錄的落地入口（見 CommandRecordFunc）。
//
// 與 onCommand 分離而非改其簽章：既有呼叫端與測試以
// `NewCommandParser(store.Enqueue, protocol)` 建構，改簽章會把一個純新增的能力
// 變成一次全域改寫，而那些呼叫點一個字都不需要改。
func (p *CommandParser) SetRecordSink(fn CommandRecordFunc) {
	p.onRecord = fn
}

// WriteInput 處理使用者輸入方向的資料。
//
// data 是使用者端送來的原始一幀，**切分完全由使用者控制**——貼上、或自製客戶端
// 都能把任意位元組塞進同一幀。因此本函式把一幀當成「可能含多個事件的序列」逐段處理，
// 不能處理完第一個事件就把其後的位元組整批丟掉：那等於交出一條
// 「把指令藏在中斷鍵後面就不留痕」的規避路徑（實測見下方 interrupt 分支的註解）。
func (p *CommandParser) WriteInput(data []byte) {
	// pending 中：前一輪已送出、正等回顯結算。此刻抵達的輸入**整段**排入佇列
	// （含中斷鍵，順序原樣保留），結算後重放——語義等同於「這些位元組晚一點才抵達」。
	// 原先此處是整段丟棄：指令在遠端正常執行、審計零紀錄，而送出時機與封包切分
	// 由使用者端控制，故可主動觸發（goal-charter §6 B 類）。
	if p.pending {
		p.enqueueReplay(data)
		return
	}

	for len(data) > 0 {
		// Enter 與中斷鍵以**位置先後**決定，不是以種類決定：
		//   - Enter 先到：那一行已經送出，必須結算；同段內後到的中斷鍵中止的是
		//     執行中的行程而非輸入行（`sleep 100\r` 與 0x03 落在同一次 read 時，
		//     若讓中斷鍵優先就會把已執行的指令漏記）。
		//   - 中斷鍵先到：當輪作廢，其後的位元組另起一輪（見下）。
		enter := bytes.IndexByte(data, '\r')
		interrupt := bytes.IndexAny(data, interruptKeys)

		if interrupt >= 0 && (enter < 0 || interrupt < enter) {
			// 中斷鍵先到：當輪作廢，已累積的 echo 整批丟棄（語義見 abortTyping）。
			//
			// 同幀其後的位元組**必須另起一輪**。它們不是可有可無的殘渣：實測
			// （ssh-test 靶機、bash+readline）`sleep` 執行中單幀送出 "\x03echo X\r"，
			// 遠端確實印出 X——那條指令真的執行了。若跟著中止一起丟掉，使用者只要
			// 把指令塞在中斷鍵後面同一幀，就能執行而完全不進審計；那是規避留痕，
			// 依 goal-charter §6「今天存在＝是」必修。
			//
			// 已知代價（如實記載，不含糊）：新起的那一輪，其原點取自 tailBuf，
			// 而 shell 因中斷而重印的提示符此刻尚未抵達，於是——
			//   - shell 閒置（tailBuf 內仍有前一個提示符，即中斷鍵落在幀首、
			//     其前無人開過輪的情形）：原點正確，結算值乾淨。
			//   - 中斷前已有打字（該輪 beginTyping 已把 tailBuf 清掉）或 shell 忙碌
			//     （tailBuf 內沒有提示符）：原點為空，結算值會夾帶 `^C` 與
			//     重繪造成的空白／提示符前綴。
			// 第二種是可接受的降級：使用者實際打的指令仍完整落在字串裡，
			// 稽核做子字串比對找得到；不記則什麼都查不到。紀錄不完美好過沒有紀錄。
			if p.typing {
				p.abortTyping()
			}
			data = data[interrupt+1:]
			continue
		}

		// 走到這裡代表本段之前不再有中斷鍵：這一段是一輪輸入（或其延續）。
		if !p.typing && !p.pending {
			p.beginTyping()
		}
		if !p.typing {
			// pending 中：那一輪已送出、正等回顯結算，輸入不影響它
			return
		}
		// 本輪是否收到過「Enter 以外」的位元組。**只記這個事實，不記內容**——
		// 輸入方向的內容留存是獨立能力（獨立資料流、獨立加密、查看須留痕），
		// 不在本 change 的射程內。看得到不等於可以記。
		body := data
		if enter >= 0 {
			body = data[:enter]
		}
		if len(body) > 0 {
			p.roundHasInput = true
		}
		if enter >= 0 {
			// Enter 已送出：echo 可能尚未到齊，進入 pending 等回顯換行再結算。
			// 同幀 Enter 之後的剩餘位元組（`cmd1\rcmd2\r` 型的同幀多指令）排入佇列，
			// 由 drainReplay 在本輪結算後重放。使用者貼上一段多行指令即命中此路徑。
			p.typing = false
			p.pending = true
			p.pendingLen = 0
			p.enqueueReplay(data[enter+1:])
		}
		return
	}
}

// abortTyping 中斷鍵中止當輪輸入：狀態回到閒置，已累積的 echo 整批丟棄。
//
// 丟棄是語義正確而非湊合——Ctrl-C 中止的就是當前輸入行，那些字從未被送出執行，
// 讓它們以任何形式進審計都是偽證。
//
// 回到閒置之後，shell 隨後印的 `^C`、換行與**重印的提示符**會落進 tailBuf（閒置路徑），
// 下一次按鍵的 beginTyping 因而重新取得正確的原點。缺了這一步，那些位元組會全部
// 落進同一輪 typingBuf，而該輪的原點與 promptText 皆為空（中斷發生時游標確實在行首），
// 三條剝除規則同時落空，結算值就是「提示符＋下一條指令」這種使用者從未輸入過的字串
// （實錄 ctrl-c 情境曾入庫 `ssh-test-server:~$ exit`，design.md D4.2／D4.3）。
func (p *CommandParser) abortTyping() {
	p.typing = false
	p.pending = false
	p.pendingLen = 0
	p.roundTainted = false
	p.roundAltScreen = false
	p.roundHasInput = false
	p.resetReplayRound()
	p.typingBuf.Reset()
	p.promptText = ""
	p.originText = ""
	p.originX = 0
}

// WriteOutput 處理伺服器輸出方向的資料
func (p *CommandParser) WriteOutput(data []byte) {
	p.scanAltScreen(data)

	switch {
	case p.pending:
		p.appendPending(data)
	case p.typing:
		p.appendCapped(&p.typingBuf, data, typingBufMax)
	default:
		p.appendTail(data)
	}
}

// Resize 虛擬螢幕無固定寬度（行不換列），尺寸變更無需處理；保留介面一致性
func (p *CommandParser) Resize(cols, rows int) {}

// Flush 會話結束時結算未完成的 pending 指令與累積中的 SQL 語句
func (p *CommandParser) Flush() {
	if p.pending {
		if p.replayRound {
			p.finalizeReplayFallback()
		} else {
			p.finalize()
		}
	}
	// 佇列殘留＝使用者已送出、但對端從未回顯到可供結算的輪次。
	// 以輸入錨結算而非丟棄：那些位元組確實送出了，漏記正是本 change 要消滅的東西。
	p.flushReplayQueue()
	if p.sqlMode && p.stmtBuf.Len() > 0 {
		p.emit(p.stmtBuf.String())
		p.stmtBuf.Reset()
		p.stmtLen = 0
	}
}

// beginTyping 進入輸入狀態：從 tailBuf 一次取三個值（design.md D4.2）——
// promptText（語義不變，既有剝除路徑照舊使用）、
// originText（游標所在列的原文，**未 trim**）、originX（游標顯示欄）。
//
// 原點不能改用 promptText：後者經 TrimSpace，`ssh-test-server:~$ `（19 欄）
// 會變成 18 欄，種進去就又差一欄；且 tail 尾端若是換行（游標已在新的一列、
// 原點應為空），promptText 取到的是上一列的結果文字。
func (p *CommandParser) beginTyping() {
	p.typing = true
	if !p.inReplay {
		// 汙染旗標只由「使用者的下一次真實按鍵」清除。
		// 重放輪**繼承**它：佇列裡那些位元組是在同一個全螢幕情境中送出的，
		// 換一輪不會讓它們變回 shell 指令。清得太早正是第一版原型漏掉
		// `LINE_B_C8M2V` 的原因（實測）。
		p.roundTainted = false
		p.roundAltScreen = false
	}
	p.roundHasInput = false
	if p.altScreenMarked {
		// 對端仍在 alternate screen 標記區間內：新的一輪從一開始就是髒的。
		// 寫在 inReplay 判斷之外，是因為重放輪也可能在「本輪期間才進入標記區間」
		// 之後才開出來，那時上一輪的旗標還是乾淨的。
		p.roundTainted = true
		p.roundAltScreen = true
	}
	if p.inReplay {
		// 重放輪：前一輪的 Enter 回顯換行已經過去，游標實際在新的一列的行首，
		// **原點為空才是當下真實的螢幕狀態**——種入上一輪的原點會讓渲染出的
		// 第一列變成「舊提示符 ＋ 新提示符 ＋ 指令」，反而多出一段沒人打過的字。
		// promptText 保留：同一個 shell 的提示符不變，剝除前綴仍靠它。
		// 此刻不從 tailBuf 重新快照，因為新提示符還沒到（實測：它與本輪 echo
		// 黏在下一個輸出幀裡）。
		p.originText = ""
		p.originX = 0
		p.typingBuf.Reset()
		return
	}
	screen := p.renderScreen("", 0, p.tailBuf.Bytes())
	p.promptText = lastNonEmptyLine(screen.lines)
	p.originText = screen.currentLine
	p.originX = screen.cursorX
	p.tailBuf.Reset()
	p.typingBuf.Reset()
}

// appendPending Enter 後收 echo：見到換行（Enter 的回顯）即結算
func (p *CommandParser) appendPending(data []byte) {
	if p.replayRound {
		p.appendReplayPending(data)
		return
	}

	if idx := bytes.IndexByte(data, '\n'); idx != -1 {
		p.appendCapped(&p.typingBuf, data[:idx], typingBufMax)
		p.finalize()
		p.dispatchAfterFinalize(data[idx+1:])
		return
	}

	p.appendCapped(&p.typingBuf, data, typingBufMax)
	p.pendingLen += len(data)
	if p.pendingLen > pendingFlushMax {
		// 換行遲遲未到（如指令觸發即時輸出）：強制結算避免吞掉下一條指令
		p.finalize()
		p.drainReplay()
	}
}

// === 重放佇列（command-audit-pending-queue）===
//
// 缺陷形態：Enter 送出後那一輪要等回顯換行才結算，期間抵達的輸入原先被整段丟棄——
// 指令在遠端正常執行、審計零紀錄。兩種觸發形態皆已於 ssh-test 靶機實跑復現：
// 同一封包內多條指令（貼上多行即命中）、前一條回顯未返回即送出下一條。
//
// 修法的難點不在「把輸入留下來」，在**重放輪要在輸出流的哪個位置結算**。
// 實測（2026-08-18，ssh-test 靶機、bash+readline）第二條指令的 echo 與前一條的
// 執行結果、新提示符**黏在同一個輸出幀**：
//
//	"A\r\n\x1b[?2004hssh-test-server:~$ echo B\r\n\x1b[?2004l\rB\r\n\x1b[?2004hssh-test-server:~$ "
//
// 沿用「見第一個換行即結算」會把執行結果 A 記成一條使用者從未輸入的指令——
// 那是比漏記更嚴重的捏造。故重放輪改以**輸入錨**（使用者確實送出的那一行）
// 在輸出流中定位屬於自己的那個換行。

// enqueueReplay 把結算期間抵達的輸入排入佇列。
//
// 上界不是防禦性裝飾：對端**正是不受信的納管主機**，它若永不回顯，
// 結算永不完成、佇列無限增長。滿載即停止入列並留下可觀測訊號，不靜默丟棄。
func (p *CommandParser) enqueueReplay(data []byte) {
	if len(data) == 0 {
		return
	}
	if p.replayQueue.Len() == 0 {
		// 佇列已清空：上一次溢出的區段已經結束，下一次溢出是另一個事實。
		p.overflowRecorded = false
	}
	remain := replayQueueMax - p.replayQueue.Len()
	if remain <= 0 {
		p.noteReplayOverflow()
		return
	}
	if len(data) > remain {
		p.replayQueue.Write(data[:remain])
		p.noteReplayOverflow()
		return
	}
	p.replayQueue.Write(data)
}

// takeReplaySegment 自佇列取出一輪的輸入：到第一個 Enter（含）為止；
// 沒有 Enter 就整段取出（那是尚未送出的殘段，接回輸入狀態繼續打字）。
func (p *CommandParser) takeReplaySegment() []byte {
	if p.replayQueue.Len() == 0 {
		return nil
	}
	n := p.replayQueue.Len()
	if i := bytes.IndexByte(p.replayQueue.Bytes(), '\r'); i >= 0 {
		n = i + 1
	}
	// 複製：Next 回傳的切片在下次寫入佇列後即失效
	return append([]byte(nil), p.replayQueue.Next(n)...)
}

// replaySegBody 取一段重放輸入中 Enter 之前的位元組。
func replaySegBody(seg []byte) []byte {
	if i := bytes.IndexByte(seg, '\r'); i >= 0 {
		return seg[:i]
	}
	return seg
}

// dispatchAfterFinalize 一輪結算後，把同一輸出幀的剩餘位元組交給正確的下一個狀態。
//
// **關鍵順序**：先 drainReplay 讓佇列裡待重放的下一輪進入 pending，**再**把剩餘餵回。
// 反過來（舊版：先 appendTail 剩餘、後 drainReplay）會把剩餘——其中可能含下一個重放輪
// 的 echo——當成閒置 tail 丟掉，使該輪等不到自己的回顯而漏記。
// 那正是情境 4（pending 期間上鍵召回，真 WS 實跑約 15% 間歇漏記）的真因：
// f1 的 echo、執行結果、召回輪的 echo 落在同一幀時，召回 echo 被 finalize 後的
// appendTail 吃掉。分幀落點決定漏不漏，故間歇；單幀實測則穩定復現。
func (p *CommandParser) dispatchAfterFinalize(rest []byte) {
	p.drainReplay()
	if len(rest) == 0 {
		return
	}
	if p.pending {
		// drainReplay 已開下一個重放輪：剩餘進 appendReplayPending 找它的 echo。
		p.appendPending(rest)
		return
	}
	// 佇列已空：剩餘是結算後的閒置輸出，照舊截尾保留供下一輪取原點。
	p.appendTail(rest)
}

// drainReplay 結算完成後依序重放佇列內容，使其正常走入下一輪輸入期。
//
// 重放走的是與真實輸入完全相同的 WriteInput 路徑——不是另一條旁路，
// 故中斷鍵、多重 Enter 等既有語義自動沿用。
func (p *CommandParser) drainReplay() {
	for !p.pending && p.replayQueue.Len() > 0 {
		seg := p.takeReplaySegment()
		if len(seg) == 0 {
			return
		}
		if len(replaySegBody(seg)) == 0 {
			// 該輪只按了 Enter：遠端只會多印一個提示符，沒有指令可記。
			// 開一輪只會讓它在輸出流裡亂咬一個換行。跳過。
			continue
		}
		p.replayAnchor = p.replayAnchorText(seg)
		p.replayRound = true
		p.replayScanned = 0
		p.replayScanLine = 0
		p.inReplay = true
		p.WriteInput(seg)
		p.inReplay = false
		if !p.pending {
			// 未進入等待結算（該段無 Enter，或被中斷鍵作廢）：本輪作廢，
			// 否則後續真實輸入的那一輪會拿著上一段的錨去比對。
			p.resetReplayRound()
		}
	}
}

// replayAnchorText 取一段重放輸入的可見文字，作為定位 echo 的錨。
//
// 以虛擬螢幕渲染，故退格與游標移動在此正確反映。
// **已知邊界**：tab 補全與歷史鍵的結果只存在於 echo 中，輸入位元組裡沒有，
// 此處取到的是補全前的字面（`ec\tho`）。那類輸入在結算期間送出時，
// 錨會定位不到自身 echo 而走 fallback——記到的是使用者確實送出的位元組，
// 不等於實際執行的指令。相較於原先的完全漏記仍是改善，但不宣稱等價。
func (p *CommandParser) replayAnchorText(seg []byte) string {
	body := replaySegBody(seg)
	if len(body) == 0 {
		return ""
	}
	screen := p.renderScreen("", 0, body)
	return strings.TrimSpace(lastNonEmptyRawLine(screen.lines))
}

// appendReplayPending 重放輪的 pending 收斂：以輸入錨在輸出流中定位自身 echo。
//
// 逐個換行檢查候選：前一條指令的執行結果不會等於使用者送出的那一行，
// 本輪 echo 才會。兩個上界（掃描位元組數、換行數）任一達成即 fallback，
// 避免對端不回顯或回顯被改寫時無限等待。
func (p *CommandParser) appendReplayPending(data []byte) {
	for {
		idx := bytes.IndexByte(data, '\n')
		if idx < 0 {
			break
		}
		// 含換行一併寫入：不匹配時要繼續掃描，螢幕必須保持連續
		p.appendCapped(&p.typingBuf, data[:idx+1], typingBufMax)
		p.replayScanned += idx + 1
		p.replayScanLine++
		if cmd, ok := p.replayCandidate(); ok {
			p.finalizeReplay(cmd)
			p.dispatchAfterFinalize(data[idx+1:])
			return
		}
		data = data[idx+1:]
		if p.replayScanLine >= replayScanLines || p.replayScanned >= replayScanMax {
			p.finalizeReplayFallback()
			p.dispatchAfterFinalize(data)
			return
		}
	}

	p.appendCapped(&p.typingBuf, data, typingBufMax)
	p.replayScanned += len(data)
	if p.replayScanned >= replayScanMax {
		p.finalizeReplayFallback()
		p.drainReplay()
	}
}

// replayCandidate 判斷目前累積的輸出是否已含本輪的 echo。
//
// 判準是「剝除前綴後的候選**等於**輸入錨，或以其結尾」——相等是常態；
// HasSuffix 涵蓋提示符在兩輪之間改變（如 cd 之後）而剝不乾淨的情形。
// 回傳值取錨本身而非候選：HasSuffix 命中時候選的前綴正是那個沒剝掉的提示符，
// 留著會讓審計文字夾帶一段使用者沒打過的字。
func (p *CommandParser) replayCandidate() (string, bool) {
	screen := p.renderRound(p.typingBuf.Bytes())
	raw := lastNonEmptyRawLine(screen.lines)
	stripped, _ := p.stripCommandPrefixes(raw, false)
	cand := strings.TrimSpace(stripped)
	if cand == "" {
		return "", false
	}

	if p.replayAnchor != "" {
		if cand == p.replayAnchor || strings.HasSuffix(cand, p.replayAnchor) {
			return p.replayAnchor, true
		}
		return "", false
	}

	// 錨不可用：歷史鍵（上鍵）與 tab 補全的可見文字只存在於 echo 中，
	// 輸入位元組裡沒有。**這條路徑今天可觸發**——ssh-test 靶機實測，
	// pending 期間送 "\x1b[A\r"，遠端確實重繪並執行了前一條指令。
	// 改以「該行帶提示符」定位：重放輪的 echo 接在新印的提示符之後，
	// 前一條的執行結果不帶提示符。
	//
	// 代價（如實記載）：執行結果中若有一行**以提示符開頭**，會被誤認為本輪 echo。
	// 那需要刻意構造（如 echo 出一個長得像提示符的字串），且僅在錨不可用時才走到；
	// 相對於這條路徑原本的完全漏記，取這個交換。
	if p.promptText != "" && strings.HasPrefix(strings.TrimSpace(raw), p.promptText) {
		return cand, true
	}
	return "", false
}

// finalizeReplay 結算一個重放輪並讓狀態機回到閒置。
func (p *CommandParser) finalizeReplay(command string) {
	p.pending = false
	p.pendingLen = 0
	p.resetReplayRound()
	p.typingBuf.Reset()

	if command == "" {
		return
	}
	if p.roundAltScreen {
		// 重放輪落在標記區間內：它的「錨」是使用者餵給全螢幕程式的按鍵，
		// 而 replayCandidate 只要在螢幕上看到同一串字就會認定命中——
		// 那串字是全螢幕程式自己畫上去的，不是 shell 的指令回顯。
		// 可達路徑：進入標記與前一輪的結算落在同一幀，且佇列非空。
		p.noteAltScreenRound()
		// sqlMode 下與 finalize 的同名分支一致：累積中的半條語句一併丟棄，
		// 否則被後續乾淨輪焊成假語句（charter backlog #23 的重放路徑同形態）。
		p.discardSQLStatement()
		return
	}
	if !p.sqlMode {
		p.emit(command)
		return
	}
	p.accumulateSQL(command)
}

// finalizeReplayFallback 錨定失敗的終態：以使用者送出的輸入位元組結算。
//
// 為什麼不是放棄該輪：放棄＝漏記，而漏記正是本 change 要消滅的東西。
// 錨的內容是使用者確實送出的位元組，記下它不構成捏造；但它可能不等於
// 實際執行的指令（見 replayAnchorText 的已知邊界），故留下可觀測訊號。
func (p *CommandParser) finalizeReplayFallback() {
	anchor := p.replayAnchor
	if p.roundTainted {
		// 當輪的回顯是整螢幕重繪 ⇒ 這些按鍵是餵給全螢幕程式的，不是 shell 指令。
		// 以輸入位元組結算會記下 `LINE_B_C8M2V` 這種「使用者確實打過、但從未當成指令執行」
		// 的字串（實測：enter 標記被切幀的 vim 會話多出 5 筆）。
		p.noteTaintedDrop()
		p.emitDegraded(model.DegradeFullScreenInput)
		// sqlMode 下丟棄累積中的半條語句（同 finalize 的降級分支，backlog #23）：
		// finalizeReplay("") 走 command=="" 早退、不會清 stmtBuf，故在此明確丟棄。
		p.discardSQLStatement()
		p.finalizeReplay("")
		return
	}
	p.noteReplayFallback()
	p.finalizeReplay(anchor)
}

// flushReplayQueue 會話結束時處理佇列殘留：對端從未回顯到可供結算的輪次。
//
// 「對端永不回顯」不是理論情境——對端就是不受信的納管主機。
// 已送出的輪次以輸入錨結算；尾端沒有 Enter 的殘段則**不記**，
// 那些字從未送出，記錄它們就是捏造（與 abortTyping 同一條紀律）。
func (p *CommandParser) flushReplayQueue() {
	if p.roundTainted {
		// 會話在「全螢幕程式仍在吃按鍵」的狀態下結束：佇列殘留是那支程式的按鍵。
		// 舊行為會把它們逐段當成指令記下（vim 情境實測 4 筆）。
		if p.replayQueue.Len() > 0 {
			p.noteTaintedDrop()
			p.emitDegradedPerRound(p.replayQueue.Bytes(), model.DegradeQueueDiscardedAtClose)
			p.replayQueue.Reset()
		}
		return
	}
	for p.replayQueue.Len() > 0 {
		seg := p.takeReplaySegment()
		if len(seg) == 0 {
			return
		}
		if bytes.IndexByte(seg, '\r') < 0 {
			return
		}
		anchor := p.replayAnchorText(seg)
		// 錨為空（歷史鍵等）：可見文字只在 echo 裡，而 echo 從未到達。
		// 這是 echo 重建原理的邊界，不是本次可補的漏。
		if anchor == "" {
			continue
		}
		p.noteReplayFallback()
		if p.sqlMode {
			p.accumulateSQL(anchor)
			continue
		}
		p.emit(anchor)
	}
}

// resetReplayRound 清除當前重放輪的狀態（錨與兩個掃描計數）。
func (p *CommandParser) resetReplayRound() {
	p.replayRound = false
	p.replayAnchor = ""
	p.replayScanned = 0
	p.replayScanLine = 0
}

// emitDegraded 發出一筆降級紀錄。**command 恆為空字串**：
// 「無法還原即記為無法還原」，不得以任何形式猜測其內容。
func (p *CommandParser) emitDegraded(reason string) {
	if p.onRecord == nil {
		return
	}
	p.onRecord("", true, reason, time.Now())
}

// emitDegradedPerRound 佇列丟棄類降級：以佇列中的 Enter 數發出**等量**降級列。
//
// `bytes.Count` 是**計數不是猜測**——那些 `\r` 是使用者確實送出的位元組，
// 一個 Enter 就是一輪。尾端沒有 Enter 的殘段不計：那些字從未送出
// （與 flushReplayQueue、abortTyping 同一條紀律）。
//
// **唯一例外**：本連線的佇列曾達上限時，溢出後抵達的輸入根本沒進佇列，
// 這個計數只是**下界**，故改用 DegradeQueueUncounted——
// spec 與 UI SHALL NOT 宣稱該區段的輪數正確。
func (p *CommandParser) emitDegradedPerRound(queue []byte, reason string) {
	rounds := bytes.Count(queue, []byte{'\r'})
	if rounds == 0 {
		return
	}
	if p.replayOverflowed {
		reason = model.DegradeQueueUncounted
	}
	for i := 0; i < rounds; i++ {
		p.emitDegraded(reason)
	}
}

// noteReplayOverflow 佇列滿載的可觀測訊號：旗標供測試斷言，日誌供運維，
// 降級紀錄供稽核。與既有降級日誌同紀律——不含任何指令位元組，每連線最多一行。
//
// 降級紀錄**一次溢出一筆**（佇列清空後再溢出即再記一筆），不是每個被丟棄的
// 位元組一筆：溢出的整段語義是「自此刻起輸入不再排隊，其後的輪數不可知」，
// 那是一個事實不是 N 個。
func (p *CommandParser) noteReplayOverflow() {
	p.replayOverflowed = true
	if !p.overflowRecorded {
		p.overflowRecorded = true
		p.emitDegraded(model.DegradeQueueOverflow)
	}
	if p.overflowLogged {
		return
	}
	p.overflowLogged = true
	log.Printf("[SSHProxy] 指令審計降級：重放佇列達上限 %d bytes，其後抵達的輸入不再排隊（本連線僅記錄一次）", replayQueueMax)
}

// noteAltScreenRound 「當輪落在 alternate screen 標記區間內」的可觀測訊號。
func (p *CommandParser) noteAltScreenRound() {
	p.altScreenRound = true
	p.emitDegraded(model.DegradeAltScreen)
	if p.altScreenLog {
		return
	}
	p.altScreenLog = true
	log.Print("[SSHProxy] 指令審計降級：對端處於 alternate screen 標記區間，該輪不以指令結算（本連線僅記錄一次）")
}

// noteEmptyRound 結算文字為空的兩種情形，**只有其中一種是降級**。
//
//   - 只按 Enter（roundHasInput 為假）：正常的空輸入，遠端只會多印一個提示符。
//     記它等於為每個空 Enter 製造一筆噪音。
//   - 打了字卻重組不出任何文字：**對端關掉了回顯**（`stty -echo`、密碼提示），
//     或虛擬螢幕觸及記憶體上限而丟棄了內容。兩者的共同事實是「這一輪沒有可還原的文字」。
//     第一種**連錄影都救不回**——asciicast 只有輸出方向的 "o" 事件，
//     回顯關掉就沒有輸出，回放看到的是一片空白。舊行為在此靜默 return，
//     於是「關掉回顯後提權」這條路徑在審計與回放兩側同時無跡可循。
//
// **不寫日誌是刻意的**：本終態已有一筆可搜尋、可告警的資料列，那比一行
// 每連線僅一次的日誌強；且多寫這一行會使既有守衛
// TestCommandParserDropLogsOnceWithoutCommandBytes（釘的是該情境的日誌總行數）
// 轉紅——那條守衛的射程不該被本 change 順手改掉。
func (p *CommandParser) noteEmptyRound() {
	if !p.roundHasInput {
		return
	}
	p.noEcho = true
	p.emitDegraded(model.DegradeNoEcho)
}

// noteUnanchored 「認不出這是不是指令行」的可觀測訊號。
// 這是原型 D 把捏造換成漏記的那個交換點，必須留下告警面（design §4.5）。
//
// **降級紀錄在此發出**（tasks 2.3 列的第一個終態）：不發指令文字是對的，
// 但該輪確實存在——使用者按了 Enter、遠端執行了某件事。只設旗標而不發紀錄
// 等於「該輪在審計上沒發生過」，正是 spec「SHALL NOT 為零紀錄」禁止的形態，
// 且旗標是連線內一次性的，第二輪之後連旗標都不再變化。
// 由 TestUnanchoredRoundProducesDegradedRecord 釘住。
func (p *CommandParser) noteUnanchored() {
	p.unanchored = true
	p.emitDegraded(model.DegradeRedrawUnanchored)
	if p.unanchorLogged {
		return
	}
	p.unanchorLogged = true
	log.Print("[SSHProxy] 指令審計降級：結算行無法錨定到提示符（螢幕曾被全螢幕重繪），該輪不入庫（本連線僅記錄一次）")
}

// noteTaintedDrop 「當輪回顯是全螢幕重繪，故不以輸入位元組結算」的可觀測訊號。
func (p *CommandParser) noteTaintedDrop() {
	p.taintedDropped = true
	if p.taintedLogged {
		return
	}
	p.taintedLogged = true
	log.Print("[SSHProxy] 指令審計降級：當輪回顯為全螢幕重繪，該輪的輸入不以指令結算（本連線僅記錄一次）")
}

// noteReplayFallback 錨定失敗的可觀測訊號，並把下一筆入庫文字標為**受限定**。
//
// **不共用 degraded 旗標**（design §6.6）：這一類是「已入庫但文字可能≠實際執行」，
// 與「無文字」不同型。塞進同一個旗標會讓「degraded=false ⇒ 文字可信」也變成假話，
// 而那正是稽核員唯一能倚賴的推論。
func (p *CommandParser) noteReplayFallback() {
	p.pendingCaveat = model.QualifyReplayFallback
	p.replayFellBack = true
	if p.fallbackLogged {
		return
	}
	p.fallbackLogged = true
	log.Print("[SSHProxy] 指令審計降級：重放輪未能在輸出中定位自身回顯，改以使用者送出的輸入位元組結算（本連線僅記錄一次）")
}

// discardFullScreenQueue 在「當輪確為全螢幕重繪且錨全部落空」被證實的那一刻，
// 把仍排在佇列中的輸入一併丟棄並讓狀態機回到閒置。
//
// **判斷與 scanAltScreen 進入 alternate screen 時清空佇列（見該函式）完全同一條**，
// 只是證據來源不同：那裡靠對端印出的標記，這裡靠螢幕上實際發生的重繪。
// 佇列裡的位元組是在同一個全螢幕情境中送出的，重放它們是捏造。
//
// **不清空的後果是漏記，且漏的是真指令**（charter backlog #13，實測）：
// 那些位元組會留在佇列裡，由下一個重放輪帶著一個**永遠不會出現的錨**
// 去掃輸出流。錨定不到就一路掃到 replayScanMax／replayScanLines 為止——
// 實測 session-222 到會話結束都沒掃滿（121 bytes／4 行，上界是 32KB／256 行），
// 於是 pending 永遠不解除，使用者離開 vim 之後才送出的 `echo done-VIMNOALT`
// 與 `exit` 全部排進同一個佇列，最後被 flushReplayQueue 整批丟掉。
// 回到閒置則相反：離開全螢幕程式後的下一次按鍵開的是乾淨的一輪，正常入庫。
func (p *CommandParser) discardFullScreenQueue() {
	if p.replayQueue.Len() == 0 {
		return
	}
	p.noteTaintedDrop()
	p.emitDegradedPerRound(p.replayQueue.Bytes(), model.DegradeQueueDiscarded)
	p.resetReplayRound()
	p.replayQueue.Reset()
}

// discardSQLStatement 丟棄 sqlMode 下累積中的多行 SQL 半條語句。
//
// 多行 SQL 靠 accumulateSQL 跨續行收集到 stmtBuf，遇結束符才 emit。當某一輪因
// 全螢幕重繪／alternate-screen 標記而降級（不以指令結算）時，那一輪正是這條語句的
// 組成輪之一，整條語句因而無法可信重組。**半條語句必須在此丟棄**：不丟則它留在
// stmtBuf 裡，被後續乾淨輪的 accumulateSQL 接上去，焊成一條使用者從未送出的語句
// 且 degraded=false——跨語句焊接的假語句，比漏記更嚴重（charter backlog #23，
// postgres／mysql 實測；mssql 共用 sqlMode 同一路徑）。SSH 等逐行協議無此路徑：
// 每輪各自 emit，不跨輪累積。
//
// **丟棄不是漏記**：留在 stmtBuf 的是續行提示符下**尚未終止、尚未作為一條指令
// 執行**的前綴（DB CLI 在語句未見結束符時顯示續行提示符，該半條從未獨立執行）；
// 而呼叫端已在該輪發出降級紀錄，位置上已有可搜尋、可歸因的訊號——整條語句因此
// 呈現為「一筆降級」而非「一條假語句」，也非靜默少一列。
//
// 呼叫點與 discardFullScreenQueue 一致：finalize 與重放輪的每一條降級／丟棄終端。
// stmtBuf 為空或非 sqlMode 時為 no-op，故乾淨的累積路徑不受影響。
func (p *CommandParser) discardSQLStatement() {
	if !p.sqlMode || p.stmtBuf.Len() == 0 {
		return
	}
	p.stmtBuf.Reset()
	p.stmtLen = 0
}

// roundSpannedRows 回報「當輪的重組螢幕，內容落在第 0 列以外的列上」。
//
// 判準的依據與 vtscreen.Redrawn 同型，是**能力邊界**而非統計特徵，
// 但問的是另一個問題——不是「這段位元組是不是一次行編輯」，
// 而是「螢幕上那個最後的非空白行，我們有沒有證據說它就是使用者在編輯的那一行」。
//
// 一輪的螢幕以 beginTyping 快照的原點種入，游標恆在第 0 列；**行編輯只編輯一列**，
// 故乾淨的一輪其內容不會離開第 0 列，「最後一個非空白行」與「使用者在編輯的那一行」
// 必然是同一行。這正是 anchorNone 仍可發出的唯一理由
// （TestCommandParserOriginPrefixIsVerifiedNotAssumed 釘的 `\r` 覆蓋提示符形態）。
//
// 一旦內容跨到第 1 列以後，該恆等式斷裂：最後那一行可能是對端印下去的任何東西，
// 而錨全部落空代表我們手上**沒有任何證據**把它綁回使用者的輸入。此時發出去即是捏造。
// 合法的跨列重繪不落在這裡——多候選補全會把提示符重印出來（anchorPrompt 命中），
// 那正是 Scenario「重繪自帶 prompt 的情形不受原點種入影響」所要求的行為。
//
// 這條補的是 Redrawn 的偽陰性面（charter backlog #18）：GNU `less -X`
// 與經由它的 `man` 只用 `\r` ＋ `ESC[K` 逐行重畫，一次絕對定位都不送，
// Redrawn 抓不到；但它們逐行重畫必然跨列，故落在本條。
// **不以「重畫幾行」為判準**——那是統計特徵；本條問的是列的恆等式是否成立，
// 一列與多列的差別是二分的。
func roundSpannedRows(screen screenRender) bool {
	return len(screen.lines) > 1
}

// finalize 解析 echo 緩衝、剝除前綴、發出指令。
//
// 螢幕以 beginTyping 快照的原點種入後才寫入 echo：種入的即是真實終端在輸入起始
// 那一刻的螢幕狀態，欄位算術因而與 shell 一致（design.md D4.2）。
func (p *CommandParser) finalize() {
	p.pending = false
	p.pendingLen = 0

	screen := p.renderRound(p.typingBuf.Bytes())
	p.typingBuf.Reset()

	spanned := roundSpannedRows(screen)
	stripped, kind := p.stripCommandPrefixes(lastNonEmptyRawLine(screen.lines), spanned)
	if p.roundAltScreen {
		// 對端仍在 alternate screen 標記區間內：這一輪的回顯是全螢幕程式畫的，
		// **任何錨都可能只是巧合對上**（實測：vim 內按 Enter 那一輪的原點錨命中，
		// 結算值是使用者打進檔案的內文 `hello`）。故此處不看錨、一律不發指令文字。
		//
		// 佇列一併結清（discardFullScreenQueue）：與舊行為在標記命中時
		// `replayQueue.Reset()` 是同一條判斷，差別在**丟棄不再是靜默的**
		// ——每個已送出的 Enter 各留一筆降級紀錄。不結清則那些位元組會被開成
		// 重放輪，帶著一個永遠不會出現的錨吃光剩餘輸出流，使用者離開全螢幕程式後
		// 送出的真指令全部漏記（charter backlog #13 的形狀，實測復現於
		// vi-altscreen 語料：`exit` 消失）。
		p.noteAltScreenRound()
		p.discardFullScreenQueue()
		p.discardSQLStatement()
		return
	}
	if kind == anchorNone && (p.roundTainted || spanned) {
		// 錨全部落空 **且**（當輪回顯是全螢幕重繪 **或** 當輪跨了列）⇒ 不發。
		// **這是原型 D 的整個重點**：此時發出去的會是螢幕殘留
		// （實測形態：`<提示符> <指令>` 整行、vim 的檔案訊息列、插入模式打進檔案的內文），
		// 即捏造。降級為可告警的漏記（design §4.5 的誠實天花板）。
		//
		// 為什麼不是「認不出就一律不發」：當輪只有一列時，最後一個非空白行**就是**
		// 使用者當時在編輯的那一行——伺服器以 `\r` 蓋掉提示符（進度條形態）即屬此類，
		// 既有測試 TestCommandParserOriginPrefixIsVerifiedNotAssumed 釘的正是它；
		// 解析降級（render panic → stripControlLines）同樣落在這一格，
		// TestCommandParserDegradeLogsOnceWithoutCommandBytes 釘的是它。
		// 一律不發會把這兩條規則一起殺掉，而它們與本缺陷無關（實測：拿掉條件打紅 6 支測試）。
		p.noteUnanchored()
		p.discardFullScreenQueue()
		p.discardSQLStatement()
		return
	}
	command := strings.TrimSpace(stripped)
	if command == "" {
		p.noteEmptyRound()
		return
	}
	p.learnPrompt(kind)

	if !p.sqlMode {
		p.emit(command)
		return
	}
	p.accumulateSQL(command)
}

// renderRound 還原「當輪回顯緩衝」的螢幕，並在其中出現整螢幕層級重繪時標記當輪。
//
// 為什麼判定放在 render 而不是 WriteOutput 的逐幀掃描：緩衝在此**整段**餵進解析器，
// 被 4096 邊界切成兩幀的 `\x1b[?1049h`／`\x1b[30;0H` 在這裡自然接回去。
// 逐幀 bytes.Contains 正是既有缺陷 #9 的形狀，不可在修法裡重蹈。
func (p *CommandParser) renderRound(data []byte) screenRender {
	screen := p.renderScreen(p.originText, p.originX, data)
	if screen.redrawn {
		p.roundTainted = true
	}
	return screen
}

// anchorKind 指認一條候選指令行**憑什麼**被認定為指令行。
//
// 這是原型 D 的核心：舊實作在四段剝除全部落空時 `return line` 原樣發出，
// 等於把「我認不出這是什麼」處理成「那就當成指令」。實測那正是捏造的來源
// （busybox less 之後入庫的 `ssh-test-server:~$ echo done-BBLESS` 即出自該路徑）。
type anchorKind uint8

const (
	// anchorNone 沒有任何錨命中，且並非「無錨可比」：不得發出。
	anchorNone anchorKind = iota
	anchorSqlcmd
	anchorOrigin
	anchorPrompt
	anchorLearned
	// anchorBare 原點、當輪提示符、已學提示符三者皆空——確實無前綴可剝，
	// 回顯本身即是整行（會話首條指令、以及不印提示符的對端）。
	anchorBare
)

// stripCommandPrefixes 依 design.md D4.3 的順序剝除指令行的前綴，
// 並回傳**憑什麼**認定它是指令行。raw 為螢幕最後一個非空白行的**原文**（未 trim）。
//
// 順序寫死，不可顛倒：sqlcmd 的提示符逐行遞增（1>／2>／…／55>），
// 快照到的可能是半截（`55`）；若先做原點切除，半截快照會把 `55` 切掉
// 而留下孤立的 `>`，那是另一種污染形態。先做 sqlcmd 剝除則直接得到乾淨語句。
func (p *CommandParser) stripCommandPrefixes(raw string, spanned bool) (string, anchorKind) {
	line := strings.TrimSpace(raw)

	// 1. sqlcmd 洩漏剝除（僅 mssql；誤剝閘門在 stripLeakedSqlcmdPrompt 內）：命中即結束
	if p.tsqlMode {
		if stripped := stripLeakedSqlcmdPrompt(line, p.promptText); stripped != line {
			return stripped, anchorSqlcmd
		}
	}
	// 2. 原點切除：種入的原點是輸入起始那一刻的螢幕內容，切掉它剩下的才是使用者打的字。
	//    比對用未 trim 的原文——提示符尾端那一格空白是內容的一部分，trim 掉就差一欄。
	if p.originText != "" && strings.HasPrefix(raw, p.originText) {
		return raw[len(p.originText):], anchorOrigin
	}
	// 3. 既有 promptText 前綴剝除（行為不變）：歷史鍵／補全的整行重繪會重印提示符
	if p.promptText != "" && strings.HasPrefix(line, p.promptText) {
		return line[len(p.promptText):], anchorPrompt
	}
	// 4. 已學提示符：當輪的原點與提示符都被全螢幕重繪汙染時的最後一個**有據**的錨。
	//    它不是猜測——那個字串在本連線內曾經真的把一條指令錨定成功過。
	//
	//    **只在 roundTainted 或當輪跨列時啟用**：它是重繪的救援手段，不是常態剝除規則。
	//    無條件啟用會改動乾淨輪次的既有結果（實測 psql-meta：`\q` 被 pager 吃掉、
	//    螢幕只剩重印的提示符，舊行為結算為 `custodexa=#`；一律套已學提示符會把它
	//    剝成空字串而少一筆紀錄。那一筆是既有的已知缺口，不該由本修法順手改形態）。
	//
	//    加上 spanned 這個觸發條件是 backlog #18 的另一半：`less -X` 這類只用
	//    `\r` ＋ `ESC[K` 逐行重畫的 pager，Redrawn 抓不到（roundTainted 為假），
	//    但它照樣把原點與提示符換成自己的狀態列。沒有這一條，該輪只能降級為漏記
	//    ——實測 session-266 少記一條真指令 `echo done-…`
	//    （TestCommandParserRelativeRedrawPagerDoesNotFabricate 的 (b) 段釘的正是它）。
	if (p.roundTainted || spanned) && p.learnedPrompt != "" && strings.HasPrefix(line, p.learnedPrompt) {
		return line[len(p.learnedPrompt):], anchorLearned
	}
	// 5. 原點與當輪提示符皆空：確實無前綴可剝，回顯即整行。
	if p.originText == "" && p.promptText == "" {
		return line, anchorBare
	}
	// 6. 有錨但一個都對不上 ⇒ 這一行不是我們追的那條指令行。
	//    舊實作在此 `return line`，把螢幕殘留當成指令發出去；原型 D 在此止住。
	return line, anchorNone
}

// learnPrompt 記住這一輪成功用來錨定的提示符，供其後被重繪汙染的輪次使用。
func (p *CommandParser) learnPrompt(kind anchorKind) {
	switch kind {
	case anchorOrigin:
		if t := strings.TrimSpace(p.originText); t != "" {
			p.learnedPrompt = t
		}
	case anchorPrompt:
		if p.promptText != "" {
			p.learnedPrompt = p.promptText
		}
	}
}

// emit 發出一條結算後的指令。
//
// pendingCaveat 非空代表這條文字的可信度已被限定（目前唯一來源是
// noteReplayFallback）：改走 onRecord 以 degraded=false ＋ 限定碼入庫。
// onRecord 未掛載時退回 onCommand——文字本來就會入庫，
// 落地形式不該因為觀測管道缺席而改變。
func (p *CommandParser) emit(command string) {
	caveat := p.pendingCaveat
	p.pendingCaveat = ""
	if caveat != "" && p.onRecord != nil {
		p.onRecord(command, false, caveat, time.Now())
		return
	}
	if p.onCommand != nil {
		p.onCommand(command, time.Now())
	}
}

// accumulateSQL DB CLI 多行語句累積：跨續行收集，遇語句結束符才結算為單一指令。
// 過度合併（如把元命令併入下一語句）不致產生安全漏洞——危險關鍵字仍在合併字串內、
// 告警照樣命中；真正的漏洞是「欠合併」（拆行讓關鍵字分散），此處正是消除它。
func (p *CommandParser) accumulateSQL(line string) {
	if p.stmtBuf.Len() > 0 {
		p.stmtBuf.WriteByte('\n')
	}
	p.stmtBuf.WriteString(line)
	p.stmtLen += len(line) + 1

	// typingBufMax 作為失控保險：語句異常長（未見結束符）即強制結算
	if sqlStatementComplete(line) || (p.tsqlMode && tsqlBatchTerminator(line)) || p.stmtLen > typingBufMax {
		p.emit(p.stmtBuf.String())
		p.stmtBuf.Reset()
		p.stmtLen = 0
	}
}

// sqlStatementComplete 啟發式判斷一行是否結束一條 SQL 語句：
//   - 尾端 ;（標準終止符）
//   - 尾端 \g / \G（mysql go / 縱向顯示終止）
//   - 開頭 \（psql/mysql backslash 元命令，單行即完成，不應併入下一語句）
//
// 邊界（如尾端 ; 落在未閉合字串內）採簡單啟發、不做完整 SQL 詞法分析（YAGNI）：
// 此類過度結算僅影響審計呈現，不開安全缺口。
func sqlStatementComplete(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	if strings.HasPrefix(t, `\`) {
		return true
	}
	return strings.HasSuffix(t, ";") || strings.HasSuffix(t, `\g`) || strings.HasSuffix(t, `\G`)
}

// tsqlBatchTerminator 判斷一行是否為 T-SQL 的批次終止符（mssql 專用，D4）。
//
// T-SQL 的執行單位是批次，以**獨立一行的 GO** 送出（sqlcmd 的 batchTerminatorRegex）；
// `;` 只是語句分隔符、不觸發執行。不認 GO 的話，審計看到的切分與實際執行的批次
// 永久錯位，且 SQL 危險規則比對的是錯的對象。
//
// 規則：整行 trim 後不分大小寫等於 GO，或 GO 後接一個正整數（重複執行次數）。
// **必須是整行**——`SELECT 'GO'` 這類行內出現的 GO 不得誤判為終止。
func tsqlBatchTerminator(line string) bool {
	t := strings.TrimSpace(line)
	if len(t) < 2 || !strings.EqualFold(t[:2], "GO") {
		return false
	}
	rest := strings.TrimSpace(t[2:])
	if rest == "" {
		return true
	}
	// GO <正整數>：全為數字且至少一位非零
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return strings.Trim(rest, "0") != ""
}

// stripLeakedSqlcmdPrompt 剝除 mssql 指令行開頭殘留的 sqlcmd 提示符（僅 tsqlMode 呼叫）。
//
// 為什麼只有 mssql 需要：sqlcmd 的提示符**逐行遞增**（1>／2>／…／55>），而 ssh／mysql／postgres
// 的提示符是靜態的。beginTyping 只在輸入起始時快照單一 promptText，且實測 sqlcmd 送出
// 「Enter 回顯的換行」與「下一行提示符」是**兩次獨立的 write**；使用者按上鍵（其重繪會重印提示符，
// 實測序列 \x1b[1G55> SELECT name\x1b[0K\x1b[16G）若落在這兩次 write 之間，快照就會取到空字串或
// 半截提示符，重繪帶進的提示符因而留在審計文字裡（產品資料庫實查命中：`SELECT name\n55> SELECT name\n…`）。
// 靜態提示符的協議取到的是上一行的同一字串，剝除照常成功，故對此競態天然免疫。
//
// 誤剝防線：snapshot 本身即為提示符形態時，代表提示符正常抵達、既有單次剝除已足夠，
// 此處整個不啟動——使用者自行輸入、以 `<數字>> ` 起頭的內容因而不會被剝。
// 只剝一次不迴圈：實測殘留一律是單一數字段（55>／555>／66> 皆為一段連續數字，
// 數字長度隨虛擬螢幕對 \x1b[1G 的重疊而異），迴圈只會擴大誤剝面。
func stripLeakedSqlcmdPrompt(command, promptSnapshot string) string {
	if isSqlcmdPrompt(promptSnapshot) {
		return command
	}
	rest, ok := trimSqlcmdPromptPrefix(command)
	// 剝完是空的代表整行就只有那個「提示符」：寧可原樣入庫也不吞掉一筆審計記錄
	if !ok || strings.TrimSpace(rest) == "" {
		return command
	}
	return rest
}

// isSqlcmdPrompt 判斷字串是否整體即為一個 sqlcmd 提示符（trim 後形如 `<數字>>`）
func isSqlcmdPrompt(s string) bool {
	rest, ok := trimSqlcmdPromptPrefix(s)
	return ok && strings.TrimSpace(rest) == ""
}

// trimSqlcmdPromptPrefix 剝除開頭單一 `<數字>>` 前綴與其後至多一個空白，
// 回傳剩餘字串與是否命中。行首以外位置的 `<數字>>` 不在射程內。
func trimSqlcmdPromptPrefix(s string) (string, bool) {
	t := strings.TrimLeft(s, " \t")
	digits := 0
	for digits < len(t) && t[digits] >= '0' && t[digits] <= '9' {
		digits++
	}
	if digits == 0 || digits >= len(t) || t[digits] != '>' {
		return s, false
	}
	rest := t[digits+1:]
	if len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
		rest = rest[1:]
	}
	return rest, true
}

// scanAltScreen 偵測 alternate screen 進出標記，維護 altScreenMarked 這個**汙染源旗標**。
//
// **標記由抑制器降格為汙染源（design §6.1）。** 舊行為是命中進入標記即整段早退
// （輸入與輸出都不進狀態機、佇列清空），後果是那些輪次**在狀態機裡根本不存在**：
//   - vim 內按 Enter 的每一輪零紀錄——ADDED Scenario「vim 中編輯並多次按 Enter →
//     存在可歸因的降級紀錄」無從產生；
//   - 輸出流中出現同一串位元組即令其後整段會話靜音，而那些位元組由**被稽核主機**
//     送出——全螢幕程式送的與其他來源送的無從分辨，故該標記不可作為唯一依據。
//
// 現行行為：標記只把當輪之後的每一輪標成「這段回顯不是 shell 的指令回顯」，
// 輸入輸出照常流經狀態機，故每一輪仍各自結算——只是結算結果是降級紀錄而非指令文字。
//
// **不清空佇列、不中止當輪**（舊行為兩者都做）：清空佇列會讓那些輪次連降級紀錄
// 都沒有，正是本 change 要消滅的零紀錄；當輪則交給 finalize 依當時的證據判斷
// （進入標記與當輪結算落在同一幀時，該輪的緩衝裡本來就有重繪，Redrawn／spanned
// 接得住），標記本身不追溯汙染已經開始的那一輪——那會把 `vim notes.txt`
// 這種**真指令**換成降級紀錄。
func (p *CommandParser) scanAltScreen(data []byte) {
	if !p.altScreenMarked {
		for _, mark := range altScreenEnterMarks {
			if bytes.Contains(data, mark) {
				p.altScreenMarked = true
				return
			}
		}
		return
	}

	for _, mark := range altScreenExitMarks {
		if bytes.Contains(data, mark) {
			p.altScreenMarked = false
			p.settleAltScreenRound()
			return
		}
	}
}

// settleAltScreenRound 離開標記區間的那一刻，結清仍在飛行中的那一輪。
//
// **這是硬邊界**：全螢幕程式剛剛終止，還在等回顯的那一輪等的是那支程式的畫面，
// 而它再也不會印出可辨識的結算點。舊行為在進入標記時就把整輪殺掉，
// 故這條邊界本來就存在；差別在於現在**丟棄不是靜默的**。
//
// **不結清的後果是漏記真指令**（vi-altscreen 語料實測）：`:q!` 那一輪的 `\n`
// 永遠不來，於是使用者離開 vi 後送出的 `echo after-vi` 排進同一個佇列，
// 隨下一次結算被整批丟棄——真指令換成一筆降級列，比修法前更糟。
//
// 已送出的一輪（pending）記一筆降級；只打了字還沒按 Enter 的（typing）不記——
// 那些字從未送出，記它就是捏造（與 abortTyping 同一條紀律）。
func (p *CommandParser) settleAltScreenRound() {
	if p.pending {
		p.noteAltScreenRound()
	}
	if p.pending || p.typing {
		p.discardFullScreenQueue()
	}
	p.typing = false
	p.pending = false
	p.pendingLen = 0
	p.typingBuf.Reset()
	p.roundTainted = false
	p.roundAltScreen = false
	p.roundHasInput = false
	p.resetReplayRound()
}

// appendCapped 受上限保護的追加：滿載即丟棄後續（degrade 不阻斷）
func (p *CommandParser) appendCapped(buf *bytes.Buffer, data []byte, max int) {
	remain := max - buf.Len()
	if remain <= 0 {
		return
	}
	if len(data) > remain {
		data = data[:remain]
	}
	buf.Write(data)
}

// appendTail 追加並只保留尾端 tailBufMax bytes（prompt 必在輸出尾端）
func (p *CommandParser) appendTail(data []byte) {
	p.tailBuf.Write(data)
	if p.tailBuf.Len() > tailBufMax {
		tail := p.tailBuf.Bytes()[p.tailBuf.Len()-tailBufMax:]
		trimmed := make([]byte, tailBufMax)
		copy(trimmed, tail)
		p.tailBuf.Reset()
		p.tailBuf.Write(trimmed)
	}
}

// screenRender 為一次螢幕還原的結果。
type screenRender struct {
	lines       []string
	currentLine string // 游標所在列的原文（未 trim）
	cursorX     int    // 游標顯示欄（0-based）
	dropped     bool   // 曾因虛擬螢幕記憶體上限丟棄內容
	redrawn     bool   // 曾出現整螢幕層級的定位／清除（見 vtscreen.Redrawn）
}

type screenRenderFunc func(seedLine string, seedX int, data []byte) screenRender

// renderWithVTScreen 產品路徑的螢幕還原：種入原點後餵入原始輸出。
func renderWithVTScreen(seedLine string, seedX int, data []byte) screenRender {
	s := vtscreen.New()
	if seedLine != "" || seedX != 0 {
		s.Seed(seedLine, seedX)
	}
	s.Write(data)
	return screenRender{
		lines:       s.Lines(),
		currentLine: s.CurrentLine(),
		cursorX:     s.CursorX(),
		dropped:     s.Dropped(),
		redrawn:     s.Redrawn(),
	}
}

// renderScreen 將原始終端輸出餵進虛擬螢幕，還原為可見文字行。
//
// recover 降級保留（design.md D7.2）：它防的是「審計旁路 panic 打死整個連線行程」
// 這條紅線，與解析器品質無關，也是對「我們自己寫錯」的最後防線。
// 降級內容改為「剝除所有控制序列與 C0 後的純文字行」——寧可少字，
// 不可讓原始 ESC 位元組進審計（D7.3）。
func (p *CommandParser) renderScreen(seedLine string, seedX int, data []byte) (res screenRender) {
	if len(data) == 0 && seedLine == "" {
		return screenRender{}
	}

	defer func() {
		if r := recover(); r != nil {
			res = screenRender{lines: stripControlLines(data)}
			p.logDegrade(len(data))
		}
	}()

	render := p.render
	if render == nil {
		render = renderWithVTScreen
	}
	res = render(seedLine, seedX, data)
	if res.dropped {
		p.logDrop(len(data))
	}
	return res
}

// logDegrade 記錄解析降級（design.md D7.4）。每個 CommandParser 實例最多一行。
//
// 內容只有原因與輸入長度：指令文字可能含使用者在終端打錯位置的密碼，
// 一個位元組都不得進日誌。panic 值同樣不記——它可能夾帶輸入內容。
func (p *CommandParser) logDegrade(n int) {
	if p.degradeLogged {
		return
	}
	p.degradeLogged = true
	log.Printf("[SSHProxy] 指令解析降級：虛擬螢幕解析 panic，改以純文字剝除，輸入 %d bytes（本連線僅記錄一次）", n)
}

// logDrop 記錄虛擬螢幕觸及記憶體上限而丟棄內容（design.md D14 第 11 條）。
// 同樣每個實例最多一行、且不含任何指令位元組。
func (p *CommandParser) logDrop(n int) {
	if p.dropLogged {
		return
	}
	p.dropLogged = true
	log.Printf("[SSHProxy] 指令解析降級：虛擬螢幕觸及記憶體上限並丟棄內容，還原文字不完整，輸入 %d bytes（本連線僅記錄一次）", n)
}

// stripControlLines 降級路徑：把原始輸出剝成純文字行（design.md D7.3）。
//
// 虛擬螢幕已經出事，此處刻意只做最簡單的線性掃描、不再呼叫解析器。
// 控制序列與 C0 一律丟棄，只有換行切行——降級時寧可少字，
// 不可讓原始 ESC 位元組流進審計文字。
func stripControlLines(data []byte) []string {
	var (
		lines []string
		cur   []byte
	)
	for i := 0; i < len(data); {
		b := data[i]
		switch {
		case b == 0x1B:
			i += escapeLen(data[i:]) // 至少前進 1，不會空轉
			continue
		case b == '\n':
			lines = append(lines, string(cur))
			cur = cur[:0]
		case b < 0x20 || b == 0x7F:
			// 其餘 C0 與 DEL：丟棄
		default:
			cur = append(cur, b)
		}
		i++
	}
	if len(cur) > 0 {
		lines = append(lines, string(cur))
	}
	return lines
}

// escapeLen 回傳自 ESC 起算、應整段丟棄的位元組數；恆 >=1 以保證掃描前進。
func escapeLen(data []byte) int {
	if len(data) < 2 {
		return len(data)
	}
	switch data[1] {
	case '[': // CSI：參數與中間位元組之後，以 0x40-0x7E 結束
		for i := 2; i < len(data); i++ {
			if data[i] >= 0x40 && data[i] <= 0x7E {
				return i + 1
			}
		}
		return len(data)
	case ']', 'P', 'X', '^', '_': // OSC／DCS／SOS／PM／APC：以 BEL 或 ESC \ 結束
		for i := 2; i < len(data); i++ {
			if data[i] == 0x07 {
				return i + 1
			}
			if data[i] == 0x1B && i+1 < len(data) && data[i+1] == '\\' {
				return i + 2
			}
		}
		return len(data)
	default: // 其餘 ESC 序列：中間位元組（0x20-0x2F）之後接一個 final byte
		if data[1] < 0x20 {
			return 1 // ESC 後緊接 C0：只丟掉 ESC，C0 交回主迴圈
		}
		for i := 1; i < len(data); i++ {
			if data[i] < 0x20 || data[i] > 0x2F {
				return i + 1
			}
		}
		return len(data)
	}
}

// lastNonEmptyRawLine 取最後一個非空白行的**原文**（未 trim）。
// 原點切除比對的是原文：提示符尾端那一格空白是內容的一部分。
func lastNonEmptyRawLine(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return ""
}

// lastNonEmptyLine 取最後一個非空白行（trim 後）
func lastNonEmptyLine(lines []string) string {
	return strings.TrimSpace(lastNonEmptyRawLine(lines))
}
