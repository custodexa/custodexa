<template>
  <div class="ssh-terminal">
    <div
      v-if="status !== 'connected'"
      class="status-overlay"
    >
      <template v-if="status === 'waiting' || status === 'connecting'">
        <el-icon
          class="is-loading"
          :size="32"
        >
          <Loading />
        </el-icon>
        <p>{{ status === 'waiting' ? $t('sshTerminal.preparing') : $t('sshTerminal.connecting') }}</p>
      </template>
      <template v-else>
        <el-result
          :icon="status === 'error' ? 'error' : 'info'"
          :title="status === 'error' ? $t('sshTerminal.errorTitle') : $t('sshTerminal.disconnectedTitle')"
          :sub-title="statusDetail"
        >
          <template #extra>
            <!-- host key 變更引導（ssh-connect-error-surfacing）：admin 直達資產
                 編輯框重置入口，非 admin 提示聯繫管理員 -->
            <p
              v-if="isHostKeyError && !isAdmin"
              class="host-key-hint"
            >
              {{ $t('sshTerminal.hostKeyContactAdmin') }}
            </p>
            <el-button
              v-if="isHostKeyError && isAdmin"
              type="warning"
              @click="openAssetHostKey"
            >
              {{ $t('sshTerminal.hostKeyGoReset') }}
            </el-button>
            <el-button
              type="primary"
              @click="reconnect"
            >
              {{ $t('sshTerminal.reconnect') }}
            </el-button>
            <el-button @click="openSystem">
              {{ $t('sshTerminal.backToSystem') }}
            </el-button>
          </template>
        </el-result>
      </template>
    </div>

    <!-- 外層留白、內層為無 padding 的掛載點：FitAddon 量 parent 的
         clientHeight 含 padding，直接掛在有 padding 的容器會高估行數，
         導致最底行被裁半（使用者實測於 seq 1 100 後輸入行只見一半） -->
    <!-- 行動快捷鍵列（mobile-terminal-keys）：觸控鍵盤沒有 ESC／Tab／Ctrl，補上最常用的控制序列 -->
    <div
      v-if="showMobileKeys"
      class="mobile-key-row"
    >
      <button
        v-for="key in MOBILE_KEYS"
        :key="key.label"
        class="mobile-key"
        @click="sendKey(key.seq)"
      >
        {{ key.label }}
      </button>
    </div>

    <!-- mssql 批次終止符提示（mssql-cli-audit-fidelity D6）：同一個 web CLI 上
         mysql/postgres 以 `;` 執行、mssql 需要獨立一行的 GO，差異無說明時首次使用者
         會把「打了分號沒反應」誤判為連線失敗。提示由前端呈現，**不寫入終端輸出流**
         （寫進去會混進 asciicast 錄影與會話輸出基準）。關閉後本次會話不再出現。 -->
    <el-alert
      v-if="showBatchHint"
      class="protocol-hint"
      type="info"
      show-icon
      :closable="true"
      :title="t(BATCH_HINT_KEY)"
      @close="dismissBatchHint"
    />

    <!-- 浮層（搜尋列、延遲徽章）錨在終端主體容器、不錨在 .ssh-terminal：
         提示條進了直向 flex 流會把終端主體往下推，但絕對定位元素不會跟著移動，
         錨在外層時徽章／搜尋列會**壓在提示條上**並吃掉關閉鈕的點擊
         （Playwright 實點回報 latency-badge subtree intercepts pointer events；
         ja-JP 於 1024px 折兩行時還會壓住文字）。錨在主體容器則兩者永不重疊。 -->
    <div
      ref="containerRef"
      class="terminal-container"
    >
      <div
        v-if="searchVisible"
        class="search-bar"
      >
        <el-input
          ref="searchInputRef"
          v-model="searchTerm"
          size="small"
          :placeholder="$t('sshTerminal.searchPlaceholder')"
          @input="searchIncremental"
          @keydown.enter.exact="searchNext"
          @keydown.shift.enter="searchPrev"
          @keydown.esc="closeSearch"
        />
        <el-button
          size="small"
          @click="searchPrev"
        >
          ↑
        </el-button>
        <el-button
          size="small"
          @click="searchNext"
        >
          ↓
        </el-button>
        <el-button
          size="small"
          @click="closeSearch"
        >
          ✕
        </el-button>
      </div>

      <el-tag
        v-if="latencyMs !== null"
        class="latency-badge"
        size="small"
        :type="latencyType"
      >
        {{ latencyMs }}ms
      </el-tag>

      <div
        ref="mountRef"
        class="terminal-mount"
      />
    </div>
  </div>
</template>

<script setup>
import { ref, computed, nextTick, watch, onMounted, onBeforeUnmount } from 'vue'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { SearchAddon } from '@xterm/addon-search'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { Loading } from '@element-plus/icons-vue'
import { createConnectTokenWithConsent } from '@/api/connect'
import '@xterm/xterm/css/xterm.css'
import { xtermTheme } from '@/styles/terminal-theme'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import { useRoles } from '@/composables/useRoles'

const RESIZE_DEBOUNCE_MS = 200
const PING_INTERVAL_MS = 10000

const props = defineProps({
  assetId: {
    type: [Number, String],
    required: true
  },
  // 所選資產帳號（asset-multi-account D2）：由 Workspace 經帳號選擇器帶入，
  // 只進 connect-token 簽發 body，不進 WS query（帳號綁定已封在 token 內）
  accountId: { type: [Number, String], default: null },
  // K8s 連線時選 pod（k8s-exec）：由 Workspace 經選擇器帶入，附加到 WS URL query
  k8sPod: { type: String, default: '' },
  k8sContainer: { type: String, default: '' },
  k8sMode: { type: String, default: '' },
  // 資產協議：目前只用於協議專屬的使用者提示（mssql 的 GO 批次終止符）。
  // 協議一律由父層自資產資料帶入，**不從終端輸出內容推測**
  protocol: { type: String, default: '' }
})

const emit = defineEmits(['status-change', 'session-id'])

const containerRef = ref(null)
const mountRef = ref(null)
// waiting: 等待容器尺寸 | connecting | connected | closed | error
const status = ref('waiting')
const statusDetail = ref('')
// 撥號失敗的機器可讀錯誤碼（ssh-connect-error-surfacing）：host key 變更時據此出引導
const errorCode = ref('')
const { isAdmin } = useRoles()
const isHostKeyError = computed(() => errorCode.value === 'RULE_SSH_HOST_KEY_CHANGED')
// K8s distroless 無 shell：偵測到後於斷線遮罩顯示，避免被泛化「連線已中斷」蓋掉
const noShellHint = ref('')

// mssql 批次終止符提示：連線成功後顯示，使用者關閉後本次會話不再出現。
// 刻意不落 localStorage——「永久不再顯示」會讓共用同一台機器的下一個人看不到。
const batchHintDismissed = ref(false)
const BATCH_HINT_KEY = 'sshTerminal.mssqlBatchHint'
const showBatchHint = computed(
  () => status.value === 'connected' && props.protocol === 'mssql' && !batchHintDismissed.value
)
function dismissBatchHint() {
  batchHintDismissed.value = true
}

// 延遲徽章（session-latency）：重用 keepalive ping/pong 量測 RTT
const LATENCY_GOOD_MS = 100
const LATENCY_FAIR_MS = 300
const latencyMs = ref(null)
let lastPingSentAt = null

const latencyType = computed(() => {
  if (latencyMs.value < LATENCY_GOOD_MS) return 'success'
  if (latencyMs.value < LATENCY_FAIR_MS) return 'warning'
  return 'danger'
})

const statusIsTerminal = computed(() => status.value === 'closed' || status.value === 'error')

// 工作區頁籤狀態視覺化（workspace-tab-status）：對外發布連線狀態
watch(status, (value) => emit('status-change', value))

let terminal = null
let fitAddon = null
let searchAddon = null
let socket = null
let resizeObserver = null
let resizeTimer = null
let pingTimer = null

// 終端搜尋（terminal-search）
const searchVisible = ref(false)
const searchTerm = ref('')
const searchInputRef = ref(null)

onMounted(() => {
  detectMobile()
  window.addEventListener('resize', detectMobile)
  initTerminal()
  waitForSizeAndConnect()
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', detectMobile)
  cleanup()
})

function initTerminal() {
  // K8s logs 模態為唯讀串流：停用輸入並隱藏游標，避免使用者以為可輸入（UI 對抗審查 R2）
  const readOnly = props.k8sMode === 'logs'
  terminal = new Terminal({
    cursorBlink: !readOnly,
    cursorInactiveStyle: readOnly ? 'none' : 'outline',
    disableStdin: readOnly,
    fontSize: 14,
    fontFamily: 'Menlo, Consolas, "Courier New", monospace',
    theme: xtermTheme,
    scrollback: 5000
  })
  fitAddon = new FitAddon()
  terminal.loadAddon(fitAddon)
  searchAddon = new SearchAddon()
  terminal.loadAddon(searchAddon)
  terminal.loadAddon(new WebLinksAddon())
  terminal.open(mountRef.value)

  terminal.onData((data) => {
    if (props.k8sMode === 'logs') return // logs 唯讀，不送輸入
    sendMessage('data', data)
  })

  // 自訂鍵位：搜尋與剪貼簿（native-parity）——瀏覽器原生 Ctrl+F／Ctrl+C 會搶走終端語義，此處攔截後改綁終端行為
  terminal.attachCustomKeyEventHandler((event) => {
    if (event.type !== 'keydown') return true

    // Ctrl/Cmd+F：開啟終端搜尋而非瀏覽器原生搜尋
    if ((event.ctrlKey || event.metaKey) && event.key === 'f') {
      event.preventDefault()
      openSearch()
      return false
    }

    // Ctrl+Shift+C：複製選取（Windows/Linux 慣例；Cmd+C / Ctrl+Insert 仍由瀏覽器原生處理）
    if (event.ctrlKey && event.shiftKey && (event.key === 'C' || event.key === 'c')) {
      const selection = terminal.getSelection()
      if (selection) {
        event.preventDefault()
        copyToClipboard(selection)
        return false
      }
      return true // 無選取則放行，不吞鍵
    }

    // Ctrl+Shift+V：貼上（terminal.paste 自動套 bracketed-paste，避免多行被逐行執行）
    if (event.ctrlKey && event.shiftKey && (event.key === 'V' || event.key === 'v')) {
      event.preventDefault()
      pasteFromClipboard()
      return false
    }

    return true
  })
}

// 剪貼簿輔助：失敗不中斷終端，僅記錄（權限被拒/非安全上下文時降級）
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text)
  } catch (err) {
    console.warn('[SshTerminal] 複製到剪貼簿失敗:', err)
  }
}

async function pasteFromClipboard() {
  try {
    const text = await navigator.clipboard.readText()
    if (text) terminal.paste(text)
  } catch (err) {
    console.warn('[SshTerminal] 自剪貼簿貼上失敗:', err)
  }
}

// 等待容器首個非零尺寸才連線：杜絕 layout 未完成時測得 0 而退回
// 寫死解析度的根因（design D5）
function waitForSizeAndConnect() {
  resizeObserver = new ResizeObserver(() => {
    const el = containerRef.value
    if (!el || el.clientWidth === 0 || el.clientHeight === 0) return

    if (status.value === 'waiting') {
      safeFit()
      connect()
    } else if (status.value === 'connected') {
      scheduleResize()
    }
  })
  resizeObserver.observe(containerRef.value)
}

async function connect() {
  status.value = 'connecting'
  statusDetail.value = ''
  errorCode.value = ''
  noShellHint.value = ''

  // 兩段式連線（connect-token）：先以 JWT 換一次性 token，
  // WS URL 不再攜帶長效 JWT（query string 防洩漏）；
  // warn 檔命中傳輸風險（DB 未啟 TLS）時內含同意對話框，拒絕即中止
  let connectToken
  try {
    const resp = await createConnectTokenWithConsent(props.assetId, props.accountId)
    connectToken = resp.connect_token
  } catch (err) {
    console.error('[SshTerminal] 取得連線 token 失敗:', err)
    status.value = 'error'
    statusDetail.value = resolveApiError(
      err.response?.data,
      err.response?.status,
      t('sshTerminal.tokenFailed')
    )
    return
  }

  const params = new URLSearchParams({
    connect_token: connectToken,
    cols: String(terminal.cols),
    rows: String(terminal.rows)
  })
  // K8s 連線時選定的 pod/container/模態（namespace 由後端取自資產，不經前端）
  if (props.k8sPod) {
    params.set('k8s_pod', props.k8sPod)
    if (props.k8sContainer) params.set('k8s_container', props.k8sContainer)
    if (props.k8sMode) params.set('k8s_mode', props.k8sMode)
  }
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const wsUrl = `${wsProtocol}//${window.location.host}/api/v1/ssh?${params.toString()}`

  socket = new WebSocket(wsUrl)

  socket.onmessage = (event) => {
    let msg
    try {
      msg = JSON.parse(event.data)
    } catch {
      return
    }

    switch (msg.type) {
      case 'data':
        terminal.write(msg.data)
        if (!noShellHint.value && msg.data &&
          (msg.data.includes('executable file not found') || msg.data.includes('OCI runtime exec failed'))) {
          noShellHint.value = t('sshTerminal.noShellHint')
        }
        break
      case 'connected':
        status.value = 'connected'
        try {
          const payload = JSON.parse(msg.data || '{}')
          if (payload.session_id) emit('session-id', payload.session_id)
        } catch { /* 舊版後端空 payload，忽略 */ }
        startPing()
        terminal.focus()
        // 防誤關（terminal-navigation D3）：連線中關閉分頁需確認
        window.addEventListener('beforeunload', confirmUnload)
        break
      case 'pong':
        if (lastPingSentAt !== null) {
          latencyMs.value = Math.round(performance.now() - lastPingSentAt)
          lastPingSentAt = null
        }
        break
      case 'notice':
        // 後端控制通知（backend-i18n-unification D7）：目前唯一用途是指令阻斷
        // 警告。會話未斷，故不動 status——僅在終端內以紅字留痕
        writeNotice(msg)
        break
      case 'error':
        status.value = 'error'
        // code 三層降級（resolveApiError）：譯文 → 後端 zh data → 通用語
        errorCode.value = msg.code || ''
        statusDetail.value = resolveApiError(
          { error: msg.data, code: msg.code, params: msg.params },
          undefined,
          t('common.unknownError')
        )
        break
      default:
        break
    }
  }

  socket.onclose = (event) => {
    stopPing()
    if (statusIsTerminal.value) return

    if (status.value === 'connecting') {
      status.value = 'error'
      statusDetail.value = event.reason || t('sshTerminal.connectFailed')
    } else {
      status.value = 'closed'
      statusDetail.value = noShellHint.value || t('sshTerminal.connectionClosed')
    }
  }

  socket.onerror = () => {
    if (status.value === 'connecting') {
      status.value = 'error'
      statusDetail.value = t('sshTerminal.connectFailed')
    }
  }
}

// sanitizeForTerminal 注入 xterm 前的縱深防禦（design D7）：後端組幀時
// params 值已過 sanitizeOpaque，前端再剝一次控制字元——譯文插值後才是真正
// 寫進終端的字串，只在後端把關等於信任了一條跨行程的假設。
// 剝除 C0（含 ESC 0x1b）、DEL 與 C1（0x80-0x9f，含 8-bit CSI 0x9b）
// eslint-disable-next-line no-control-regex -- 本正則的用途就是比對控制字元
const TERMINAL_CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/g

function sanitizeForTerminal(text) {
  return String(text ?? '').replace(TERMINAL_CONTROL_CHARS, '')
}

// writeNotice 查譯 MsgNotice 控制幀並以紅字注入終端。
// 查譯走 resolveApiError 同構三層降級（apiError 譯文 → 後端 zh data → 通用語）；
// 規則名為 opaque 值，另以 noticeWithRule 組字（apiError 模板不含 {rule}——
// 它與後端 registry.ZhFallback 逐字對齊，不可在前端單方面加插值位）
function writeNotice(msg) {
  const base = resolveApiError(
    { error: msg.data, code: msg.code, params: msg.params },
    undefined,
    t('common.unknownError')
  )
  const rule = typeof msg.params?.rule === 'string' ? msg.params.rule.trim() : ''
  const text = rule ? t('sshTerminal.noticeWithRule', { message: base, rule }) : base
  terminal?.write(`\r\n\x1b[31m${sanitizeForTerminal(text)}\x1b[0m\r\n`)
}

function reconnect() {
  disposeSocket()
  terminal.reset()
  status.value = 'waiting'

  const el = containerRef.value
  if (el && el.clientWidth > 0 && el.clientHeight > 0) {
    safeFit()
    connect()
  }
  // 尺寸為零時維持 waiting，ResizeObserver 會在尺寸就緒後接手連線
}

function sendMessage(type, data) {
  if (!socket || socket.readyState !== WebSocket.OPEN) return
  socket.send(JSON.stringify(data ? { type, data } : { type }))
}

// 行動快捷鍵（mobile-terminal-keys D2）：六鍵＝觸控鍵盤缺席的控制鍵最小集（ESC／Tab／Ctrl+B／Ctrl+C／上下方向）
const MOBILE_KEYS = [
  { label: 'ESC', seq: '\x1b' },
  { label: 'Tab', seq: '\x09' },
  { label: 'Ctrl+B', seq: '\x02' },
  { label: 'Ctrl+C', seq: '\x03' },
  { label: '↑', seq: '\x1b[A' },
  { label: '↓', seq: '\x1b[B' },
]

const showMobileKeys = ref(false)

function detectMobile() {
  showMobileKeys.value =
    window.matchMedia('(pointer: coarse)').matches || window.innerWidth < 768
}

function sendKey(seq) {
  sendMessage('data', seq)
  terminal?.focus()
}

// 片段注入（terminal-snippets D1）：寫入終端輸入不附換行，使用者確認後自行執行
function sendText(text) {
  if (!text) return
  sendMessage('data', text)
  terminal?.focus()
}

defineExpose({ sendText, sendKey, showMobileKeys })

// resize 防抖：拖動視窗期間避免向 PTY 連發 window-change
function scheduleResize() {
  clearTimeout(resizeTimer)
  resizeTimer = setTimeout(() => {
    if (!fitAddon || status.value !== 'connected') return
    safeFit()
    sendMessage('resize', JSON.stringify({ cols: terminal.cols, rows: terminal.rows }))
  }, RESIZE_DEBOUNCE_MS)
}

function startPing() {
  stopPing()
  pingTimer = setInterval(() => {
    lastPingSentAt = performance.now()
    sendMessage('ping', '')
  }, PING_INTERVAL_MS)
}

function stopPing() {
  if (pingTimer) {
    clearInterval(pingTimer)
    pingTimer = null
  }
  // 會話不再活躍：解除防誤關、清空延遲顯示
  window.removeEventListener('beforeunload', confirmUnload)
  latencyMs.value = null
  lastPingSentAt = null
}

// beforeunload 處理器：僅在連線中攔截（stopPing 時解除）
function confirmUnload(event) {
  event.preventDefault()
  event.returnValue = ''
}

// 回系統開新分頁：另開分頁而非 router 跳轉，當前會話因此不被銷毀；元件也不必依賴 router
function openSystem() {
  window.open('/', '_blank')
}

// host key 變更時 admin 直達資產編輯框（Assets.vue 讀 edit query 自動開啟並捲至
// 主機金鑰欄位）；開新分頁保留工作區既有頁籤
function openAssetHostKey() {
  window.open(`/assets?edit=${props.assetId}`, '_blank')
}

// safeFit 帶防禦的尺寸適配：fit 後實測渲染高度，像素取整/DPR/字型度量
// 在部分螢幕仍可能溢出半行，超出可視區即退一行保證最底行完整可見
function safeFit() {
  if (!fitAddon || !terminal) return
  fitAddon.fit()

  const mountEl = mountRef.value
  const screenEl = mountEl?.querySelector('.xterm-screen')
  if (mountEl && screenEl && screenEl.clientHeight > mountEl.clientHeight && terminal.rows > 2) {
    terminal.resize(terminal.cols, terminal.rows - 1)
  }
}

// 終端搜尋列
function openSearch() {
  searchVisible.value = true
  nextTick(() => searchInputRef.value?.focus())
}

function closeSearch() {
  searchVisible.value = false
  searchTerm.value = ''
  searchAddon?.clearDecorations()
  terminal?.focus()
}

function searchIncremental() {
  if (searchTerm.value) {
    searchAddon?.findNext(searchTerm.value, { incremental: true })
  }
}

function searchNext() {
  if (searchTerm.value) {
    searchAddon?.findNext(searchTerm.value)
  }
}

function searchPrev() {
  if (searchTerm.value) {
    searchAddon?.findPrevious(searchTerm.value)
  }
}

function disposeSocket() {
  stopPing()
  if (socket) {
    socket.onclose = null
    socket.onerror = null
    socket.onmessage = null
    socket.close()
    socket = null
  }
}

function cleanup() {
  disposeSocket()
  clearTimeout(resizeTimer)
  if (resizeObserver) {
    resizeObserver.disconnect()
    resizeObserver = null
  }
  if (terminal) {
    terminal.dispose()
    terminal = null
  }
}
</script>

<style scoped>
/* 直向 flex：讓行內元素（快捷鍵列、協議提示條）與終端容器共分高度。
   終端容器若維持 height:100% 會被行內元素擠出可視區，最底行被裁。
   絕對定位的狀態遮罩（inset:0，本就該蓋滿全域）不受 flex 影響；
   搜尋列與延遲徽章改錨在 .terminal-container，故不會壓到提示條。 */
.ssh-terminal {
  position: relative;
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--ot-terminal-bg, #0d1117);
}

.mobile-key-row {
  display: flex;
  flex: 0 0 auto;
  height: 40px;
  background: #1b1b1b;
}

.protocol-hint {
  flex: 0 0 auto;
  border-radius: 0;
}

.mobile-key {
  flex: 1;
  border: none;
  background: transparent;
  color: #fff;
  font-size: 13px;
  cursor: pointer;
}

.mobile-key:active {
  background: #333;
}

.terminal-container {
  position: relative; /* 搜尋列／延遲徽章的定位錨點：使其永遠落在提示條下方 */
  flex: 1 1 auto;
  min-height: 0;
  padding: 8px;
  box-sizing: border-box;
}

.terminal-mount {
  height: 100%;
  overflow: hidden;
}

.latency-badge {
  position: absolute;
  top: 8px;
  right: 12px;
  z-index: 5;
  opacity: 0.85;
}

.search-bar {
  position: absolute;
  top: 8px;
  right: 70px;
  z-index: 6;
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 4px 6px;
  background: #1c2128;
  border: 1px solid #30363d;
  border-radius: 6px;
}

.search-bar .el-input {
  width: 180px;
}

.status-overlay {
  position: absolute;
  inset: 0;
  z-index: 10;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  color: var(--ot-terminal-fg, #e6edf3);
  background: var(--ot-terminal-bg, #0d1117);
}

.host-key-hint {
  margin: 0 0 12px;
  font-size: 13px;
  color: var(--el-color-warning);
}
</style>
