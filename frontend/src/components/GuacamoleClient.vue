<template>
  <div class="guacamole-client">
    <div class="client-toolbar">
      <el-button
        v-if="!connected"
        type="primary"
        :loading="connecting"
        size="small"
        @click="connect"
      >
        {{ $t('guacClient.connectTo', { name: assetLabel }) }}
      </el-button>
      <el-button
        v-else
        type="danger"
        size="small"
        @click="disconnect"
      >
        {{ $t('guacClient.disconnect') }}
      </el-button>
      <el-button
        v-if="connected"
        size="small"
        :title="$t('guacClient.ctrlAltDelTooltip')"
        @click="sendCtrlAltDel"
      >
        Ctrl+Alt+Del
      </el-button>
      <!-- 剪貼簿與上傳鈕依有效能力呈現不可用＋原因（data-transfer-control 6.3）。
           **這是介面呈現，不是強制點**：剪貼簿由 guacd 連線參數強制、檔案由
           tunnel 攔截強制，前端把鈕變灰只是省一次白工 -->
      <el-button
        v-if="connected"
        size="small"
        :disabled="!canClipboardSend"
        :title="canClipboardSend
          ? $t('guacClient.pasteTooltip')
          : $t('transferCapability.clipboardSendDenied')"
        @click="pasteToRemote(false)"
      >
        {{ $t('guacClient.paste') }}
      </el-button>
      <el-button
        v-if="connected"
        size="small"
        :disabled="!canClipboardRecv"
        :title="canClipboardRecv
          ? $t('guacClient.copyRemoteTooltip')
          : $t('transferCapability.clipboardRecvDenied')"
        @click="copyRemoteToLocal"
      >
        {{ $t('guacClient.copyRemote') }}
      </el-button>
      <el-button
        v-if="connected && hasRemoteFs"
        size="small"
        :disabled="!canFileUpload"
        :title="canFileUpload
          ? $t('guacClient.uploadTooltip')
          : $t('transferCapability.deniedReason')"
        @click="triggerFilePicker"
      >
        {{ $t('guacClient.upload') }}
      </el-button>
      <input
        ref="fileInputRef"
        type="file"
        style="display: none"
        @change="uploadFileToRemote"
      >
      <el-tag
        :type="statusType"
        size="small"
      >
        {{ statusText }}
      </el-tag>
      <span
        v-if="connected"
        class="info-text"
      >{{ assetLabel }}</span>
    </div>

    <!-- 調試信息：僅開發模式顯示，正式環境保持乾淨介面 -->
    <div
      v-if="isDev"
      class="debug-info"
    >
      <div class="debug-line">
        {{ $t('guacClient.debugFrontendVersion') }}: v6.1-Unified ({{ buildTime }})
      </div>
      <div class="debug-line">
        {{ $t('common.protocol') }}: {{ props.protocol.toUpperCase() }}
      </div>
      <div class="debug-line">
        {{ $t('guacClient.debugClientState') }}: {{ debugClientState }}
      </div>
      <div class="debug-line">
        {{ $t('guacClient.debugLastMessage') }}: {{ debugLastMessage }}
      </div>
      <div class="debug-line">
        {{ $t('guacClient.debugResolution') }}: {{ displayWidth }}x{{ displayHeight }}
      </div>
    </div>

    <div
      ref="displayContainer"
      class="display-container"
      tabindex="0"
    />
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount, computed } from 'vue'
import { createConnectTokenWithConsent } from '@/api/connect'
import { useTransferCapabilities } from '@/composables/useTransferCapabilities'
import { ElMessage } from 'element-plus'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'

// Guacamole 通過 index.html 中的 script 標籤載入為全局對象
const Guacamole = window.Guacamole

// 本元件限圖形協議（RDP/VNC）：SSH 走 SshTerminal.vue 原生直連。
// 連線收口：只收資產參照，憑證由後端注入，前端零接觸明文
const emit = defineEmits(['status-change'])

const props = defineProps({
  assetId: {
    type: [Number, String],
    required: true
  },
  protocol: {
    type: String,
    default: 'rdp',
    validator: (value) => ['rdp', 'vnc'].includes(value)
  },
  assetName: {
    type: String,
    default: ''
  },
  // 所選資產帳號：只進 connect-token 簽發 body
  accountId: {
    type: [Number, String],
    default: null
  }
})

const displayContainer = ref(null)
const connected = ref(false)
const connecting = ref(false)
const isDev = import.meta.env.DEV

// 使用者按下連線但容器尚未完成 layout：等 ResizeObserver 回報非零尺寸再連
const pendingConnect = ref(false)

// 剪貼簿同步狀態：pendingRemoteClipboard 暫存頁面未聚焦時收到的遠端內容，
// lastClipboardText 為最後同步值（雙向去重，避免 focus 把剛收到的內容回送形成迴圈）
let pendingRemoteClipboard = null
let lastClipboardText = null
// 遠端最後一次送來的剪貼簿內容（供「取遠端剪貼簿」鈕以使用者手勢寫入本機，
// 繞過瀏覽器對非手勢 clipboard.writeText 的封鎖）
let remoteClipboardText = ''
// RDP 上傳檔案的隱藏 file input
const fileInputRef = ref(null)

// Debug 狀態 - 簡化版
const debugClientState = ref(t('guacClient.debugUninitialized'))
const debugLastMessage = ref(t('guacClient.debugWaitingConnect'))
const buildTime = ref(new Date().toLocaleString('zh-TW', { hour12: false }))
const displayWidth = ref(1024)
const displayHeight = ref(768)

let guacClient = null
let keyboard = null
let mouse = null
// 遠端檔案系統物件（由 onfilesystem 提供）——RDP=重導磁碟、VNC=SFTP 側車
// （vnc-file-transfer），上傳檔案走它的 createOutputStream
let remoteFs = null
// 檔案系統掛載才顯示上傳入口（未啟用 SFTP 的 VNC 不出現，RDP 磁碟就緒前也不出現）
const hasRemoteFs = ref(false)
let resizeObserver = null

const statusType = computed(() => {
  if (connected.value) return 'success'
  if (connecting.value) return 'warning'
  return 'info'
})

const statusText = computed(() => {
  if (connected.value) return t('guacClient.statusConnected')
  if (connecting.value) return t('guacClient.statusConnecting')
  return t('guacClient.statusDisconnected')
})

// 資料傳輸有效能力（data-transfer-control 6.2／6.3）：**呈現用，非強制點**。
// 剪貼簿的實際強制在 guacd 連線參數（disable-copy／disable-paste），檔案上傳的
// 實際強制在 tunnel 攔截；此處只決定鈕亮不亮與滑過去看到什麼原因
const { load: loadCapabilities, allows: allowsTransfer } = useTransferCapabilities()
const canClipboardSend = computed(() => allowsTransfer('clipboard_send'))
const canClipboardRecv = computed(() => allowsTransfer('clipboard_recv'))
const canFileUpload = computed(() => allowsTransfer('file_upload'))

// 資產顯示名（無名稱時回退到「資產 {id}」）；連線鈕與資訊列共用
const assetLabel = computed(
  () => props.assetName || t('guacClient.assetFallback', { id: props.assetId })
)

onMounted(() => {
  console.log('[GuacamoleClient] Component mounted - RDP/VNC 圖形協議組件')
  setupResizeObserver()
  // 開籤即連（與 SSH 行為一致，2026-06-12 走查體驗債）：
  // 尺寸未就緒時 connect 內部會掛起待 ResizeObserver 接手
  connect()
})

onBeforeUnmount(() => {
  clearTimeout(resizeTimer)
  if (resizeObserver) {
    resizeObserver.disconnect()
    resizeObserver = null
  }
  cleanup()
})

function setupResizeObserver() {
  if (!displayContainer.value) return

  resizeObserver = new ResizeObserver((entries) => {
    for (const entry of entries) {
      const { width, height } = entry.contentRect
      if (width <= 0 || height <= 0) continue

      // 連線前按下連線鈕但尺寸未就緒：此刻補發起連線
      if (pendingConnect.value) {
        pendingConnect.value = false
        doConnect(Math.floor(width), Math.floor(height))
        continue
      }

      if (connected.value && guacClient) {
        scheduleResize(Math.floor(width), Math.floor(height))
      }
    }
  })

  resizeObserver.observe(displayContainer.value)
}

// resize 防抖：拖動視窗期間避免向 guacd 連發 size 指令
let resizeTimer = null
const RESIZE_DEBOUNCE_MS = 200

function scheduleResize(width, height) {
  clearTimeout(resizeTimer)
  resizeTimer = setTimeout(() => handleResize(width, height), RESIZE_DEBOUNCE_MS)
}

// 全圖形協議（RDP/VNC）皆同步尺寸：RDP 走 display-update 由伺服器重設解析度，
// VNC 伺服器框緩衝固定，由 fitDisplay 縮放填滿容器
function handleResize(width, height) {
  if (!connected.value || !guacClient) return

  console.log(`[GuacamoleClient] Resizing ${props.protocol} to ${width}x${height}`)
  debugLastMessage.value = t('guacClient.debugResizing', { width, height })
  displayWidth.value = width
  displayHeight.value = height

  try {
    guacClient.sendSize(width, height)
  } catch (err) {
    console.error('[GuacamoleClient] Resize error:', err)
  }
  fitDisplay()
  // RDP 放大後新區域伺服器未重繪（黑屏至下次輸入）→ 同連線後模式 nudge 重繪
  triggerRdpRepaint()
}

// RDP 顯示激活：推伺服器重繪目前框（連線首幀／resize 放大黑屏，同根因）。
// 合成 mousemove 對「連線首幀」夠用、對「放大」無效；改補一個協議層無害 Shift 按放
// （直接走 guac 協議當 RDP 輸入觸發重繪，不輸入任何字元、無副作用），延遲拉長確保伺服器已 resize。
function triggerRdpRepaint() {
  if (props.protocol !== 'rdp' || !guacClient) return
  setTimeout(() => {
    try {
      const el = guacClient.getDisplay().getElement()
      el.dispatchEvent(new MouseEvent('mousemove', {
        bubbles: true, cancelable: true, view: window, clientX: 10, clientY: 10
      }))
      const KEYSYM_SHIFT = 0xffe1
      guacClient.sendKeyEvent(1, KEYSYM_SHIFT)
      guacClient.sendKeyEvent(0, KEYSYM_SHIFT)
    } catch (err) {
      console.warn('[GuacamoleClient] RDP 重繪 nudge 失敗:', err)
    }
  }, 350)
}

// 送出 Ctrl+Alt+Del 到遠端（RDP native-parity：Windows 登入/解鎖剛需，原 UI 缺此入口）
function sendCtrlAltDel() {
  if (!connected.value || !guacClient) return
  const KEYSYM_CTRL = 0xffe3
  const KEYSYM_ALT = 0xffe9
  const KEYSYM_DEL = 0xffff
  // 依序按下，反序放開
  guacClient.sendKeyEvent(1, KEYSYM_CTRL)
  guacClient.sendKeyEvent(1, KEYSYM_ALT)
  guacClient.sendKeyEvent(1, KEYSYM_DEL)
  guacClient.sendKeyEvent(0, KEYSYM_DEL)
  guacClient.sendKeyEvent(0, KEYSYM_ALT)
  guacClient.sendKeyEvent(0, KEYSYM_CTRL)
}

// 將遠端畫面等比縮放至容器：伺服器無法配合解析度時（VNC 固定框緩衝、
// RDP 不支援 display-update 的舊伺服器）仍可填滿可視區域
function fitDisplay() {
  if (!guacClient || !displayContainer.value) return

  const display = guacClient.getDisplay()
  const remoteWidth = display.getWidth()
  const remoteHeight = display.getHeight()
  if (remoteWidth === 0 || remoteHeight === 0) return

  const containerWidth = displayContainer.value.clientWidth
  const containerHeight = displayContainer.value.clientHeight
  if (containerWidth === 0 || containerHeight === 0) return

  const scale = Math.min(containerWidth / remoteWidth, containerHeight / remoteHeight)
  display.scale(scale)
}

// guacd error instruction 的 status code → apierror 碼。
// guacamole-common-js 的 client error handler 只把 args[0] 當訊息、args[1] 當狀態碼，
// 兩種逾時因此必須用不同狀態碼才分得開（後端 proxy/tunnel.go 拆碼的理由）。
// 值刻意映射到既有 apiError 碼而非另立 UI 鍵：那兩條譯文已與後端 registry 的
// ZhFallback 逐字釘住（TestCodeTranslationsComplete），複製一份等於製造漂移面。
const GUAC_STATUS_CODES = {
  // CLIENT_TIMEOUT（0x0308）：閒置逾時
  776: 'RULE_SESSION_IDLE_TIMEOUT',
  // SESSION_CLOSED（0x020B）：達會話時間上限，伺服端主動結束
  523: 'RULE_SESSION_MAX_DURATION',
}

// guacamole status CLIENT_FORBIDDEN（0x0303）：後端 tunnel 拒絕檔案串流時回送的
// ack 狀態碼（proxy/file_tap.go 的 guacAckClientForbidden）。兩處必須同值
const GUAC_STREAM_FORBIDDEN = 771

// guacErrorMessage 三層降級：碼查譯 → 後端 args[0] 的 zh fallback → 通用語
function guacErrorMessage(error) {
  return resolveApiError(
    { error: error?.message, code: GUAC_STATUS_CODES[Number(error?.code)] },
    undefined,
    t('common.unknownError')
  )
}

function connect() {
  connecting.value = true
  buildTime.value = new Date().toLocaleString('zh-TW', { hour12: false })

  // 不使用寫死的 fallback 解析度：容器尚未完成 layout（尺寸為零）時
  // 延後到 ResizeObserver 回報首個非零尺寸再連線
  const containerWidth = displayContainer.value?.clientWidth || 0
  const containerHeight = displayContainer.value?.clientHeight || 0
  if (containerWidth === 0 || containerHeight === 0) {
    console.log('[GuacamoleClient] 容器尺寸未就緒，等待 layout 完成後連線')
    pendingConnect.value = true
    return
  }

  doConnect(containerWidth, containerHeight)
}

async function doConnect(containerWidth, containerHeight) {
  try {
    connecting.value = true
    // 傳輸能力快照（data-transfer-control 6.2）：**剪貼簿兩鍵是連線參數**，
    // 由 guacd 於握手時吃下，連線期間改政策不影響本條連線。故此處取的值就是
    // 這條連線的實際能力，之後不再刷新——刷新反而會讓按鈕狀態與連線實況不符
    // （政策改開＝按鈕亮但 guacd 仍擋；政策改關＝按鈕暗但其實還能貼）。
    // 檔案上傳走 tunnel 逐次判定，另於開檔案挑選器時重取（見 triggerFilePicker）
    await loadCapabilities(props.assetId)
    console.log('[GuacamoleClient] 開始連線...', `${containerWidth}x${containerHeight}`)
    displayWidth.value = containerWidth
    displayHeight.value = containerHeight

    // 兩段式連線：先換一次性 token，URL 不帶 JWT；
    // warn 檔命中傳輸風險時內含同意對話框（428→立據→重試），拒絕即中止
    let connectToken
    try {
      const resp = await createConnectTokenWithConsent(props.assetId, props.accountId)
      connectToken = resp.connect_token
    } catch (err) {
      console.error('[GuacamoleClient] 取得連線 token 失敗:', err)
      connecting.value = false
      emit('status-change', 'closed')
      return
    }

    // 連線收口：只送一次性 token 與實測尺寸，目標主機與憑證由後端解析注入
    const params = new URLSearchParams({
      connect_token: connectToken,
      width: containerWidth.toString(),
      height: containerHeight.toString()
    })

    // 使用相對路徑，讓 Vite proxy 處理
    // 將參數直接附加到 URL（可用版本的方式）
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsHost = window.location.host
    const wsUrl = `${wsProtocol}//${wsHost}/api/v1/connect?${params.toString()}`

    // 不記錄 wsUrl：其 query 含一次性 connect_token，印到 console 或狀態列等同
    // 憑證外洩、破壞連線收口（前端零接觸明文憑證紅線）
    debugLastMessage.value = t('guacClient.debugEstablishing')

    // 官方標準模式：創建 tunnel → 創建 client → 添加 display
    const tunnel = new Guacamole.WebSocketTunnel(wsUrl)
    guacClient = new Guacamole.Client(tunnel)

    // 將 display 添加到容器
    displayContainer.value.innerHTML = ''
    displayContainer.value.appendChild(guacClient.getDisplay().getElement())

    // 遠端畫面尺寸變化（首幀、伺服器端重設解析度）時重新適配縮放
    guacClient.getDisplay().onresize = fitDisplay

    // 遠端 → 本機剪貼簿
    guacClient.onclipboard = handleRemoteClipboard

    // 遠端檔案系統掛載（RDP 重導磁碟／VNC SFTP 側車）——捕獲 filesystem 物件供上傳
    guacClient.onfilesystem = (object, name) => {
      remoteFs = object
      hasRemoteFs.value = true
      console.log('[GuacamoleClient] 遠端檔案系統已掛載:', name)
    }

    console.log('[GuacamoleClient v6.1] Guacamole Client 已創建，遵循官方標準')

    // 設定狀態處理器（不干擾指令處理鏈）
    guacClient.onstatechange = function(state) {
      console.log('[GuacamoleClient v6.1] Client state:', state)

      const stateNames = {
        0: 'IDLE',
        1: 'CONNECTING',
        2: 'WAITING',
        3: 'CONNECTED',
        4: 'DISCONNECTING',
        5: 'DISCONNECTED'
      }
      debugClientState.value = stateNames[state] || `UNKNOWN(${state})`
      debugLastMessage.value = t('guacClient.debugStateChange', { state: debugClientState.value })

      if (state === Guacamole.Client.State.CONNECTED) {
        connecting.value = false
        connected.value = true
        emit('status-change', 'connected')
        ElMessage.success(t('guacClient.connectedMsg'))
        setupInput()

        // 本機 → 遠端剪貼簿：視窗回焦時同步
        window.addEventListener('focus', syncClipboardOnFocus)
        syncClipboardOnFocus()
        console.log('[GuacamoleClient v6.1] 連線成功')

        // RDP 連線首幀黑屏：nudge 重繪（與 resize 放大黑屏同根因，共用 triggerRdpRepaint）
        triggerRdpRepaint()
      } else if (state === Guacamole.Client.State.CONNECTING) {
        console.log('[GuacamoleClient v6.1] 正在連線...')
        debugLastMessage.value = t('guacClient.debugConnecting')
      } else if (state === Guacamole.Client.State.DISCONNECTED) {
        connected.value = false
        connecting.value = false
        emit('status-change', 'closed')
        console.log('[GuacamoleClient v6.1] 已斷線')
        debugLastMessage.value = t('guacClient.debugDisconnected')
      }
    }

    // 錯誤處理
    guacClient.onerror = function(error) {
      console.error('[GuacamoleClient v6.1] Client error:', error)
      const message = guacErrorMessage(error)
      debugLastMessage.value = t('guacClient.debugError', { message })
      ElMessage.error(t('guacClient.connectError', { message }))
      connecting.value = false
      connected.value = false
    }

    // 開始連線 - 使用可用版本的方式
    // URL 已包含所有參數，connect() 不傳參數
    console.log('[GuacamoleClient v6.1] 調用 Client.connect()')
    guacClient.connect()

  } catch (err) {
    console.error('[GuacamoleClient v6.1] 連線失敗:', err)
    ElMessage.error(t('guacClient.connectFailed', { message: err.message }))
    connecting.value = false
    connected.value = false
  }
}

// handleRemoteClipboard 遠端剪貼簿進站：聚合 text stream 後寫入本機剪貼簿。
// 頁面未聚焦時瀏覽器會拒絕寫入，暫存待 focus 補寫；其餘失敗靜默降級
function handleRemoteClipboard(stream, mimetype) {
  if (mimetype !== 'text/plain') return

  const reader = new Guacamole.StringReader(stream)
  let text = ''
  reader.ontext = (chunk) => {
    text += chunk
  }
  reader.onend = () => {
    lastClipboardText = text
    remoteClipboardText = text
    if (!navigator.clipboard?.writeText) return
    navigator.clipboard.writeText(text).catch(() => {
      // 非聚焦/非手勢被瀏覽器擋：暫存待 focus 補寫，亦可由「取遠端剪貼簿」鈕手動取
      pendingRemoteClipboard = text
    })
  }
}

// 遠端 → 本機（使用者手勢觸發，繞過瀏覽器對非手勢 writeText 的封鎖）
async function copyRemoteToLocal() {
  if (!remoteClipboardText) {
    ElMessage.info(t('guacClient.remoteClipboardEmpty'))
    return
  }
  try {
    await navigator.clipboard.writeText(remoteClipboardText)
    pendingRemoteClipboard = null
    ElMessage.success(t('guacClient.copiedRemoteToLocal'))
  } catch {
    ElMessage.warning(t('guacClient.writeLocalFailed'))
  }
}

// 上傳本機檔案到遠端（RDP 走 guacd "file" 串流→重導磁碟）
function triggerFilePicker() {
  // 檔案能力於 tunnel 側逐次判定（即時生效），開挑選器前重取一次，
  // 使呈現跟得上會話進行中的政策改動；剪貼簿不重取（見 doConnect 註解）
  loadCapabilities(props.assetId)
  fileInputRef.value?.click()
}

function uploadFileToRemote(event) {
  const file = event.target.files?.[0]
  event.target.value = '' // 重置以便重複上傳同一檔
  if (!file) return
  if (!connected.value || !guacClient) {
    ElMessage.warning(t('guacClient.notConnectedUpload'))
    return
  }
  if (!remoteFs) {
    ElMessage.warning(t('guacClient.remoteDiskNotMounted'))
    return
  }
  try {
    // 走重導磁碟物件的 output stream（寫到磁碟根目錄），非 client.createFileStream
    const stream = remoteFs.createOutputStream(file.type || 'application/octet-stream', '/' + file.name)
    const writer = new Guacamole.BlobWriter(stream)
    // BlobWriter.onprogress 簽名為 (blob, offset)，非 (length)——用 offset 算百分比
    writer.onprogress = (_blob, offset) => {
      if (file.size > 0) debugLastMessage.value = t('guacClient.debugUploading', { name: file.name, pct: Math.round((offset / file.size) * 100) })
    }
    writer.oncomplete = () => {
      // 關鍵：BlobWriter.sendBlob 不會結束串流——必須手動 sendEnd 關閉 Windows 端
      // 檔案 handle，否則真 Windows 卡在未關閉的重導磁碟 handle 上、整個畫面凍結。
      stream.sendEnd()
      ElMessage({
        type: 'success',
        message: t('guacClient.uploadDone', { name: file.name }),
        duration: 7000
      })
    }
    // 串流被政策拒絕的可辨識回應（data-transfer-control 5.3）：後端 tunnel 於
    // 攔下 put 時回送 ack 帶 CLIENT_FORBIDDEN(771)，guacamole-common-js 據此
    // 觸發 onerror。不查碼就只會說「上傳失敗」，使用者無從得知是政策擋的
    writer.onerror = (_blob, _offset, status) => {
      stream.sendEnd()
      if (Number(status?.code) === GUAC_STREAM_FORBIDDEN) {
        ElMessage.error(t('transferCapability.streamDenied'))
        return
      }
      ElMessage.error(t('guacClient.uploadFailed', { name: file.name }))
    }
    writer.sendBlob(file)
    ElMessage.info(t('guacClient.uploading', { name: file.name }))
  } catch (err) {
    ElMessage.error(t('guacClient.uploadErrorGeneric', { message: err?.message || t('common.unknownError') }))
  }
}

// syncClipboardOnFocus 視窗回焦時的雙向補同步：
// 先補寫未聚焦期間收到的遠端內容，再把本機新內容送往遠端（去重）
async function syncClipboardOnFocus() {
  if (pendingRemoteClipboard !== null && navigator.clipboard?.writeText) {
    const pending = pendingRemoteClipboard
    pendingRemoteClipboard = null
    navigator.clipboard.writeText(pending).catch(() => {})
  }
  await pasteToRemote(true)
}

// 本機剪貼簿 → 遠端（gap B：顯式「貼上到遠端」鈕 + focus 自動同步共用此路徑）
// silent=true 為 focus 自動同步（去重、靜默降級）；false 為使用者顯式點擊（給回饋、不去重）
async function pasteToRemote(silent = false) {
  if (!connected.value || !guacClient || !navigator.clipboard?.readText) {
    if (!silent) ElMessage.warning(t('guacClient.clipboardUnavailable'))
    return
  }
  try {
    const text = await navigator.clipboard.readText()
    if (!text) return
    if (silent && text === lastClipboardText) return
    lastClipboardText = text
    const stream = guacClient.createClipboardStream('text/plain')
    const writer = new Guacamole.StringWriter(stream)
    writer.sendText(text)
    writer.sendEnd()
    if (!silent) {
      ElMessage.success(t('guacClient.pastedToRemote'))
      // 顯式點擊才補送 Ctrl+V 真的貼到游標處（只設剪貼簿、不按 Ctrl+V 是先前「沒用」的主因）；
      // auto-sync（silent）不觸發，避免視窗回焦時亂貼。延遲讓遠端剪貼簿先到位。
      setTimeout(() => {
        if (!connected.value || !guacClient) return
        const KEYSYM_CTRL = 0xffe3
        const KEYSYM_V = 0x76
        guacClient.sendKeyEvent(1, KEYSYM_CTRL)
        guacClient.sendKeyEvent(1, KEYSYM_V)
        guacClient.sendKeyEvent(0, KEYSYM_V)
        guacClient.sendKeyEvent(0, KEYSYM_CTRL)
      }, 200)
    }
  } catch {
    if (!silent) ElMessage.warning(t('guacClient.readClipboardFailed'))
  }
}

function setupInput() {
  console.log('[GuacamoleClient v6.1] Setting up input handlers')

  // 獲取 Guacamole 的 Mouse 和 Keyboard
  mouse = new Guacamole.Mouse(guacClient.getDisplay().getElement())
  keyboard = new Guacamole.Keyboard(document)

  // 連線鼠標事件：座標除以縮放比例，對應回遠端原始解析度
  mouse.onmousedown =
  mouse.onmouseup =
  mouse.onmousemove = function(mouseState) {
    const scale = guacClient.getDisplay().getScale()
    if (scale > 0 && scale !== 1) {
      mouseState.x /= scale
      mouseState.y /= scale
    }
    guacClient.sendMouseState(mouseState)
  }

  // 連線鍵盤事件
  keyboard.onkeydown = function(keysym) {
    guacClient.sendKeyEvent(1, keysym)
  }

  keyboard.onkeyup = function(keysym) {
    guacClient.sendKeyEvent(0, keysym)
  }

  console.log('[GuacamoleClient v6.1] Input handlers set up')
}

function disconnect() {
  console.log('[GuacamoleClient v6.1] Disconnecting...')
  cleanup()
}

function cleanup() {
  console.log('[GuacamoleClient v6.1] Cleaning up...')

  // 解除剪貼簿同步監聽
  window.removeEventListener('focus', syncClipboardOnFocus)
  pendingRemoteClipboard = null

  // 清理鍵盤
  if (keyboard) {
    keyboard.onkeydown = null
    keyboard.onkeyup = null
    keyboard = null
  }

  // 清理滑鼠
  if (mouse) {
    mouse.onmousedown = null
    mouse.onmouseup = null
    mouse.onmousemove = null
    mouse = null
  }

  // 斷開並清理 client
  if (guacClient) {
    guacClient.disconnect()
    guacClient = null
  }
  remoteFs = null
  hasRemoteFs.value = false

  // 清空容器
  if (displayContainer.value) {
    displayContainer.value.innerHTML = ''
  }

  // 重置所有狀態變數
  connected.value = false
  connecting.value = false
  debugClientState.value = t('guacClient.debugUninitialized')
  debugLastMessage.value = t('guacClient.debugWaitingConnect')
}

// 測試掛點：剪貼簿同步邏輯依賴瀏覽器權限，無法在自動化 E2E 驗證，
// 以元件測試直接驅動（見 __tests__/GuacamoleClient.spec.js）
defineExpose({
  handleRemoteClipboard,
  syncClipboardOnFocus,
  // guacd error instruction 的查譯：真連線才觸發 onerror，以純函式暴露供單測
  guacErrorMessage,
  // 傳輸能力呈現狀態外露供 6.3 守衛測試（禁止時鈕不可用、允許時可用）
  canClipboardSend,
  canClipboardRecv,
  canFileUpload,
  loadCapabilities,
  __test__setConnectedClient(client) {
    guacClient = client
    connected.value = true
  }
})
</script>

<style scoped>
.guacamole-client {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: transparent; /* Allows Guacamole's z-index: -1 canvas to display correctly */
}

/* 精簡工具列高度——對齊 SSH 終端的低調 chrome，不壓縮遠端桌面可視區 */
.client-toolbar {
  padding: 3px 8px;
  background: #3d3d3d;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  border-bottom: 1px solid #4d4d4d;
}

.info-text {
  color: #999;
  font-size: 12px;
  margin-left: auto;
}

.display-container {
  flex: 1;
  overflow: auto;
  background: transparent; /* 修復：讓 Guacamole Canvas 正確顯示 */
  position: relative;
}

.display-container:focus {
  outline: 2px solid var(--ot-primary);
  outline-offset: -2px;
}

/* 不修改 Guacamole 官方設計，保持 z-index: -1 和 position: relative 的原始行為 */

/* 調試信息面板（僅 dev 顯示）：壓到單行高度，不在 dev 也吃掉桌面空間 */
.debug-info {
  padding: 2px 8px;
  background: #3d3d3d;
  border-bottom: 1px solid #4d4d4d;
  font-family: 'Courier New', monospace;
  font-size: 10px;
  display: flex;
  flex-wrap: wrap;
  gap: 0 12px;
}

.debug-line {
  margin: 0;
  color: #888;
}

.debug-line:first-child {
  color: var(--ot-primary);
  font-weight: bold;
}
</style>
