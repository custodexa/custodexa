<template>
  <div class="monitor-terminal">
    <div class="monitor-banner">
      <el-button
        size="small"
        @click="$emit('back')"
      >
        {{ $t('monitorTerminal.backToSessions') }}
      </el-button>
      <el-tag type="warning">
        {{ $t('monitorTerminal.readonlyTag') }}
      </el-tag>
      <span class="session-label">Session {{ props.sessionId }}</span>
      <el-tag
        v-if="ended"
        type="info"
      >
        {{ $t('monitorTerminal.sessionEnded') }}
      </el-tag>
    </div>

    <div
      v-if="errorText"
      class="status-overlay"
    >
      <el-result
        icon="error"
        :title="$t('monitorTerminal.cannotMonitorTitle')"
        :sub-title="errorText"
      />
    </div>

    <div
      ref="containerRef"
      class="terminal-container"
    />
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { xtermTheme } from '@/styles/terminal-theme'
import { t } from '@/i18n'

const PING_INTERVAL_MS = 10000

const props = defineProps({
  sessionId: {
    type: [Number, String],
    required: true
  },
  // 覆寫 WS 路徑（session-share D4）：分享頁傳 /api/v1/sessions/share/<code>/ws
  wsPath: {
    type: String,
    default: ''
  }
})

defineEmits(['back'])

const containerRef = ref(null)
const ended = ref(false)
const errorText = ref('')

let terminal = null
let fitAddon = null
let socket = null
let pingTimer = null

onMounted(() => {
  // 唯讀終端：尺寸跟隨會話端（後端 resize 訊息驅動 terminal.resize），
  // 觀察者視窗大小不影響被監看會話的 PTY
  terminal = new Terminal({
    disableStdin: true,
    cursorBlink: false,
    fontSize: 14,
    fontFamily: 'Menlo, Consolas, "Courier New", monospace',
    theme: xtermTheme,
    scrollback: 5000
  })
  fitAddon = new FitAddon()
  terminal.loadAddon(fitAddon)
  terminal.open(containerRef.value)

  connect()
})

onBeforeUnmount(() => {
  cleanup()
})

function connect() {
  const params = new URLSearchParams({
    token: localStorage.getItem('token') || ''
  })
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const path = props.wsPath || `/api/v1/sessions/${props.sessionId}/monitor`
  const wsUrl = `${wsProtocol}//${window.location.host}${path}?${params.toString()}`

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
        break
      case 'resize': {
        try {
          const { cols, rows } = JSON.parse(msg.data)
          terminal.resize(cols, rows)
        } catch {
          // 無效 resize 內容：忽略
        }
        break
      }
      case 'error':
        ended.value = true
        stopPing()
        break
      default:
        break
    }
  }

  socket.onopen = () => {
    pingTimer = setInterval(() => {
      if (socket?.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'ping' }))
      }
    }, PING_INTERVAL_MS)
  }

  socket.onclose = (event) => {
    stopPing()
    if (!ended.value && event.code !== 1000) {
      errorText.value = t('monitorTerminal.disconnected')
    }
    ended.value = true
  }
}

function stopPing() {
  if (pingTimer) {
    clearInterval(pingTimer)
    pingTimer = null
  }
}

function cleanup() {
  stopPing()
  if (socket) {
    socket.onclose = null
    socket.onmessage = null
    socket.close()
    socket = null
  }
  if (terminal) {
    terminal.dispose()
    terminal = null
  }
}
</script>

<style scoped>
.monitor-terminal {
  position: relative;
  display: flex;
  flex-direction: column;
  height: 100vh;
  background: var(--ot-terminal-bg, #0d1117);
}

.monitor-banner {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 16px;
  color: var(--ot-terminal-fg, #e6edf3);
}

.session-label {
  font-size: 13px;
  opacity: 0.7;
}

.terminal-container {
  flex: 1;
  padding: 8px;
  overflow: auto;
  box-sizing: border-box;
}

.status-overlay {
  position: absolute;
  inset: 40px 0 0;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--ot-terminal-bg, #0d1117);
}
</style>
