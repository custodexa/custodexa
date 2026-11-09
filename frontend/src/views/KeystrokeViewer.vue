<template>
  <div
    class="keystroke-viewer"
    data-test="keystroke-viewer"
  >
    <PageHeader
      :title="$t('keystrokeView.viewer.title')"
      :description="$t('keystrokeView.viewer.description', { id: sessionId })"
    >
      <template #actions>
        <el-button
          data-test="keystroke-back"
          @click="goBack"
        >
          <el-icon><ArrowLeft /></el-icon>
          {{ $t('keystrokeView.viewer.back') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 重新整理或直接開網址：內容不保存，需重新填理由 -->
    <div
      v-if="phase === 'needReason'"
      class="state-card"
      data-test="keystroke-reenter"
    >
      <el-icon
        :size="28"
        class="state-icon"
      >
        <Lock />
      </el-icon>
      <div class="state-title">
        {{ $t('keystrokeView.viewer.reenter.title') }}
      </div>
      <div class="state-body">
        {{ $t('keystrokeView.viewer.reenter.body') }}
      </div>
      <div class="state-actions">
        <el-button @click="goBack">
          {{ $t('keystrokeView.viewer.back') }}
        </el-button>
        <el-button
          type="primary"
          data-test="keystroke-reenter-action"
          @click="reenter"
        >
          {{ $t('keystrokeView.viewer.reenter.action') }}
        </el-button>
      </div>
    </div>

    <div
      v-else-if="phase === 'loading'"
      class="state-card"
    >
      <el-icon
        class="is-loading"
        :size="28"
      >
        <LoaderCircle />
      </el-icon>
      <div class="state-body">
        {{ $t('keystrokeView.viewer.loading') }}
      </div>
    </div>

    <template v-else>
      <div class="summary-grid">
        <div class="sbox">
          <div class="slabel">
            {{ $t('keystrokeView.viewer.summary.connection') }}
          </div>
          <dl class="kv">
            <dt>{{ $t('keystrokeView.viewer.summary.user') }}</dt>
            <dd>{{ session?.user?.username || '-' }}</dd>
            <dt>{{ $t('keystrokeView.viewer.summary.asset') }}</dt>
            <dd>{{ session?.asset?.name || '-' }}</dd>
            <dt>{{ $t('keystrokeView.viewer.summary.protocol') }}</dt>
            <dd>{{ session ? protocolKindText(session.protocol) : '-' }}</dd>
            <dt>{{ $t('keystrokeView.viewer.summary.range') }}</dt>
            <dd>{{ rangeText }}</dd>
          </dl>
        </div>

        <div
          class="sbox"
          data-test="keystroke-integrity"
          :data-kind="integrity.kind"
        >
          <div class="slabel">
            {{ $t('keystrokeView.viewer.summary.status') }}
          </div>
          <div>
            <el-tag :type="integrity.tag">
              {{ integrityTitle }}
            </el-tag>
          </div>
          <div class="shint">
            {{ integrityHint }}
          </div>
        </div>

        <div class="sbox">
          <div class="slabel">
            {{ $t('keystrokeView.viewer.summary.reason') }}
          </div>
          <div
            class="reason-text"
            data-test="keystroke-reason-text"
          >
            {{ reason }}
          </div>
          <div class="shint">
            {{ $t('keystrokeView.viewer.summary.logged', { time: firstLoggedText }) }}
          </div>
        </div>
      </div>

      <!-- 檔案缺失：整張表換成說明卡，不顯示空表格 -->
      <div
        v-if="integrity.kind === 'fileMissing'"
        class="state-card"
        data-test="keystroke-file-missing"
      >
        <el-icon
          :size="28"
          class="state-icon danger"
        >
          <FileX />
        </el-icon>
        <div class="state-title">
          {{ $t('keystrokeView.viewer.integrity.fileMissingTitle') }}
        </div>
        <div class="state-body">
          {{ $t('keystrokeView.viewer.integrity.fileMissingBody') }}
        </div>
        <div class="shint">
          {{ $t('keystrokeView.viewer.integrity.fileMissingLogged') }}
        </div>
      </div>

      <template v-else>
        <!-- 圖形連線（畫稿 D）：沒有位元組可看，不分可讀文字／十六進位；按鍵代碼退到勾選框開的第二層 -->
        <div
          v-if="isGraphics"
          class="toolbar"
          data-test="keystroke-graphics-toolbar"
        >
          <div class="toolbar-left">
            <span class="section-title">{{ $t('keystrokeView.viewer.toolbar.keyEvents') }}</span>
            <span class="shint">{{ $t('keystrokeView.viewer.toolbar.range', { from: fmtNum(events.length ? 1 : 0), to: fmtNum(events.length), total: fmtNum(totalCount) }) }}</span>
          </div>
          <div class="toolbar-right">
            <el-checkbox
              v-model="showKeyCodes"
              data-test="keystroke-show-codes"
            >
              {{ $t('keystrokeView.viewer.toolbar.showKeyCodes') }}
            </el-checkbox>
          </div>
        </div>
        <div
          v-else
          class="toolbar"
        >
          <div class="toolbar-left">
            <span class="section-title">{{ $t('keystrokeView.viewer.toolbar.events') }}</span>
            <span class="shint">{{ $t('keystrokeView.viewer.toolbar.count', { shown: fmtNum(events.length), total: fmtNum(totalCount) }) }}</span>
          </div>
          <div class="toolbar-right">
            <span class="shint">{{ $t('keystrokeView.viewer.toolbar.display') }}</span>
            <el-radio-group
              v-model="displayMode"
              size="small"
              data-test="keystroke-mode"
            >
              <el-radio-button value="text">
                {{ $t('keystrokeView.viewer.toolbar.text') }}
              </el-radio-button>
              <el-radio-button value="hex">
                {{ $t('keystrokeView.viewer.toolbar.hex') }}
              </el-radio-button>
            </el-radio-group>
          </div>
        </div>

        <!-- 十六進位模式只隱藏不移除：保留高度，切換時表格不跳動（畫稿 C2） -->
        <div
          v-if="!isGraphics"
          class="legend"
          :class="{ 'legend-hidden': displayMode !== 'text' }"
          :aria-hidden="displayMode !== 'text'"
        >
          <span>{{ $t('keystrokeView.viewer.legend.title') }}</span>
          <span><code class="cc">&lt;CR&gt;</code> {{ $t('keystrokeView.viewer.legend.enter') }}</span>
          <span><code class="cc">&lt;TAB&gt;</code> {{ $t('keystrokeView.viewer.legend.tab') }}</span>
          <span><code class="cc">&lt;ESC&gt;</code> {{ $t('keystrokeView.viewer.legend.esc') }}</span>
          <span><code class="cc">&lt;BS&gt;</code> {{ $t('keystrokeView.viewer.legend.backspace') }}</span>
          <span><code class="cc">^C</code> {{ $t('keystrokeView.viewer.legend.ctrlC') }}</span>
          <span><code class="cc">&lt;↑&gt;</code> {{ $t('keystrokeView.viewer.legend.arrows') }}</span>
          <span><code class="cc">\x00</code> {{ $t('keystrokeView.viewer.legend.other') }}</span>
        </div>

        <div
          class="ev-table"
          data-test="keystroke-events"
          role="table"
        >
          <div
            class="ev-row ev-head"
            role="row"
          >
            <div>{{ $t('keystrokeView.viewer.table.seq') }}</div>
            <div>{{ $t('keystrokeView.viewer.table.offset') }}</div>
            <div>{{ $t('keystrokeView.viewer.table.time') }}</div>
            <template v-if="isGraphics">
              <div>{{ $t('keystrokeView.viewer.table.action') }}</div>
              <div>{{ $t('keystrokeView.viewer.table.key') }}</div>
            </template>
            <template v-else>
              <div>{{ $t('keystrokeView.viewer.table.source') }}</div>
              <div>{{ displayMode === 'hex' ? $t('keystrokeView.viewer.table.contentHex') : $t('keystrokeView.viewer.table.content') }}</div>
            </template>
          </div>

          <template
            v-for="row in rows"
            :key="row.key"
          >
            <div
              v-if="row.divider"
              class="ev-divider"
              data-test="keystroke-page-divider"
            >
              {{ $t('keystrokeView.viewer.paging.divider', { n: row.divider.n, time: row.divider.time }) }}
            </div>
            <div
              v-else
              class="ev-row"
              :class="row.cls"
              role="row"
              data-test="keystroke-event-row"
            >
              <div class="dim">
                {{ row.seq }}
              </div>
              <div class="mono">
                {{ row.offset }}
              </div>
              <div
                class="mono"
                :title="row.fullTime"
              >
                {{ row.clock }}
              </div>
              <div v-if="isGraphics">
                <span
                  v-if="row.action"
                  class="act"
                  data-test="keystroke-action"
                >{{ $t(`keystrokeView.viewer.action.${row.action}`) }}</span>
                <el-tag
                  v-else-if="row.system"
                  size="small"
                  type="info"
                >
                  {{ $t('keystrokeView.viewer.source.system') }}
                </el-tag>
                <span
                  v-else
                  class="dim"
                >—</span>
              </div>
              <div v-else>
                <el-tag
                  size="small"
                  :type="row.source === 'platform' ? 'warning' : 'info'"
                >
                  {{ $t(`keystrokeView.viewer.source.${row.source}`) }}
                </el-tag>
              </div>
              <div
                v-if="isGraphics"
                class="content"
              >
                <el-tag
                  v-if="row.blocked"
                  size="small"
                  type="danger"
                  class="blocked-tag"
                >
                  {{ $t('keystrokeView.viewer.blocked') }}
                </el-tag>
                <span
                  v-if="row.system"
                  class="muted"
                >{{ row.system }}</span>
                <template v-else-if="row.keyInfo">
                  <span
                    class="kcap"
                    :class="{ unknown: !row.keyInfo.label }"
                    data-test="keystroke-key"
                  >{{ row.keyInfo.label || $t('keystrokeView.viewer.key.unknown') }}</span>
                  <span
                    v-if="showKeyCodes && row.keyInfo.x11"
                    class="kcode"
                    data-test="keystroke-key-x11"
                  >{{ row.keyInfo.x11 }}</span>
                  <span
                    v-if="showKeyCodes || !row.keyInfo.label"
                    class="kcode"
                    data-test="keystroke-key-hex"
                  >{{ row.keyInfo.hex }}</span>
                </template>
                <span
                  v-else
                  class="hx"
                >{{ row.hex }}</span>
                <span
                  v-if="row.platformHint"
                  class="shint inline-hint"
                >{{ $t('keystrokeView.viewer.platformHint') }}</span>
              </div>
              <div
                v-else
                class="content"
              >
                <el-tag
                  v-if="row.blocked"
                  size="small"
                  type="danger"
                  class="blocked-tag"
                >
                  {{ $t('keystrokeView.viewer.blocked') }}
                </el-tag>
                <span
                  v-if="row.system"
                  class="muted"
                >{{ row.system }}</span>
                <span
                  v-else-if="displayMode === 'hex'"
                  class="hx"
                >{{ row.hex }}</span>
                <template v-else>
                  <span
                    v-for="(tok, i) in row.tokens"
                    :key="i"
                    :class="tok.kind === 'plain' ? 'k1' : 'cc'"
                  >{{ tok.text }}</span>
                </template>
                <span
                  v-if="row.platformHint"
                  class="shint inline-hint"
                >{{ $t('keystrokeView.viewer.platformHint') }}</span>
              </div>
            </div>
          </template>
        </div>

        <!-- 表尾：之後為什麼沒有，緊接在最後一筆事件之後 -->
        <el-alert
          v-if="tailText"
          :type="tailType"
          :closable="false"
          show-icon
          data-test="keystroke-tail"
        >
          {{ tailText }}
          <el-button
            v-if="integrity.kind === 'recording'"
            link
            type="primary"
            data-test="keystroke-refresh"
            :loading="loadingPage"
            @click="refresh"
          >
            {{ $t('keystrokeView.viewer.tail.refresh') }}
          </el-button>
        </el-alert>
        <el-alert
          v-else-if="events.length === 0"
          type="info"
          :closable="false"
          show-icon
        >
          {{ $t('keystrokeView.viewer.tail.empty') }}
        </el-alert>
        <div
          v-else-if="showEnd"
          class="tail-end"
          data-test="keystroke-end"
        >
          {{ endText }}
        </div>

        <div
          v-if="nextEvent !== null"
          class="pager"
          :class="{ failed: !!pageError }"
          data-test="keystroke-pager"
        >
          <div
            v-if="pageError"
            class="pager-error"
          >
            {{ pageError }}
          </div>
          <el-button
            type="primary"
            :loading="loadingPage"
            data-test="keystroke-next"
            @click="loadNext"
          >
            {{ pageError ? $t('keystrokeView.viewer.paging.retry') : $t('keystrokeView.viewer.paging.next', { from: fmtNum(nextEvent + 1), to: fmtNum(nextEvent + PAGE_LIMIT) }) }}
          </el-button>
          <div class="shint">
            {{ $t('keystrokeView.viewer.paging.note') }}
          </div>
        </div>
      </template>
    </template>

    <KeystrokeReasonDialog
      v-model="reasonOpen"
      :session-id="sessionId"
      @success="onReenterSuccess"
      @rights-lost="goBack"
    />
  </div>
</template>

<script setup>
// 鍵盤紀錄檢視頁：內容只在記憶體；離開即清除；不寫任何瀏覽器儲存、不印 console。
import { computed, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, FileX, LoaderCircle, Lock } from 'lucide-vue-next'
import PageHeader from '@/components/PageHeader.vue'
import KeystrokeReasonDialog from '@/components/keystroke/KeystrokeReasonDialog.vue'
import { getSession } from '@/api/sessions'
import { getKeystrokeMeta, viewKeystrokes } from '@/api/keystrokes'
import { t, te } from '@/i18n'
import { formatBytes, formatDateTime } from '@/utils/format'
import { protocolKindText } from '@/utils/protocol'
import { bytesToHex, bytesToTokens, mergeEventRows } from '@/utils/keystrokeText'
import { KIND_KEYSYM, KIND_KEYSYM_RAW, decodeKeyEvent, keysymLabel, keysymName } from '@/utils/keysym'
import {
  classifyKeystrokeError, clearKeystrokeView, describeIntegrity, formatClock, formatOffsetMs, takeKeystrokeView,
} from '@/utils/keystrokeView'

const PAGE_LIMIT = 5000

const route = useRoute()
const router = useRouter()
const sessionId = String(route.params.id)

const phase = ref('loading') // loading | needReason | ready
const session = ref(null)
const meta = ref(null)
const reason = ref('')
const firstLoggedAt = ref(null)
// 事件原始資料用 shallowRef：數千筆不需要深層響應
const events = shallowRef([])
const pages = shallowRef([]) // [{ at: Date, startIndex }]
const nextEvent = ref(null)
const integrityValue = ref('')
const recordStatus = ref('')
const lastEventMs = ref(0)
const failedSegment = ref(null)
const loadingPage = ref(false)
const pageError = ref('')
const displayMode = ref('text')
// 圖形連線第二層（X11 名稱與十六進位）；只在本頁記憶體，不寫瀏覽器儲存
const showKeyCodes = ref(false)
const reasonOpen = ref(false)

const fmtNum = (n) => Number(n).toLocaleString()

const GRAPHICS_PROTOCOLS = ['rdp', 'vnc']
const isKeyEventKind = (k) => k === KIND_KEYSYM || k === KIND_KEYSYM_RAW
// 圖形連線：以連線協定判斷；連線摘要未取得時（失敗或尚在載入）以事件種類補判
const isGraphics = computed(() => GRAPHICS_PROTOCOLS.includes(session.value?.protocol)
  || events.value.some((e) => isKeyEventKind(e.kind)))

const integrity = computed(() => describeIntegrity(integrityValue.value, recordStatus.value))
const totalCount = computed(() => {
  const fromMeta = meta.value?.event_count
  if (typeof fromMeta === 'number') return Math.max(fromMeta, events.value.length)
  return events.value.length + (nextEvent.value !== null ? 1 : 0)
})
const firstLoggedText = computed(() => (firstLoggedAt.value ? formatDateTime(firstLoggedAt.value) : '-'))

const rangeText = computed(() => {
  const s = session.value
  if (!s?.start_time) return '-'
  return s.end_time
    ? `${formatDateTime(s.start_time)} → ${formatClock(s.end_time)}`
    : formatDateTime(s.start_time)
})

const lastReadableText = computed(() => {
  const list = events.value
  if (!list.length) return '-'
  return formatDateTime(list[list.length - 1].at)
})
const causeText = computed(() => {
  const c = meta.value?.failure_cause
  return c && te(`keystrokeView.failureCause.${c}`) ? t(`keystrokeView.failureCause.${c}`) : ''
})

const integrityTitle = computed(() => {
  const k = integrity.value.kind
  return k === 'truncated'
    ? t('keystrokeView.viewer.integrity.truncated', { time: lastReadableText.value })
    : t(`keystrokeView.viewer.integrity.${k}`)
})
const integrityHint = computed(() => {
  const k = integrity.value.kind
  const base = 'keystrokeView.viewer.integrity'
  switch (k) {
    case 'complete': {
      const count = typeof meta.value?.event_count === 'number' ? meta.value.event_count : events.value.length
      const size = typeof meta.value?.byte_size === 'number' ? ` ${formatBytes(meta.value.byte_size)}` : ''
      if (isGraphics.value) {
        // 計數含系統列（與文字協定一致稱「事件」）；標點隨語系，整句放在語系檔
        return t('keystrokeView.viewer.summary.keyCountWithNote', { count: fmtNum(count) })
      }
      const head = t('keystrokeView.viewer.summary.countSize', { count: fmtNum(count), size: size.trim() || '-' })
      return `${head}；${t(`${base}.completeHint`)}`
    }
    case 'truncated': return t(`${base}.truncatedHint`, { time: lastReadableText.value })
    case 'failed':
      return causeText.value ? t(`${base}.failedHint`, { cause: causeText.value }) : t(`${base}.failedHintNoCause`)
    case 'tampered':
      return failedSegment.value !== null
        ? t(`${base}.tamperedHint`, { segment: failedSegment.value + 1 })
        : t(`${base}.tamperedHintNoSegment`)
    case 'fileMissing': return t(`${base}.fileMissingBody`)
    default: return t(`${base}.${k}Hint`)
  }
})
const tailText = computed(() => {
  const k = integrity.value.kind
  const base = 'keystrokeView.viewer.tail'
  switch (k) {
    case 'recording': return t(`${base}.recording`)
    case 'incomplete': return t(`${base}.incomplete`)
    case 'truncated': return t(`${base}.truncated`, { time: lastReadableText.value })
    case 'failed': return causeText.value ? t(`${base}.failed`, { cause: causeText.value }) : t(`${base}.failedNoCause`)
    case 'tampered': return t(`${base}.tampered`)
    default: return ''
  }
})
const tailType = computed(() => {
  const k = integrity.value.kind
  if (k === 'recording') return 'info'
  if (k === 'incomplete' || k === 'truncated') return 'warning'
  return 'error'
})

const markerText = (code) => (te(`keystrokeView.viewer.marker.${code}`)
  ? t(`keystrokeView.viewer.marker.${code}`)
  : t('keystrokeView.viewer.marker.unknown', { code }))

const buildRow = (group) => {
  const ev = group.first
  const row = {
    key: `e${group.index}-${ev.seq}`,
    seq: ev.seq + 1,
    offset: formatOffsetMs(ev.t_ms),
    clock: formatClock(ev.at),
    fullTime: formatDateTime(ev.at),
    source: ev.source === 'platform' ? 'platform' : 'user',
    blocked: !!ev.blocked,
    cls: '',
    system: '',
    tokens: [],
    hex: '',
    platformHint: false,
    action: null,
    keyInfo: null,
  }
  if (ev.kind === 0x10) {
    // 系統列是紀錄內的狀態事件，不是任何人的輸入，不編號
    row.seq = '—'
    row.source = 'system'
    row.system = markerText(ev.marker)
    row.cls = 'sys'
    return row
  }
  row.hex = bytesToHex(group.bytes)
  if (ev.kind === 0x01) {
    row.tokens = bytesToTokens(group.bytes)
  } else if (isKeyEventKind(ev.kind)) {
    // 圖形按鍵：一個事件一列；查無名稱或無法解析者顯示「未知按鍵」與數值
    const dec = decodeKeyEvent(ev.kind, group.bytes)
    if (dec.keysym !== null) {
      const info = keysymName(dec.keysym)
      row.action = dec.pressed ? 'down' : 'up'
      row.keyInfo = { label: keysymLabel(info, t), x11: info.x11, hex: info.hex }
      if (!dec.pressed) row.cls = 'rel'
    } else {
      row.keyInfo = { label: null, x11: null, hex: bytesToHex(dec.raw) || '—' }
    }
  } else {
    // 尚未有解碼的事件種類：以種類碼原樣呈現
    row.tokens = [{ kind: 'ctrl', text: t('keystrokeView.viewer.unknownKind', { kind: Number(ev.kind).toString(16).toUpperCase().padStart(2, '0') }) }]
  }
  if (row.blocked) row.cls = `${row.cls} blk`.trim()
  else if (row.source === 'platform') { row.cls = `${row.cls} plt`.trim(); row.platformHint = true }
  return row
}

// 顯示列：連續輸入併成一列（呈現層合併，事件計數不變），夾頁分隔線。
// 事件多時以 content-visibility 讓畫面外的列不佈局
const rows = computed(() => {
  const out = []
  const starts = new Map(pages.value.map((p, i) => [p.startIndex, { n: i + 1, time: formatDateTime(p.at) }]))
  const groups = mergeEventRows(events.value, { breakAt: new Set(starts.keys()) })
  groups.forEach((g) => {
    if (starts.has(g.index)) out.push({ key: `p${g.index}`, divider: starts.get(g.index) })
    out.push(buildRow(g))
  })
  return out
})

const showEnd = computed(() => integrity.value.kind === 'complete' && nextEvent.value === null && events.value.length > 0)
const endText = computed(() => t(pages.value.length > 1 ? 'keystrokeView.viewer.tail.end' : 'keystrokeView.viewer.tail.allOnePage', { n: fmtNum(totalCount.value) }))

const applyPage = (data, loggedAt, replace) => {
  const incoming = Array.isArray(data?.events) ? data.events : []
  events.value = replace ? incoming : events.value.concat(incoming)
  pages.value = replace
    ? [{ at: loggedAt, startIndex: 0 }]
    : pages.value.concat([{ at: loggedAt, startIndex: events.value.length - incoming.length }])
  nextEvent.value = Number.isInteger(data?.next_event) ? data.next_event : null
  integrityValue.value = data?.integrity || ''
  recordStatus.value = data?.record_status || ''
  lastEventMs.value = Number(data?.last_event_ms) || 0
  failedSegment.value = Number.isInteger(data?.failed_segment) ? data.failed_segment : null
}

const errorReason = (err) => {
  const c = classifyKeystrokeError(err)
  return t(`keystrokeView.error.${c.kind}.title`)
}

const loadNext = async () => {
  if (loadingPage.value || nextEvent.value === null) return
  loadingPage.value = true
  pageError.value = ''
  const n = pages.value.length + 1
  try {
    const res = await viewKeystrokes(sessionId, { reason: reason.value, from_event: nextEvent.value, limit: PAGE_LIMIT })
    applyPage(res?.data, new Date(), false)
  } catch (err) {
    const c = classifyKeystrokeError(err)
    if (c.kind === 'noPermission') { wipe(); goBack(); return }
    pageError.value = t('keystrokeView.viewer.paging.failed', { n, reason: errorReason(err) })
  } finally {
    loadingPage.value = false
  }
}

// 紀錄中：沿用本次理由從頭重送（每次都留一筆查看紀錄）
const refresh = async () => {
  if (loadingPage.value) return
  loadingPage.value = true
  try {
    const res = await viewKeystrokes(sessionId, { reason: reason.value, limit: PAGE_LIMIT })
    applyPage(res?.data, new Date(), true)
    firstLoggedAt.value = new Date()
  } catch (err) {
    const c = classifyKeystrokeError(err)
    if (c.kind === 'noPermission') { wipe(); goBack(); return }
    pageError.value = t('keystrokeView.viewer.paging.failed', { n: pages.value.length + 1, reason: errorReason(err) })
  } finally {
    loadingPage.value = false
  }
}

const startFrom = (held) => {
  reason.value = held.reason
  firstLoggedAt.value = held.loggedAt || new Date()
  applyPage(held.data, firstLoggedAt.value, true)
  phase.value = 'ready'
}
const onReenterSuccess = ({ reason: r, data, loggedAt }) => startFrom({ reason: r, data, loggedAt })
const reenter = () => { reasonOpen.value = true }

// 連線摘要與紀錄中繼資料：失敗不影響已取得的內容，只少顯示欄位
const loadSupport = async () => {
  // 連線詳情端點回傳本體即會話物件（不包 data），與 SessionDetail 相同
  try { session.value = (await getSession(sessionId)) ?? null } catch { session.value = null }
  try { meta.value = (await getKeystrokeMeta(sessionId))?.data ?? null } catch { meta.value = null }
}

const wipe = () => {
  events.value = []
  pages.value = []
  reason.value = ''
  nextEvent.value = null
  clearKeystrokeView()
}
const goBack = () => {
  wipe()
  router.push({ name: 'SessionDetail', params: { id: sessionId } })
}

onMounted(() => {
  const held = takeKeystrokeView(sessionId)
  if (held) {
    startFrom({ reason: held.reason, data: held.firstPage?.data, loggedAt: held.firstPage?.loggedAt })
  } else {
    phase.value = 'needReason'
  }
  void loadSupport()
})
onBeforeUnmount(wipe)
</script>

<style scoped>
.keystroke-viewer { display: flex; flex-direction: column; gap: 16px; }
.state-card { display: flex; flex-direction: column; align-items: center; gap: 10px; padding: 28px 16px; border: 1px solid var(--ot-border); border-radius: 10px; background: var(--ot-bg-card, transparent); text-align: center; }
.state-icon { color: var(--ot-text-secondary); }
.state-icon.danger { color: var(--ot-danger, #e5604f); }
.state-title { font-size: 15px; font-weight: 600; color: var(--ot-text-primary); }
.state-body { color: var(--ot-text-secondary); line-height: 1.65; max-width: 640px; }
.state-actions { display: flex; gap: 10px; margin-top: 6px; }
.summary-grid { display: grid; grid-template-columns: 1.25fr 1fr 1fr; gap: 12px; }
.sbox { border: 1px solid var(--ot-border); border-radius: 8px; padding: 12px 14px; display: flex; flex-direction: column; gap: 6px; min-width: 0; font-size: 13px; line-height: 1.6; }
.slabel { font-size: 12.5px; color: var(--ot-text-secondary); }
.shint { font-size: 12.5px; color: var(--ot-text-secondary); }
.kv { display: grid; grid-template-columns: 64px 1fr; gap: 2px 10px; margin: 0; }
.kv dt { color: var(--ot-text-secondary); }
.kv dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
.reason-text { white-space: pre-wrap; overflow-wrap: anywhere; font-size: 14px; }
.toolbar { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
.toolbar-left, .toolbar-right { display: flex; align-items: center; gap: 12px; }
.section-title { font-size: 15px; font-weight: 600; }
.legend-hidden { visibility: hidden; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 12.5px; color: var(--ot-text-secondary); align-items: center; }
.ev-table { border: 1px solid var(--ot-border); border-radius: 8px; overflow: hidden; font-size: 13px; }
.ev-row { display: grid; grid-template-columns: 72px 104px 96px 88px 1fr; content-visibility: auto; contain-intrinsic-size: auto 38px; border-bottom: 1px solid var(--ot-border); }
.ev-row > div { padding: 9px 12px; min-width: 0; display: flex; align-items: center; gap: 6px; }
.ev-row:last-child { border-bottom: none; }
.ev-head { background: var(--ot-bg-subtle, rgba(127, 127, 127, 0.1)); color: var(--ot-text-secondary); font-weight: 500; content-visibility: visible; }
.ev-row.blk { background: rgba(229, 96, 79, 0.07); }
.ev-row.plt { background: rgba(122, 165, 255, 0.06); }
.ev-row.sys { background: rgba(127, 127, 127, 0.08); color: var(--ot-text-secondary); }
.ev-row .content { flex-wrap: wrap; }
.ev-divider { padding: 8px 12px; font-size: 12.5px; color: var(--ot-text-secondary); text-align: center; border-bottom: 1px solid var(--ot-border); background: var(--ot-bg-subtle, rgba(127, 127, 127, 0.06)); }
.dim { color: var(--ot-text-secondary); }
.muted { color: var(--ot-text-secondary); }
.mono, .k1, .hx, .cc { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.k1 { white-space: pre-wrap; overflow-wrap: anywhere; }
.hx { font-size: 12.5px; word-spacing: 2px; overflow-wrap: anywhere; }
.cc { display: inline-block; background: rgba(217, 169, 62, 0.18); color: #c58e12; border: 1px solid rgba(217, 169, 62, 0.35); border-radius: 3px; padding: 0 3px; margin: 0 1px; font-size: 12px; line-height: 17px; }
.inline-hint { margin-left: 8px; }
.act { display: inline-block; padding: 0 6px; border: 1px solid var(--ot-border); border-radius: 3px; font-size: 12px; line-height: 18px; color: var(--ot-text-primary); }
.ev-row.rel .act, .ev-row.rel .kcap, .ev-row.rel .kcode { color: var(--ot-text-secondary); }
.kcap { display: inline-block; padding: 0 7px; border: 1px solid var(--ot-border); border-radius: 4px; background: var(--ot-bg-subtle, rgba(127, 127, 127, 0.1)); font-size: 12.5px; line-height: 20px; white-space: nowrap; }
.kcap.unknown { border-style: dashed; }
.kcode { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; color: var(--ot-text-secondary); overflow-wrap: anywhere; }
.tail-end { padding: 14px 16px; border: 1px dashed var(--ot-border); border-radius: 8px; text-align: center; color: var(--ot-text-secondary); font-size: 13px; }
.pager { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 16px; border: 1px dashed var(--ot-border); border-radius: 8px; text-align: center; }
.pager.failed { border-color: rgba(229, 96, 79, 0.5); }
.pager-error { color: var(--ot-danger, #e5604f); }
@media (max-width: 900px) { .summary-grid { grid-template-columns: 1fr; } }
</style>
