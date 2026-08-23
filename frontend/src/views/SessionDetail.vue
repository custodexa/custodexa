<template>
  <div class="session-detail">
    <!-- 共用 PageHeader（左對齊，與全站一致） -->
    <PageHeader
      :title="$t('sessionDetail.title')"
      :description="!loading && session ? `Session ID: ${session.id}` : ''"
    >
      <template #actions>
        <el-button @click="goBack">
          <el-icon><Back /></el-icon>
          {{ $t('sessionDetail.backToList') }}
        </el-button>
        <el-button
          v-if="session?.has_recording"
          type="primary"
          :loading="downloading"
          @click="handleDownload"
        >
          <el-icon><Download /></el-icon>
          {{ $t('sessionDetail.downloadRecording') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- Loading State -->
    <div
      v-if="loading"
      class="state-container"
    >
      <el-icon
        class="is-loading"
        :size="40"
        style="color: var(--ot-text-disabled)"
      >
        <Loading />
      </el-icon>
      <p class="state-text">
        {{ $t('sessionDetail.loading') }}
      </p>
    </div>

    <!-- Error State -->
    <div
      v-else-if="error"
      class="state-container"
    >
      <el-result
        icon="error"
        :title="$t('sessionDetail.loadFailedTitle')"
        :sub-title="error"
      >
        <template #extra>
          <el-button
            type="primary"
            @click="goBack"
          >
            {{ $t('sessionDetail.backToList') }}
          </el-button>
          <el-button @click="fetchSessionDetail">
            {{ $t('sessionDetail.retry') }}
          </el-button>
        </template>
      </el-result>
    </div>

    <!-- Content -->
    <div
      v-else
      class="content"
    >
      <!-- Session Metadata Card -->
      <div class="info-card">
        <div class="card-header">
          <span class="card-title">{{ $t('sessionDetail.infoTitle') }}</span>
          <el-tag :type="getStatusTagType(session.status)">
            {{ getStatusText(session.status) }}
          </el-tag>
        </div>

        <el-descriptions
          :column="2"
          border
        >
          <el-descriptions-item :label="$t('common.user')">
            {{ session.user?.username || '-' }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('common.protocol')">
            <el-tag :type="protocolTagType(session.protocol)">
              {{ session.protocol.toUpperCase() }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('common.asset')">
            {{ session.asset?.name || '-' }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('sessionDetail.host')">
            {{ session.asset?.host || '-' }}:{{ session.asset?.port || '-' }}
          </el-descriptions-item>
          <!-- 連線帳號：連線當下的 username 快照，
               帳號日後改名／刪除不改寫此欄 -->
          <el-descriptions-item :label="$t('sessionDetail.account')">
            <span
              v-if="session.account_username"
              class="account-cell"
            >{{ session.account_username }}</span>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('sessions.clientIp')">
            {{ session.client_ip || '-' }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('sessionDetail.recordingStatus')">
            <!-- 錄影失敗誠實標示：
                 失敗與「本來就無錄製」是兩回事，須帶原因可辨 -->
            <el-tooltip
              v-if="session.recording_error"
              :content="$t('sessions.recordingErrorTooltip', { error: auditCauseLabel(session.recording_error) })"
              placement="top"
            >
              <el-tag type="danger">
                {{ $t('sessionDetail.noRecordingFailed') }}
              </el-tag>
            </el-tooltip>
            <el-tag
              v-else-if="session.has_recording"
              type="success"
            >
              <el-icon><VideoPlay /></el-icon>
              {{ $t('sessionDetail.hasRecording') }}
            </el-tag>
            <el-tag
              v-else
              type="info"
            >
              {{ $t('sessionDetail.noRecording') }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('sessions.startTime')">
            {{ formatDateTime(session.start_time) }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('sessions.endTime')">
            {{ formatDateTime(session.end_time) }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('sessions.duration')">
            {{ formatDurationSeconds(session.duration) }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('sessions.endReason')">
            <el-tag
              v-if="session.status !== 'active'"
              :type="getEndReasonTagType(session.end_reason)"
            >
              {{ getEndReasonText(session.end_reason) }}
            </el-tag>
            <span v-else>-</span>
          </el-descriptions-item>
        </el-descriptions>
      </div>

      <!-- 回放定位提示：帶 ?t= 進來時**一律**
           給出結果，含做不到的情形。靜默忽略會讓稽核以為畫面上就是那一刻。
           `:description` 不可省：el-alert 的描述段以 `$slots.default || description`
           決定是否渲染，而具名 slot 由「無 → 有」時（提示先出現、播放器稍後才回報落點）
           不會讓 el-alert 重新求值 `$slots.default`，補充說明會整段消失（實測）。
           綁上 description 讓它隨資料變動，slot 只負責掛 data-test 與樣式 -->
      <el-alert
        v-if="seek.present"
        :type="seek.level"
        :closable="false"
        show-icon
        class="seek-alert"
        data-test="seek-notice"
        :title="seek.message"
        :description="seek.detail || ''"
      >
        <template
          v-if="seek.detail"
          #default
        >
          <span data-test="seek-detail">{{ seek.detail }}</span>
        </template>
      </el-alert>

      <!-- Recording Player Card -->
      <div
        v-if="session.has_recording"
        ref="playerCardRef"
        class="player-card"
      >
        <div class="card-header">
          <span class="card-title">{{ $t('sessionDetail.playbackTitle') }}</span>
          <el-tag type="success">
            {{ $t('sessionDetail.protocolRecording', { protocol: session.protocol.toUpperCase() }) }}
          </el-tag>
        </div>

        <!-- 文字終端錄製回放（SSH 與資料庫 CLI，asciicast 格式） -->
        <div
          v-if="isTextTerminal(session.protocol)"
          class="player-wrapper"
        >
          <!-- 等 recordingUrl（一次性 token 取得後才有值）就緒才掛載播放器，
               避免對空 URL 初始化導致 asciinema 抓到 SPA index.html、解析失敗的殘留錯誤層 -->
          <AsciinemaPlayer
            v-if="recordingUrl"
            :recording-url="recordingUrl"
            :auto-play="false"
            :start-at="startAtSeconds"
            @start-at-applied="onStartAtApplied"
          />
          <EmptyState
            v-else-if="session.has_recording"
            :title="$t('sessionDetail.recordingLoadingTitle')"
            :hint="$t('sessionDetail.recordingLoadingHint')"
          />
        </div>

        <!-- RDP/VNC Recording Player (Guacamole native format) -->
        <div
          v-else-if="session.protocol === 'rdp' || session.protocol === 'vnc'"
          class="player-wrapper"
        >
          <GuacamolePlayer
            :recording-url="recordingStreamUrl"
            :auto-play="false"
            :start-at="startAtSeconds"
            @start-at-applied="onStartAtApplied"
          />
        </div>

        <!-- Other Protocols -->
        <div
          v-else
          class="player-placeholder"
        >
          <el-result
            icon="info"
            :title="$t('sessionDetail.unsupportedTitle')"
            :sub-title="$t('sessionDetail.unsupportedSubtitle', { protocol: session.protocol.toUpperCase() })"
          >
            <template #extra>
              <el-button
                type="primary"
                @click="handleDownload"
              >
                <el-icon><Download /></el-icon>
                {{ $t('sessionDetail.downloadRecording') }}
              </el-button>
            </template>
          </el-result>
        </div>
      </div>

      <!-- Command Records Card (SSH only, hidden when empty) -->
      <div
        v-if="showCommands"
        class="commands-card"
      >
        <div class="card-header">
          <div class="card-title-group">
            <span class="card-title">{{ $t('sessionDetail.commandsTitle') }}</span>
            <span class="card-note">{{ $t('sessionDetail.commandsNote') }}</span>
          </div>
          <div class="card-tag-group">
            <el-tag type="info">
              {{ $t('sessionDetail.commandCount', { n: commands.length }) }}
            </el-tag>
            <!-- 無法還原的輪次另計：混在總數裡會讓「N 筆指令」聽起來像 N 筆都有內容 -->
            <el-tag
              v-if="degradedCount > 0"
              type="warning"
              data-test="degraded-count"
            >
              {{ $t('sessionDetail.degradedCount', { n: degradedCount }) }}
            </el-tag>
          </div>
        </div>

        <el-table
          :data="commands"
          stripe
          style="width: 100%"
        >
          <el-table-column
            prop="seq"
            :label="$t('sessionDetail.seqColumn')"
            width="80"
          />
          <el-table-column
            prop="executed_at"
            :label="$t('common.time')"
            width="180"
          >
            <template #default="{ row }">
              {{ formatDateTime(row.executed_at) }}
            </template>
          </el-table-column>
          <el-table-column
            prop="command"
            :label="$t('commands.commandColumn')"
            min-width="300"
            show-overflow-tooltip
          >
            <template #default="{ row }">
              <CommandCell
                :row="row"
                :recording-state="commandRecordingState"
                @seek="seekToCommand"
              />
            </template>
          </el-table-column>
        </el-table>
      </div>

      <!-- No Recording Card -->
      <div
        v-if="!session.has_recording"
        class="no-recording-card"
      >
        <EmptyState
          :title="$t('sessionDetail.noRecordingContent')"
        >
          <template #action>
            <el-button
              type="primary"
              @click="goBack"
            >
              {{ $t('sessionDetail.backToList') }}
            </el-button>
          </template>
        </EmptyState>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  Back,
  Download,
  Loading,
  VideoPlay,
} from '@element-plus/icons-vue'
import PageHeader from '@/components/PageHeader.vue'
import AsciinemaPlayer from '@/components/AsciinemaPlayer.vue'
import GuacamolePlayer from '@/components/GuacamolePlayer.vue'
import EmptyState from '@/components/EmptyState.vue'
import CommandCell from '@/components/audit/CommandCell.vue'
import { isDegradedRow } from '@/constants/command-degrade'
import { getSession, getRecordingUrl, getRecordingToken, recordingStreamUrlByToken, downloadRecording } from '@/api/sessions'
import { getSessionCommands } from '@/api/commands'
import { isTextTerminal, protocolTagType } from '@/utils/protocol'
import { getEndReasonText, getEndReasonTagType } from '@/utils/end-reason'
import { formatDateTime, formatDurationSeconds } from '@/utils/format'
import { t } from '@/i18n'
// recording_error 存機器碼（cause code），
// 散文僅存量資料才有——auditCauseLabel 未知值原樣回傳，兩者共存不需分支
import { auditCauseLabel } from '@/constants/audit-enums'

const route = useRoute()
const router = useRouter()

const sessionId = route.params.id
const loading = ref(true)
const error = ref(null)
const session = ref(null)
const downloading = ref(false)
const commands = ref([])

const playerCardRef = ref(null)

// 文字終端會話（SSH/資料庫 CLI）且有指令資料時顯示指令記錄卡
const showCommands = computed(
  () => isTextTerminal(session.value?.protocol) && commands.value.length > 0
)

// 無法還原的輪次數（degraded 列）。與指令總數分開呈現
const degradedCount = computed(() => commands.value.filter(isDegradedRow).length)

// 降級列能不能給「查看該時段錄影」這個下一步：沒有錄影就不能，文案須據實改口
const commandRecordingState = computed(() =>
  session.value?.has_recording && hasPlayer.value ? 'available' : 'unavailable'
)

// ---------------------------------------------------------------------------
// 回放定位錨點（?t=）
//
// 工作台送來的 t 是「事件時刻 − 會話 StartTime」的秒數，但回放的 elapsed=0 是
// **錄影起點**，兩者不同源。正確落點 p = t − (recording_started_at −
// start_time)；直接 seek(t) 的誤差恆等於那個差，方向依協議而異：
//   文字終端 錄影晚於建檔（差為正）→ 未校正**偏晚、衝過目標指令**（危險側）；
//   圖形     guacd 握手早於建檔（差為負）→ 未校正偏早。
// 該欄位缺席（存量資料）時退回未校正值並在提示中明說，不假裝已校正。
// ---------------------------------------------------------------------------
const queryValue = (key) => {
  const raw = Array.isArray(route.query?.[key]) ? route.query[key][0] : route.query?.[key]
  return raw === undefined || raw === null || raw === '' ? null : raw
}
const rawSeekParam = queryValue('t')
const seekParamPresent = rawSeekParam !== null
// `at`＝事件的**絕對時刻**（RFC3339）。跨會話的指令審計頁沒有會話起點這個欄位，
// 送相對秒數會逼它先查一次會話；改送絕對時刻，換算留在這一頁（起點就在手上）。
// 兩者並存時 `t` 優先，行為固定不看順序。
const rawAtParam = queryValue('at')

// 頁內手動定位（點降級列的「查看該時段錄影」）。設值即覆蓋 URL 帶進來的錨點
const manualOffsetSeconds = ref(null)

const parseOffsetParam = (raw) => {
  const v = Number(raw)
  return Number.isFinite(v) && v >= 0 ? v : null
}

// `at` → 相對會話起點的秒數。會話載入前算不出來（回 null，此時尚不判定合法性）
const atOffsetSeconds = computed(() => {
  if (rawAtParam === null || !session.value?.start_time) return null
  const at = new Date(rawAtParam).getTime()
  const start = new Date(session.value.start_time).getTime()
  if (Number.isNaN(at) || Number.isNaN(start)) return null
  return Math.max(0, (at - start) / 1000)
})

// 事件相對「會話起點」的秒數；null＝缺席或非法
const eventOffsetSeconds = computed(() => {
  if (manualOffsetSeconds.value !== null) return manualOffsetSeconds.value
  if (seekParamPresent) return parseOffsetParam(rawSeekParam)
  return atOffsetSeconds.value
})

const seekAnchorPresent = computed(
  () => manualOffsetSeconds.value !== null || seekParamPresent || rawAtParam !== null
)

const seekAnchorInvalid = computed(() => {
  if (manualOffsetSeconds.value !== null) return false
  if (seekParamPresent) return parseOffsetParam(rawSeekParam) === null
  if (rawAtParam !== null) {
    if (Number.isNaN(new Date(rawAtParam).getTime())) return true
    // 會話還沒載入時無從換算，先不判非法（載入後才有結論）
    return session.value?.start_time ? atOffsetSeconds.value === null : false
  }
  return false
})

// 播放器實際落點的回報（`applied` 是播放器**實際停在**的位置，不是請求值；
// 越界時 clamped=true）
const seekOutcome = ref(null)
const onStartAtApplied = (payload) => {
  seekOutcome.value = payload
}

// 錄影起點與會話起點的差（秒）。null＝無法校正
const recordingSkewSeconds = computed(() => {
  const s = session.value
  if (!s?.recording_started_at || !s?.start_time) return null
  const rec = new Date(s.recording_started_at).getTime()
  const start = new Date(s.start_time).getTime()
  if (Number.isNaN(rec) || Number.isNaN(start)) return null
  return (rec - start) / 1000
})

// 本協議是否有回放能力（無播放器的協議做不到定位，須誠實處理）
const hasPlayer = computed(() => {
  const p = session.value?.protocol
  return isTextTerminal(p) || p === 'rdp' || p === 'vnc'
})

// 傳給播放器的定位秒數（錄影自身時間軸）。null＝不定位
const startAtSeconds = computed(() => {
  const offset = eventOffsetSeconds.value
  if (offset === null || !session.value?.has_recording || !hasPlayer.value) {
    return null
  }
  const skew = recordingSkewSeconds.value
  if (skew === null) return offset
  return Math.max(0, offset - skew)
})

// 秒數 → MM:SS。**取整方式與播放器的時間顯示一致（無條件捨去）**：四捨五入會讓
// 提示上的落點比播放器時鐘多出一秒，讀者無從判斷哪個才是真的落點。
const formatOffset = (seconds) => {
  const total = Math.max(0, Math.floor(Number(seconds) || 0))
  const mins = Math.floor(total / 60)
  const secs = total % 60
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
}

// 落點與請求值的偏差要不要說出來的門檻（秒）。MM:SS 顯示的解析度是 1 秒，
// 低於 1 秒的偏差在畫面上看不出來，也不影響讀者判讀哪一幕。
const SEEK_DRIFT_TOLERANCE_SECONDS = 1

// 偏差秒數的呈現：留一位小數，不假裝整秒（落點本身就不是整秒）
const formatDrift = (seconds) => String(Math.round(Math.abs(seconds) * 10) / 10)

// 提示文案：一律以「前後」表述，不宣稱精確
const seek = computed(() => {
  if (!seekAnchorPresent.value) return { present: false }
  if (seekAnchorInvalid.value) {
    return { present: true, level: 'warning', message: t('sessionDetail.seekInvalid') }
  }
  if (!session.value) return { present: false }
  if (!session.value.has_recording) {
    return { present: true, level: 'warning', message: t('sessionDetail.seekNoRecording') }
  }
  if (!hasPlayer.value) {
    return {
      present: true,
      level: 'warning',
      message: t('sessionDetail.seekUnsupported', {
        protocol: String(session.value.protocol).toUpperCase(),
      }),
    }
  }
  const uncorrected =
    recordingSkewSeconds.value === null ? t('sessionDetail.seekUncorrected') : ''
  if (!seekOutcome.value) {
    return { present: true, level: 'info', message: t('sessionDetail.seekPending'), detail: uncorrected }
  }
  if (seekOutcome.value.clamped) {
    return { present: true, level: 'warning', message: t('sessionDetail.seekBeyond'), detail: uncorrected }
  }
  // 實際落點與請求值的偏差：錄影是離散幀（圖形協議的 `.guac` 在畫面靜止時可以數十秒
  // 無幀），落點只能是某一幀。偏差本身不是缺陷，**看不見才是**——尤其落在目標**之後**
  // 代表目標事件可能已經播過去，而畫面不會告訴讀者這件事。
  const drift = Number(seekOutcome.value.applied) - Number(seekOutcome.value.requested)
  const driftNotice =
    Number.isFinite(drift) && Math.abs(drift) >= SEEK_DRIFT_TOLERANCE_SECONDS
      ? t(drift > 0 ? 'sessionDetail.seekDriftAfter' : 'sessionDetail.seekDriftBefore', {
        seconds: formatDrift(drift),
      })
      : ''
  return {
    present: true,
    // 落在目標之後＝可能已錯過該事件，須升為警示；落在之前只是提示
    level: driftNotice && drift > 0 ? 'warning' : 'success',
    message: t('sessionDetail.seekApplied', { time: formatOffset(seekOutcome.value.applied) }),
    detail: [driftNotice, uncorrected].filter(Boolean).join(' '),
  }
})

// 降級列的下一步：把回放定位到該輪的時刻。**錄影可能保留該時段畫面，但不保證**
//（回顯被關閉的那一類連錄影都沒有畫面），故文案在 CommandCell 內按原因碼分流，
// 這裡只負責定位與回報落點——落點由既有的 seek 提示誠實回報（含越界、偏差）。
const seekToCommand = (row) => {
  const startTime = session.value?.start_time
  if (!row?.executed_at || !startTime) return
  const offset =
    (new Date(row.executed_at).getTime() - new Date(startTime).getTime()) / 1000
  if (!Number.isFinite(offset)) return
  const target = Math.max(0, offset)
  // 同一個錨點再點一次不重設回報狀態，否則提示會卡在「定位中」
  if (manualOffsetSeconds.value !== target) {
    seekOutcome.value = null
    manualOffsetSeconds.value = target
  }
  const el = playerCardRef.value
  if (el && typeof el.scrollIntoView === 'function') {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }
}

// 錄影串流 URL（asciinema/SSH）：改用一次性、不透明的錄影 token，
// URL 不再含長效登入 JWT（JWT 會被 gin access log 完整記下）。
// asciinema 播放器只能吃 URL、無法加 header，故走短時效 token 而非 Bearer。
const recordingUrl = ref('')

async function loadRecordingUrl() {
  recordingUrl.value = ''
  if (!session.value || !session.value.has_recording) {
    return
  }
  try {
    const { token } = await getRecordingToken(session.value.id)
    recordingUrl.value = recordingStreamUrlByToken(token)
  } catch (err) {
    console.error('[SessionDetail] 取得錄影 token 失敗:', err)
  }
}

// Computed recording stream URL for RDP (guacamole player - uses fetch with Bearer token)
const recordingStreamUrl = computed(() => {
  if (!session.value || !session.value.has_recording) {
    return ''
  }
  // GuacamolePlayer will use fetch with Authorization header
  return getRecordingUrl(session.value.id)
})

// Fetch session detail
const fetchSessionDetail = async () => {
  try {
    loading.value = true
    error.value = null

    console.log('[SessionDetail] 載入 Session:', sessionId)

    const response = await getSession(sessionId)
    session.value = response

    console.log('[SessionDetail] Session 載入成功:', session.value)

    if (!session.value.has_recording) {
      ElMessage.warning(t('sessionDetail.noRecordingContent'))
    }

    // 文字終端會話載入指令記錄（失敗不影響詳情頁）
    if (isTextTerminal(session.value.protocol)) {
      fetchCommands()
      loadRecordingUrl()
    }
  } catch (err) {
    console.error('[SessionDetail] 載入失敗:', err)

    if (err.response?.status === 404) {
      error.value = t('sessionDetail.notFound')
    } else if (err.response?.status === 403) {
      error.value = t('sessionDetail.noPermission')
    } else {
      error.value = err.message || t('sessionDetail.loadFailed')
    }

  } finally {
    loading.value = false
  }
}

// Fetch SSH command records (best-effort; failures stay silent)
const fetchCommands = async () => {
  try {
    const response = await getSessionCommands(sessionId)
    commands.value = response.data || []
  } catch (err) {
    console.error('[SessionDetail] 載入指令記錄失敗:', err)
    commands.value = []
  }
}

// Handle download recording
const handleDownload = async () => {
  if (!session.value || !session.value.has_recording) {
    ElMessage.warning(t('sessionDetail.noRecordingContent'))
    return
  }

  try {
    downloading.value = true

    console.log('[SessionDetail] 下載錄製檔案:', sessionId)

    const blob = await downloadRecording(sessionId)

    // Create download link
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url

    // Generate filename
    const filename = `session-${sessionId}-${session.value.protocol}.cast`
    link.download = filename

    // Trigger download
    document.body.appendChild(link)
    link.click()

    // Cleanup
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)

    ElMessage.success(t('sessionDetail.downloaded'))
  } catch (err) {
    console.error('[SessionDetail] 下載失敗:', err)
  } finally {
    downloading.value = false
  }
}

// Go back to list
const goBack = () => {
  router.push('/sessions')
}

// Status tag type
const getStatusTagType = (status) => {
  const typeMap = {
    active: 'success',
    closed: 'info',
    disconnected: 'danger',
  }
  return typeMap[status] || ''
}

// Status text（i18n：閉集走 enum.sessionStatus、未知值原樣顯示）
const SESSION_STATUS_VALUES = ['active', 'closed', 'disconnected']
const getStatusText = (status) =>
  SESSION_STATUS_VALUES.includes(status) ? t(`enum.sessionStatus.${status}`) : status

// Lifecycle
onMounted(() => {
  fetchSessionDetail()
})
</script>

<style scoped>
.session-detail {
  max-width: 1400px;
  margin: 0 auto;
}

/* .content 已有 flex gap，此處不再加 margin，避免與 gap 疊加成雙倍間距 */
.seek-alert {
  margin: 0;
}

.account-cell {
  font-family: var(--ot-font-mono, monospace);
}

.state-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 400px;
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.state-text {
  margin-top: var(--ot-space-md);
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-secondary);
}

.content {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}

.info-card,
.player-card,
.commands-card {
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-md);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--ot-space-md);
}

.card-title {
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.card-title-group {
  display: flex;
  align-items: baseline;
  gap: var(--ot-space-sm);
}

.card-tag-group {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.card-note {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.player-wrapper {
  width: 100%;
  background: var(--ot-terminal-bg);
  border-radius: var(--ot-radius-md);
  overflow: hidden;
}

.player-placeholder {
  min-height: 400px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.no-recording-card {
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  min-height: 300px;
  display: flex;
  align-items: center;
  justify-content: center;
}
</style>
