<template>
  <div
    ref="pageRef"
    class="session-detail"
  >
    <!-- 共用 PageHeader（左對齊，與全站一致） -->
    <PageHeader
      :title="$t('sessionDetail.title')"
      :description="!loading && session ? `Session ID: ${session.id}` : ''"
    >
      <template #actions>
        <el-button @click="goBack">
          <el-icon><ArrowLeft /></el-icon>
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
        <LoaderCircle />
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
              <el-icon><CirclePlay /></el-icon>
              {{ $t('sessionDetail.hasRecording') }}
            </el-tag>
            <el-tag
              v-else
              type="info"
            >
              {{ $t('sessionDetail.noRecording') }}
            </el-tag>
          </el-descriptions-item>
          <!-- 離機保存（evidence-offsite-storage）：錄影狀態旁的第二個事實——
               「這份證據有沒有離開這台機器」。
               **不渲染的判準是帳冊零列**而非「有無現行世代」：
               停止離機後仍有帳冊列的會話照常渲染，否則關閉後的取回失敗無處可見。
               本頁拿不到全域帳冊列數（離機端點全為 admin），故判準收斂為
               「這一列自己有帳冊態」或「admin 讀到設定表非空」——讀不到就不宣稱 -->
          <el-descriptions-item
            v-if="offsiteVisible"
            :label="$t('sessionDetail.offsiteStatus')"
          >
            <el-tooltip
              :content="offsiteTooltip"
              placement="top"
            >
              <el-tag
                :type="offsiteTagType"
                data-test="offsite-status"
              >
                {{ $t(`offsite.state.${offsiteStatus || 'none'}`) }}
              </el-tag>
            </el-tooltip>
            <!-- 重試是列內動作故走 link（C2）。integrity_mismatch 的重試語義＝
                 以本機檔重傳，本機無檔時做不到，故停用並說明 -->
            <el-button
              v-if="offsiteRetryable"
              type="primary"
              link
              size="small"
              :disabled="!offsiteRetryEnabled"
              :loading="offsiteRetrying"
              data-test="offsite-retry"
              @click="handleOffsiteRetry"
            >
              {{ $t('offsite.retry') }}
            </el-button>
            <span
              v-if="offsiteRetryable && !offsiteRetryEnabled"
              class="offsite-retry-hint"
              data-test="offsite-retry-hint"
            >{{ $t('offsite.retryNeedsLocalFile') }}</span>
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

        <!-- 主控台的錄影是轉錄而非畫面重播：稽核員若以為看到的是全部，
             會把「錄影裡沒有」讀成「沒發生」 -->
        <el-alert
          v-if="session.db_console"
          class="recording-note"
          type="info"
          show-icon
          :closable="false"
          data-test="console-recording-note"
          :title="$t('sessionDetail.consoleRecordingNote')"
        />

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
            <!-- 兩種載體的來源不同：命令列的文字重組自按鍵流，主控台的列是
                 語句送出時登記的原文。同一句話對兩邊都說即有一邊是假的 -->
            <span class="card-note">{{ isConsoleSession
              ? $t('sessionDetail.consoleCommandsNote')
              : $t('sessionDetail.commandsNote') }}</span>
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
            width="70"
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
            min-width="220"
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
          <!-- 主控台會話才有的結果事實。命令列會話這幾欄恆空，
               整組不渲染比逐格顯示 '-' 誠實 -->
          <template v-if="isConsoleSession">
            <el-table-column
              :label="$t('sessionDetail.targetDatabaseColumn')"
              width="130"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                {{ row.target_database || '-' }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessionDetail.resultStatusColumn')"
              width="130"
            >
              <template #default="{ row }">
                <el-tag
                  v-if="row.result_status"
                  :type="consoleStatusTagType(row)"
                  data-test="result-status"
                >
                  {{ consoleStatusLabel(row) }}
                </el-tag>
                <span v-else>-</span>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessionDetail.resultReasonColumn')"
              width="130"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                {{ row.result_reason ? resultReasonLabel(row.result_reason) : '-' }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessionDetail.resultRowsColumn')"
              width="90"
            >
              <template #default="{ row }">
                {{ consoleRowsText(row) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessionDetail.durationColumn')"
              width="90"
            >
              <template #default="{ row }">
                {{ row.duration_ms === null || row.duration_ms === undefined
                  ? '-' : $t('sessionDetail.durationMs', { n: row.duration_ms }) }}
              </template>
            </el-table-column>
            <!-- 事件識別是主控台的深連結錨點：結果未知橫幅指回這一格 -->
            <el-table-column
              :label="$t('sessionDetail.eventIdColumn')"
              width="230"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                <span
                  v-if="row.event_id"
                  :id="`cmd-${row.event_id}`"
                  :title="row.event_id"
                  class="event-id-cell"
                  :class="{ 'is-anchored': anchoredEventId === row.event_id }"
                  data-test="event-id"
                >{{ row.event_id }}</span>
                <span v-else>-</span>
              </template>
            </el-table-column>
          </template>
        </el-table>
      </div>

      <!-- Clipboard Records Card（調閱面：列表只給事實，按「解密調閱」才解密單筆。
           無事件不渲染整卡——空殼區塊會讓「沒有剪貼簿流量」看起來像功能壞掉 -->
      <div
        v-if="showClipboard"
        id="clipboard"
        ref="clipboardCardRef"
        class="clipboard-card"
        data-test="clipboard-card"
      >
        <div class="card-header">
          <div class="card-title-group">
            <span class="card-title">{{ $t('sessionDetail.clipboardTitle') }}</span>
            <!-- 按鍵＝解密＝留痕，事先講明：稽核員不該在不知情下留下調閱紀錄 -->
            <span class="card-note">{{ $t('sessionDetail.clipboardNote') }}</span>
          </div>
          <div class="card-tag-group">
            <el-tag type="info">
              {{ $t('sessionDetail.clipboardCount', { n: clipboardEvents.length }) }}
            </el-tag>
            <!-- 缺口筆數另計：混在總數裡會讓「N 筆」聽起來像 N 筆都能調閱 -->
            <el-tag
              v-if="clipboardFailedCount > 0"
              type="warning"
              data-test="clipboard-failed-count"
            >
              {{ $t('sessionDetail.clipboardFailedCount', { n: clipboardFailedCount }) }}
            </el-tag>
          </div>
        </div>

        <el-table
          ref="clipboardTableRef"
          :data="clipboardEvents"
          stripe
          row-key="id"
          style="width: 100%"
        >
          <el-table-column type="expand">
            <template #default="{ row }">
              <!-- 缺口列：展開給失敗說明而非呼端點——內容不存在，呼了也只是
                   多一筆「交付了空無」的留痕；說明要講清楚「事件存在、內容缺席」 -->
              <div
                v-if="row.content_status !== 'available'"
                class="clipboard-expand"
              >
                <el-alert
                  type="warning"
                  :closable="false"
                  show-icon
                  :title="$t('sessionDetail.clipboardStatus.failed')"
                  :description="$t('sessionDetail.clipboardGapDetail')"
                  data-test="clipboard-gap-detail"
                />
              </div>
              <div
                v-else
                class="clipboard-expand"
                data-test="clipboard-content-pane"
              >
                <div
                  v-if="clipboardContentState[row.id]?.loading"
                  class="clipboard-content-loading"
                  data-test="clipboard-content-loading"
                >
                  <el-icon class="is-loading">
                    <LoaderCircle />
                  </el-icon>
                  {{ $t('sessionDetail.clipboardContentLoading') }}
                </div>
                <el-alert
                  v-else-if="clipboardContentState[row.id]?.error"
                  type="error"
                  :closable="false"
                  show-icon
                  :title="$t('sessionDetail.clipboardContentError')"
                  data-test="clipboard-content-error"
                >
                  <el-button
                    size="small"
                    data-test="clipboard-content-retry"
                    @click="loadClipboardContent(row)"
                  >
                    {{ $t('common.retry') }}
                  </el-button>
                </el-alert>
                <template v-else-if="clipboardContentState[row.id]?.loaded">
                  <!-- 留痕回饋：內容之上先講「這一次調閱已經被記下來了」，
                       時刻＝前端收到內容的時刻（語義為調閱時刻）。
                       沒有這一行，解密內容看起來就跟本來就是明文一樣 -->
                  <div
                    class="clipboard-access-logged"
                    data-test="clipboard-access-logged"
                  >
                    <el-icon><CircleCheck /></el-icon>
                    {{ $t('sessionDetail.clipboardAccessLogged', {
                      time: clipboardAccessTimeText(clipboardContentState[row.id]?.accessedAt),
                    }) }}
                  </div>
                  <pre
                    class="clipboard-content"
                    data-test="clipboard-content"
                  >{{ clipboardContentState[row.id]?.content }}</pre>
                </template>
                <!-- 尚未解密：展開只給「上鎖」狀態，不直載內容。
                     展開本身不呼端點，唯一的解密入口是列上的「解密調閱」鍵 -->
                <div
                  v-else
                  class="clipboard-locked"
                  data-test="clipboard-locked-hint"
                >
                  <el-icon><Lock /></el-icon>
                  {{ $t('sessionDetail.clipboardLockedHint') }}
                </div>
              </div>
            </template>
          </el-table-column>
          <el-table-column
            prop="created_at"
            :label="$t('common.time')"
            width="180"
          >
            <template #default="{ row }">
              {{ formatDateTime(row.created_at) }}
            </template>
          </el-table-column>
          <el-table-column
            prop="direction"
            :label="$t('sessionDetail.clipboardDirectionColumn')"
            min-width="200"
          >
            <template #default="{ row }">
              {{ clipboardDirectionText(row.direction) }}
            </template>
          </el-table-column>
          <el-table-column
            prop="content_length"
            :label="$t('sessionDetail.clipboardLengthColumn')"
            width="140"
            align="right"
          />
          <el-table-column
            :label="$t('sessionDetail.clipboardStatusColumn')"
            width="160"
          >
            <template #default="{ row }">
              <el-tag
                v-if="row.content_status === 'available'"
                type="success"
                size="small"
              >
                {{ $t('sessionDetail.clipboardStatus.available') }}
              </el-tag>
              <el-tag
                v-else
                type="warning"
                size="small"
                data-test="clipboard-status-failed"
              >
                {{ $t('sessionDetail.clipboardStatus.failed') }}
              </el-tag>
            </template>
          </el-table-column>
          <!-- 調閱欄：鎖頭圖示標明「內容是加密留存的」，解密要按鍵才發生。
               缺口列不給鍵——內容不存在，按了只會留下「交付了空無」的紀錄 -->
          <el-table-column
            :label="$t('sessionDetail.clipboardActionColumn')"
            width="170"
          >
            <template #default="{ row }">
              <div
                v-if="row.content_status === 'available'"
                class="clipboard-action"
              >
                <el-icon
                  class="clipboard-lock"
                  data-test="clipboard-lock-icon"
                >
                  <Lock />
                </el-icon>
                <el-button
                  size="small"
                  type="primary"
                  plain
                  :loading="clipboardContentState[row.id]?.loading"
                  data-test="clipboard-decrypt-btn"
                  @click="revealClipboardContent(row)"
                >
                  {{ $t('sessionDetail.clipboardDecryptButton') }}
                </el-button>
              </div>
              <span
                v-else
                class="clipboard-action-none"
                data-test="clipboard-action-none"
              >—</span>
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
import { ref, reactive, computed, onMounted, onBeforeUnmount, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  ArrowLeft,
  CircleCheck,
  Download,
  LoaderCircle,
  Lock,
  CirclePlay,
} from 'lucide-vue-next'
import PageHeader from '@/components/PageHeader.vue'
import AsciinemaPlayer from '@/components/AsciinemaPlayer.vue'
import GuacamolePlayer from '@/components/GuacamolePlayer.vue'
import EmptyState from '@/components/EmptyState.vue'
import CommandCell from '@/components/audit/CommandCell.vue'
import { isDegradedRow } from '@/constants/command-degrade'
import { getSession, getRecordingUrl, getRecordingToken, recordingStreamUrlByToken, downloadRecording } from '@/api/sessions'
import { getSessionCommands } from '@/api/commands'
import { getSessionClipboardEvents, getClipboardEventContent } from '@/api/clipboardEvents'
import { isTextTerminal, protocolTagType } from '@/utils/protocol'
import { getEndReasonText, getEndReasonTagType } from '@/utils/end-reason'
import { formatDateTime, formatDurationSeconds } from '@/utils/format'
import { t, currentLocale } from '@/i18n'
// recording_error 存機器碼（cause code），
// 散文僅存量資料才有——auditCauseLabel 未知值原樣回傳，兩者共存不需分支
import { auditCauseLabel } from '@/constants/audit-enums'
import {
  resultStatusLabel,
  resultStatusTagType,
  resultReasonLabel,
} from '@/constants/db-console'
import { isKnownOffsiteStatus, offsiteStatusTagType } from '@/constants/offsite'
import { getOffsiteSettings, retryOffsiteObject } from '@/api/offsiteStorage'
import { useRoles } from '@/composables/useRoles'

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

// ---------------------------------------------------------------------------
// 查詢主控台會話的結果事實（db-query-console）
// ---------------------------------------------------------------------------

const isConsoleSession = computed(() => session.value?.db_console === true)

// 會話已經結束，列卻還停在 running：那不是「執行中」，是結果沒有回填。
// 照字面顯示會讓稽核員把「不知道」讀成「還在跑」
const isUnsettledRow = (row) =>
  row.result_status === 'running' && session.value?.status !== 'active'

const consoleStatusLabel = (row) =>
  isUnsettledRow(row)
    ? t('sessionDetail.resultUnsettled')
    : resultStatusLabel(row.result_status)

const consoleStatusTagType = (row) =>
  isUnsettledRow(row) ? 'warning' : resultStatusTagType(row.result_status)

// 查詢回列數、寫入回影響列數，兩者互斥出現；都沒有＝不適用或未回填
const consoleRowsText = (row) => {
  if (row.result_rows !== null && row.result_rows !== undefined) return String(row.result_rows)
  if (row.rows_affected !== null && row.rows_affected !== undefined) {
    return t('sessionDetail.rowsAffected', { n: row.rows_affected })
  }
  return '-'
}

// `#cmd-<event_id>` 深連結：主控台的「結果未知」橫幅指回這一列
const anchoredEventId = ref('')
const ANCHOR_TICK_BUDGET = 4

const anchorConsoleEvent = async () => {
  const hash = route.hash || ''
  if (!hash.startsWith('#cmd-')) return
  const eventId = hash.slice('#cmd-'.length)
  if (!commands.value.some((c) => c.event_id === eventId)) return
  anchoredEventId.value = eventId
  // 自頁面根節點查起而非 document：詳情頁可能掛在未接上 document 的容器裡，
  // 那時 getElementById 會回 null、定位靜默落空。
  // 表格的列渲染不在同一個 tick 完成，單次 nextTick 會撲空——多等幾拍再放棄
  let el = null
  for (let i = 0; i < ANCHOR_TICK_BUDGET && !el; i += 1) {
    await nextTick()
    el = pageRef.value?.querySelector(`[id="cmd-${eventId}"]`)
  }
  if (el && typeof el.scrollIntoView === 'function') {
    el.scrollIntoView({ block: 'center' })
  }
}

// ---------------------------------------------------------------------------
// 離機保存狀態（evidence-offsite-storage）
// ---------------------------------------------------------------------------

const { isAdmin } = useRoles()
const offsiteRetrying = ref(false)
// 設定表是否非空（`configured`）。**三態**：null＝還沒讀到／讀不到（本頁不宣稱）、
// true／false＝伺服端事實。只有 admin 讀得到離機端點，故非 admin 恆為 null。
//
// 為什麼用 `/offsite-storage/settings` 而不是 `/status`：後者會對現行世代發
// `ProbeBucket` 遠端探測，把它掛在會話詳情的載入路徑上，成本與收益不相稱
const offsiteConfigured = ref(null)

const offsiteStatus = computed(() => {
  const raw = session.value?.offsite_status ?? ''
  // 未知值不顯示裸機器碼：值域是前端閉集（constants/offsite.js 硬拷後端）
  return isKnownOffsiteStatus(raw) ? raw : ''
})

// 帳冊零列＝整項不渲染。這一列自己有帳冊態時恆渲染（含停用態的 foreign），
// `''`（未排入）則要靠「設定表非空」才能斷言——讀不到就不渲染，
// 不把「我不知道」呈現成「尚未排入」
const offsiteVisible = computed(() => {
  if (!session.value) return false
  if (offsiteStatus.value !== '') return true
  return offsiteConfigured.value === true
})

const offsiteTagType = computed(() => offsiteStatusTagType(offsiteStatus.value))

const offsiteTooltip = computed(() => t(`offsite.stateHint.${offsiteStatus.value || 'none'}`))

// 重試只對「卡住的兩態」開放，且只有 admin 打得通端點（後端才是強制點）
const OFFSITE_RETRYABLE_STATES = ['failed', 'integrity_mismatch']
const offsiteRetryable = computed(
  () => isAdmin.value && OFFSITE_RETRYABLE_STATES.includes(offsiteStatus.value)
)
// 重試＝以**本機檔**重傳同一個 key；本機沒有檔就沒有可傳的東西
const offsiteRetryEnabled = computed(() => session.value?.has_recording === true)

const fetchOffsiteConfigured = async () => {
  if (!isAdmin.value) return
  try {
    const res = await getOffsiteSettings({ skipErrorToast: true })
    offsiteConfigured.value = res?.configured === true
  } catch {
    // 讀不到＝不知道，維持 null（fail-safe：不宣稱本頁驗證不了的事）
    offsiteConfigured.value = null
  }
}

const handleOffsiteRetry = async () => {
  const objectId = session.value?.offsite_object_id
  if (!objectId) return
  offsiteRetrying.value = true
  try {
    await retryOffsiteObject(objectId)
    ElMessage.success(t('offsite.retryQueued', { count: 1 }))
    const response = await getSession(sessionId)
    session.value = response
  } catch (err) {
    console.error('[SessionDetail] 離機重試失敗:', err?.message)
  } finally {
    offsiteRetrying.value = false
  }
}

// ---------------------------------------------------------------------------
// 剪貼簿調閱面（按鍵才解密）
//
// 列表只給事實（時間、方向、長度、狀態），按「解密調閱」才呼單筆端點解密——
// 「指定閱讀」語義：按鍵即解密即留痕（伺服器端逐筆審計，fail-close）。
//
// 為何不再「展開即直載」（使用者實走後裁決）：展開後內容直接出現，讀起來
// 就像那些內容本來就是明文躺著，稽核員感受不到自己剛做了一次受控解密、也不
// 知道這次調閱已經留痕。故改成鎖頭＋按鍵的顯式動作，並在內容之上回報留痕。
//
// 無事件不渲染整卡；`#clipboard` 錨點供工作台時間軸一鍵抵達。
// ---------------------------------------------------------------------------
const clipboardEvents = ref([])
const clipboardCardRef = ref(null)
const clipboardTableRef = ref(null)
// 每筆解密內容的載入狀態（key＝事件 id）。收合再展開、或再按一次解密鍵都不
// 重複呼叫：內容已在手上，重呼只會多出一筆語義相同的調閱留痕
const clipboardContentState = reactive({})

// 調閱時刻只取時分秒：同一列左邊已經有「事件時刻」，帶完整日期的第二個時間
// 反而容易被讀成事件時間。hour12: false 沿審計場景的 24h 慣例（見 format.js）。
// 這裡就地格式化而非進 format.js：全站僅此一處需要純時分秒，
// state 存的仍是 raw timestamp、render 期才格式化（切語言會跟著重繪）
const CLIPBOARD_ACCESS_TIME_OPTIONS = {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
}
const clipboardAccessTimeText = (ts) => {
  if (!ts) return ''
  const date = new Date(ts)
  if (!Number.isFinite(date.getTime())) return ''
  return new Intl.DateTimeFormat(currentLocale(), CLIPBOARD_ACCESS_TIME_OPTIONS).format(date)
}

const showClipboard = computed(() => clipboardEvents.value.length > 0)

// 缺口（內容留存失敗）筆數。判準用 content_status 明確欄位，
// 不以長度為零或內容為空推斷（spec：SHALL NOT 以空值推斷）
const clipboardFailedCount = computed(
  () => clipboardEvents.value.filter((e) => e.content_status !== 'available').length
)

// 方向值域閉集查譯、未知值原樣顯示（與 getStatusText 同型防禦）
const CLIPBOARD_DIRECTION_VALUES = ['send', 'recv']
const clipboardDirectionText = (direction) =>
  CLIPBOARD_DIRECTION_VALUES.includes(direction)
    ? t(`sessionDetail.clipboardDirection.${direction}`)
    : direction

// 載入事實列表（best-effort；失敗不影響詳情頁——與指令記錄同準則）。
// 資料就緒後才處理 #clipboard 錨點：卡片以資料驅動渲染，
// DOM 尚不存在時捲動只會靜默落空
const fetchClipboardEvents = async () => {
  try {
    const response = await getSessionClipboardEvents(sessionId)
    clipboardEvents.value = response.data || []
  } catch (err) {
    console.error('[SessionDetail] 載入剪貼簿記錄失敗:', err)
    clipboardEvents.value = []
  }
  if (clipboardEvents.value.length > 0 && route.hash === '#clipboard') {
    await nextTick()
    anchorClipboardCard()
  }
}

// ---------------------------------------------------------------------------
// #clipboard 錨點捲動
//
// 首捲發生在剪貼簿資料就緒當下，但上方佈局還在長高：播放器等 recordingUrl
// 才掛載、terminal/guac 容器掛載後才定高、指令表格與定位提示也晚於首捲。
// 瀏覽器會把捲動量 clamp 在「當時的」最大值，卡片隨後被推到視窗外且無人補捲
//（實證：帶 ?t= 進頁 cardTop=1058 > viewport 900）。
// 修法：首捲後以 ResizeObserver 盯住頁面根元素，佈局每動一次就補捲，
// 佈局靜默 SETTLE_MS 或總計 MAX_MS 即收工；使用者一有捲動意圖
//（滾輪/觸控/按鍵）立即停手，不與人搶捲軸。
//
// 兩項刻意選擇，都是踩過才知道的（修復波第二輪，瀏覽器實測）：
//   1. 首捲用 instant 而非 smooth。深連結落地本就該直接到位（原生 #fragment
//      即如此）；smooth 期間補捲會蓋掉動畫，等於每次都在跟自己搶捲軸。
//   2. **不跳過首個 RO 回報**。ResizeObserver 會把回報批次合併：長高若發生在
//      observe 之後、首次回報派送之前，那次長高就併在「首個回報」裡。曾以
//      `initialReport` 無條件跳過首報（為了不蓋掉 smooth），結果是長高落在首批
//      時唯一的補捲機會被吃掉、其後再無回報，卡片停在視窗外——實測 /sessions/10
//      不帶 ?t= 連開六次重現 2 次（cardTop 809、卡底 1003 > 視窗 900）。
//      補捲是冪等的（捲到同一處），寧可多捲一次也不要漏掉那一次。
// ---------------------------------------------------------------------------
const pageRef = ref(null)
const CLIPBOARD_ANCHOR_SETTLE_MS = 400
const CLIPBOARD_ANCHOR_MAX_MS = 3000
let stopClipboardAnchorWatch = null

const anchorClipboardCard = () => {
  const el = clipboardCardRef.value
  if (!el || typeof el.scrollIntoView !== 'function') return
  el.scrollIntoView({ block: 'start' })
  if (typeof ResizeObserver === 'undefined' || !pageRef.value) return
  stopClipboardAnchorWatch?.()
  let settleTimer = null
  let maxTimer = null
  let observer = null
  const cancelEvents = ['wheel', 'touchmove', 'keydown']
  const stop = () => {
    observer?.disconnect()
    observer = null
    clearTimeout(settleTimer)
    clearTimeout(maxTimer)
    cancelEvents.forEach((type) => window.removeEventListener(type, stop))
    stopClipboardAnchorWatch = null
  }
  const armSettle = () => {
    clearTimeout(settleTimer)
    settleTimer = setTimeout(stop, CLIPBOARD_ANCHOR_SETTLE_MS)
  }
  observer = new ResizeObserver(() => {
    el.scrollIntoView({ block: 'start' })
    armSettle()
  })
  observer.observe(pageRef.value)
  armSettle()
  maxTimer = setTimeout(stop, CLIPBOARD_ANCHOR_MAX_MS)
  cancelEvents.forEach((type) => window.addEventListener(type, stop, { passive: true }))
  stopClipboardAnchorWatch = stop
}

onBeforeUnmount(() => {
  stopClipboardAnchorWatch?.()
})

// 呼單筆端點載入解密內容。載入中／失敗態都要看得見；
// 失敗給重試鍵，不靜默留一格空白
const loadClipboardContent = async (row) => {
  if (!clipboardContentState[row.id]) {
    clipboardContentState[row.id] = {
      loading: false,
      error: false,
      loaded: false,
      content: null,
      accessedAt: null,
    }
  }
  // 賦值後必須**重讀** proxy：`(obj[k] = {...})` 運算式回傳的是 raw 物件，
  // 對 raw 寫入不經 reactive set 攔截、不觸發重渲染——載入完成後畫面會
  // 永卡「正在解密內容…」直到任何無關重渲染才更新
  const state = clipboardContentState[row.id]
  state.loading = true
  state.error = false
  try {
    const response = await getClipboardEventContent(sessionId, row.id)
    state.content = response.data?.content ?? ''
    // 調閱時刻＝前端收到內容的時刻。伺服器端的審計時戳才是權威紀錄，
    // 這裡回報的是「這一次動作」發生的當下，供人對得上自己剛做了什麼
    state.accessedAt = Date.now()
    state.loaded = true
  } catch (err) {
    console.error('[SessionDetail] 載入剪貼簿內容失敗:', err)
    state.error = true
  } finally {
    state.loading = false
  }
}

// 「解密調閱」鍵：唯一的解密入口。展開列本身不再觸發任何請求——
// 沒按鍵就沒解密、沒留痕。按鍵先把該列展開（內容要有地方顯示），
// 內容已在手上時只展開不重呼：同一份內容不該留下第二筆調閱紀錄
const revealClipboardContent = async (row) => {
  if (row.content_status !== 'available') return
  clipboardTableRef.value?.toggleRowExpansion?.(row, true)
  const state = clipboardContentState[row.id]
  if (state?.loaded || state?.loading) return
  await loadClipboardContent(row)
}

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

    // 剪貼簿事實列表：不分協議一律查（卡片以資料驅動——有事件才渲染；
    // 綁協議判斷會在後端擴協議時靜默漏卡）
    fetchClipboardEvents()
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
  await anchorConsoleEvent()
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
  // 與會話讀取獨立：離機設定讀不到不得吞掉會話詳情
  fetchOffsiteConfigured()
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

.recording-note {
  margin-bottom: var(--ot-space-md);
}

/* 事件識別要能被選取複製；深連結落點另加底色，否則捲到了也看不出是哪一列 */
.event-id-cell {
  font-family: var(--ot-font-mono, monospace);
  font-size: 12px;
  user-select: all;
}

.event-id-cell.is-anchored {
  padding: 1px 4px;
  border-radius: 3px;
  background: var(--el-color-warning-light-8);
}

/* 重試不可用的理由必須與被停用的按鈕相鄰：只把按鈕變灰等於沒說 */
.offsite-retry-hint {
  margin-left: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
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
.commands-card,
.clipboard-card {
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-md);
}

/* 展開面：內容全文與缺口說明的容器 */
.clipboard-expand {
  padding: var(--ot-space-sm) var(--ot-space-md);
}

/* 內容全文：等寬、pre-wrap（保留換行與空白但不撐破版面）。
   長內容限高內捲——單筆上限 64KB，攤平會把整頁推走 */
.clipboard-content {
  margin: 0;
  font-family: var(--ot-font-mono, monospace);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 320px;
  overflow-y: auto;
  background: var(--ot-bg-elevated);
  border-radius: var(--ot-radius-md);
  padding: var(--ot-space-sm);
}

.clipboard-content-loading {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

/* 留痕回饋：貼在內容正上方，讓「已解密」與「已留痕」同時進眼 */
.clipboard-access-logged {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  margin-bottom: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

/* 未解密的展開面：上鎖狀態，講清楚解密要按鍵才發生 */
.clipboard-locked {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.clipboard-action {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.clipboard-lock {
  color: var(--ot-text-secondary);
}

.clipboard-action-none {
  color: var(--ot-text-tertiary, var(--ot-text-secondary));
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
