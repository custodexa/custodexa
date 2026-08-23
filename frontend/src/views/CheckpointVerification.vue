<template>
  <div class="checkpoint-verification">
    <PageHeader
      :title="$t('menu.checkpointVerification')"
      :description="$t('checkpointVerification.headerDesc')"
    >
      <template #actions>
        <el-button @click="loadAll">
          <el-icon><Refresh /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!--
      降級橫幅（spec：SHALL NOT 可被關閉或摺疊至不可見）。
      :closable="false" 是規範要求而非樣式選擇——沒有離機備份時，本地鏈的
      證明力有一個結構性缺口，使用者不得在不知情下讀鏈健康總覽。

      三段式（為什麼需要／怎麼啟用／既有缺口如何處置）是刻意的：標題只描述
      部署狀態而不恐嚇後果，且不得只講後果不給行動——稽核讀到「可被整套換掉」
      卻沒有下一步，會把部署未完成誤讀成設計缺陷
    -->
    <el-alert
      v-if="chain && chain.anchor_disabled"
      class="degrade-banner"
      type="warning"
      :closable="false"
      show-icon
      :title="$t('checkpointVerification.degraded.title')"
    >
      <p data-test="degraded-why">
        {{ $t('checkpointVerification.degraded.why') }}
      </p>
      <p data-test="degraded-action">
        {{ $t('checkpointVerification.degraded.action') }}
      </p>
      <p data-test="degraded-gap">
        {{ $t('checkpointVerification.degraded.gap') }}
      </p>
    </el-alert>

    <!-- 鏈健康總覽 -->
    <div class="panel">
      <div class="panel-title">
        {{ $t('checkpointVerification.overview.title') }}
      </div>
      <el-alert
        v-if="loadError"
        type="error"
        :closable="false"
        show-icon
        :title="$t('checkpointVerification.loadFailed')"
        :description="loadError"
        class="load-error"
      />
      <el-descriptions
        v-loading="loadingChain"
        :column="3"
        border
      >
        <el-descriptions-item :label="$t('checkpointVerification.overview.structureStatus')">
          <el-tag
            :type="statusTagType(chain?.status)"
            data-test="chain-status"
          >
            {{ statusLabel(chain?.status) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item :label="$t('checkpointVerification.overview.total')">
          {{ chain?.total ?? '-' }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('checkpointVerification.overview.latestSeq')">
          {{ chain?.latest_seq ?? '-' }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('checkpointVerification.overview.passedFailed')">
          {{ chain?.passed ?? '-' }} / {{ chain?.failed ?? '-' }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('checkpointVerification.overview.oldestSeq')">
          {{ chain?.oldest_seq ?? '-' }}
          <span
            v-if="chain?.trimmed_through_seq"
            class="muted"
          >
            {{ $t('checkpointVerification.overview.trimmedThrough', { seq: chain.trimmed_through_seq }) }}
          </span>
        </el-descriptions-item>
        <el-descriptions-item :label="$t('checkpointVerification.overview.unsealed')">
          <span data-test="unsealed-rows">{{ chain?.unsealed_rows ?? '-' }}</span>
          <span class="muted">
            {{ $t('checkpointVerification.overview.unsealedHint', { id: chain?.unsealed_from_id ?? '-' }) }}
          </span>
        </el-descriptions-item>
      </el-descriptions>

      <el-table
        v-if="chain?.failures?.length"
        :data="chain.failures"
        class="failure-table"
        size="small"
        stripe
      >
        <el-table-column
          prop="seq"
          label="seq"
          width="90"
        />
        <el-table-column
          :label="$t('checkpointVerification.table.status')"
          width="200"
        >
          <template #default="{ row }">
            <el-tag :type="statusTagType(row.status)">
              {{ statusLabel(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          prop="detail"
          :label="$t('checkpointVerification.table.detail')"
        />
      </el-table>
    </div>

    <!--
      自動驗證的運作狀態。

      **必須看得見**：偵測控制若在畫面上不存在，稽核只能假設它沒在跑；而排程器
      靜默停擺時不會有任何告警（沒跑就沒有異常可報），兩層各自的最近執行時點是
      唯一能讓人看出「它其實沒在運作」的訊號。

      **同樣必須看得見的是它不是證明**：本區塊的數值不在鏈的覆蓋範圍內，可被
      資料庫直寫改成「最近驗過、全數通過」。那句話寫在區塊最前面而非註解裡——
      寫在註解裡的誠實，稽核讀不到。

      狀態取不到時顯示明說取不到的橫幅，**不隱藏整個區塊**：看不到區塊的人
      會讀成「沒有這個機制」，那比顯示一個取不到值的區塊更糟。
    -->
    <div
      class="panel"
      data-test="auto-verify"
    >
      <div class="panel-title">
        {{ $t('checkpointVerification.autoVerify.title') }}
      </div>
      <p
        class="muted block"
        data-test="auto-verify-not-evidence"
      >
        {{ $t('checkpointVerification.autoVerify.notEvidence') }}
      </p>

      <el-alert
        v-if="!autoVerify"
        type="info"
        :closable="false"
        show-icon
        data-test="auto-verify-unavailable"
        :title="$t('checkpointVerification.autoVerify.unavailable')"
      />
      <template v-else>
        <div class="section-title">
          {{ $t('checkpointVerification.autoVerify.recentTitle') }}
        </div>
        <p class="muted block">
          {{ $t('checkpointVerification.autoVerify.recentDesc') }}
        </p>
        <el-descriptions
          :column="3"
          border
        >
          <el-descriptions-item :label="$t('checkpointVerification.autoVerify.lastRun')">
            <span data-test="auto-verify-recent-run">{{ runAtLabel(autoVerify.recent_last_run_at) }}</span>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('checkpointVerification.autoVerify.result')">
            <el-tag
              :type="resultTagType(autoVerify.recent_last_status)"
              data-test="auto-verify-recent-result"
            >
              {{ resultLabel(autoVerify.recent_last_status) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('checkpointVerification.autoVerify.window')">
            <span data-test="auto-verify-window">{{ windowLabel }}</span>
          </el-descriptions-item>
        </el-descriptions>

        <div class="section-title">
          {{ $t('checkpointVerification.autoVerify.fullTitle') }}
        </div>
        <p class="muted block">
          {{ $t('checkpointVerification.autoVerify.fullDesc') }}
        </p>
        <el-descriptions
          :column="3"
          border
        >
          <el-descriptions-item :label="$t('checkpointVerification.autoVerify.lastRun')">
            <span data-test="auto-verify-full-run">{{ runAtLabel(autoVerify.full_last_run_at) }}</span>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('checkpointVerification.autoVerify.result')">
            <el-tag
              :type="resultTagType(autoVerify.full_last_status)"
              data-test="auto-verify-full-result"
            >
              {{ resultLabel(autoVerify.full_last_status) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('checkpointVerification.autoVerify.interval')">
            <span data-test="auto-verify-interval">{{ intervalLabel }}</span>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('checkpointVerification.autoVerify.progress')">
            <span data-test="auto-verify-progress">{{ autoVerify.content_cursor_seq || '-' }}</span>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('checkpointVerification.autoVerify.cycle')">
            <span data-test="auto-verify-cycle">{{ cycleLabel }}</span>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('checkpointVerification.autoVerify.lastCycle')">
            {{ runAtLabel(autoVerify.last_full_cycle_at) }}
          </el-descriptions-item>
        </el-descriptions>

        <el-descriptions
          class="open-failed"
          :column="1"
          border
        >
          <el-descriptions-item :label="$t('checkpointVerification.autoVerify.openFailed')">
            <el-tag
              :type="autoVerify.open_failed_intervals > 0 ? 'danger' : 'success'"
              data-test="auto-verify-open-failed"
            >
              {{ autoVerify.open_failed_intervals ?? 0 }}
            </el-tag>
            <span class="muted">
              {{ $t('checkpointVerification.autoVerify.openFailedHint') }}
            </span>
          </el-descriptions-item>
        </el-descriptions>
      </template>
    </div>

    <!-- 範圍內容驗證 -->
    <div
      ref="contentPanelRef"
      class="panel"
    >
      <div class="panel-title">
        {{ $t('checkpointVerification.content.title') }}
      </div>
      <p class="muted">
        {{ $t('checkpointVerification.content.hint') }}
      </p>
      <!-- 調查頁帶入的範圍：**只預填、不自動執行**。成本以一次刻意的點擊被看見 -->
      <el-alert
        v-if="prefillApplied"
        type="info"
        :closable="false"
        show-icon
        class="prefill-note"
        data-test="range-prefilled"
        :title="$t('checkpointVerification.content.prefilled')"
      />
      <el-alert
        v-if="prefillIgnored"
        type="warning"
        :closable="false"
        show-icon
        class="prefill-note"
        data-test="range-prefill-ignored"
        :title="$t('checkpointVerification.content.prefillIgnored')"
      />
      <div class="range-bar">
        <el-input-number
          v-model="seqFrom"
          :min="1"
          :controls="false"
          class="seq-input"
          data-test="seq-from"
          :placeholder="$t('checkpointVerification.content.seqFrom')"
        />
        <span class="range-sep">-</span>
        <el-input-number
          v-model="seqTo"
          :min="1"
          :controls="false"
          class="seq-input"
          data-test="seq-to"
          :placeholder="$t('checkpointVerification.content.seqTo')"
        />
        <el-button
          type="primary"
          :loading="loadingContent"
          data-test="run-content"
          @click="runContentVerify"
        >
          {{ $t('checkpointVerification.content.run') }}
        </el-button>
      </div>
      <el-alert
        v-if="contentError"
        type="error"
        :closable="false"
        show-icon
        :title="contentError"
        class="load-error"
      />
      <el-table
        v-if="content"
        :data="content.intervals"
        class="content-table"
        size="small"
        stripe
      >
        <el-table-column
          prop="seq"
          label="seq"
          width="90"
        />
        <el-table-column
          :label="$t('checkpointVerification.table.range')"
          width="180"
        >
          <template #default="{ row }">
            [{{ row.id_from }}, {{ row.id_to }}]
          </template>
        </el-table-column>
        <el-table-column
          prop="row_count"
          :label="$t('checkpointVerification.table.rowCount')"
          width="110"
        />
        <el-table-column
          prop="remain_rows"
          :label="$t('checkpointVerification.table.remainRows')"
          width="110"
        />
        <el-table-column
          :label="$t('checkpointVerification.table.anchor')"
          width="120"
        >
          <template #default="{ row }">
            {{ anchorLabel(row.anchor_status) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('checkpointVerification.table.status')">
          <template #default="{ row }">
            <el-tag :type="statusTagType(row.status)">
              {{ statusLabel(row.status) }}
            </el-tag>
            <span class="muted">{{ statusHint(row.status) }}</span>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 檢查點清單 -->
    <div class="panel">
      <div class="panel-title">
        {{ $t('checkpointVerification.list.title') }}
      </div>
      <el-table
        v-loading="loadingList"
        :data="checkpoints"
        size="small"
        stripe
      >
        <el-table-column
          prop="seq"
          label="seq"
          width="90"
        />
        <el-table-column
          :label="$t('checkpointVerification.table.range')"
          width="180"
        >
          <template #default="{ row }">
            [{{ row.id_from }}, {{ row.id_to }}]
          </template>
        </el-table-column>
        <el-table-column
          prop="row_count"
          :label="$t('checkpointVerification.table.rowCount')"
          width="110"
        />
        <el-table-column
          :label="$t('checkpointVerification.table.sealedAt')"
          width="200"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.sealed_at) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('checkpointVerification.table.anchor')"
          width="140"
        >
          <template #default="{ row }">
            {{ anchorLabel(row.anchor_status) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('checkpointVerification.table.purged')">
          <template #default="{ row }">
            <span v-if="row.purged_at">
              {{ $t('checkpointVerification.list.purgedAt', { at: formatDateTime(row.purged_at) }) }}
            </span>
            <span
              v-else
              class="muted"
            >-</span>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination
        v-if="listTotal > pageSize"
        class="pager"
        layout="prev, pager, next"
        :total="listTotal"
        :page-size="pageSize"
        :current-page="page"
        @current-change="onPageChange"
      />
    </div>

    <!-- 公鑰（離線驗章入口） -->
    <div class="panel">
      <div class="panel-title">
        {{ $t('checkpointVerification.publicKey.title') }}
      </div>
      <p class="muted">
        {{ $t('checkpointVerification.publicKey.hint') }}
      </p>
      <el-descriptions
        v-if="publicKey"
        :column="2"
        border
      >
        <el-descriptions-item :label="$t('checkpointVerification.publicKey.algorithm')">
          {{ publicKey.algorithm }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('checkpointVerification.publicKey.version')">
          v{{ publicKey.version }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('checkpointVerification.publicKey.fingerprint')">
          <code>{{ publicKey.fingerprint }}</code>
        </el-descriptions-item>
        <el-descriptions-item :label="$t('checkpointVerification.publicKey.value')">
          <code class="pubkey">{{ publicKey.public_key }}</code>
        </el-descriptions-item>
      </el-descriptions>
    </div>

    <!--
      保護範圍與邊界聲明（spec「檢查點鏈的保護範圍與邊界聲明」）。
      **不是免責條款而是產品的一部分**：每一條都對應一個本機制防不了的
      攻擊面，讀者據此判斷還需要哪些外部控制。

      呈現順序是規範要求而非版面偏好：保護範圍 SHALL 在邊界之前——稽核先讀到
      本機制證明什麼，後面的邊界才會被讀成範圍界定，而不是一份缺陷清單。
      每條邊界亦 SHALL 同時載明「由什麼承擔」，只列防不了什麼會使讀者誤判
      整體控制失效
    -->
    <div class="panel">
      <div class="panel-title">
        {{ $t('checkpointVerification.limits.title') }}
      </div>

      <div class="section-title">
        {{ $t('checkpointVerification.limits.protectionTitle') }}
      </div>
      <ul
        class="limits"
        data-test="protection-scope"
      >
        <li
          v-for="code in PROTECTION_CODES"
          :key="code"
        >
          {{ $t(`checkpointVerification.limits.protection.${code}`) }}
        </li>
      </ul>

      <div class="section-title">
        {{ $t('checkpointVerification.limits.boundaryTitle') }}
      </div>
      <p class="muted block">
        {{ $t('checkpointVerification.limits.intro') }}
      </p>
      <ul
        class="limits"
        data-test="honest-limits"
      >
        <li
          v-for="code in LIMIT_CODES"
          :key="code"
          :data-test="`limit-${code}`"
        >
          <span class="limit-code">{{ code }}</span>
          <div class="limit-part">
            <span class="limit-label">{{ $t('checkpointVerification.limits.scenarioLabel') }}</span>
            <span :data-test="`limit-${code}-scenario`">
              <!-- 插值統一傳給每一條：只有 R5 用得到 window，其餘忽略未使用的參數 -->
              {{ $t(`checkpointVerification.limits.${code}.scenario`, { window: sealWindow }) }}
            </span>
          </div>
          <div class="limit-part">
            <span class="limit-label">{{ $t('checkpointVerification.limits.mitigationLabel') }}</span>
            <span :data-test="`limit-${code}-mitigation`">
              {{ $t(`checkpointVerification.limits.${code}.mitigation`) }}
            </span>
          </div>
        </li>
      </ul>
    </div>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { Refresh } from '@element-plus/icons-vue'
import PageHeader from '@/components/PageHeader.vue'
import { formatDateTime } from '@/utils/format'
import { resolveApiError } from '@/api/error'
import { t } from '@/i18n'
import {
  getCheckpointPublicKey,
  listCheckpoints,
  verifyChain,
  verifyCheckpointContent,
} from '@/api/auditCheckpoints'

// 保護範圍三點與邊界 R0-R6：以固定清單驅動渲染，缺任一條會在 i18n 完備性
// 守衛與頁面守衛測試同時現形（spec 要求「涵蓋 R0 至 R6」且保護範圍在前）
const PROTECTION_CODES = ['P1', 'P2', 'P3', 'P4']
const LIMIT_CODES = ['R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6']

// 九態的視覺分級。**purged_legal 不得為錯誤色**：它是系統依保留政策的
// 合法清除，染紅等於天天對自己發假警報，真的竄改反而淹沒在噪音裡
const STATUS_TAG = {
  passed: 'success',
  purged_legal: 'info',
  extra_rows_valid_hmac: 'warning',
  purged_invalid: 'danger',
  count_mismatch: 'danger',
  hash_mismatch: 'danger',
  signature_invalid: 'danger',
  chain_broken: 'danger',
  seq_gap: 'danger',
}

const chain = ref(null)
const content = ref(null)
const checkpoints = ref([])
const publicKey = ref(null)
const loadingChain = ref(false)
const loadingContent = ref(false)
const loadingList = ref(false)
const loadError = ref('')
const contentError = ref('')
const seqFrom = ref(null)
const seqTo = ref(null)
const page = ref(1)
const pageSize = ref(20)
const listTotal = ref(0)

const statusTagType = (status) => STATUS_TAG[status] || 'info'

// R5 的未封窗口上界。**取自後端回傳的現行門檻，不在文案寫死**：這兩個值
// 管理員可在安全政策頁調整，寫死的「最長一小時」會在調整後變成對稽核的
// 假陳述。尚未載入時回空字串——句子少掉括號仍是完整且為真的敘述，
// 寧可暫時少一個數字，不可先顯示一個可能錯的數字
const sealWindow = computed(() => {
  const secs = chain.value?.seal_interval_seconds
  const rows = chain.value?.seal_row_threshold
  if (!secs || !rows) return ''
  let interval
  if (secs % 3600 === 0) interval = t('checkpointVerification.limits.intervalHours', { n: secs / 3600 })
  else if (secs % 60 === 0) interval = t('checkpointVerification.limits.intervalMinutes', { n: secs / 60 })
  else interval = t('checkpointVerification.limits.intervalSeconds', { n: secs })
  return t('checkpointVerification.limits.window', { interval, rows: rows.toLocaleString() })
})
// ---------------------------------------------------------------------------
// 自動驗證的運作狀態（隨結構層報告一起回，無獨立端點）
//
// **一律以後端回傳的生效值顯示，前端不補預設**：窗口天數是政策值經保留天數
// clamp 後的結果、掃描速率是經上下界收束後的值，前端若自己算或塞預設，
// 頁面上的數字就會與系統實際跑的不一致——那正是本專案在別處拒絕的
// 「顯示值 ≠ 生效值」。取不到就顯示取不到。
// ---------------------------------------------------------------------------
const autoVerify = computed(() => chain.value?.auto_verify || null)

// 兩層各自的結果分級：未跑過（空字串）不是「通過」，故為中性色
const RESULT_TAG = { passed: 'success', failed: 'danger', error: 'warning' }
const RESULT_LABEL = {
  passed: 'resultPassed',
  failed: 'resultFailed',
  error: 'resultError',
}
const resultTagType = (s) => RESULT_TAG[s] || 'info'
const resultLabel = (s) =>
  RESULT_LABEL[s]
    ? t(`checkpointVerification.autoVerify.${RESULT_LABEL[s]}`)
    : t('checkpointVerification.autoVerify.never')

// 從未執行過要說「尚未執行過」而不是留白：留白會被讀成版面缺陷，
// 而「這一層根本沒跑過」正是本區塊最該讓人看見的狀態
const runAtLabel = (at) =>
  at ? formatDateTime(at) : t('checkpointVerification.autoVerify.never')

const windowLabel = computed(() => {
  const n = autoVerify.value?.recent_window_days_effective
  if (!n) return t('checkpointVerification.autoVerify.never')
  return t('checkpointVerification.autoVerify.windowDays', { n })
})

// 間隔沿用 R5 窗口那三支既有單位樣板（同一個系統的同一種時間量，
// 兩處各造一套用詞會讓稽核以為講的是兩件事）
const intervalLabel = computed(() => {
  const secs = autoVerify.value?.full_interval_seconds
  if (!secs) return '-'
  if (secs % 3600 === 0)
    return t('checkpointVerification.limits.intervalHours', { n: secs / 3600 })
  if (secs % 60 === 0)
    return t('checkpointVerification.limits.intervalMinutes', { n: secs / 60 })
  return t('checkpointVerification.limits.intervalSeconds', { n: secs })
})

// 繞行一輪的預估：**照實顯示，不隱藏**。逐筆重驗是十億列級的
// 掃描，任何宣稱「持續全量驗證」的設計都是在說謊或在拖垮生產庫；可調的是
// 速率與間隔，不可調的是「一定有在滾、已知異常區間每輪必重驗」
const cycleLabel = computed(() => {
  const h = autoVerify.value?.cycle_estimate_hours
  if (h === undefined || h === null) return '-'
  if (h <= 0) return t('checkpointVerification.autoVerify.cycleNone')
  if (h < 1) return t('checkpointVerification.autoVerify.cycleUnderHour')
  if (h < 48)
    return t('checkpointVerification.autoVerify.cycleHours', { n: Math.round(h) })
  return t('checkpointVerification.autoVerify.cycleDays', {
    n: Math.round(h / 24),
  })
})

const statusLabel = (status) =>
  status ? t(`checkpointVerification.status.${status}`) : '-'
const statusHint = (status) =>
  status && status !== 'passed'
    ? t(`checkpointVerification.statusHint.${status}`)
    : ''
const anchorLabel = (v) =>
  v ? t(`checkpointVerification.anchor.${v}`) : '-'

const fetchChain = async () => {
  loadingChain.value = true
  loadError.value = ''
  try {
    const res = await verifyChain()
    chain.value = res.data?.chain || null
  } catch (error) {
    console.error('結構層驗證失敗:', error)
    loadError.value = resolveApiError(
      error?.response?.data,
      error?.response?.status,
      t('common.serverError')
    )
  } finally {
    loadingChain.value = false
  }
}

const fetchList = async () => {
  loadingList.value = true
  try {
    const res = await listCheckpoints({
      page: page.value,
      page_size: pageSize.value,
    })
    checkpoints.value = res.data?.items || []
    listTotal.value = res.data?.total || 0
  } catch (error) {
    console.error('查詢檢查點列表失敗:', error)
  } finally {
    loadingList.value = false
  }
}

const fetchPublicKey = async () => {
  try {
    const res = await getCheckpointPublicKey()
    publicKey.value = res.data || null
  } catch (error) {
    console.error('取得檢查點公鑰失敗:', error)
  }
}

// 內容層：範圍為必填（後端亦擋，前端先擋是為了少一次無謂往返）
const runContentVerify = async () => {
  contentError.value = ''
  if (!seqFrom.value || !seqTo.value || seqFrom.value > seqTo.value) {
    contentError.value = t('checkpointVerification.content.rangeRequired')
    return
  }
  loadingContent.value = true
  try {
    const res = await verifyCheckpointContent({
      seq_from: seqFrom.value,
      seq_to: seqTo.value,
    })
    content.value = res.data?.content || null
    if (res.data?.chain) chain.value = res.data.chain
  } catch (error) {
    console.error('內容層驗證失敗:', error)
    contentError.value = resolveApiError(
      error?.response?.data,
      error?.response?.status,
      t('common.serverError')
    )
  } finally {
    loadingContent.value = false
  }
}

const onPageChange = (p) => {
  page.value = p
  fetchList()
}

// ---------------------------------------------------------------------------
// 調查頁帶入的範圍（?seq_from=&seq_to=）
//
// **只預填，絕不自動觸發驗證。** 三個可指認的理由：
//   1. 內容層驗證對範圍大小無上限——未清除區間要 COUNT(*)＋重算聚合＋逐列比對；
//   2. 調查頁帶來的是「已清除檢查點的最小／最大序號」，閉區間中間可能夾著
//      大量未清除區間，一次跳頁就變成無界重掃；
//   3. 這個 URL 可分享、可加書籤、可重整——自動觸發等於每開一次連結重跑一次全掃描。
// 故一律停在「已填好、等你按」，讓成本以一次刻意的點擊被看見。
// 參數名維持 seq_from／seq_to（機器介面，與後端 handler 兩端固定），
// 但畫面上一律以序號稱呼，不裸露參數名。
// ---------------------------------------------------------------------------
const prefillApplied = ref(false)
const prefillIgnored = ref(false)
const contentPanelRef = ref(null)

// 正整數解析：非數字、含小數、零或負一律不合格
const parsePositiveInt = (raw) => {
  const s = Array.isArray(raw) ? raw[0] : raw
  if (s === undefined || s === null || s === '') return null
  if (!/^\d+$/.test(String(s).trim())) return null
  const n = Number(String(s).trim())
  return Number.isSafeInteger(n) && n > 0 ? n : null
}

// route 於單元測試等無 router 環境下為 undefined——以可選鏈退化為「無預填」，
// 不讓深連結能力把元件綁死在 router 上
const applyRangeFromQuery = (query) => {
  const rawFrom = query?.seq_from
  const rawTo = query?.seq_to
  if (rawFrom === undefined && rawTo === undefined) return
  const from = parsePositiveInt(rawFrom)
  const to = parsePositiveInt(rawTo)
  // 半套（只帶一邊）、非數字、from > to 一律不套用並明示原因——
  // 半填會讓使用者以為另一半是自己忘了填
  if (from === null || to === null || from > to) {
    prefillIgnored.value = true
    return
  }
  seqFrom.value = from
  seqTo.value = to
  prefillApplied.value = true
}

const loadAll = () => {
  fetchChain()
  fetchList()
  fetchPublicKey()
}

const route = useRoute()

onMounted(async () => {
  applyRangeFromQuery(route?.query)
  loadAll()
  // 帶了範圍就把該區塊捲進視野——**只捲不執行**。頁面上半部是鏈健康總覽，
  // 不捲的話使用者看不到自己剛帶進來的範圍已經填好了。jsdom 無 scrollIntoView，
  // 故以可選呼叫，缺失時靜默略過（捲動不是正確性的一部分）
  if (prefillApplied.value || prefillIgnored.value) {
    await nextTick()
    contentPanelRef.value?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  }
})
</script>

<style scoped>
.panel {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  margin-bottom: var(--ot-space-md);
}

.panel-title {
  font-weight: 600;
  margin-bottom: var(--ot-space-sm);
}

.degrade-banner {
  margin-bottom: var(--ot-space-md);
}

.load-error {
  margin-bottom: var(--ot-space-md);
}

.prefill-note {
  margin-bottom: var(--ot-space-md);
}

.range-bar {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-md);
  flex-wrap: wrap;
}

.seq-input {
  width: 140px;
}

.range-sep {
  color: var(--el-text-color-secondary);
}

.muted {
  color: var(--el-text-color-secondary);
  font-size: 12px;
  margin-left: var(--ot-space-xs);
}

.failure-table,
.content-table {
  margin-top: var(--ot-space-md);
}

.open-failed {
  margin-top: var(--ot-space-md);
}

.pager {
  margin-top: var(--ot-space-md);
  justify-content: flex-end;
}

.section-title {
  font-weight: 600;
  margin: var(--ot-space-md) 0 var(--ot-space-sm);
}

.section-title:first-of-type {
  margin-top: 0;
}

.block {
  display: block;
  margin: 0 0 var(--ot-space-sm);
}

.limits {
  margin: 0;
  padding-left: var(--ot-space-md);
  line-height: 1.8;
}

.limits > li + li {
  margin-top: var(--ot-space-sm);
}

.limit-code {
  font-weight: 600;
}

/* 標籤與內文各為 flex item，flex 會吃掉 item 尾端的空白：英文若靠譯文的尾隨
   空格分隔，會渲染成「Situation:Someone…」。故譯文一律不留尾隨空格，
   間距改由 gap 承擔（中日文的全形冒號自帶視覺留白，再加 0.25em 不致過寬） */
.limit-part {
  display: flex;
  gap: 0.25em;
}

.limit-label {
  flex: 0 0 auto;
  color: var(--el-text-color-secondary);
}

.degrade-banner p {
  margin: 0 0 var(--ot-space-xs);
  line-height: 1.7;
}

.degrade-banner p:last-child {
  margin-bottom: 0;
}

.pubkey {
  word-break: break-all;
}
</style>
