<template>
  <div class="audit-exports">
    <PageHeader
      :title="$t('menu.auditExports')"
      :description="$t('auditExports.headerDesc')"
    >
      <template #actions>
        <el-button
          :loading="loading || reportLoading"
          data-test="exports-refresh"
          @click="refreshActive()"
        >
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 兩種產物分頁並列：兩者的清單規則不同（證據包只列本人、報告對所有
         具稽核檢視權限者是同一份），混在一張表裡就說不清楚哪一列適用哪一條 -->
    <el-tabs
      v-model="activeTab"
      data-test="exports-tabs"
      @tab-change="onTabChange"
    >
      <el-tab-pane
        :label="$t('auditExports.tab.mine')"
        name="mine"
      >
        <!-- 只列本人：與下載授權同判準。不寫出來，使用者會把「這裡沒有」
             誤讀成「系統沒產出」，而不是「那不是你發起的」 -->
        <el-alert
          type="info"
          :closable="false"
          show-icon
          data-test="exports-requester-only"
          :title="$t('auditExports.requesterOnlyNote')"
        />

        <el-alert
          v-if="hasActive && !autoRefreshStopped"
          type="info"
          :closable="false"
          data-test="exports-polling"
          :title="$t('auditExports.polling', { sec: POLL_SECONDS })"
        />
        <el-alert
          v-else-if="autoRefreshStopped"
          type="warning"
          :closable="false"
          data-test="exports-polling-stopped"
          :title="$t('auditExports.pollingStopped')"
        />
        <el-alert
          v-if="loadFailed"
          type="error"
          :closable="false"
          show-icon
          data-test="exports-load-failed"
          :title="$t('auditExports.loadFailed')"
        />

        <el-card v-loading="loading">
          <el-empty
            v-if="!jobs.length && !loading"
            data-test="exports-empty"
            :description="$t('auditExports.empty')"
          />
          <el-table
            v-else
            :data="jobs"
            style="width: 100%"
            stripe
            row-key="id"
          >
            <!-- 欄位語義刻意**與來源無關**（產物／範圍／狀態／大小／保留期限／操作）：
             目前唯一來源是稽核匯出 job，未來其他非同步產物掛進來時只多一種
             kind，不必重畫一張表（後端不預建通用框架，前端也只到這個程度） -->
            <el-table-column
              :label="$t('auditExports.column.artifact')"
              width="180"
            >
              <template #default="{ row }">
                <div
                  class="artifact-kind"
                  :data-test="`export-kind-${row.id}`"
                >
                  {{ $t('auditExports.kind.auditExport') }}
                </div>
                <div class="artifact-sub">
                  {{ $t('auditExports.requestedAt', { time: formatDateTime(row.requested_at) }) }}
                </div>
                <div
                  v-if="row.artifact_sha256"
                  class="artifact-sub artifact-sha"
                  :title="$t('auditExports.shaTip', { sha: row.artifact_sha256 })"
                >
                  {{ row.artifact_sha256.slice(0, 12) }}…
                </div>
              </template>
            </el-table-column>

            <el-table-column :label="$t('auditExports.column.scope')">
              <template #default="{ row }">
                <div :data-test="`export-scope-${row.id}`">
                  <div
                    v-for="line in scopeLines(row)"
                    :key="line"
                    class="scope-line"
                  >
                    {{ line }}
                  </div>
                </div>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('auditExports.column.status')"
              width="150"
            >
              <template #default="{ row }">
                <el-tag
                  :type="statusTagType(row.status)"
                  effect="plain"
                  :data-test="`export-status-${row.id}`"
                >
                  {{ statusLabel(row.status) }}
                </el-tag>
                <div class="status-hint">
                  {{ statusHint(row.status) }}
                </div>
                <!-- 失敗要說得出原因：只說「失敗」，使用者不知道該重試還是該找管理員 -->
                <div
                  v-if="row.status === 'failed'"
                  class="status-hint status-failure"
                  :data-test="`export-failure-${row.id}`"
                >
                  {{ failureReason(row.error_summary) }}
                </div>
                <!-- 離機保存狀態（evidence-offsite-storage）：只在這個包**確實有**
                 帳冊態時加一行。帳冊零列或 `''`（未排入）不加——
                 對「這個包還下不下得到」沒有增量資訊的狀態不佔一行 -->
                <div
                  v-if="offsiteLine(row)"
                  class="status-hint status-offsite"
                  :data-test="`export-offsite-${row.id}`"
                >
                  {{ offsiteLine(row) }}
                </div>
                <!-- 遠端副本的去留不由產品決定：只印「已離機保存」＋「已過期」，
                 讀者會合理誤以為遠端那一份也一併沒了，或反過來以為產品會去清它 -->
                <div
                  v-if="offsiteRetentionNote(row)"
                  class="status-hint status-offsite-note"
                  :data-test="`export-offsite-retention-${row.id}`"
                >
                  {{ offsiteRetentionNote(row) }}
                </div>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('auditExports.column.size')"
              width="100"
            >
              <template #default="{ row }">
                <span v-if="row.artifact_size > 0">{{ formatBytes(row.artifact_size) }}</span>
                <span
                  v-else
                  class="muted"
                >—</span>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('auditExports.column.expires')"
              width="170"
            >
              <template #default="{ row }">
                <div :data-test="`export-expiry-${row.id}`">
                  {{ expiryText(row) }}
                </div>
                <div
                  v-if="row.expires_at"
                  class="artifact-sub"
                >
                  {{ $t('auditExports.expiresAt', { time: formatDateTime(row.expires_at) }) }}
                </div>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('auditExports.column.actions')"
              width="150"
            >
              <template #default="{ row }">
                <!-- 下載鈕只在**真的拿得到**時出現：done 且未逾期。
                 對 pending/running/failed/expired 掛一顆按下去必然失敗的鈕，
                 等於把後端的收斂錯誤變成使用者的困惑 -->
                <el-button
                  v-if="canDownload(row)"
                  type="primary"
                  link
                  :loading="busyId === row.id"
                  :data-test="`export-download-${row.id}`"
                  @click="download(row)"
                >
                  {{ $t('auditExports.download') }}
                </el-button>
                <el-button
                  v-else-if="row.status === 'failed'"
                  link
                  :loading="busyId === row.id"
                  :disabled="!row.filter"
                  :data-test="`export-retry-${row.id}`"
                  @click="retry(row)"
                >
                  {{ $t('auditExports.retry') }}
                </el-button>
                <span
                  v-else
                  class="muted"
                >—</span>
              </template>
            </el-table-column>
          </el-table>

          <div
            v-if="total > 0"
            class="pagination"
          >
            <el-pagination
              v-model:current-page="page"
              v-model:page-size="pageSize"
              :page-sizes="[10, 20, 50]"
              :total="total"
              layout="total, sizes, prev, pager, next"
              @size-change="fetchJobs()"
              @current-change="fetchJobs()"
            />
          </div>
        </el-card>
      </el-tab-pane>

      <el-tab-pane
        :label="$t('auditExports.tab.reports')"
        name="reports"
      >
        <!-- 報告不綁申請者：任一具稽核檢視權限者看到的是同一份清單。
             這與左邊那一頁的規則相反，故必須寫出來——否則使用者會拿
             「我沒發起過卻看得到」當成權限出錯 -->
        <el-alert
          type="info"
          :closable="false"
          show-icon
          data-test="reports-shared-note"
          :title="$t('auditExports.reportsSharedNote')"
        />

        <el-alert
          v-if="reportLoadFailed"
          type="error"
          :closable="false"
          show-icon
          data-test="reports-load-failed"
          :title="$t('auditExports.loadFailed')"
        />

        <el-card v-loading="reportLoading">
          <el-empty
            v-if="!reportJobs.length && !reportLoading"
            data-test="reports-empty"
            :description="$t('auditExports.reportsEmpty')"
          />
          <el-table
            v-else
            :data="reportJobs"
            style="width: 100%"
            stripe
            row-key="id"
          >
            <!-- 來源欄同時承載「誰產的」與「什麼時候產的」：排程名缺席即手動產出。
                 兩件事併一欄是為了讓整表在 1280 內收得下，不必橫捲 -->
            <el-table-column
              :label="$t('auditExports.column.reportSource')"
              width="200"
            >
              <template #default="{ row }">
                <div :data-test="`report-source-${row.id}`">
                  {{ reportSource(row) }}
                </div>
                <div class="artifact-sub">
                  {{ $t('auditExports.requestedAt', { time: formatDateTime(row.requested_at) }) }}
                </div>
                <div
                  v-if="row.artifact_sha256"
                  class="artifact-sub artifact-sha"
                  :title="$t('auditExports.shaTip', { sha: row.artifact_sha256 })"
                >
                  {{ row.artifact_sha256.slice(0, 12) }}…
                </div>
              </template>
            </el-table-column>

            <el-table-column :label="$t('auditExports.column.reportScope')">
              <template #default="{ row }">
                <div :data-test="`report-scope-${row.id}`">
                  {{ reportScopeText(row) }}
                </div>
                <div class="artifact-sub">
                  {{ reportPeriodText(row) }}
                </div>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('auditExports.column.status')"
              width="150"
            >
              <template #default="{ row }">
                <el-tag
                  :type="statusTagType(row.status)"
                  effect="plain"
                  :data-test="`report-status-${row.id}`"
                >
                  {{ statusLabel(row.status) }}
                </el-tag>
                <div class="status-hint">
                  {{ statusHint(row.status) }}
                </div>
                <div
                  v-if="offsiteLine(row)"
                  class="status-hint status-offsite"
                  :data-test="`report-offsite-${row.id}`"
                >
                  {{ offsiteLine(row) }}
                </div>
                <div
                  v-if="offsiteRetentionNote(row)"
                  class="status-hint status-offsite-note"
                  :data-test="`report-offsite-retention-${row.id}`"
                >
                  {{ offsiteRetentionNote(row) }}
                </div>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('auditExports.column.size')"
              width="100"
            >
              <template #default="{ row }">
                <span v-if="row.artifact_size > 0">{{ formatBytes(row.artifact_size) }}</span>
                <span
                  v-else
                  class="muted"
                >—</span>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('auditExports.column.expires')"
              width="170"
            >
              <template #default="{ row }">
                <div :data-test="`report-expiry-${row.id}`">
                  {{ expiryText(row) }}
                </div>
                <div
                  v-if="row.expires_at"
                  class="artifact-sub"
                >
                  {{ $t('auditExports.expiresAt', { time: formatDateTime(row.expires_at) }) }}
                </div>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('auditExports.column.actions')"
              width="120"
            >
              <template #default="{ row }">
                <el-button
                  v-if="canDownload(row)"
                  type="primary"
                  link
                  :loading="busyId === row.id"
                  :data-test="`report-download-${row.id}`"
                  @click="downloadReport(row)"
                >
                  {{ $t('auditExports.download') }}
                </el-button>
                <span
                  v-else
                  class="muted"
                >—</span>
              </template>
            </el-table-column>
          </el-table>

          <div
            v-if="reportTotal > 0"
            class="pagination"
          >
            <el-pagination
              v-model:current-page="reportPage"
              v-model:page-size="reportPageSize"
              :page-sizes="[10, 20, 50]"
              :total="reportTotal"
              layout="total, sizes, prev, pager, next"
              @size-change="fetchReportJobs()"
              @current-change="fetchReportJobs()"
            />
          </div>
        </el-card>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import {
  createAuditExportJob,
  downloadAuditExportJob,
  listAuditExportJobs,
} from '@/api/auditExport'
import { TIMELINE_TYPES, typeLabel } from '@/components/audit/timelineSummary'
import { OFFSITE_EXPORT_ROW_STATUSES } from '@/constants/offsite'
import { formatBytes, formatDateTime, formatUptimeSeconds } from '@/utils/format'
import { downloadBlob } from '@/utils/download'

// 下載中心。
//
// **只列本人**：後端 `ListJobs` 以申請者為範圍查詢，沒有跨帳號的檢視面；
// 這與下載授權同一判準（使用者裁決不得放寬）。前端不做「全部使用者」
// 的篩選，也不演一個查不到東西的搜尋框。
//
// **欄位語義與來源無關**：產物／範圍／狀態／大小／保留期限／操作。目前唯一
// 來源是稽核匯出 job，未來其他非同步產物掛入時擴充 kind 即可——後端不預建
// 通用 downloads 框架（框架化門檻未到），前端也只做到欄位語義這一層。

const { t } = useI18n()
// 本頁不導航，只讀落地時的分頁指定；沒有 router 的掛載情境（單元測試）
// 讀不到即維持預設分頁，不因此中斷渲染
const route = useRoute()

// 自動更新：**只在有打包進行中時才發請求**（pending／running），且整頁的
// 自動更新有硬上限——長迴圈必須有上限，否則忘了關的分頁會整天打後端。
// 到頂之後停下來並明說已停，使用者按「重新整理」即可繼續。
const POLL_SECONDS = 5
const POLL_MS = POLL_SECONDS * 1000
const MAX_TICKS = 720 // 5 秒 × 720 ＝ 1 小時
const ACTIVE_STATES = ['pending', 'running']

const jobs = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const loading = ref(false)
const loadFailed = ref(false)
const busyId = ref(0)
// now 只驅動過期倒數的顯示（純本地推進，不發請求）
const now = ref(Date.now())
const ticks = ref(0)
const autoRefreshStopped = computed(() => ticks.value >= MAX_TICKS)

const hasActive = computed(() => jobs.value.some((j) => ACTIVE_STATES.includes(j.status)))

// 「輪替報告」分頁。**清單規則與證據包相反**（不綁申請者），故自成一組狀態，
// 不與上面的 jobs 共用——共用會讓「這一列適用哪一條規則」在程式碼裡也講不清楚。
// 種類參數只有這一頁帶：缺省種類的查詢一字未動
const REPORT_KIND = 'rotation_report'
const activeTab = ref('mine')
const reportJobs = ref([])
const reportTotal = ref(0)
const reportPage = ref(1)
const reportPageSize = ref(20)
const reportLoading = ref(false)
const reportLoadFailed = ref(false)
const reportLoaded = ref(false)

const fetchReportJobs = async () => {
  reportLoading.value = true
  try {
    const res = await listAuditExportJobs({
      kind: REPORT_KIND,
      page: reportPage.value,
      page_size: reportPageSize.value,
    })
    reportJobs.value = res?.data || []
    reportTotal.value = Number(res?.total) || 0
    now.value = Date.now()
    reportLoadFailed.value = false
  } catch (_e) {
    reportLoadFailed.value = true
  } finally {
    reportLoading.value = false
    reportLoaded.value = true
  }
}

// 報告清單**只在使用者真的切過去時才載**：多數進到本頁的人是來取自己剛發起的
// 證據包，替他先打一支他不會看的查詢沒有意義
const onTabChange = (name) => {
  if (name === 'reports' && !reportLoaded.value) fetchReportJobs()
}

const refreshActive = () => (activeTab.value === 'reports' ? fetchReportJobs() : fetchJobs())

const fetchJobs = async ({ silent = false } = {}) => {
  if (!silent) loading.value = true
  try {
    const res = await listAuditExportJobs({ page: page.value, page_size: pageSize.value })
    jobs.value = res?.data || []
    total.value = Number(res?.total) || 0
    now.value = Date.now()
    loadFailed.value = false
  } catch (_e) {
    // 靜默輪詢的失敗不掛紅：一次沒問到不代表清單壞了，下一輪自然補上。
    // 使用者主動觸發的載入失敗才要說——他正等著看結果
    if (!silent) loadFailed.value = true
  } finally {
    if (!silent) loading.value = false
  }
}

let timer = null

const stopTimer = () => {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
}

const onTick = () => {
  ticks.value += 1
  now.value = Date.now()
  if (ticks.value >= MAX_TICKS) {
    stopTimer()
    return
  }
  if (hasActive.value && !loading.value) fetchJobs({ silent: true })
}

onMounted(() => {
  fetchJobs()
  // 深連結 ?tab=reports：輪替證據頁發起產出後把人帶到取件的地方，
  // 落地即在報告分頁上，而不是讓他自己再點一次
  if (route?.query?.tab === 'reports') {
    activeTab.value = 'reports'
    fetchReportJobs()
  }
  timer = setInterval(onTick, POLL_MS)
})

// 卸載必清：留著的計時器會在頁面離開後繼續打後端，
// 單測裡則會讓已卸載的元件持續更新而拖出偶發逾時
onUnmounted(stopTimer)

const statusTagType = (status) =>
  ({
    pending: 'info',
    running: 'primary',
    done: 'success',
    failed: 'danger',
    expired: 'info',
  })[status] || 'info'

// 狀態值域硬拷後端 `model/audit_export_job.go:11-21`。
// **值域外的狀態原樣顯示、不留白**：後端日後多一態時，畫面會出現一個沒翻譯的
// 代號（看得見、修得掉），而不是一列什麼都不寫的空白（沒人會發現）
const KNOWN_STATES = ['pending', 'running', 'done', 'failed', 'expired']
const statusLabel = (status) =>
  KNOWN_STATES.includes(status) ? t(`auditExports.status.${status}`) : status || ''
const statusHint = (status) =>
  KNOWN_STATES.includes(status) ? t(`auditExports.statusHint.${status}`) : ''

// 離機保存狀態行（第三列）。
//
// **只呈現子集**：`local_purged`／`skipped_*`／`''` 對「這個包還下不下得到」
// 沒有增量資訊（產物本來就有 30 天壽命，本機副本去留由保留清理承擔），
// 加一行只會把真正要看的兩件事——已離機保存、離機取回出問題——擠淡。
// 值域外的狀態同樣不加行：這一行是輔助說明，不是狀態的權威呈現面
// **雜湊只在後端給了才附**（狀態行第三列「已離機保存 · <sha256 前 12>」）：
// 那是帳冊列記下的整檔雜湊，與左欄的產物雜湊不同來源；取不到就只留狀態，
// 不留一個後面空著的分隔點。截法與產物欄同一套（前 12＋省略號）
const offsiteLine = (row) => {
  const status = row?.offsite_status
  if (!OFFSITE_EXPORT_ROW_STATUSES.includes(status)) return ''
  const label = t(`offsite.exportRow.${status}`)
  const sha = row?.offsite_sha256
  return sha ? `${label} · ${String(sha).slice(0, 12)}…` : label
}

// 遠端副本存在的狀態：帳冊上真的有一份在儲存端（上傳完成、完整性不符、
// 舊儲存設定留下的）。上傳中或失敗的沒有那一份，不該對讀者暗示有。
const OFFSITE_RETAINED_STATUSES = ['uploaded', 'integrity_mismatch', 'foreign']

// 遠端副本的保留說明：離機那一份的存續由儲存端的保留政策決定，產品不會刪除它。
const offsiteRetentionNote = (row) =>
  OFFSITE_RETAINED_STATUSES.includes(row?.offsite_status)
    ? t('offsite.exportRow.retentionNote')
    : ''

// 失敗摘要是後端的機器碼（`model/audit_export_job.go:26-30` 的 ExportJobErr*）：
// 去前綴後查譯。**沒有紀錄**才說「原因未記錄」；有紀錄但查不到譯文時原樣附上代碼
// ——把一個已記錄的原因說成「未記錄」是說謊，而且是靜默的那種（沒人會發現）
const FAILURE_CODES = ['pack_failed', 'requester_revoked']
const failureReason = (summary) => {
  const code = String(summary || '').replace(/^export_job\./, '')
  if (!code) return t('auditExports.failureReason.unknown')
  return FAILURE_CODES.includes(code)
    ? t(`auditExports.failureReason.${code}`)
    : t('auditExports.failureReason.unmapped', { code })
}

const expired = (row) => Boolean(row.expires_at) && new Date(row.expires_at).getTime() <= now.value

// 可下載＝done 且未逾期。過期清掃是輪詢式的，狀態可能還停在 done 而檔案已到期，
// 故以時刻判定為準（與後端下載端點同一判準，兩邊看的是同一件事）
const canDownload = (row) => row.status === 'done' && !expired(row)

const expiryText = (row) => {
  if (!row.expires_at) return t('auditExports.noExpiry')
  if (expired(row) || row.status === 'expired') return t('auditExports.expiredAlready')
  const seconds = Math.floor((new Date(row.expires_at).getTime() - now.value) / 1000)
  return t('auditExports.expiresIn', { duration: formatUptimeSeconds(seconds) })
}

// scopeTypeCodes 篩選快照的類別碼（`types` 是碼的 csv，與 manifest 的 filter 段
// 同一字串化規則）。**缺席＝全部類別**，故缺席時展開為六類而非留白——
// 留白會讓「只收了兩類」與「六類全收」在下載中心長得一模一樣，而那兩包
// 能證明的事差很遠。顯示順序一律回正規順序（與類別籤同一排列），
// 使用者勾選的先後不該讓同一組類別看起來像兩種範圍
const scopeTypeCodes = (f) => {
  const raw = String(f.types || '').trim()
  if (!raw) return [...TIMELINE_TYPES]
  const picked = raw.split(',').map((s) => s.trim()).filter(Boolean)
  const known = TIMELINE_TYPES.filter((v) => picked.includes(v))
  // 未知碼原樣附在後面：後端日後多一類時，這裡要照樣說得出「有這一類」，
  // 不得靜默吞掉（吞掉＝對取件者少報範圍）
  return [...known, ...picked.filter((v) => !TIMELINE_TYPES.includes(v))]
}

// 範圍摘要沿後端 `DisplayMap`（與 manifest 的 filter 段同一字串化規則）：
// 鍵就是發起時的 query 參數名，故也能原樣回送做重新發起
const scopeLines = (row) => {
  const f = row.filter || {}
  // 篩選快照整個缺席（後端解析不出來時 filter 欄不出站）：此時連
  // 「types 缺席＝全收」的推斷都沒有依據，故一個字都不談，只講不知道
  if (!Object.keys(f).length) return [t('auditExports.scopeUnknown')]
  const lines = []
  if (f.user_id) lines.push(t('auditExports.scopeUser', { id: f.user_id }))
  if (f.asset_id) lines.push(t('auditExports.scopeAsset', { id: f.asset_id }))
  if (f.session_id) lines.push(t('auditExports.scopeSession', { id: f.session_id }))
  if (f.start_time || f.end_time) {
    lines.push(
      t('auditExports.scopeRange', {
        from: formatDateTime(f.start_time),
        to: formatDateTime(f.end_time),
      })
    )
  }
  const codes = scopeTypeCodes(f)
  lines.push(
    t('auditExports.scopeTypes', {
      types: codes.map(typeLabel).join(t('common.listSeparator')),
      count: codes.length,
    })
  )
  return lines.length ? lines : [t('auditExports.scopeUnknown')]
}

const download = async (row) => {
  if (busyId.value) return
  busyId.value = row.id
  try {
    const blob = await downloadAuditExportJob(row.id)
    downloadBlob(blob, `audit-evidence-job-${row.id}.zip`)
  } catch (_e) {
    // 全域攔截器已 toast 技術原因；此處講後果——沒有拿到任何檔案
    ElMessage.error(t('auditExports.downloadFailed'))
  } finally {
    busyId.value = 0
  }
}

// —— 輪替報告列的呈現 ——
//
// 報告列以 `report` 段取代證據包的 `filter` 段。**排程名缺席＝手動產出**：
// 這兩者的差別是稽核讀者第一個要問的事（例行產出還是有人臨時要的），
// 不能只留一個空白讓人自己猜
const reportSource = (row) => {
  const name = row?.report?.schedule_name
  if (name) return name
  const by = row?.report?.generated_by || row?.requester
  return by
    ? t('auditExports.reportManualBy', { user: by })
    : t('auditExports.reportManual')
}

const REPORT_SCOPE_KINDS = ['all', 'node', 'plan']
const reportScopeText = (row) => {
  const kind = row?.report?.scope_kind
  return REPORT_SCOPE_KINDS.includes(kind)
    ? t(`auditExports.reportScope.${kind}`)
    : t('auditExports.scopeUnknown')
}

const reportPeriodText = (row) => {
  const from = row?.report?.period_start
  const to = row?.report?.period_end
  if (!from || !to) return t('auditExports.scopeUnknown')
  return t('auditExports.scopeRange', {
    from: formatDateTime(from),
    to: formatDateTime(to),
  })
}

const downloadReport = async (row) => {
  if (busyId.value) return
  busyId.value = row.id
  try {
    const blob = await downloadAuditExportJob(row.id)
    downloadBlob(blob, `rotation-report-job-${row.id}.zip`)
  } catch (_e) {
    ElMessage.error(t('auditExports.downloadFailed'))
  } finally {
    busyId.value = 0
  }
}

// 重新發起：以該 job 的**篩選快照原樣**再發一次，不重組條件——
// 重組就有機會發出一個與原本不同的範圍，而使用者以為是同一份
const retry = async (row) => {
  if (busyId.value || !row.filter) return
  busyId.value = row.id
  try {
    await createAuditExportJob({ ...row.filter })
    ElMessage.success(t('auditExports.retrySuccess'))
    await fetchJobs()
  } catch (_e) {
    ElMessage.error(t('auditExports.retryFailed'))
  } finally {
    busyId.value = 0
  }
}
</script>

<style scoped>
.audit-exports {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}

.artifact-kind {
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-sm);
}

.artifact-sub {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.artifact-sha {
  font-family: var(--ot-font-mono);
}

.scope-line {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
}

.status-hint {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.5;
  margin-top: var(--ot-space-xs);
}

.status-failure {
  color: var(--ot-danger);
}

/* 離機狀態是次要事實：與失敗原因同層級但不搶色——
   它多數時候是好消息（已離機保存），走 hint 的中性色即可 */
.status-offsite {
  color: var(--ot-text-secondary);
}

/* 保留說明是背景知識而非狀態：比狀態行再淡一階，不與它爭同一眼 */
.status-offsite-note {
  color: var(--ot-text-disabled);
}

.muted {
  color: var(--ot-text-secondary);
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--ot-space-md);
}
</style>
