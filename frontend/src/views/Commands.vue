<template>
  <div class="commands-page">
    <PageHeader
      :title="$t('menu.commands')"
      :description="$t('commands.headerDesc')"
    >
      <template #actions>
        <el-button @click="fetchCommands">
          <el-icon><RefreshCw /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 搜尋列 -->
    <div class="filter-bar">
      <el-form
        :inline="true"
        :model="filters"
        @submit.prevent
      >
        <el-form-item :label="$t('commands.keyword')">
          <el-input
            v-model="filters.keyword"
            clearable
            :placeholder="$t('commands.keywordPlaceholder')"
            style="width: 220px"
            @keyup.enter="handleSearch"
          />
        </el-form-item>

        <el-form-item :label="$t('sessions.timeRange')">
          <el-date-picker
            v-model="timeRange"
            type="datetimerange"
            :range-separator="$t('sessions.rangeSeparator')"
            :start-placeholder="$t('sessions.startTime')"
            :end-placeholder="$t('sessions.endTime')"
            format="YYYY-MM-DD HH:mm"
            value-format="YYYY-MM-DDTHH:mm:ssZ"
            style="width: 360px"
            @change="handleSearch"
          />
        </el-form-item>

        <el-form-item>
          <el-button
            type="primary"
            @click="handleSearch"
          >
            {{ $t('common.search') }}
          </el-button>
          <el-button @click="handleReset">
            {{ $t('common.reset') }}
          </el-button>
        </el-form-item>
      </el-form>
    </div>

    <!-- 資料表格 -->
    <div class="list-card">
      <!-- 關鍵字搜尋的誠實橫幅（2.7）：keyword 走 `command ILIKE`，而降級列的
           command 是空字串，**永遠不會命中**。搜 `rm -rf` 得到 0 筆的稽核員
           必須知道這區間還有幾輪根本沒有文字，否則 0 筆會被讀成「沒發生過」。 -->
      <el-alert
        v-if="degradeNotice.show"
        class="degrade-banner"
        type="warning"
        :closable="false"
        show-icon
        :title="degradeNotice.text"
        data-test="degrade-keyword-banner"
      >
        <template #default>
          <el-button
            link
            type="primary"
            size="small"
            data-test="degrade-banner-clear"
            @click="clearKeyword"
          >
            {{ $t('commands.degrade.bannerClear') }}
          </el-button>
        </template>
      </el-alert>

      <el-table
        v-loading="loading"
        :data="commands"
        stripe
        style="width: 100%"
      >
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
          :label="$t('common.user')"
          width="120"
        >
          <template #default="{ row }">
            {{ row.username || row.user_id }}
          </template>
        </el-table-column>

        <el-table-column
          :label="$t('common.asset')"
          width="160"
        >
          <template #default="{ row }">
            {{ row.asset_name || row.asset_id }}
          </template>
        </el-table-column>

        <el-table-column
          prop="command"
          :label="$t('commands.commandColumn')"
          min-width="300"
          show-overflow-tooltip
        >
          <template #default="{ row }">
            <!-- 跨會話頁不知道該會話有沒有錄影（列表未帶該欄），故 recordingState
                 留 unknown：文案只說「可能保留」，到了詳情頁再由那一頁誠實回報 -->
            <CommandCell
              :row="row"
              @seek="goToRecordingAt"
            />
          </template>
        </el-table-column>

        <el-table-column
          :label="$t('common.actions')"
          width="120"
          fixed="right"
        >
          <template #default="{ row }">
            <el-button
              link
              type="primary"
              @click="goToSession(row)"
            >
              {{ $t('commands.viewSession') }}
            </el-button>
          </template>
        </el-table-column>

        <template #empty>
          <EmptyState
            :title="$t('commands.emptyTitle')"
            :hint="$t('commands.emptyHint')"
          />
        </template>
      </el-table>

      <!-- 分頁 -->
      <div class="pagination">
        <el-pagination
          v-model:current-page="pagination.page"
          v-model:page-size="pagination.page_size"
          :page-sizes="[10, 20, 50, 100]"
          :total="pagination.total"
          layout="total, sizes, prev, pager, next, jumper"
          @size-change="handleSizeChange"
          @current-change="fetchCommands"
        />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { RefreshCw } from 'lucide-vue-next'
import { searchCommands } from '@/api/commands'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import CommandCell from '@/components/audit/CommandCell.vue'
import { isDegradedRow } from '@/constants/command-degrade'
import { formatDateTime } from '@/utils/format'
import { t } from '@/i18n'

const router = useRouter()

const commands = ref([])
const loading = ref(false)
const timeRange = ref([])

const filters = ref({
  keyword: '',
})

// 已套用到目前這份結果的關鍵字（**不是輸入框的即時值**）：橫幅描述的是
// 眼前這份結果的涵蓋範圍，隨打字閃動只會讓人不信任它
const appliedKeyword = ref('')

const pagination = ref({
  page: 1,
  page_size: 20,
  total: 0,
})

// ---------------------------------------------------------------------------
// 降級列涵蓋範圍探測（2.7）
//
// 後端 `SessionCommandFilter` 目前**沒有** degraded 過濾條件，回應也沒有
// degraded 總數，故「此區間有幾筆降級列」無法由 API 直接問到（缺口已回報）。
// 這裡改以「同一時間窗、拿掉關鍵字」的一次有界查詢自行清點：
//   - 該窗總筆數 <= 探測上限 → 手上就是全窗，筆數**精確**；
//   - 超過上限                → 只能給**下界**，文案據實寫「至少」；
//   - 探測失敗                → 不知道，**倒向揭露**（顯示不帶數字的橫幅）。
// 三種情形都不得讓稽核員在「有降級列」時看不到橫幅——漏報是靜默的錯誤方向。
// ---------------------------------------------------------------------------
const DEGRADE_PROBE_PAGE_SIZE = 200

const degradeProbe = ref({ key: null, known: false, exact: false, count: 0 })

const probeKeyOf = (params) => `${params.start_time || ''}|${params.end_time || ''}`

const runDegradeProbe = async (params) => {
  const key = probeKeyOf(params)
  if (degradeProbe.value.known && degradeProbe.value.key === key) return
  const probeParams = { page: 1, page_size: DEGRADE_PROBE_PAGE_SIZE }
  if (params.start_time) probeParams.start_time = params.start_time
  if (params.end_time) probeParams.end_time = params.end_time
  try {
    const response = await searchCommands(probeParams)
    const rows = response.data || []
    const total = response.total || 0
    degradeProbe.value = {
      key,
      known: true,
      exact: total <= DEGRADE_PROBE_PAGE_SIZE,
      count: rows.filter(isDegradedRow).length,
    }
  } catch (error) {
    console.error('探測降級紀錄失敗:', error)
    degradeProbe.value = { key, known: false, exact: false, count: 0 }
  }
}

const degradeNotice = computed(() => {
  // 沒有關鍵字時降級列本來就在表格裡（各自渲染成狀態列），不必多一行橫幅
  if (!appliedKeyword.value) return { show: false, text: '' }
  const probe = degradeProbe.value
  if (!probe.known) return { show: true, text: t('commands.degrade.bannerUnknown') }
  if (probe.exact) {
    return probe.count > 0
      ? { show: true, text: t('commands.degrade.bannerExact', { n: probe.count }) }
      : { show: false, text: '' }
  }
  return probe.count > 0
    ? {
      show: true,
      text: t('commands.degrade.bannerAtLeast', {
        n: probe.count,
        limit: DEGRADE_PROBE_PAGE_SIZE,
      }),
    }
    : { show: true, text: t('commands.degrade.bannerUnknown') }
})

// 查詢指令記錄
const fetchCommands = async () => {
  loading.value = true
  try {
    const params = {
      page: pagination.value.page,
      page_size: pagination.value.page_size,
    }

    if (filters.value.keyword) params.keyword = filters.value.keyword

    if (timeRange.value && timeRange.value.length === 2) {
      params.start_time = timeRange.value[0]
      params.end_time = timeRange.value[1]
    }

    const response = await searchCommands(params)
    commands.value = response.data || []
    pagination.value.total = response.total || 0
    appliedKeyword.value = params.keyword || ''

    // 只有關鍵字查詢會漏掉降級列，其餘情形不必多打一次查詢
    if (appliedKeyword.value) await runDegradeProbe(params)
  } catch (error) {
    console.error('查詢指令記錄失敗:', error)
  } finally {
    loading.value = false
  }
}

// 搜尋（重置頁碼）
const handleSearch = () => {
  pagination.value.page = 1
  fetchCommands()
}

// 變更每頁大小
const handleSizeChange = () => {
  pagination.value.page = 1
  fetchCommands()
}

// 重置過濾器
const handleReset = () => {
  filters.value = { keyword: '' }
  timeRange.value = []
  handleSearch()
}

// 跳轉會話詳情
const goToSession = (row) => {
  router.push(`/sessions/${row.session_id}`)
}

// 降級列的下一步：帶該列的**絕對時刻**進會話詳情。
// 這裡刻意不自行換算相對秒數——換算要用該會話的起點（本頁沒有這個欄位），
// 且回放時間軸還要再扣一次錄影起點的差；那兩步由詳情頁做，並由它誠實回報落點。
const goToRecordingAt = (row) => {
  if (!row?.session_id) return
  router.push({
    path: `/sessions/${row.session_id}`,
    query: { at: String(row.executed_at) },
  })
}

// 橫幅上的下一步：清掉關鍵字，讓降級列自己出現在表格裡
const clearKeyword = () => {
  filters.value.keyword = ''
  handleSearch()
}


onMounted(() => {
  fetchCommands()
})
</script>

<style scoped>
.commands-page {
  /* MainLayout main-content 已有 padding，此處不重複加 */
}

.filter-bar {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  margin-bottom: var(--ot-space-md);
}

.list-card {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.pagination {
  margin-top: var(--ot-space-md);
  display: flex;
  justify-content: flex-end;
}

.degrade-banner {
  margin-bottom: var(--ot-space-sm);
}
</style>
