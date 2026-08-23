<template>
  <div class="transmission-inventory">
    <PageHeader
      :title="$t('menu.transmissionInventory')"
      :description="$t('transmission.headerDesc')"
    >
      <template #actions>
        <el-button
          :loading="exporting"
          @click="handleExport"
        >
          {{ $t('transmission.exportSnapshot') }}
        </el-button>
        <el-button
          :loading="loading"
          @click="fetchInventory"
        >
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 傳輸政策鍵設定區（域收編）：
         政策與清冊同頁，等級變更儲存後清冊即時重載反映 -->
    <PolicyPciBanner
      :loading="policyLoading"
      :saving="saving"
      :is-dirty="isDirty"
      :deviation-count="pageDeviationCount"
      :deviation-text="$t('policyForm.pageDeviation', { n: pageDeviationCount }, pageDeviationCount)"
      :overview-count="totalDeviationCount"
      :epayment-deviation-count="pageEPaymentDeviationCount"
      @apply="applyPagePCI"
      @apply-epayment="applyPageEPayment"
      @reset="resetForm"
      @save="handleSavePolicies"
    />

    <PolicyKeySections
      :sections="visibleSections"
      :form-values="formValues"
      :saved-values="savedValues"
      @update:value="(key, value) => (formValues[key] = value)"
    />

    <el-card
      v-loading="loading"
      class="section-card"
    >
      <template #header>
        <div class="card-header">
          <span class="card-title">{{ $t('transmission.channelStatusTitle') }}</span>
          <span class="card-hint">{{ $t('transmission.channelStatusHint') }}</span>
        </div>
      </template>
      <el-table
        :data="channels"
        style="width: 100%"
        stripe
      >
        <el-table-column
          :label="$t('transmission.channelColumn')"
          width="140"
        >
          <template #default="{ row }">
            <span class="channel-name">{{ channelLabel(row.channel) }}</span>
            <el-tag
              v-if="row.deployment"
              size="small"
              type="info"
              effect="plain"
              class="dep-tag"
            >
              {{ $t('transmission.deploymentManaged') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('transmission.levelColumn')"
          width="120"
        >
          <template #default="{ row }">
            <el-tag
              v-if="row.level"
              :type="levelTagType(row.level)"
              effect="plain"
            >
              {{ levelLabel(row.level) }}
            </el-tag>
            <span
              v-else
              class="muted"
            >—</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('transmission.countColumn')"
          width="90"
        >
          <template #default="{ row }">
            {{ row.total_count }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('transmission.deviationColumn')"
          width="100"
        >
          <template #default="{ row }">
            <el-tag
              v-if="row.at_risk_count > 0"
              type="warning"
              effect="plain"
            >
              {{ row.at_risk_count }}
            </el-tag>
            <el-tag
              v-else
              type="success"
              effect="plain"
            >
              0
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('transmission.detailColumn')">
          <template #default="{ row }">
            <div
              v-if="Object.keys(inventoryDetail(row)).length"
              class="detail-line"
            >
              <span
                v-for="(count, key) in inventoryDetail(row)"
                :key="key"
                class="detail-item"
              >
                {{ key }}: {{ count }}
              </span>
            </div>
            <div
              v-for="risk in row.risks || []"
              :key="risk.key"
              class="risk-line"
            >
              {{ riskLabel(risk, row.display_params) }}
            </div>
            <div
              v-if="inventoryPreflight(row)"
              class="preflight"
            >
              {{ inventoryPreflight(row) }}
            </div>
            <div
              v-if="inventoryNote(row)"
              class="note"
            >
              {{ inventoryNote(row) }}
            </div>
            <!-- 產品內設定入口：LDAP 自本 change 起
                 由 UI 維護（清冊 note 已改口徑、部署方徽章僅剩 nginx），清冊只是
                 狀態面板——說了「在設定頁維護」就必須指得出那一頁在哪 -->
            <router-link
              v-if="channelSettingsPath(row.channel)"
              class="settings-link"
              :to="channelSettingsPath(row.channel)"
            >
              {{ $t('transmission.gotoChannelSettings') }}
            </router-link>
          </template>
        </el-table-column>
      </el-table>

      <p
        v-if="generatedAt"
        class="footer-meta"
      >
        {{ $t('transmission.generatedAt', { time: formatDateTime(generatedAt) }) }}
      </p>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import PolicyPciBanner from '@/components/PolicyPciBanner.vue'
import PolicyKeySections from '@/components/PolicyKeySections.vue'
import { usePolicyForm } from '@/composables/usePolicyForm'
import { TRANSPORT_SECTIONS } from '@/constants/policyDomains'
import { formatDateTime } from '@/utils/format'
import { t } from '@/i18n'
import {
  getTransmissionInventory,
  exportTransmissionInventory,
} from '@/api/transmissionInventory'
import {
  riskLabel,
  inventoryNote,
  inventoryPreflight,
  inventoryDetail,
} from '@/utils/transportDisplay'

// 傳輸政策鍵（域收編）：與下方清冊同頁，儲存後清冊重載同步政策等級欄
const {
  loading: policyLoading,
  saving,
  formValues,
  savedValues,
  visibleSections,
  isDirty,
  pageDeviationCount,
  pageEPaymentDeviationCount,
  totalDeviationCount,
  loadPolicies,
  applyPagePCI,
  applyPageEPayment,
  resetForm,
  save,
} = usePolicyForm(TRANSPORT_SECTIONS)

const handleSavePolicies = async () => {
  await save()
  fetchInventory()
}

const loading = ref(false)
const exporting = ref(false)
const channels = ref([])
const generatedAt = ref('')

// 通道名／政策等級（i18n：閉集走 enum.transmissionChannel / enum.transportLevel、
// 未知值原樣顯示）；值域與後端清冊通道一致
const CHANNEL_VALUES = ['ssh', 'rdp', 'vnc', 'db', 'ldap', 'syslog', 'notify', 'nginx']
const channelLabel = (c) =>
  CHANNEL_VALUES.includes(c) ? t(`enum.transmissionChannel.${c}`) : c

// 通道 → 產品內設定頁。**只列「本產品 UI 可改」的通道**：nginx 等部署層通道
// 沒有可導向的頁面，硬給連結只會把人送到一個改不了東西的地方。
// LDAP 已由 env 遷入 DB＋UI，故列入本表
const CHANNEL_SETTINGS_ROUTES = { ldap: '/ldap-directory' }
const channelSettingsPath = (c) => CHANNEL_SETTINGS_ROUTES[c] || ''

const LEVEL_VALUES = ['off', 'warn', 'strict']
const levelLabel = (l) =>
  LEVEL_VALUES.includes(l) ? t(`enum.transportLevel.${l}`) : l
const levelTagType = (l) =>
  ({ off: 'info', warn: 'warning', strict: 'danger' })[l] || 'info'

const fetchInventory = async () => {
  loading.value = true
  try {
    const resp = await getTransmissionInventory()
    channels.value = resp.data?.channels || []
    // state 留 raw timestamp、顯示時才格式化（切語言要能重繪）
    generatedAt.value = resp.data?.generated_at || ''
  } catch (error) {
    console.error('取得通道清冊失敗:', error)
  } finally {
    loading.value = false
  }
}

const handleExport = async () => {
  exporting.value = true
  try {
    const snapshot = await exportTransmissionInventory()
    downloadJSON(snapshot)
    ElMessage.success(t('transmission.exported'))
  } catch (error) {
    console.error('匯出清冊失敗:', error)
  } finally {
    exporting.value = false
  }
}

const downloadJSON = (data) => {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: 'application/json',
  })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `transmission-inventory-${Date.now()}.json`
  a.click()
  URL.revokeObjectURL(url)
}

onMounted(() => {
  loadPolicies()
  fetchInventory()
})
</script>

<style scoped>
.card-header {
  display: flex;
  align-items: baseline;
  gap: 12px;
}
.card-title {
  font-weight: 600;
}
.card-hint {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.channel-name {
  font-weight: 500;
}
.dep-tag {
  margin-left: 6px;
}
.muted {
  color: var(--el-text-color-placeholder);
}
.detail-line {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  color: var(--el-text-color-regular);
  font-size: 13px;
}
.risk-line {
  color: var(--el-color-warning);
  font-size: 13px;
}
.preflight {
  color: var(--el-color-danger);
  font-size: 12px;
  margin-top: 4px;
}
.note {
  color: var(--el-text-color-secondary);
  font-size: 12px;
  margin-top: 4px;
}
.settings-link {
  display: inline-block;
  margin-top: 4px;
  color: var(--el-color-primary);
  font-size: 12px;
}
.footer-meta {
  color: var(--el-text-color-secondary);
  font-size: 12px;
  margin-top: 12px;
}
</style>
