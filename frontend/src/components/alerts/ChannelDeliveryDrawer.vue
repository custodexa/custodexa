<template>
  <el-drawer
    :model-value="modelValue"
    :title="channel ? $t('alerts.log.title', { name: channel.name }) : ''"
    size="760px"
    data-test="channel-delivery-drawer"
    @update:model-value="(v) => emit('update:modelValue', v)"
    @open="onOpen"
  >
    <template v-if="channel">
      <!-- 三張摘要卡：與列表同一個起算時間（目的地最後變更之後） -->
      <div class="log-cards">
        <div
          class="log-card"
          data-test="log-card-ok"
        >
          <div class="log-card__value">
            {{ health.last_delivered_at ? formatLogTime(health.last_delivered_at) : $t('alerts.health.neverOk') }}
          </div>
          <div class="log-card__label">
            {{ $t('alerts.health.lastOk') }}{{ cardSuffix }}
          </div>
        </div>
        <div
          class="log-card"
          :class="{ 'log-card--danger': failing }"
          data-test="log-card-fail"
        >
          <div class="log-card__value">
            {{ health.last_failed_at ? formatLogTime(health.last_failed_at) : $t('alerts.health.noFail') }}
          </div>
          <div class="log-card__label">
            {{ $t('alerts.health.lastFail') }}{{ cardSuffix }}
          </div>
        </div>
        <div
          class="log-card"
          :class="{ 'log-card--warning': abandoned7d > 0 }"
          data-test="log-card-abandoned"
        >
          <div class="log-card__value">
            {{ $t('alerts.log.countValue', { n: abandoned7d }) }}
          </div>
          <div class="log-card__label">
            {{ $t('alerts.log.abandoned7dLabel') }}{{ cardSuffix }}
          </div>
        </div>
      </div>
      <p class="log-intro">
        {{ $t('alerts.retryPolicyHint') }}{{ targetsUsers ? $t('alerts.log.introExtraDm') : $t('alerts.log.introExtra') }}
      </p>

      <div class="log-toolbar">
        <!-- 收件對象：只有能以個人為對象的型別才有個人訊息紀錄 -->
        <div
          v-if="targetsUsers"
          class="log-filter-group"
        >
          <span class="log-filter-label">{{ $t('alerts.log.audience') }}</span>
          <el-radio-group
            v-model="audience"
            size="small"
            data-test="log-audience"
            @change="load(1)"
          >
            <el-radio-button
              v-for="a in AUDIENCE_KEYS"
              :key="a"
              :value="a"
              :data-test="`log-audience-${a}`"
            >
              {{ $t(AUDIENCE_LABEL_KEYS[a]) }}
            </el-radio-button>
          </el-radio-group>
          <span class="log-filter-label">{{ $t('common.status') }}</span>
        </div>
        <el-radio-group
          v-model="filter"
          size="small"
          data-test="log-filter"
          @change="load(1)"
        >
          <el-radio-button
            v-for="f in FILTER_KEYS"
            :key="f"
            :value="f"
          >
            {{ $t(`alerts.log.filter.${f}`) }}
          </el-radio-button>
        </el-radio-group>
        <span class="log-order">{{ $t('alerts.log.order', { tz: utcOffsetText() }) }}</span>
      </div>

      <div
        v-loading="loading"
        class="log-table"
      >
        <div class="log-row log-row--head">
          <span class="log-col-time">{{ $t('alerts.log.colTime') }}</span>
          <span>{{ $t('alerts.log.colStatus') }}</span>
        </div>
        <div
          v-for="row in rows"
          :key="row.id"
          class="log-row"
          data-test="log-row"
        >
          <span class="log-col-time">{{ formatLogTime(row.created_at) }}</span>
          <div class="log-col-main">
            <div class="log-line">
              <el-tag
                :type="DELIVERY_STATE_TAG_TYPES[row.state] || 'info'"
                :class="{ [NEUTRAL_TAG_CLASS]: NEUTRAL_DELIVERY_STATES.includes(row.state) }"
                size="small"
                data-test="log-state"
              >
                {{ deliveryStateLabel(row.state) }}
              </el-tag>
              <el-tag
                v-if="targetsUsers || row.audience === 'user'"
                size="small"
                effect="plain"
                :type="row.audience === 'user' ? 'primary' : 'info'"
                :class="{ [NEUTRAL_TAG_CLASS]: row.audience !== 'user' }"
                data-test="log-audience-tag"
              >
                <el-icon
                  v-if="row.audience === 'user'"
                  class="log-audience-icon"
                >
                  <UserRound />
                </el-icon>{{ $t(row.audience === 'user' ? 'alerts.log.audienceUser' : 'alerts.log.audienceChannel') }}
              </el-tag>
              <span class="log-category">{{ categoryLabel(row.category) }}</span>
              <strong
                v-if="eventName(row)"
                class="log-event"
              >{{ eventName(row) }}</strong>
              <el-tag
                v-if="row.severity"
                :type="SEVERITY_TAG_TYPES[row.severity] || 'info'"
                size="small"
                effect="plain"
              >
                {{ severityLabel(row.severity) }}
              </el-tag>
              <span
                v-if="row.snapshot_before_change"
                class="log-snapshot"
                data-test="log-snapshot"
              >{{ $t('alerts.log.snapshotTag') }}</span>
            </div>
            <!-- 個人訊息：收件的系統帳號與對應到的 Slack 帳號（不顯示電子郵件） -->
            <i18n-t
              v-if="row.audience === 'user'"
              keypath="alerts.log.recipient"
              scope="global"
              tag="div"
              class="log-recipient"
              data-test="log-recipient"
            >
              <template #username>
                <strong>{{ row.recipient_username || '-' }}</strong>
              </template>
              <template #slack_id>
                <span :class="row.recipient_slack_id ? 'mono-text' : 'log-unmapped'">{{ row.recipient_slack_id || $t('alerts.log.recipientUnmapped') }}</span>
              </template>
            </i18n-t>
            <div
              v-if="deliveryDescription(row)"
              class="log-desc"
              data-test="log-desc"
            >
              {{ deliveryDescription(row) }}
            </div>
          </div>
        </div>

        <!-- 空狀態：通道從未投遞／篩選後沒有結果 -->
        <EmptyState
          v-if="!loading && !rows.length && filter === 'all' && audience === 'all'"
          compact
          :icon="Send"
          :icon-size="24"
          :title="$t('alerts.log.emptyTitle')"
          :hint="$t('alerts.log.emptyHint')"
          data-test="log-empty"
        />
        <EmptyState
          v-else-if="!loading && !rows.length"
          compact
          :icon="Send"
          :icon-size="24"
          :title="$t('alerts.log.emptyFilteredTitle', { filter: emptyFilterLabel })"
          :hint="$t('alerts.log.emptyFilteredHint')"
          data-test="log-empty-filtered"
        />
      </div>

      <div class="log-footer">
        <el-pagination
          v-model:current-page="page"
          :page-size="PAGE_SIZE"
          :total="total"
          layout="total, prev, pager, next"
          small
          @current-change="load"
        />
      </div>
    </template>
  </el-drawer>
</template>

<script setup>
// 投遞紀錄抽屜：只列狀態，不顯示通知內容與目的地網址。
// 篩選以 state 參數交給伺服器（「未送達」＝pending,retrying），total 是篩選後的筆數。
import { ref, computed } from 'vue'
import { Send, UserRound } from 'lucide-vue-next'
import { CHANNEL_TYPES_TARGET_USER } from '@/constants/notification-channels'
import { t } from '@/i18n'
import EmptyState from '@/components/EmptyState.vue'
import { getChannelDeliveries } from '@/api/alerts'
import {
  LOG_FILTERS,
  DELIVERY_STATE_TAG_TYPES,
  NEUTRAL_TAG_CLASS,
  NEUTRAL_DELIVERY_STATES,
  SEVERITY_TAG_TYPES,
  deliveryStateLabel,
  categoryLabel,
  eventName,
  severityLabel,
  deliveryDescription,
  formatLogTime,
  utcOffsetText,
  healthStatus,
} from './channelDelivery'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  /** 通道列（列表回應的一列，含 health） */
  channel: { type: Object, default: null },
})
const emit = defineEmits(['update:modelValue'])

const FILTER_KEYS = Object.keys(LOG_FILTERS)
const PAGE_SIZE = 50
// 收件對象篩選 → 伺服器的 audience 參數（全部＝不帶）
const AUDIENCE_KEYS = ['all', 'channel', 'user']
const AUDIENCE_LABEL_KEYS = {
  all: 'alerts.log.audienceAll',
  channel: 'alerts.log.audienceChannel',
  user: 'alerts.log.audienceUser',
}

const rows = ref([])
const total = ref(0)
const page = ref(1)
const loading = ref(false)
const filter = ref('all')
const audience = ref('all')

// 能以個人為對象的型別：顯示收件對象篩選、每列的收件對象，摘要卡標明只算頻道
const targetsUsers = computed(() => CHANNEL_TYPES_TARGET_USER.includes(props.channel?.type))
const cardSuffix = computed(() => (targetsUsers.value ? t('alerts.log.sumChannelSuffix') : ''))
const emptyFilterLabel = computed(() =>
  filter.value !== 'all' ? t(`alerts.log.filter.${filter.value}`) : t(AUDIENCE_LABEL_KEYS[audience.value]))

const health = computed(() => props.channel?.health || {})
const abandoned7d = computed(() => Number(health.value.abandoned_7d) || 0)
const failing = computed(() => props.channel && healthStatus({ ...props.channel, enabled: true }) === 'failing')

const onOpen = () => {
  filter.value = 'all'
  audience.value = 'all'
  void load(1)
}

const load = async (p = 1) => {
  if (!props.channel) return
  page.value = p
  loading.value = true
  try {
    const params = { page: p, page_size: PAGE_SIZE }
    const states = LOG_FILTERS[filter.value]
    if (states) params.state = states.join(',')
    if (targetsUsers.value && audience.value !== 'all') params.audience = audience.value
    const res = await getChannelDeliveries(props.channel.id, params)
    rows.value = Array.isArray(res?.data) ? res.data : []
    total.value = Number(res?.total) || 0
  } catch (error) {
    console.error('取得投遞紀錄失敗:', error)
    rows.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

defineExpose({ load, filter, audience, rows })
</script>

<style scoped>
.log-cards {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: var(--ot-space-sm);
}

.log-card {
  padding: 10px 14px;
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  background: var(--el-fill-color-lighter);
}

.log-card__value {
  font-weight: 600;
}

.log-card__label {
  margin-top: 2px;
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
}

.log-card--danger .log-card__value {
  color: var(--ot-danger);
}

.log-card--warning {
  border-color: var(--ot-warning);
}

.log-card--warning .log-card__value {
  color: var(--ot-warning);
}

.log-intro {
  margin: var(--ot-space-sm) 0;
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  color: var(--el-text-color-secondary);
}

.log-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-sm);
}

.log-order {
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
}

.log-table {
  min-height: 120px;
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.log-row {
  display: grid;
  grid-template-columns: 110px minmax(0, 1fr);
  gap: var(--ot-space-sm);
  padding: 10px 12px;
  border-top: 1px solid var(--ot-border-subtle);
  font-size: var(--ot-font-size-sm);
}

.log-row--head {
  border-top: none;
  background: var(--el-fill-color-light);
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
}

.log-col-time {
  color: var(--el-text-color-secondary);
  white-space: nowrap;
}

.log-line {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}

.log-filter-group {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ot-space-sm);
}

.log-filter-label {
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
}

.log-audience-icon {
  margin-right: 2px;
  vertical-align: -2px;
}

.log-recipient {
  margin-top: 4px;
  color: var(--el-text-color-secondary);
}

.log-recipient strong {
  margin: 0 6px;
  color: var(--el-text-color-primary);
}

.log-recipient .mono-text {
  font-family: var(--ot-font-mono);
}

.log-unmapped {
  color: var(--el-text-color-secondary);
}

.log-category {
  color: var(--el-text-color-secondary);
}

.log-snapshot {
  padding: 0 6px;
  border: 1px dashed var(--el-border-color);
  border-radius: var(--ot-radius-sm);
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
}

.log-desc {
  margin-top: 4px;
  line-height: 1.6;
}

.log-footer {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: var(--ot-space-sm);
  margin-top: var(--ot-space-sm);
}
</style>
