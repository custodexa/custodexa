<template>
  <el-drawer
    :model-value="modelValue"
    :title="$t('workspace.systemMonitor')"
    size="320px"
    :append-to-body="true"
    @update:model-value="$emit('update:modelValue', $event)"
    @open="start"
    @close="stop"
  >
    <div
      v-if="error"
      class="stats-error"
    >
      {{ error }}
    </div>
    <template v-else-if="stats">
      <div class="stats-row">
        <span class="stats-label">{{ $t('sessionDetail.host') }}</span><span>{{ stats.hostname }}</span>
      </div>
      <div class="stats-row">
        <span class="stats-label">{{ $t('sessionStats.uptime') }}</span><span>{{ formatUptimeSeconds(stats.uptime_sec) }}</span>
      </div>
      <div class="stats-row">
        <span class="stats-label">{{ $t('sessionStats.load') }}</span>
        <span>{{ stats.load1.toFixed(2) }} / {{ stats.load5.toFixed(2) }} / {{ stats.load15.toFixed(2) }}</span>
      </div>

      <div class="stats-section">
        CPU
      </div>
      <el-progress
        :percentage="cpuPercent"
        :stroke-width="14"
        :format="(p) => p.toFixed(1) + '%'"
      />

      <div class="stats-section">
        {{ $t('sessionStats.memory') }}
      </div>
      <el-progress
        :percentage="memPercent"
        :stroke-width="14"
        :format="(p) => p.toFixed(1) + '%'"
      />
      <div class="stats-hint">
        {{ $t('sessionStats.memUsed', {
          used: formatKB(stats.mem_total_kb - stats.mem_avail_kb),
          total: formatKB(stats.mem_total_kb),
        }) }}
      </div>

      <div class="stats-section">
        {{ $t('sessionStats.network') }}
      </div>
      <div class="stats-row">
        <span class="stats-label">{{ $t('sessionStats.downlink') }}</span><span>{{ formatRate(rxRate) }}</span>
      </div>
      <div class="stats-row">
        <span class="stats-label">{{ $t('sessionStats.uplink') }}</span><span>{{ formatRate(txRate) }}</span>
      </div>
    </template>
    <el-skeleton
      v-else
      :rows="5"
      animated
    />
  </el-drawer>
</template>

<script setup>
import { ref, computed, onBeforeUnmount } from 'vue'
import { getSessionStats } from '@/api/sessions'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import { formatUptimeSeconds } from '@/utils/format'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  sessionId: { type: [Number, String], default: null },
})
defineEmits(['update:modelValue'])

const POLL_MS = 2000

const stats = ref(null)
const error = ref('')
const prev = ref(null)
let timer = null

// CPU%/網速由兩次輪詢差分（後端 stateless）
const cpuPercent = computed(() => {
  if (!stats.value || !prev.value) return 0
  const dTotal = stats.value.cpu_total - prev.value.cpu_total
  const dBusy = stats.value.cpu_busy - prev.value.cpu_busy
  if (dTotal <= 0) return 0
  return Math.min(100, Math.max(0, (dBusy / dTotal) * 100))
})

const memPercent = computed(() => {
  if (!stats.value || !stats.value.mem_total_kb) return 0
  return ((stats.value.mem_total_kb - stats.value.mem_avail_kb) / stats.value.mem_total_kb) * 100
})

const rxRate = computed(() => diffRate('net_rx_bytes'))
const txRate = computed(() => diffRate('net_tx_bytes'))

function diffRate(field) {
  if (!stats.value || !prev.value) return 0
  return Math.max(0, (stats.value[field] - prev.value[field]) / (POLL_MS / 1000))
}

async function poll() {
  if (!props.sessionId) {
    error.value = t('sessionStats.noSession')
    return
  }
  try {
    const data = await getSessionStats(props.sessionId)
    prev.value = stats.value
    stats.value = data
    error.value = ''
  } catch (err) {
    error.value = resolveApiError(err.response?.data, err.response?.status, t('sessionStats.queryFailed'))
  }
}

function start() {
  stop()
  stats.value = null
  prev.value = null
  error.value = ''
  poll()
  timer = setInterval(poll, POLL_MS)
}

function stop() {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
}

onBeforeUnmount(stop)

function formatKB(kb) {
  if (kb >= 1024 * 1024) return (kb / 1024 / 1024).toFixed(1) + ' GB'
  return (kb / 1024).toFixed(0) + ' MB'
}

function formatRate(bps) {
  if (bps >= 1024 * 1024) return (bps / 1024 / 1024).toFixed(1) + ' MB/s'
  if (bps >= 1024) return (bps / 1024).toFixed(1) + ' KB/s'
  return bps.toFixed(0) + ' B/s'
}

defineExpose({ start, stop, poll, stats, prev, cpuPercent, rxRate })
</script>

<style scoped>
.stats-row {
  display: flex;
  justify-content: space-between;
  font-size: 13px;
  padding: 4px 0;
}

.stats-label {
  color: var(--el-text-color-secondary);
}

.stats-section {
  margin: 14px 0 6px;
  font-size: 12px;
  font-weight: 600;
  color: var(--el-text-color-secondary);
}

.stats-hint {
  margin-top: 4px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.stats-error {
  font-size: 13px;
  color: var(--el-color-warning);
}
</style>
