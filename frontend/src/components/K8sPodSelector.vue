<!--
  K8sPodSelector：連線時選 pod 選擇器（k8s-exec）。
  對標 k9s 最小可用集：即時清單 + 狀態色 + 即時篩選 + Ready/Age/重啟/容器/image；
  多容器讀 default-container 預選；錯誤呈現後端分類的五類人話。
-->
<template>
  <el-dialog
    :model-value="modelValue"
    :title="dialogTitle"
    width="760px"
    @update:model-value="(v) => emit('update:modelValue', v)"
    @open="onOpen"
  >
    <div class="k8s-sel">
      <div class="k8s-sel__bar">
        <el-radio-group
          v-model="mode"
          size="small"
        >
          <el-radio-button label="">
            {{ $t('podSelector.modeTerminal') }}
          </el-radio-button>
          <el-radio-button label="logs">
            {{ $t('podSelector.modeLogs') }}
          </el-radio-button>
        </el-radio-group>
        <el-input
          v-model="filter"
          size="small"
          :placeholder="$t('podSelector.filterPlaceholder')"
          clearable
          class="k8s-sel__search"
        />
        <el-button
          size="small"
          :loading="loading"
          @click="load"
        >
          {{ $t('common.refresh') }}
        </el-button>
      </div>

      <el-alert
        v-if="error"
        :title="error"
        type="error"
        :closable="false"
        show-icon
        class="k8s-sel__err"
      />

      <el-table
        v-else
        v-loading="loading"
        :data="filtered"
        height="340"
        size="small"
        highlight-current-row
        @current-change="onSelect"
        @row-dblclick="onRowDblClick"
      >
        <el-table-column
          :label="$t('common.status')"
          width="150"
        >
          <template #default="{ row }">
            <el-tag
              :type="phaseType(row.phase)"
              size="small"
              effect="dark"
            >
              {{ row.phase }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          prop="name"
          label="Pod"
          min-width="220"
          show-overflow-tooltip
        />
        <el-table-column
          prop="ready"
          label="Ready"
          width="80"
        />
        <el-table-column
          prop="restarts"
          :label="$t('podSelector.restartsColumn')"
          width="70"
        />
        <el-table-column
          label="Age"
          width="80"
        >
          <template #default="{ row }">
            {{ age(row.started_at) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('podSelector.containersColumn')"
          min-width="120"
        >
          <template #default="{ row }">
            {{ $t('podSelector.containerCount', { n: row.containers.length }) }}
          </template>
        </el-table-column>
        <template #empty>
          <span class="k8s-sel__empty">{{ loading ? $t('podSelector.loading') : $t('podSelector.emptyPods') }}</span>
        </template>
      </el-table>

      <div
        v-if="selected && selected.containers.length > 1"
        class="k8s-sel__container"
      >
        <span class="k8s-sel__label">{{ $t('podSelector.containerLabel') }}</span>
        <el-select
          v-model="container"
          size="small"
          style="width: 240px"
        >
          <el-option
            v-for="c in selected.containers"
            :key="c.name"
            :value="c.name"
            :label="c.ready ? c.name : $t('podSelector.containerNotReady', { name: c.name })"
          />
        </el-select>
        <span class="k8s-sel__img">{{ selectedImage }}</span>
      </div>
    </div>

    <template #footer>
      <span class="k8s-sel__hint">{{ selected ? $t('podSelector.willEnter', { name: selected.name }) : $t('podSelector.pleaseSelect') }}</span>
      <el-button @click="emit('update:modelValue', false)">
        {{ $t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :disabled="!selected"
        @click="confirm"
      >
        {{ $t('common.connect') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed } from 'vue'
import { listK8sPods } from '@/api/assets'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  assetId: { type: [Number, String], default: null },
  assetName: { type: String, default: '' },
  assetNamespace: { type: String, default: '' },
})
const emit = defineEmits(['update:modelValue', 'confirm'])

// 對話框標題（computed：切語言即時反映）
const dialogTitle = computed(() =>
  props.assetNamespace
    ? t('podSelector.titleWithNamespace', { name: props.assetName, namespace: props.assetNamespace })
    : t('podSelector.title', { name: props.assetName })
)

const loading = ref(false)
const error = ref('')
const pods = ref([])
const filter = ref('')
const mode = ref('')
const selected = ref(null)
const container = ref('')

const filtered = computed(() => {
  const f = filter.value.trim().toLowerCase()
  return f ? pods.value.filter((p) => p.name.toLowerCase().includes(f)) : pods.value
})
const selectedImage = computed(() => {
  if (!selected.value) return ''
  const c = selected.value.containers.find((x) => x.name === container.value)
  return c ? c.image : ''
})

function phaseType(phase) {
  if (phase === 'Running') return 'success'
  if (phase === 'Pending') return 'warning'
  if (phase === 'CrashLoopBackOff' || phase === 'Failed') return 'danger'
  return 'info'
}

function age(startedAt) {
  if (!startedAt) return '-'
  const secs = Math.max(0, (Date.now() - new Date(startedAt).getTime()) / 1000)
  if (secs < 60) return `${Math.floor(secs)}s`
  if (secs < 3600) return `${Math.floor(secs / 60)}m`
  if (secs < 86400) return `${Math.floor(secs / 3600)}h`
  return `${Math.floor(secs / 86400)}d`
}

function onSelect(row) {
  selected.value = row
  if (!row) return
  container.value = row.default_container || (row.containers[0] && row.containers[0].name) || ''
}

// 雙擊直接連線（k9s 式快捷；用 default container）
function onRowDblClick(row) {
  onSelect(row)
  confirm()
}

async function onOpen() {
  selected.value = null
  container.value = ''
  filter.value = ''
  await load()
}

async function load() {
  if (!props.assetId) return
  loading.value = true
  error.value = ''
  try {
    const resp = await listK8sPods(props.assetId)
    pods.value = resp.pods || []
  } catch (err) {
    error.value = resolveApiError(err.response?.data, err.response?.status, t('podSelector.listFailed'))
    pods.value = []
  } finally {
    loading.value = false
  }
}

function confirm() {
  if (!selected.value) return
  emit('confirm', {
    pod: selected.value.name,
    container: container.value,
    mode: mode.value,
  })
  emit('update:modelValue', false)
}
</script>

<style scoped>
.k8s-sel__bar {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}
.k8s-sel__search {
  flex: 1;
}
.k8s-sel__err {
  margin-bottom: 12px;
}
.k8s-sel__container {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 12px;
}
.k8s-sel__label {
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
.k8s-sel__img {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  font-family: monospace;
}
.k8s-sel__empty {
  color: var(--el-text-color-secondary);
  font-size: 13px;
}
.k8s-sel__hint {
  margin-right: auto;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
:deep(.el-dialog__footer) {
  display: flex;
  align-items: center;
}
</style>
