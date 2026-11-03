<template>
  <el-dialog
    :model-value="modelValue"
    :title="$t('hostInventory.ignore.title')"
    width="480px"
    append-to-body
    :close-on-click-modal="false"
    @update:model-value="(v) => emit('update:modelValue', v)"
    @open="reset"
  >
    <div
      v-if="finding"
      class="ignore-summary"
      data-test="ignore-summary"
    >
      <HostInventoryName
        :value="finding.username"
        :badges="false"
      />
      <span class="ignore-asset">{{ assetName }}</span>
      <HostInventoryReasons :reasons="finding.privileged_reasons" />
    </div>
    <label
      class="ignore-label"
      for="inv-ignore-reason"
    >{{ $t('hostInventory.ignore.reasonLabel') }}</label>
    <el-input
      id="inv-ignore-reason"
      v-model="reason"
      type="textarea"
      :rows="3"
      :placeholder="$t('hostInventory.ignore.placeholder')"
      data-test="ignore-reason"
    />
    <p
      v-if="problem"
      class="ignore-error"
      data-test="ignore-problem"
    >
      {{ problem }}
    </p>
    <p class="ignore-note">
      {{ $t('hostInventory.ignore.note') }}
    </p>
    <template #footer>
      <el-button
        data-test="ignore-cancel"
        @click="emit('update:modelValue', false)"
      >
        {{ $t('hostInventory.ignore.cancel') }}
      </el-button>
      <el-button
        v-preview-write
        type="primary"
        :disabled="!!problem || !trimmed || submitting"
        :loading="submitting"
        data-test="ignore-submit"
        @click="submit"
      >
        {{ $t('hostInventory.ignore.submit') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { t } from '@/i18n'
import { ignoreInventoryFinding } from '@/api/hostInventory'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import { visibleText } from '@/utils/visibleName'
import HostInventoryName from './HostInventoryName.vue'
import HostInventoryReasons from './HostInventoryReasons.vue'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  assetId: { type: [Number, String], default: 0 },
  assetName: { type: String, default: '' },
  finding: { type: Object, default: null },
})
const emit = defineEmits(['update:modelValue', 'done', 'gone', 'denied'])

const reason = ref('')
const submitting = ref(false)
const serverProblem = ref('')

const trimmed = computed(() => reason.value.trim())
const length = computed(() => Array.from(trimmed.value).length)

// 本地驗證：空白與超長不顯示錯誤（空白時按鈕停用即可），控制字元與超長就地說明
const problem = computed(() => {
  if (serverProblem.value) return serverProblem.value
  if (!trimmed.value) return ''
  if (length.value > 500) return t('hostInventory.ignore.errLong', { n: length.value })
  if (/\p{Cc}/u.test(trimmed.value)) return t('hostInventory.ignore.errControl')
  return ''
})

function reset() {
  reason.value = ''
  serverProblem.value = ''
  submitting.value = false
}

async function submit() {
  if (!props.finding || problem.value || !trimmed.value) return
  submitting.value = true
  serverProblem.value = ''
  try {
    const res = await ignoreInventoryFinding(props.assetId, props.finding.id, trimmed.value)
    ElMessage.success(t('hostInventory.ignore.success', { name: visibleText(props.finding.username) }))
    emit('done', { id: props.finding.id, status: res?.status || 'ignored', reason: trimmed.value })
    emit('update:modelValue', false)
  } catch (err) {
    const status = err?.response?.status
    const code = err?.response?.data?.code
    if (code === 'VALIDATION_INVENTORY_IGNORE_REASON') {
      serverProblem.value = t('apiError.VALIDATION_INVENTORY_IGNORE_REASON')
    } else if (code === 'NOTFOUND_INVENTORY_FINDING' || code === 'VALIDATION_INVALID_FINDING_ID') {
      ElMessage.error(t('hostInventory.err.itemGone'))
      emit('gone')
      emit('update:modelValue', false)
    } else if (status === 403 || status === 404) {
      ElMessage.error(t('hostInventory.err.notInScope'))
      emit('denied')
      emit('update:modelValue', false)
    } else {
      ElMessage.error(t('hostInventory.err.generic'))
    }
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.ignore-summary {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 12px;
  padding: 10px 12px;
  margin-bottom: 14px;
  background: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.ignore-asset {
  color: var(--ot-text-secondary);
  font-size: 13px;
}

.ignore-label {
  display: block;
  margin-bottom: 6px;
  font-size: 14px;
  color: var(--ot-text-primary);
}

.ignore-error {
  margin: 6px 0 0;
  font-size: 13px;
  color: var(--ot-danger);
}

.ignore-note {
  margin: 8px 0 0;
  font-size: 13px;
  line-height: 1.6;
  color: var(--ot-text-secondary);
}
</style>
