<template>
  <el-dialog
    :model-value="modelValue"
    :title="$t('keystrokeView.noContent.dialogTitle')"
    width="460px"
    append-to-body
    data-test="keystroke-status-dialog"
    @update:model-value="(v) => $emit('update:modelValue', v)"
  >
    <div
      class="status-body"
      :data-tone="info.tone"
    >
      <div class="status-title">
        {{ title }}
      </div>
      <div class="status-text">
        {{ body }}
      </div>
      <div
        v-if="hint"
        class="status-hint"
      >
        {{ hint }}
      </div>
    </div>
    <template #footer>
      <el-button
        type="primary"
        data-test="keystroke-status-ok"
        @click="$emit('update:modelValue', false)"
      >
        {{ $t('keystrokeView.noContent.ok') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
// 沒有可查看內容時的狀態說明：只說明原因與下一步，不要求理由、不開檢視頁。
import { computed } from 'vue'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { describeNoContent } from '@/utils/keystrokeView'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  meta: { type: Object, default: null },
})
defineEmits(['update:modelValue'])

const info = computed(() => describeNoContent(props.meta))
const base = computed(() => `keystrokeView.noContent.${info.value.key}`)
const title = computed(() => t(`${base.value}.title`))
const body = computed(() => {
  const i = info.value
  if (i.key === 'preFeature' || i.key === 'purged') {
    return i.time
      ? t(`${base.value}.body`, { time: formatDateTime(i.time) })
      : t(`${base.value}.bodyNoTime`)
  }
  if (i.key === 'failedNoFile' && i.cause) {
    return t(`${base.value}.bodyCause`, { cause: t(`keystrokeView.failureCause.${i.cause}`) })
  }
  return t(`${base.value}.body`)
})
const hint = computed(() => (info.value.hint ? t(`keystrokeView.noContent.${info.value.hint}`) : ''))
</script>

<style scoped>
.status-body { display: flex; flex-direction: column; gap: 8px; line-height: 1.65; }
.status-title { font-size: 15px; font-weight: 600; color: var(--ot-text-primary); }
.status-body[data-tone='error'] .status-title { color: var(--ot-danger, #e5604f); }
.status-body[data-tone='warn'] .status-title { color: var(--ot-warning, #d9a93e); }
.status-text { color: var(--ot-text-secondary); }
.status-hint { font-size: 12.5px; color: var(--ot-text-secondary); }
</style>
