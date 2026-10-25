<template>
  <el-dialog
    :model-value="modelValue"
    :title="titleText"
    width="560px"
    :append-to-body="false"
    :close-on-click-modal="false"
    data-test="danger-combo-confirm"
    @update:model-value="onVisible"
  >
    <template v-if="unavailable">
      <p data-test="danger-preview-failed">
        {{ $t('dangerConfirm.previewFailed.body') }}
      </p>
      <p class="hint">
        {{ $t('dangerConfirm.previewFailed.hint') }}
      </p>
    </template>
    <template v-else>
      <ul
        v-if="combos.length"
        class="combo-list"
      >
        <li
          v-for="item in combos"
          :key="item.code"
          :data-test="`danger-combo-${item.code}`"
        >
          <strong>{{ comboLabel(item.code) }}</strong>
          <span class="holders">{{ $t('dangerConfirm.holdersCount', { n: item.count }) }}</span>
          <p
            v-if="hintFor(item.code)"
            class="hint"
          >
            {{ hintFor(item.code) }}
          </p>
          <p
            v-if="item.names.length"
            class="names"
            data-test="danger-combo-names"
          >
            {{ item.names.join('、') }}
          </p>
        </li>
      </ul>

      <p
        v-if="totalCount > 0"
        data-test="danger-affected-total"
      >
        {{ $t('dangerConfirm.affectedTotal', { n: totalCount }) }}
      </p>
      <p
        v-if="partial"
        data-test="danger-evaluated-partial"
      >
        {{ $t('dangerConfirm.evaluatedPartial', { total: totalCount, evaluated: evaluatedCount }) }}
      </p>

      <div
        v-if="notifies"
        class="notify"
        data-test="danger-notify"
      >
        <strong>{{ $t('dangerConfirm.notify.title') }}</strong>
        <p v-if="notifyText">
          {{ notifyText }}
        </p>
      </div>

      <p
        v-if="footnote"
        class="hint"
        data-test="danger-footnote"
      >
        {{ footnote }}
      </p>
      <p class="hint">
        {{ footerText }}
      </p>
    </template>

    <template #footer>
      <el-button
        data-test="danger-back"
        @click="$emit('back')"
      >
        {{ $t('dangerConfirm.back') }}
      </el-button>
      <el-button
        type="primary"
        data-test="danger-proceed"
        @click="$emit('confirm')"
      >
        {{ $t('dangerConfirm.proceed') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed } from 'vue'
import { t, te } from '@/i18n'
import { collectNewCombos, isPartiallyEvaluated, operationMarks } from '@/utils/dangerCombo'

/**
 * 儲存前的危險組合確認。只讀預覽回應：組合取自 subjects[].new_combos，會不會通知取自
 * operation.marks，求值範圍取自 operation.evaluated 與 total。元件不接收角色或權限清單。
 * 名稱只對呼叫端傳入的已載入主體（knownSubjects: [{ user_id, name }]）顯示，其餘以人數表示。
 * 確認只是告知，不阻擋：「仍要儲存」才觸發 confirm，「返回修改」觸發 back。
 */
const props = defineProps({
  modelValue: { type: Boolean, default: false },
  preview: { type: Object, default: null },
  unavailable: { type: Boolean, default: false },
  knownSubjects: { type: Array, default: () => [] },
  // 通知提示的情境句（由呼叫端以該畫面的 dangerConfirm.notify.* 鍵組出）
  notifyMessage: { type: String, default: '' },
  // 確認框底部的補充說明（例如「經映射加入的成員不受這次變更影響」）
  footnote: { type: String, default: '' },
})
const emit = defineEmits(['update:modelValue', 'confirm', 'back'])

const onVisible = (v) => {
  if (!v) emit('back')
  emit('update:modelValue', v)
}

const nameById = computed(() => {
  const m = new Map()
  for (const s of props.knownSubjects || []) {
    if (s && s.user_id != null && s.name) m.set(s.user_id, s.name)
  }
  return m
})

const combos = computed(() => {
  const base = collectNewCombos(props.preview)
  return base.map((item) => {
    const names = []
    for (const s of props.preview?.subjects || []) {
      if ((s?.new_combos || []).includes(item.code) && nameById.value.has(s.user_id)) {
        names.push(nameById.value.get(s.user_id))
      }
    }
    return { ...item, names }
  })
})

const marks = computed(() => operationMarks(props.preview))
const totalCount = computed(() => (Number.isInteger(props.preview?.total) ? props.preview.total : 0))
const evaluatedCount = computed(() => props.preview?.operation?.evaluated ?? 0)
const partial = computed(() => isPartiallyEvaluated(props.preview))
const selfDirection = computed(() => props.preview?.operation?.self_direction || '')
const selfChange = computed(
  () => marks.value.includes('self_authorization') || ['increase', 'decrease'].includes(selfDirection.value),
)
const notifies = computed(() => marks.value.length > 0 || selfChange.value)
const notifyText = computed(() => {
  if (props.notifyMessage) return props.notifyMessage
  return selfChange.value ? t('dangerConfirm.notify.selfChange') : ''
})

const titleText = computed(() => {
  if (props.unavailable) return t('dangerConfirm.previewFailed.title')
  return combos.value.length
    ? t('dangerConfirm.title', { n: combos.value.length })
    : t('dangerConfirm.titleGeneric')
})

const footerText = computed(() => {
  if (combos.value.length) return t('dangerConfirm.notBlocking')
  if (totalCount.value === 0) return t('dangerConfirm.notBlockingZero')
  return t('dangerConfirm.notBlockingNoCombo')
})

const comboLabel = (code) => (te(`roles.dangerCombo.${code}`) ? t(`roles.dangerCombo.${code}`) : code)
const hintFor = (code) => (te(`dangerConfirm.comboHint.${code}`) ? t(`dangerConfirm.comboHint.${code}`) : '')
</script>

<style scoped>
.combo-list {
  list-style: none;
  margin: 0 0 var(--ot-space-md);
  padding: 0;
}
.combo-list li {
  padding: var(--ot-space-sm) 0;
  border-bottom: 1px solid var(--ot-border-subtle);
}
.holders {
  margin-left: var(--ot-space-sm);
  color: var(--ot-text-secondary);
}
.hint,
.names {
  margin: var(--ot-space-xs) 0 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}
.notify {
  margin: var(--ot-space-md) 0;
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-surface);
}
</style>
