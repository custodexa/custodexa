<template>
  <div
    class="coverage-notices"
    data-test="coverage-notices"
  >
    <el-alert
      v-for="notice in notices"
      :key="notice.type"
      class="coverage-alert"
      :type="notice.level"
      :closable="false"
      show-icon
      :title="notice.text"
      :data-test="`coverage-${notice.state}-${notice.type}`"
    >
      <!-- slot 一律存在、條件放在按鈕上：把 v-if 掛在 slot template 上會讓
           el-alert 的 description 區塊整段不渲染（連結因此消失） -->
      <template #default>
        <el-button
          v-if="notice.seqRange"
          link
          type="primary"
          size="small"
          :data-test="`checkpoint-link-${notice.type}`"
          @click="emit('open-checkpoint', notice.seqRange)"
        >
          {{ $t('auditorWorkbench.coverage.checkpointLink', {
            from: notice.seqRange.from,
            to: notice.seqRange.to,
          }) }}
        </el-button>
      </template>
    </el-alert>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { TIMELINE_TYPES, typeLabel } from './timelineSummary'
import { formatDateTime } from '@/utils/format'

// 保留期三態。**任何空白區間都不得無標記**——沒有這份標記，
// 一段空白會被稽核員讀成「紀錄被刪」，工作台自己製造竄改誤報。
//
// 文案紀律：一律「已依保留政策清除」，SHALL NOT 寫成「已全部刪除」
//（分批清除、部分完成、區間化過度保留都可能有殘留），且全頁不得對
// 完整性作任何宣稱——那是檢查點驗證頁的職權
const props = defineProps({
  coverage: { type: Array, default: () => [] },
  counts: { type: Object, default: () => ({}) },
  activeTypes: { type: Array, default: () => [] },
})
const emit = defineEmits(['open-checkpoint'])

const { t } = useI18n()

const entryOf = (type) => props.coverage?.find((c) => c.type === type) || null

const purgedText = (type, entry) => {
  const category = typeLabel(type)
  const base =
    entry.policy_days !== null && entry.policy_days !== undefined && entry.last_purge_at
      ? t('auditorWorkbench.coverage.purgedDetail', {
          category,
          days: entry.policy_days,
          time: formatDateTime(entry.last_purge_at),
        })
      : t('auditorWorkbench.coverage.purgedDetailPlain', { category })
  return entry.partial
    ? `${base}${t('auditorWorkbench.coverage.partial')}`
    : base
}

const notices = computed(() =>
  TIMELINE_TYPES.filter((type) => props.activeTypes.includes(type))
    .map((type) => {
      const entry = entryOf(type)
      const state = entry?.state || 'present'
      const category = typeLabel(type)
      if (state === 'purged') {
        return {
          type,
          state,
          level: 'warning',
          text: purgedText(type, entry),
          seqRange: entry.checkpoint_seq_range || null,
        }
      }
      if (state === 'not_retained') {
        return {
          type,
          state,
          level: 'info',
          text: t('auditorWorkbench.coverage.notRetainedDetail', { category }),
          seqRange: null,
        }
      }
      // present：有資料就不必多話；一筆都沒有時必須明說「沒有紀錄」，
      // 讓空白有歸因，而不是留給讀者自行猜測
      if ((props.counts?.[type] ?? 0) === 0) {
        return {
          type,
          state,
          level: 'info',
          text: t('auditorWorkbench.coverage.emptyPresent', { category }),
          seqRange: null,
        }
      }
      return null
    })
    .filter(Boolean)
)
</script>

<style scoped>
.coverage-notices {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.coverage-alert {
  padding: 6px var(--ot-space-sm);
}

/* 沒有檢查點連結的那幾則不留空描述區塊 */
.coverage-alert :deep(.el-alert__description:empty) {
  display: none;
}
</style>
