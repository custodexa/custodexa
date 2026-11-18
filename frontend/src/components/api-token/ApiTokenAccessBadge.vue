<template>
  <span
    class="ataccess"
    data-test="access-badge"
  >
    <el-tag
      :type="isRead ? 'info' : 'warning'"
      :class="['ataccess__tag', isRead ? 'ot-tag-neutral' : '', access === 'mixed' ? 'is-mixed' : '']"
      :data-access="access"
      data-test="access-tag"
    >
      <component
        :is="isRead ? Eye : PenLine"
        :size="12"
        aria-hidden="true"
        class="ataccess__icon"
      />{{ accessLabel(access) }}
    </el-tag>
    <span
      v-if="subText"
      class="ataccess__sub"
      data-test="access-sub"
    >{{ subText }}</span>
  </span>
</template>

<script setup>
import { computed } from 'vue'
import { Eye, PenLine } from 'lucide-vue-next'
import { t } from '@/i18n'
import { API_TOKEN_ACCESS_VALUES, accessLabel } from '@/constants/apiTokens'

/**
 * 整把 API token 的權限總結：唯讀（灰）、讀寫（琥珀）、部分讀寫（琥珀虛線框）。
 * 第二行依用途擇一：清單寫「N 個角色讀寫」或「升級前建立」，明文面板寫一句說明它代表什麼。
 */
const props = defineProps({
  // read｜read_write｜mixed；不認得的值當唯讀
  value: { type: String, default: 'read' },
  // 部分讀寫時設為讀寫的角色數（清單的第二行）
  writeCount: { type: Number, default: 0 },
  // 升級前建立（清單的第二行）
  legacy: { type: Boolean, default: false },
  // 明文面板：第二行改寫成一句說明
  explain: { type: Boolean, default: false },
})

const access = computed(() => (API_TOKEN_ACCESS_VALUES.includes(props.value) ? props.value : 'read'))
const isRead = computed(() => access.value === 'read')
const subText = computed(() => {
  if (props.explain) return t(`apiTokens.reveal.accessHint.${access.value}`)
  if (props.legacy) return t('apiTokens.access.legacy')
  if (access.value === 'mixed' && props.writeCount > 0) return t('apiTokens.access.mixedCount', { n: props.writeCount })
  return ''
})
</script>

<style scoped>
.ataccess {
  display: inline-flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 4px;
}
.ataccess__tag {
  font-weight: 600;
}
.ataccess__tag.is-mixed {
  border-style: dashed;
}
.ataccess__icon {
  margin-right: 4px;
  vertical-align: -2px;
}
.ataccess__sub {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
</style>
