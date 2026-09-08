<template>
  <section class="source-section">
    <button
      type="button"
      class="source-section__head"
      :aria-expanded="open ? 'true' : 'false'"
      @click="open = !open"
    >
      <span class="source-section__title">{{ index }}. {{ title }}</span>
      <span class="source-section__hint">{{ hint }}</span>
      <span class="source-section__toggle">
        <el-icon><ChevronDown v-if="open" /><ChevronRight v-else /></el-icon>
        {{ open ? $t('identitySources.collapse') : $t('identitySources.expand') }}
      </span>
    </button>
    <el-collapse-transition>
      <div
        v-show="open"
        class="source-section__body"
      >
        <slot />
      </div>
    </el-collapse-transition>
  </section>
</template>

<script setup>
import { ref } from 'vue'
import { ChevronDown, ChevronRight } from 'lucide-vue-next'

defineProps({
  index: { type: Number, required: true },
  title: { type: String, required: true },
  hint: { type: String, default: '' },
})

// 預設全部展開：設定頁的預設狀態不該要求管理者先找到再點開
const open = ref(true)
</script>

<style scoped>
.source-section {
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  margin-bottom: var(--ot-space-md);
  overflow: hidden;
}

/* 整條標題列可點：只有小箭頭可點的折疊區是常見的可用性缺陷 */
.source-section__head {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: var(--ot-space-sm);
  width: 100%;
  padding: var(--ot-space-md);
  border: 0;
  border-bottom: 1px solid var(--ot-border-subtle);
  background: transparent;
  color: inherit;
  font: inherit;
  text-align: left;
  cursor: pointer;
}

.source-section__title {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.source-section__hint {
  flex: 1;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.source-section__toggle {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.source-section__body {
  padding: var(--ot-space-md);
}
</style>
