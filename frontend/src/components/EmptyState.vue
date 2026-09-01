<template>
  <div class="empty-state">
    <el-icon
      class="empty-icon"
      :size="40"
    >
      <component :is="icon" />
    </el-icon>
    <p class="empty-title">
      {{ displayTitle }}
    </p>
    <p
      v-if="hint"
      class="empty-hint"
    >
      {{ hint }}
    </p>
    <div
      v-if="$slots.action"
      class="empty-action"
    >
      <slot name="action" />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { FolderOpen } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps({
  // 預設文案走 i18n（computed 而非 prop default——prop default 只評估一次不隨語言）
  title: {
    type: String,
    default: '',
  },
  hint: {
    type: String,
    default: '',
  },
  icon: {
    type: [Object, Function],
    default: () => FolderOpen,
  },
})

const displayTitle = computed(() => props.title || t('common.emptyDefault'))
</script>

<style scoped>
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--ot-space-xl) var(--ot-space-lg);
  text-align: center;
}

.empty-icon {
  color: var(--ot-text-disabled);
  margin-bottom: var(--ot-space-md);
}

.empty-title {
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-secondary);
  margin: 0;
}

.empty-hint {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-disabled);
  margin: var(--ot-space-xs) 0 0;
}

.empty-action {
  margin-top: var(--ot-space-md);
}
</style>
