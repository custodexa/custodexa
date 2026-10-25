<template>
  <div
    class="empty-state"
    :class="{ 'is-compact': compact }"
  >
    <el-icon
      class="empty-icon"
      :size="iconSize"
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
  iconSize: {
    type: Number,
    default: 40,
  },
  // 窄欄用：內距縮小
  compact: {
    type: Boolean,
    default: false,
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

.empty-state.is-compact {
  padding: var(--ot-space-lg) var(--ot-space-md);
}

.empty-icon {
  color: var(--ot-text-disabled);
  margin-bottom: var(--ot-space-md);
}

.empty-title {
  font-size: var(--ot-font-size-md);
  /* 面板裡唯一的主句：跟下面的註腳同色時，整個空態讀起來就是一團灰字 */
  color: var(--ot-text-primary);
  font-weight: 600;
  margin: 0;
}

.empty-hint {
  font-size: var(--ot-font-size-sm);
  /* 空態的說明句是要讀的：disabled 階只有 3.83:1，低於 AA */
  color: var(--ot-text-secondary);
  margin: var(--ot-space-xs) 0 0;
}

.empty-action {
  margin-top: var(--ot-space-md);
}
</style>
