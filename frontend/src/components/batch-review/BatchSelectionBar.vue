<template>
  <!-- 批次列：勾選後才出現在表格上方；文字全由呼叫端給（各面的單位不同） -->
  <div
    class="batch-bar"
    :data-test="testId"
  >
    <div class="batch-bar__text">
      <span>{{ countText }}</span>
      <span
        v-if="limitText"
        class="batch-bar__limit"
        data-test="batch-limit-hint"
      >{{ limitText }}</span>
    </div>
    <div class="batch-bar__actions">
      <el-button
        data-test="batch-clear"
        @click="$emit('clear')"
      >
        {{ clearText }}
      </el-button>
      <slot />
    </div>
  </div>
</template>

<script setup>
defineProps({
  countText: { type: String, required: true },
  clearText: { type: String, required: true },
  // 達上限或全選因上限少勾時才給
  limitText: { type: String, default: '' },
  testId: { type: String, default: 'batch-bar' },
})
defineEmits(['clear'])
</script>

<style scoped>
.batch-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-md);
  padding: var(--ot-space-sm) var(--ot-space-md);
  background: var(--ot-primary-dim);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-primary);
}

.batch-bar__text {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: var(--ot-space-sm);
}

.batch-bar__limit {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-warning);
}

.batch-bar__actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-sm);
}

.batch-bar__actions :deep(.el-button + .el-button) {
  margin-left: 0;
}
</style>
