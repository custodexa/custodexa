<template>
  <!-- 批次的執行中與結果畫面：逐筆一列，狀態文字由呼叫端依面組字 -->
  <div class="batch-progress">
    <p
      v-if="phase === 'running'"
      class="batch-progress__count"
      data-test="batch-progress"
    >
      {{ progressText }}
    </p>
    <p
      v-else-if="phase === 'reconciling'"
      class="batch-progress__count"
    >
      {{ checkingText }}
    </p>
    <!-- 讀屏：結果摘要是唯一的 live region，常駐於 DOM，內容在結果態才填入 -->
    <p
      class="batch-progress__summary"
      data-test="batch-summary"
      aria-live="polite"
    >
      {{ phase === 'result' ? summaryText : '' }}
    </p>
    <ul class="batch-progress__list">
      <li
        v-for="item in items"
        :key="item.id"
        class="batch-progress__item"
        data-test="batch-item"
        :data-id="item.id"
        :data-state="item.state"
      >
        <span class="batch-progress__label">{{ item.label }}</span>
        <span :class="['batch-progress__status', `batch-progress__status--${item.state}`]">
          {{ describe(item) }}
        </span>
      </li>
    </ul>
  </div>
</template>

<script setup>
defineProps({
  phase: { type: String, required: true },
  items: { type: Array, required: true },
  progressText: { type: String, default: '' },
  summaryText: { type: String, default: '' },
  checkingText: { type: String, default: '' },
  describe: { type: Function, required: true },
})
</script>

<style scoped>
.batch-progress {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-primary);
}

.batch-progress__count,
.batch-progress__summary {
  margin: 0;
}

.batch-progress__summary:empty {
  display: none;
}

.batch-progress__summary {
  font-weight: 600;
}

.batch-progress__list {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  max-height: 50vh;
  margin: 0;
  padding: 0;
  overflow-y: auto;
  list-style: none;
  font-size: var(--ot-font-size-sm);
}

.batch-progress__item {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: var(--ot-space-xs) var(--ot-space-md);
  padding: var(--ot-space-xs) 0;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.batch-progress__label {
  overflow-wrap: anywhere;
}

.batch-progress__status {
  text-align: right;
  color: var(--ot-text-secondary);
}

.batch-progress__status--success {
  color: var(--ot-success);
}

.batch-progress__status--rejected,
.batch-progress__status--unconfirmed {
  color: var(--ot-warning);
}

.batch-progress__status--inflight {
  color: var(--ot-text-primary);
}
</style>
