<template>
  <!-- 統計數字要一眼找得到：同一面板裡「可用幾把」「停用幾把」原本寫成
       一行 14px 灰字本文，與周邊說明句同階，讀者得逐字讀完才看得到數字。
       數字升到 20px／600 並用主文字色，標籤留在灰字階——灰的是標籤，不是答案 -->
  <div
    class="stat-block"
    :data-test="dataTest"
  >
    <div
      v-for="stat in items"
      :key="stat.label"
      class="stat-block__item"
    >
      <span
        class="stat-value"
        :data-test="stat.dataTest"
      >{{ stat.value }}</span>
      <span class="stat-label">{{ stat.label }}</span>
    </div>
  </div>
</template>
<script setup>
defineProps({
  // [{ value, label, dataTest? }]：value 只放數字本身，單位與名稱一律進 label
  items: { type: Array, required: true },
  dataTest: { type: String, default: 'stat-block' },
})
</script>
<style scoped>
.stat-block { display: flex; flex-wrap: wrap; gap: var(--ot-space-lg); margin: 0; }
.stat-block__item { display: flex; flex-direction: column; gap: var(--ot-space-xs); }
.stat-value { font-size: var(--ot-font-size-xl); font-weight: 600; line-height: 1.2; color: var(--ot-text-primary); }
.stat-label { font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
</style>
