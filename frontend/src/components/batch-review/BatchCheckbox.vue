<template>
  <!-- 表格內的批次勾選框。元件庫的 checkbox 不收 aria-label（會落在外層 label 上，
       讀屏唸不到），這裡改用視覺隱藏的標籤文字給 input 一個可讀名稱 -->
  <span
    class="batch-checkbox"
    :data-test="testId"
    :data-id="dataId"
  >
    <el-checkbox
      :model-value="checked"
      :indeterminate="indeterminate"
      :disabled="disabled"
      @change="(value) => $emit('change', value)"
    >
      <span class="batch-checkbox__label">{{ label }}</span>
    </el-checkbox>
  </span>
</template>

<script setup>
defineProps({
  checked: { type: Boolean, default: false },
  indeterminate: { type: Boolean, default: false },
  disabled: { type: Boolean, default: false },
  // 讀屏用的名稱（畫面上不顯示）
  label: { type: String, required: true },
  testId: { type: String, default: undefined },
  dataId: { type: [Number, String], default: undefined },
})
defineEmits(['change'])
</script>

<style scoped>
.batch-checkbox {
  display: inline-flex;
  vertical-align: middle;
}

.batch-checkbox :deep(.el-checkbox) {
  height: auto;
  margin-right: 0;
}

.batch-checkbox :deep(.el-checkbox__label) {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
}
</style>
