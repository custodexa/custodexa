<template>
  <el-tooltip
    placement="top"
    :show-after="120"
  >
    <template #content>
      <span class="help-tip__body">{{ content }}</span>
    </template>
    <button
      type="button"
      class="help-tip"
      :aria-label="content"
    >
      <el-icon :size="14">
        <Info />
      </el-icon>
    </button>
  </el-tooltip>
</template>

<script setup>
/**
 * 邊界說明的收納處。
 *
 * 一個區塊只留得下一句說明，其餘「這個數字怎麼來的」「這一欄不是歷史快照」
 * 之類的話留在這裡：需要的人點得到，不需要的人不必先讀完三句灰字才看到重點。
 * 多句以換行分隔即可，tooltip 會照排。
 */
import { Info } from 'lucide-vue-next'

defineProps({
  content: { type: String, required: true },
})
</script>

<style scoped>
.help-tip {
  display: inline-flex;
  align-items: center;
  padding: 0;
  border: 0;
  background: none;
  color: var(--ot-text-secondary);
  cursor: help;
  vertical-align: middle;
}

.help-tip:hover,
.help-tip:focus-visible {
  color: var(--ot-primary);
}

.help-tip__body {
  display: block;
  max-width: 22rem;
  white-space: pre-line;
}
</style>
