<template>
  <ElPagination
    ref="root"
    v-bind="$attrs"
  />
</template>

<script setup>
/**
 * el-pagination 的替身：只補一件事——每頁筆數下拉的標籤。
 *
 * Element Plus 內部那顆 select 沒有任何標籤，螢幕報讀器只會讀到一個數字，
 * 而 ElPagination 不開放把 aria-label 傳進去（sizes 子元件的 props 裡沒有這一項），
 * 只能在掛載後補上。main.js 以此覆寫全域的 ElPagination 註冊，
 * 二十餘處呼叫端不必各自處理。
 */
import { ref, watch, onMounted, nextTick } from 'vue'
import { ElPagination } from 'element-plus'
import { useI18n } from 'vue-i18n'

defineOptions({ inheritAttrs: false })

const { t, locale } = useI18n()
const root = ref(null)

function labelPageSize() {
  const host = root.value?.$el
  const input = host?.querySelector?.('.el-pagination__sizes input')
  if (input) input.setAttribute('aria-label', t('common.pageSize'))
}

onMounted(() => nextTick(labelPageSize))
watch(locale, () => nextTick(labelPageSize))
</script>
