<!--
  ExecutorErrorLine：設定對話框的就地錯誤框。紅框紅底、圓形叉號、粗體首句與說明句，
  修正鈕與（轉換時的）重新檢查鈕在框內。修正鈕為主要樣式，在新分頁開啟的修正鈕帶外部連結圖示；
  重新檢查為次要樣式。按下修正鈕 emit fix()，按下重新檢查 emit fix('recheck')。
  框本身可被程式聚焦，沒有修正鈕時由它承接送出被擋後的焦點。
-->
<template>
  <ExecutorNoticeBox
    tone="danger"
    focusable
    class="dlg-error"
    data-test="dlg-error"
    :data-placement="err.placement"
  >
    <div
      class="err-text"
      data-test="dlg-error-text"
    >
      <strong
        class="err-head"
        data-test="dlg-error-head"
      >{{ lead.head }}</strong>
      <span v-if="lead.body">{{ lead.body }}</span>
    </div>
    <div
      v-if="err.fixLabel || err.recheck"
      class="fix-row"
    >
      <el-button
        v-if="err.fixLabel"
        type="primary"
        size="small"
        data-test="dlg-fix"
        @click="emit('fix')"
      >
        {{ err.fixLabel }}
        <ExternalLink
          v-if="opensNewTab"
          :size="12"
          aria-hidden="true"
          class="ext-icon"
          data-test="dlg-fix-external"
        />
      </el-button>
      <el-button
        v-if="err.recheck"
        size="small"
        data-test="dlg-recheck"
        @click="emit('fix', 'recheck')"
      >
        <RefreshCw
          :size="12"
          aria-hidden="true"
          class="lead-icon"
        />
        {{ err.recheck }}
      </el-button>
    </div>
  </ExecutorNoticeBox>
</template>

<script setup>
import { computed } from 'vue'
import { ExternalLink, RefreshCw } from 'lucide-vue-next'
import ExecutorNoticeBox from '@/components/asset/ExecutorNoticeBox.vue'
import { splitLead } from '@/utils/splitLead'

const props = defineProps({
  err: { type: Object, required: true },
})
const emit = defineEmits(['fix'])

const lead = computed(() => splitLead(props.err.text))
// 改密計劃、改密進度、憑證庫：修正鈕在新分頁開啟
const opensNewTab = computed(() => /^open/.test(props.err.fixAction || ''))
</script>

<style scoped>
.err-text {
  display: flex;
  flex-direction: column;
}

.err-head {
  font-weight: 600;
}

.fix-row {
  display: flex;
  gap: var(--ot-space-sm);
  margin-top: var(--ot-space-xs);
}

.fix-row .el-button + .el-button {
  margin-left: 0;
}

.ext-icon {
  margin-left: 4px;
}

.lead-icon {
  margin-right: 4px;
}
</style>
