<template>
  <!-- 參考資料收合（preservice-pages「服務前頁面的文案密度」）：
       收合不是刪除——展開後的三種寫法與三條生成指令與收合前完全相同。
       預設收合的理由是讀者正在處理中斷，這些不是他此刻的下一步 -->
  <el-button
    text
    size="small"
    class="format-details-toggle"
    :aria-expanded="String(expanded)"
    @click="expanded = !expanded"
  >
    {{ $t('unseal.formatDetailsTitle') }}
    <el-icon class="el-icon--right">
      <ChevronDown v-if="!expanded" />
      <ChevronUp v-else />
    </el-icon>
  </el-button>
  <div
    v-if="expanded"
    class="format-details-body"
  >
    <p class="format-details-intro">
      {{ $t('unseal.materialFormatIntro') }}
    </p>
    <ul class="format-list">
      <li>{{ $t('unseal.materialFormatPlain') }}</li>
      <li>{{ $t('unseal.materialFormatHex') }}</li>
      <li>{{ $t('unseal.materialFormatBase64') }}</li>
    </ul>
    <GenerateCommands />
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { ChevronDown, ChevronUp } from 'lucide-vue-next'
import GenerateCommands from '@/components/KEKGenerateCommands.vue'

const expanded = ref(false)
</script>

<style scoped>
.format-details-toggle {
  align-self: flex-start;
  padding: 0;
  height: auto;
}

.format-details-body {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.format-details-intro,
.format-list {
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  color: var(--el-text-color-secondary);
}

.format-details-intro {
  margin: 0;
}

.format-list {
  margin: 0;
  padding-left: 20px;
  line-height: 1.8;
}
</style>
