<template>
  <!-- 主機身分不符警示的第二層：第一層只講四件事（金鑰不同、憑證已送出、可能有人冒充、已記錄），
       技術細節收在「詳細說明」裡，預設收合 -->
  <div class="host-key-mismatch-details">
    <button
      type="button"
      class="details-toggle"
      data-test="host-key-mismatch-details-toggle"
      :aria-expanded="expanded ? 'true' : 'false'"
      @click="expanded = !expanded"
    >
      {{ expanded ? t('hostKeyMismatch.hideDetails') : t('hostKeyMismatch.showDetails') }}
      <ChevronUp
        v-if="expanded"
        :size="14"
        aria-hidden="true"
      />
      <ChevronDown
        v-else
        :size="14"
        aria-hidden="true"
      />
    </button>
    <ul
      v-if="expanded"
      class="details-list"
      data-test="host-key-mismatch-details"
    >
      <li>{{ t('hostKeyMismatch.detailHostKey') }}</li>
      <li>{{ t('hostKeyMismatch.detailCredential') }}</li>
      <li>{{ t('hostKeyMismatch.detailAlert') }}</li>
      <li
        v-for="item in extraItems"
        :key="item"
      >
        {{ item }}
      </li>
    </ul>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { ChevronDown, ChevronUp } from 'lucide-vue-next'
import { t } from '@/i18n'

defineProps({
  // 呼叫端追加的說明列（已翻譯字串），例如連線測試的「列表狀態不代表身分相符」
  extraItems: {
    type: Array,
    default: () => []
  }
})

const expanded = ref(false)
</script>

<style scoped>
.host-key-mismatch-details {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs, 4px);
}

.details-toggle {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  align-self: flex-start;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--el-color-primary);
  font-size: 13px;
  cursor: pointer;
}

.details-list {
  margin: 0;
  padding: 8px 12px 8px 28px;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 4px;
  font-size: 13px;
  line-height: 1.6;
  color: var(--el-text-color-secondary);
  display: flex;
  flex-direction: column;
  gap: 4px;
}
</style>
