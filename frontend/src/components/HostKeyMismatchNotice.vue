<template>
  <!-- 主機身分與記錄不符（host-key-verification）：連線已照常建立、憑證已送出，此處只警示與引導。
       第一層只講四件事（金鑰不同、憑證已送出、可能有人冒充請中斷、已記錄），技術細節收進「詳細說明」。
       可重置主機金鑰者（超管）給直達資產主機金鑰區塊的入口；其他人給聯絡管理員的提示。
       關閉狀態只存在本元件實例（本次分頁），刻意不落 localStorage：「永久不再顯示」會讓
       共用同一台機器的下一個人看不到警示 -->
  <el-alert
    v-if="!dismissed"
    class="host-key-mismatch-notice"
    data-test="host-key-mismatch-notice"
    type="error"
    show-icon
    :closable="true"
    :title="t('hostKeyMismatch.title')"
    @close="dismiss"
  >
    <p class="notice-body">
      {{ t('hostKeyMismatch.body') }}
    </p>
    <el-button
      v-if="canResetHostKey"
      size="small"
      type="warning"
      data-test="host-key-mismatch-go"
      @click="openAssetHostKey"
    >
      {{ t('hostKeyMismatch.goHostKey') }}
    </el-button>
    <p
      v-else
      class="notice-hint"
      data-test="host-key-mismatch-contact"
    >
      {{ t('hostKeyMismatch.contactAdmin') }}
    </p>
    <HostKeyMismatchDetails class="notice-details" />
  </el-alert>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { t } from '@/i18n'
import { can, loadCapabilities } from '@/composables/useCapabilities'
import HostKeyMismatchDetails from '@/components/HostKeyMismatchDetails.vue'

const props = defineProps({
  assetId: {
    type: [Number, String],
    required: true
  }
})

const emit = defineEmits(['dismiss'])

// 重設主機金鑰指紋是超管保留能力（hostkey:reset）；採用與重置同一入口
const canResetHostKey = computed(() => can('hostkey:reset'))

// 工作區與終端頁是另開分頁、不經需要能力的路由守衛，能力投影可能尚未載入：
// 不先載入的話，超管在這裡永遠只看到「聯絡管理員」。共用在途請求、已就緒即直接返回
onMounted(() => {
  loadCapabilities()
})
const dismissed = ref(false)

function dismiss() {
  dismissed.value = true
  emit('dismiss')
}

// 深連結沿用資產編輯框：?edit=<id> 直開抽屜並捲至主機金鑰區塊
function openAssetHostKey() {
  window.open(`/assets?edit=${props.assetId}`, '_blank')
}
</script>

<style scoped>
.host-key-mismatch-notice {
  position: relative;
  z-index: 11;
  margin-bottom: var(--ot-space-sm, 8px);
}

.notice-body {
  margin: 0 0 var(--ot-space-xs, 4px);
  line-height: 1.5;
  /* 核可稿：標題用危險色、說明用一般文字色，避免整塊紅字難讀 */
  color: var(--el-text-color-primary);
}

.notice-hint {
  margin: 0;
  font-size: 13px;
  color: var(--el-color-warning);
}

.notice-details {
  margin-top: var(--ot-space-xs, 4px);
}
</style>
