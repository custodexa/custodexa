<template>
  <!-- 連線測試成功但主機身分與記錄不符：以不自動消失的通知卡呈現（ElNotification 的內容）。
       第一層說明憑證已送出、可能有人冒充請先不要使用、已記錄；處理途徑依能力分兩種；
       技術細節與「列表狀態不代表身分相符」收進「詳細說明」 -->
  <div
    class="host-key-test-card"
    data-test="host-key-test-card"
  >
    <p class="card-body">
      <TriangleAlert
        class="card-icon"
        :size="16"
        aria-hidden="true"
      />
      <span>
        <strong class="card-title">{{ t('assets.testHostKeyMismatchLead') }}</strong>{{ t('assets.testSuccessHostKeyMismatch') }}
      </span>
    </p>
    <div class="card-actions">
      <el-button
        v-if="canResetHostKey"
        size="small"
        type="warning"
        data-test="host-key-test-go"
        @click="emit('go')"
      >
        {{ t('hostKeyMismatch.goHostKey') }}
      </el-button>
      <span
        v-else
        class="card-hint"
        data-test="host-key-test-contact"
      >
        {{ t('hostKeyMismatch.contactAdmin') }}
      </span>
    </div>
    <HostKeyMismatchDetails
      class="card-details"
      :extra-items="[t('assets.testHostKeyReachabilityNote')]"
    />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { TriangleAlert } from 'lucide-vue-next'
import { t } from '@/i18n'
import { can } from '@/composables/useCapabilities'
import HostKeyMismatchDetails from '@/components/HostKeyMismatchDetails.vue'

const emit = defineEmits(['go'])

// 採用與重置主機金鑰是超管保留能力（hostkey:reset），與終端警示同一判斷
const canResetHostKey = computed(() => can('hostkey:reset'))
</script>

<style scoped>
.host-key-test-card {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm, 8px);
}

.card-body {
  display: flex;
  gap: 8px;
  align-items: flex-start;
  margin: 0;
  font-size: 13px;
  line-height: 1.6;
  color: var(--el-text-color-primary);
}

.card-icon {
  flex: 0 0 16px;
  margin-top: 3px;
  color: var(--el-color-danger);
}

.card-title {
  color: var(--el-color-danger);
}

.card-actions,
.card-details {
  padding-left: 24px;
}

.card-hint {
  font-size: 13px;
  color: var(--el-color-warning);
}
</style>

<style>
/* ElNotification 掛在 body 下，非 scoped：卡片外框以危險色標示身分不符，寬度容納說明 */
.el-notification.host-key-test-notification {
  --el-notification-width: 400px;
  border-color: var(--el-color-danger-light-5);
}
</style>
