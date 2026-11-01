<template>
  <div
    v-if="active"
    class="role-preview-banner"
    role="status"
    data-test="role-preview-banner"
  >
    <Eye
      class="banner-icon"
      :size="16"
      aria-hidden="true"
    />
    <div class="banner-text">
      <strong data-test="role-preview-title">{{ t('rolePreview.banner.title', { name: roleName }) }}</strong>
      <span data-test="role-preview-view-only">{{ t('rolePreview.banner.viewOnly') }}</span>
      <span data-test="role-preview-data-ceiling">{{ t('rolePreview.banner.dataCeiling') }}</span>
    </div>
    <el-button
      size="small"
      class="banner-exit"
      data-test="role-preview-exit"
      @click="leave"
    >
      {{ t('rolePreview.banner.exit') }}
    </el-button>
  </div>
</template>

<script setup>
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { Eye } from 'lucide-vue-next'
import { useRolePreview } from '@/composables/useRolePreview'

const { t } = useI18n()
const router = useRouter()
const { active, roleName, exit } = useRolePreview()

// 離開一律回到最初進入預覽的角色編輯畫面（已儲存內容），不論預覽中看過哪些頁
const leave = () => {
  const origin = exit()
  if (origin) router.push(`/roles/${origin.roleId}`)
}
</script>

<style scoped>
.role-preview-banner {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-xs) var(--ot-space-md);
  background-color: var(--ot-primary-dim);
  border-bottom: 1px solid var(--ot-border-subtle);
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-sm);
}
.banner-icon {
  flex-shrink: 0;
}
.banner-text {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ot-space-xs) var(--ot-space-md);
  flex: 1;
  min-width: 0;
}
.banner-exit {
  flex-shrink: 0;
  margin-left: auto;
}
</style>
