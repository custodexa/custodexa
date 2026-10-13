<template>
  <div
    v-if="kind === 'authed'"
    class="test-authed"
    data-test="login-test-authed"
  >
    <h3 class="test-authed__title">
      {{ t('login.testSource.authedTitle') }}
    </h3>
    <p class="test-authed__body">
      {{ t('login.testSource.authedBody') }}
    </p>
    <el-button
      type="primary"
      data-test="login-test-dashboard"
      @click="router.push('/dashboard')"
    >
      {{ t('login.testSource.backToDashboard') }}
    </el-button>
  </div>
  <div
    v-else-if="kind"
    class="test-notice"
    :class="`test-notice--${kind}`"
    :data-test="`login-test-${kind}`"
  >
    <Info class="test-notice__icon" />
    <span>{{ t(kind === 'ldap' ? 'login.testSource.ldap' : 'login.testSource.notListed') }}</span>
  </div>
</template>

<script setup>
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { Info } from 'lucide-vue-next'

// kind：authed（已登入，只給說明與回儀表板）、notListed、ldap；null 不顯示
defineProps({
  kind: { type: String, default: null },
})

const { t } = useI18n()
const router = useRouter()
</script>

<style scoped>
.test-authed { padding: var(--ot-space-md) 0; text-align: center; }
.test-authed__title { margin: 0 0 var(--ot-space-sm); color: var(--ot-text-primary); font-size: var(--ot-font-size-lg); }
.test-authed__body { margin: 0 0 var(--ot-space-md); color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); line-height: 1.7; }
.test-notice {
  display: flex;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-md);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
  line-height: 1.6;
}
/* 脈絡提示而非錯誤：淡底細框，與登入頁其他說明框同一個樣式 */
.test-notice--notListed {
  background-color: color-mix(in srgb, var(--ot-warning) 10%, transparent);
  border-color: color-mix(in srgb, var(--ot-warning) 25%, transparent);
}
.test-notice--ldap {
  background-color: color-mix(in srgb, var(--ot-info) 10%, transparent);
  border-color: color-mix(in srgb, var(--ot-info) 25%, transparent);
}
.test-notice__icon { width: 16px; height: 16px; margin-top: 3px; flex-shrink: 0; }
.test-notice--notListed .test-notice__icon { color: var(--ot-warning); }
.test-notice--ldap .test-notice__icon { color: var(--ot-info); }
</style>
