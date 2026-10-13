<template>
  <div class="login-test">
    <div class="login-test__head">
      {{ $t(`${P}head`) }}
    </div>
    <template v-if="state === 'ready' && url">
      <div class="login-test__line">
        {{ $t(`${P}intro`) }}
      </div>
      <div class="login-test__box">
        <code
          class="login-test__url"
          data-test="login-test-url"
        >{{ url }}</code>
        <el-button
          size="small"
          data-test="login-test-copy"
          @click="copy"
        >
          <Copy class="login-test__copy-icon" />
          {{ $t(`${P}copy`) }}
        </el-button>
      </div>
      <!-- 不提供開新分頁：同一個瀏覽器的新分頁共用登入，正是要避免的情形 -->
      <div
        class="login-test__private"
        data-test="login-test-private"
      >
        <Info class="login-test__private-icon" />
        <span>{{ $t(`${P}privateWindow`) }}</span>
      </div>
      <div class="login-test__note">
        {{ $t(`identitySources.preflight.${type === 'ldap' ? 'loginTestNoticeLdap' : 'loginTestNoticeOidc'}`) }}
      </div>
      <div
        v-if="type !== 'ldap'"
        class="login-test__note"
      >
        {{ $t(`${P}autoRefresh`) }}
      </div>
    </template>
    <div
      v-else-if="state === 'source_disabled'"
      class="login-test__note"
      data-test="login-test-disabled"
    >
      {{ $t(`${P}sourceDisabled`) }}
    </div>
    <div
      v-else
      class="login-test__note"
      data-test="login-test-unset"
    >
      {{ $t(`${P}baseUrlUnset`) }}
    </div>
  </div>
</template>

<script setup>
import { ElMessage } from 'element-plus'
import { Copy, Info } from 'lucide-vue-next'
import { t } from '@/i18n'

const P = 'identitySources.preflight.test.'

const props = defineProps({
  type: { type: String, required: true },
  // ready／base_url_unset／source_disabled；其他值（含尚未載入）一律視為給不出連結
  state: { type: String, default: '' },
  url: { type: String, default: '' },
})

// copied：面板據此記下「開始測試了」，切回時等這次登入的結果（複製失敗時管理者多半會手動複製，照樣通知）
const emit = defineEmits(['copied'])

const copy = async () => {
  emit('copied')
  try {
    await navigator.clipboard.writeText(props.url)
    ElMessage.success(t('identitySources.copied'))
  } catch {
    ElMessage.warning(t('common.copyFailed'))
  }
}
</script>

<style scoped>
.login-test__head { margin-bottom: var(--ot-space-xs); font-weight: 600; color: var(--ot-text-primary); }
.login-test__line { font-size: var(--ot-font-size-sm); }
.login-test__box {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin: var(--ot-space-xs) 0;
  padding: var(--ot-space-xs) var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}
.login-test__url {
  flex: 1;
  min-width: 0;
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-xs);
  word-break: break-all;
}
.login-test__copy-icon { width: 14px; height: 14px; margin-right: 4px; }
.login-test__private {
  display: flex;
  gap: var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
  line-height: 1.6;
}
.login-test__private-icon { width: 16px; height: 16px; margin-top: 3px; flex-shrink: 0; color: var(--ot-warning); }
.login-test__note {
  margin-top: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}
</style>
