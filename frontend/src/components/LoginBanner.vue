<template>
  <!-- 登入前告示：純文字呈現。
       只用插值，全檔不做任何原始 HTML 綁定（測試讀原始碼釘住）——
       內容由部署方自填，一旦當成標記渲染就等於把登入頁交給填內容的人。
       標記字元一律以原字顯示 -->
  <div
    v-if="hasBody"
    class="login-banner"
    role="region"
    :aria-label="t('login.bannerRegionLabel')"
    tabindex="0"
  >
    <p
      v-if="trimmedTitle"
      class="login-banner-title"
    >
      {{ trimmedTitle }}
    </p>
    <p class="login-banner-body">
      {{ trimmedBody }}
    </p>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps({
  title: { type: String, default: '' },
  body: { type: String, default: '' },
})

const { t } = useI18n()

const trimmedTitle = computed(() => (props.title || '').trim())
const trimmedBody = computed(() => (props.body || '').trim())
// 內文為空即整塊不渲染；標題不單獨顯示（標題是內文的抬頭，沒有內文就沒有告示）
const hasBody = computed(() => trimmedBody.value.length > 0)
</script>

<style scoped>
/* max-height 取 240px：登入卡寬 380px，這個高度約容納十行內文，
   在 1440×900 下告示與帳密欄位、登入鈕同在首屏；超出的部分在區塊內捲動，
   不把表單推出視窗。區塊帶 tabindex 使鍵盤也能捲 */
.login-banner {
  max-height: 240px;
  overflow-y: auto;
  margin-bottom: var(--ot-space-md);
  padding: var(--ot-space-sm) var(--ot-space-md);
  background-color: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.login-banner-title {
  margin: 0 0 var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
  color: var(--ot-text-primary);
  overflow-wrap: anywhere;
}

.login-banner-body {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-secondary);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
</style>
