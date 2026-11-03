<!--
  ExecutorSetupHelp：「這個帳號要怎麼準備」的第二層說明。

  第一層一句白話；展開後分兩段：平台產生的金鑰要加公鑰的位置、改密所需的 sudo 規則。
  前端沒有連到外部文件的慣例，所以做成就地展開的面板（離線環境也看得到）。

  具名插槽 read-rule 在展開區末尾，無預設內容；沒填時不留空白容器。
  expanded 為真時固定展開（錨定彈出框內使用）。
  hideFirst 搭配 expanded：省略第一層句（已設定的區塊展開說明時使用，畫面不重複那一句）。
-->
<template>
  <div
    class="executor-help"
    data-test="executor-help"
  >
    <div
      v-if="!(hideFirst && expanded)"
      class="help-first"
    >
      <span data-test="executor-help-first">{{ t('assetExecutor.help.first') }}</span>
      <el-button
        v-if="!expanded"
        link
        type="primary"
        size="small"
        data-test="executor-help-toggle"
        :aria-expanded="open"
        @click="open = !open"
      >
        {{ open ? t('assetExecutor.help.collapse') : t('assetExecutor.help.expand') }}
      </el-button>
    </div>
    <div
      v-if="isOpen"
      class="help-body"
      data-test="executor-help-body"
    >
      <h4>{{ t('assetExecutor.help.generateTitle') }}</h4>
      <p>{{ t('assetExecutor.help.generateBody') }}</p>
      <h4>{{ t('assetExecutor.help.rotateTitle') }}</h4>
      <p>{{ t('assetExecutor.help.rotateBody') }}</p>
      <pre
        class="help-code"
        data-test="executor-help-sudo"
      >{{ SUDO_EXAMPLE }}</pre>
      <p
        class="help-warning"
        data-test="executor-help-sudo-warning"
      >
        {{ t('assetExecutor.help.rotateWarning') }}
      </p>
      <h4>{{ t('assetExecutor.help.passwordTitle') }}</h4>
      <p>{{ t('assetExecutor.help.passwordBody') }}</p>
      <pre
        class="help-code"
        data-test="executor-help-sudo-password"
      >{{ SUDO_PASSWORD_EXAMPLE }}</pre>
      <p
        class="help-warning"
        data-test="executor-help-sudo-password-warning"
      >
        {{ t('assetExecutor.help.passwordSudoWarning') }}
      </p>
      <p>{{ t('assetExecutor.help.passwordWindows') }}</p>
      <p class="help-pointer">
        {{ t('assetExecutor.help.docPointer') }}
      </p>
      <div
        v-if="$slots['read-rule']"
        class="help-read-rule"
        data-test="executor-help-read-rule"
      >
        <slot name="read-rule" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps({
  expanded: { type: Boolean, default: false },
  hideFirst: { type: Boolean, default: false },
})

const { t } = useI18n()
const open = ref(false)
const isOpen = computed(() => props.expanded || open.value)

// 改密所需的 sudo 規則範例（帳號名依實際為準）；字面與緊接的警告句以營運文件升級手冊
// 「以堡壘機專用帳號代改 Linux／Unix 帳號密碼」一節為準，該節改動時兩邊一起改。
const SUDO_EXAMPLE = 'cx-exec ALL=(root) NOPASSWD: /usr/sbin/chpasswd'
const SUDO_PASSWORD_EXAMPLE = 'cx-exec ALL=(root) /usr/sbin/chpasswd'

defineExpose({ open })
</script>

<style scoped>
.executor-help {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.help-body h4 {
  margin: var(--ot-space-sm) 0 2px;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}

.help-body p {
  margin: 0 0 var(--ot-space-xs);
}

.help-warning {
  color: var(--ot-text-primary);
}

.help-code {
  margin: 0 0 var(--ot-space-xs);
  padding: var(--ot-space-xs) var(--ot-space-sm);
  overflow-x: auto;
  font-family: var(--ot-font-mono, monospace);
  background: var(--ot-bg-subtle, rgba(127, 127, 127, 0.1));
  border-radius: 4px;
}
</style>
