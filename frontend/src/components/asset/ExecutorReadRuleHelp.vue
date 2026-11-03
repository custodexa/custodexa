<!--
  ExecutorReadRuleHelp：專用帳號說明面板的「讀取 sudo 規則」一段，填進區塊的 setup-help-read-rule 插槽。

  非 root 的專用帳號要讓主機帳號盤點讀到完整的 sudo 規則，需另加一條參數寫死的唯讀規則；
  範例下方緊接必讀警告（參數寫法錯了等同交出 root）。字面與警告句以營運文件為準。
-->
<template>
  <div
    class="read-rule"
    data-test="login-check-read-rule"
  >
    <h4>{{ t('assetExecutor.loginCheck.readRule.title') }}</h4>
    <p>{{ t('assetExecutor.loginCheck.readRule.body') }}</p>
    <pre
      class="help-code"
      data-test="login-check-read-rule-example"
    >{{ READ_RULE_EXAMPLE }}</pre>
    <p
      class="help-warning"
      data-test="login-check-read-rule-warning"
    >
      {{ t('assetExecutor.loginCheck.readRule.warning') }}
    </p>
    <p>{{ t('assetExecutor.loginCheck.readRule.passwordNote') }}</p>
  </div>
</template>

<script setup>
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

// 帳號名依實際為準；參數必須逐字照抄（路徑以主機上 command -v tar 為準）
const READ_RULE_EXAMPLE = 'cx-exec ALL=(root) NOPASSWD: /bin/tar -cf - -C /etc sudoers sudoers.d'
</script>

<style scoped>
.read-rule h4 {
  margin: var(--ot-space-sm) 0 2px;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}

.read-rule p {
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
