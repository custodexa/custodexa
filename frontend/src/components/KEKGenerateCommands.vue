<template>
  <div class="kek-commands">
    <p class="kek-commands-title">
      {{ $t('kekCommands.title') }}
    </p>
    <p class="kek-commands-hint">
      {{ $t('kekCommands.hint') }}
    </p>
    <ul class="kek-commands-list">
      <li
        v-for="item in commands"
        :key="item.command"
        class="kek-command-row"
      >
        <code class="kek-command">{{ item.command }}</code>
        <el-button
          text
          size="small"
          class="kek-command-copy"
          @click="copy(item.command)"
        >
          {{ $t('common.copy') }}
        </el-button>
      </li>
    </ul>
    <p class="kek-commands-entropy">
      {{ $t('kekCommands.entropyWarning') }}
    </p>
  </div>
</template>

<script setup>
// KEK 生成指令參考（kek-encoding-and-unseal-entry 決策 8）。
//
// **指令是參考、不是要求**：介面同時保留「本地生成」按鈕（不是所有人都在有 shell
// 的機器上操作）。指令字串不翻譯——它們要原樣貼進 shell；說明文字才走 i18n。
//
// 清單來自 `@/constants/kekGenerateCommands`，其 JSON 由後端守衛逐條比對
// `config.KEKGenerateCommands`——每一條都經實跑驗證其產出必然通過材料驗證。
// 缺陷史：使用者因介面沒有指令參考而自行想了一條指令（`openssl rand -hex 32`），
// 那把金鑰完全正確卻被舊規則拒絕。
import { ElMessage } from 'element-plus'
import { KEK_GENERATE_COMMANDS } from '@/constants/kekGenerateCommands'
import { t } from '@/i18n'

const commands = KEK_GENERATE_COMMANDS

const copy = async (text) => {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success(t('kekCommands.copied'))
  } catch {
    ElMessage.warning(t('common.copyFailed'))
  }
}
</script>

<style scoped>
.kek-commands {
  margin-top: 12px;
  padding: 12px;
  border-radius: 6px;
  background: var(--el-fill-color-light);
  border: 1px solid var(--el-border-color-lighter);
}

.kek-commands-title {
  margin: 0 0 4px;
  font-size: 13px;
  font-weight: 600;
}

.kek-commands-hint,
.kek-commands-entropy {
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--el-text-color-secondary);
}

.kek-commands-entropy {
  margin-top: 8px;
}

.kek-commands-list {
  margin: 8px 0 0;
  padding: 0;
  list-style: none;
}

.kek-command-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}

.kek-command {
  flex: 1;
  overflow-x: auto;
  white-space: nowrap;
  padding: 4px 8px;
  border-radius: 4px;
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color-lighter);
  font-family: var(--ot-font-mono, monospace);
  font-size: 12px;
}
</style>
