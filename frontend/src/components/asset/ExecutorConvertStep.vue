<!--
  ExecutorConvertStep：設定對話框的「轉換既有帳號」畫面。

  帳號選單列出這台的登入帳號：可轉換的排在前面並寫「專用 · 型別」，預設帳號（帶 ★）與共用憑證帳號
  排在後面、停用並寫原因（同組內維持帳號表順序）。
  伺服器擋下的錯誤框在帳號選單正下方（選單加紅框），三件事在其後的警示框內，建議改密句在框外。
  選擇以 v-model 交回對話框；錯誤列的修正與重新檢查以 emit fix 交回。
-->
<template>
  <div class="info-box">
    <Info
      :size="14"
      aria-hidden="true"
      class="info-icon"
    />
    <span>{{ t('assetExecutor.convert.desc') }}</span>
  </div>
  <el-form-item
    :label="t('assetExecutor.convert.accountLabel')"
    required
    :class="{ 'is-error': err?.placement === 'field-account' }"
  >
    <el-select
      :model-value="modelValue"
      :placeholder="t('assetExecutor.convert.placeholder')"
      :disabled="disabled"
      data-test="dlg-convert-select"
      @update:model-value="(v) => emit('update:modelValue', v)"
      @change="emit('change')"
    >
      <template #label="{ value }">
        <span class="mono">{{ accountById(value)?.username }}</span>
        <span
          class="opt-note"
          data-test="dlg-convert-selected-meta"
        >{{ optionMeta(accountById(value)) }}</span>
      </template>
      <el-option
        v-for="acc in sortedAccounts"
        :key="acc.id"
        :label="acc.username"
        :value="acc.id"
        :disabled="disabledReason(acc) !== ''"
      >
        <Star
          v-if="acc.is_default"
          :size="11"
          fill="currentColor"
          aria-hidden="true"
          class="default-star"
          :data-test="`dlg-convert-star-${acc.id}`"
        />
        <span class="mono">{{ acc.username }}</span>
        <span
          v-if="disabledReason(acc)"
          class="opt-note"
          :data-test="`dlg-convert-disabled-${acc.id}`"
        >{{ disabledReason(acc) }}</span>
        <span
          v-else
          class="opt-note"
          :data-test="`dlg-convert-meta-${acc.id}`"
        >{{ optionMeta(acc) }}</span>
      </el-option>
    </el-select>
  </el-form-item>
  <ExecutorErrorLine
    v-if="err && err.placement === 'field-account'"
    :err="err"
    @fix="(which) => emit('fix', which)"
  />
  <template v-if="selected">
    <ExecutorNoticeBox
      tone="warning"
      data-test="dlg-convert-effects"
      :title="t('assetExecutor.convert.effectsTitle', { account: selected.username })"
    >
      <ul class="effects">
        <li
          v-for="n in [1, 2, 3]"
          :key="n"
        >
          {{ t(`assetExecutor.convert.effect${n}`, { account: selected.username }) }}
        </li>
      </ul>
    </ExecutorNoticeBox>
    <p
      class="muted"
      data-test="dlg-convert-advice"
    >
      {{ t('assetExecutor.convert.rotateAdvice', { account: selected.username }) }}
    </p>
  </template>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { Info, Star } from 'lucide-vue-next'
import ExecutorErrorLine from '@/components/asset/ExecutorErrorLine.vue'
import ExecutorNoticeBox from '@/components/asset/ExecutorNoticeBox.vue'

const props = defineProps({
  accounts: { type: Array, default: () => [] },
  modelValue: { type: Number, default: null },
  err: { type: Object, default: null },
  disabled: { type: Boolean, default: false },
})
const emit = defineEmits(['update:modelValue', 'change', 'fix'])

const { t } = useI18n()

const accountById = (id) => props.accounts.find((a) => a.id === id) || null
const selected = computed(() => accountById(props.modelValue))

// 可轉換的排前、不能轉換的排後；同組內維持帳號表順序
const sortedAccounts = computed(() => {
  const ok = props.accounts.filter((a) => disabledReason(a) === '')
  const blocked = props.accounts.filter((a) => disabledReason(a) !== '')
  return [...ok, ...blocked]
})

function disabledReason(acc) {
  if (acc.is_default) return t('assetExecutor.convert.disabledDefault')
  if (acc.shared_credential) return t('assetExecutor.convert.disabledShared')
  return ''
}

// 可轉換的帳號一律是專用憑證；後綴寫「專用 · 型別」
function optionMeta(acc) {
  if (!acc) return ''
  const parts = [t('enum.credentialScope.dedicated')]
  if (acc.has_private_key) parts.push(t('enum.credentialSecretType.ssh_key'))
  else if (acc.has_password) parts.push(t('enum.credentialSecretType.password'))
  return parts.join(' · ')
}
</script>

<style scoped>
.info-box {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-xs);
  padding: var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  background: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-md);
}

.info-icon {
  flex: none;
  margin-top: 2px;
  color: var(--ot-primary);
}

.mono {
  font-family: var(--ot-font-mono, monospace);
}

.muted,
.opt-note {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.opt-note {
  margin-left: var(--ot-space-sm);
}

.effects {
  margin: 0;
  padding-left: 0;
  list-style: none;
}

.default-star {
  margin-right: 4px;
  vertical-align: -1px;
  color: var(--ot-warning);
}
</style>
