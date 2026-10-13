<template>
  <div
    class="provider-selector"
    data-test="provider-selector"
  >
    <div class="provider-selector__label">
      {{ $t('identitySources.oidc.provider.label') }}
    </div>
    <div
      class="provider-selector__group"
      role="group"
      :aria-label="$t('identitySources.oidc.provider.label')"
    >
      <button
        v-for="p in PROVIDERS"
        :key="p"
        type="button"
        class="provider-selector__option"
        :class="{ 'is-active': modelValue === p }"
        :aria-pressed="modelValue === p ? 'true' : 'false'"
        :data-test="`provider-option-${p}`"
        @click="choose(p)"
      >
        {{ $t(`identitySources.oidc.provider.${p}`) }}
      </button>
    </div>
    <div class="provider-selector__hint">
      {{ $t(isEdit ? 'identitySources.oidc.provider.hintEdit' : 'identitySources.oidc.provider.hintNew') }}
    </div>
  </div>
</template>

<script setup>
// 提供者選擇器：只切換畫面上的取值說明與欄位提示，不持久化、不送進請求
import { PROVIDERS } from '@/utils/oidcProvider'

const props = defineProps({
  modelValue: { type: String, required: true },
  isEdit: { type: Boolean, default: false },
})

const emit = defineEmits(['update:modelValue', 'select'])

const choose = (p) => {
  if (p !== props.modelValue) emit('update:modelValue', p)
  // 重按同一項也通知父頁：選 Google 後 issuer 被改掉，再按一次可以重新帶入
  emit('select', p)
}
</script>

<style scoped>
.provider-selector {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  margin-bottom: var(--ot-space-md);
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.provider-selector__label {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.provider-selector__group {
  display: flex;
  flex-wrap: wrap;
}

.provider-selector__option {
  height: 32px;
  padding: 0 16px;
  border: 1px solid var(--ot-border);
  background: transparent;
  color: var(--ot-text-primary);
  font: inherit;
  font-size: var(--ot-font-size-sm);
  cursor: pointer;
}

.provider-selector__option + .provider-selector__option {
  margin-left: -1px;
}

.provider-selector__option:first-child {
  border-radius: var(--ot-radius-md, 6px) 0 0 var(--ot-radius-md, 6px);
}

.provider-selector__option:last-child {
  border-radius: 0 var(--ot-radius-md, 6px) var(--ot-radius-md, 6px) 0;
}

.provider-selector__option.is-active {
  position: relative;
  background-color: var(--ot-primary-fill);
  border-color: var(--ot-primary-fill);
  color: #fff;
}

.provider-selector__option:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: 2px;
}

.provider-selector__hint {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}
</style>
