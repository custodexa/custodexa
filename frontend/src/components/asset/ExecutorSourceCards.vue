<!--
  ExecutorSourceCards：設定對話框的「秘密從哪裡來」來源卡片。
  每張卡片一個選取圈、標題（「建議」標與標題同列）、一句白話後果；缺權限時停用並附原因。
  選取以 emit pick(key) 交給對話框。
-->
<template>
  <div
    class="cards"
    role="radiogroup"
    :aria-label="label"
  >
    <button
      v-for="card in cards"
      :key="card.key"
      type="button"
      role="radio"
      class="source-card"
      :class="{ active: modelValue === card.key }"
      :aria-checked="modelValue === card.key ? 'true' : 'false'"
      :disabled="card.disabled || disabled"
      :data-test="`source-card-${card.key}`"
      @click="emit('pick', card.key)"
    >
      <span class="card-head">
        <span
          class="radio-dot"
          aria-hidden="true"
        />
        <strong>{{ card.title }}</strong>
        <el-tag
          v-if="card.recommended"
          size="small"
          type="success"
        >
          {{ recommendedText }}
        </el-tag>
      </span>
      <span class="card-desc">{{ card.desc }}</span>
      <span
        v-if="card.reason"
        class="card-reason"
        :data-test="`source-reason-${card.key}`"
      >{{ card.reason }}</span>
    </button>
  </div>
</template>

<script setup>
defineProps({
  cards: { type: Array, required: true },
  modelValue: { type: String, default: '' },
  disabled: { type: Boolean, default: false },
  label: { type: String, default: '' },
  recommendedText: { type: String, default: '' },
})
const emit = defineEmits(['pick'])
</script>

<style scoped>
.cards {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.source-card {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  padding: var(--ot-space-sm);
  text-align: left;
  cursor: pointer;
  color: inherit;
  background: transparent;
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.source-card.active {
  background: var(--ot-primary-dim);
  border-color: var(--ot-primary);
}

.source-card:disabled {
  cursor: not-allowed;
  opacity: 0.6;
}

.card-head {
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.radio-dot {
  width: 12px;
  height: 12px;
  flex: none;
  border: 1px solid var(--ot-border);
  border-radius: 50%;
}

.source-card.active .radio-dot {
  border: 4px solid var(--ot-primary);
}

.card-desc,
.card-reason {
  padding-left: calc(12px + var(--ot-space-xs));
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
</style>
