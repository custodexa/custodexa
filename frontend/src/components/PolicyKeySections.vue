<template>
  <!-- 分區卡片：依 key 分組渲染，後端新增政策鍵自動出現在對應區塊
       （settings-domain-restructure D7 自 SecurityPolicies.vue 抽取，四域頁共用） -->
  <div
    v-for="section in sections"
    :key="section.title"
    class="policy-card"
  >
    <div class="card-header">
      <span class="card-title">{{ section.title }}</span>
      <span class="card-hint">{{ section.hint }}</span>
    </div>

    <!-- 頁面專屬的區塊補充內容（跨欄位風險提示、專頁入口連結等） -->
    <slot
      name="section-extra"
      :section="section"
    />

    <div
      v-for="policy in section.policies"
      :key="policy.key"
      class="policy-row"
    >
      <div class="policy-label">
        <span>{{ policyLabel(policy) }}</span>
        <span
          v-if="policy.requirement"
          class="policy-req"
        >PCI {{ policy.requirement }}</span>
        <!-- 逐鍵附註（生效時機／適用協議，data-transfer-control 6.1）：
             無 policyNote.<key> 譯文者不顯示 -->
        <span
          v-if="policyNote(policy)"
          class="policy-note"
        >{{ policyNote(policy) }}</span>
      </div>

      <div class="policy-control">
        <el-input-number
          v-if="policy.type === 'int'"
          :model-value="formValues[policy.key]"
          :min="policyMin(policy)"
          :max="policy.max || 99999"
          :step="1"
          step-strictly
          :aria-label="policyLabel(policy)"
          @update:model-value="$emit('update:value', policy.key, $event)"
        />
        <el-switch
          v-else-if="policy.type === 'bool'"
          :model-value="formValues[policy.key]"
          :aria-label="policyLabel(policy)"
          @update:model-value="$emit('update:value', policy.key, $event)"
        />
        <el-radio-group
          v-else-if="policy.type === 'enum'"
          :model-value="formValues[policy.key]"
          @update:model-value="$emit('update:value', policy.key, $event)"
        >
          <el-radio-button
            v-for="option in policy.enum_order"
            :key="option"
            :value="option"
          >
            {{ enumLabel(policy, option) }}
          </el-radio-button>
        </el-radio-group>
        <span
          v-if="policyUnit(policy)"
          class="policy-unit"
        >{{ policyUnit(policy) }}</span>
      </div>

      <div class="policy-meta">
        <span
          v-if="policy.pci_value"
          class="policy-pci"
        >
          {{ $t('policyKeySections.pciRecommend', { value: formatValue(policy, policy.pci_value) }) }}
        </span>
        <span
          v-else
          class="policy-pci"
        >{{ $t('policyKeySections.noPciValue') }}</span>
        <el-tag
          v-if="isNonCompliantValue(policy, formValues[policy.key], savedValues[policy.key])"
          type="warning"
          size="small"
        >
          <el-icon><Warning /></el-icon>
          {{ $t('policyKeySections.nonCompliant') }}
        </el-tag>
        <!-- 電支基準第二欄（security-backlog-settlement D6）：與 PCI 並列而非取代，
             兩基準的建議值可能不同且方向相反，各自標示符合性 -->
        <span
          v-if="policy.epayment_value"
          class="policy-pci"
        >
          {{ $t('policyKeySections.epaymentRecommend', { value: formatValue(policy, policy.epayment_value) }) }}
        </span>
        <el-tag
          v-if="isNonCompliantEPayment(policy, formValues[policy.key], savedValues[policy.key])"
          type="warning"
          size="small"
        >
          <el-icon><Warning /></el-icon>
          {{ $t('policyKeySections.nonCompliantEPayment') }}
        </el-tag>
        <span
          v-if="policy.zero_disables && policy.type === 'int'"
          class="policy-helper"
        >{{ zeroHelperText(policy) }}</span>
      </div>
    </div>

    <!-- 區塊尾端擴充（存取管控頁的資產覆寫表格等，settings-domain-restructure D2） -->
    <slot
      name="section-footer"
      :section="section"
    />
  </div>
</template>

<script setup>
import { Warning } from '@element-plus/icons-vue'
import {
  enumLabel,
  formatValue,
  isNonCompliantEPayment,
  isNonCompliantValue,
  policyLabel,
  policyMin,
  policyNote,
  policyUnit,
  zeroHelperText,
} from '@/utils/policyFormat'

defineProps({
  // visibleSections 產物：[{ title, hint, policies: [policy] }]
  sections: { type: Array, required: true },
  // 編輯中值與已儲存值（符合性比對用）；寫入權在父層（update:value 事件）
  formValues: { type: Object, required: true },
  savedValues: { type: Object, required: true },
})

defineEmits(['update:value'])
</script>

<style scoped>
.policy-card {
  padding: var(--ot-space-md);
  margin-bottom: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.card-header {
  display: flex;
  align-items: baseline;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-sm);
  padding-bottom: var(--ot-space-sm);
  border-bottom: 1px solid var(--ot-border-subtle);
}

.card-title {
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.card-hint {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.policy-row {
  display: grid;
  grid-template-columns: 240px minmax(220px, auto) 1fr;
  align-items: center;
  gap: var(--ot-space-md);
  padding: var(--ot-space-sm) 0;
}

.policy-row + .policy-row {
  border-top: 1px solid var(--ot-border-subtle);
}

.policy-label {
  display: flex;
  flex-direction: column;
  gap: 2px;
  color: var(--ot-text-primary);
}

.policy-req {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.policy-note {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  line-height: 1.4;
}

.policy-control {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.policy-unit {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.policy-meta {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}

.policy-pci {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.policy-helper {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

@media (max-width: 900px) {
  .policy-row {
    grid-template-columns: 1fr;
    align-items: start;
  }
}
</style>
