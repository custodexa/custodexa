<template>
  <!-- 這次檢查了什麼 -->
  <el-collapse
    :model-value="modelValue"
    class="inv-coverage"
    data-test="inv-coverage"
    @update:model-value="(v) => emit('update:modelValue', v)"
  >
    <el-collapse-item
      name="coverage"
      :title="$t('hostInventory.coverage.title')"
    >
      <ul class="cov-list">
        <li
          v-for="c in coverage"
          :key="c.check"
          :class="`tone-${coverageTone(c.state)}`"
          data-test="cov-item"
        >
          <strong>{{ checkLabelWithPath(c) }}</strong>
          <span>{{ stateLabel(c) }}</span>
          <small v-if="c.reason">{{ reasonLabel(c.reason) }}</small>
          <el-button
            v-if="c.reason === 'escalation_denied' && canManageExecutor"
            link
            type="primary"
            size="small"
            data-test="cov-setup-link"
            @click="emit('goto', 'executor-test-login')"
          >
            {{ $t('hostInventory.coverage.setupLink') }}
          </el-button>
          <small v-if="c.duplicate_rows">{{ $t('hostInventory.coverage.duplicate', { n: c.duplicate_rows }) }}</small>
        </li>
      </ul>
      <p
        class="cov-groups"
        data-test="cov-groups"
      >
        {{ groupsText }}
        <router-link
          v-if="canAdjustGroups"
          to="/security-policies"
        >
          {{ $t('hostInventory.coverage.adjustGroups') }}
        </router-link>
      </p>
      <h4>{{ $t('hostInventory.coverage.fixedTitle') }}</h4>
      <ul class="cov-fixed">
        <li
          v-for="n in fixedNotes"
          :key="n"
          data-test="cov-fixed"
        >
          {{ fixedLabel(n) }}
        </li>
      </ul>
    </el-collapse-item>
  </el-collapse>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '@/i18n'
import { coverageTone } from '@/utils/hostInventoryPresentation'
import { checkLabelWithPath, fixedLabel, reasonLabel, stateLabel } from '@/utils/hostInventoryLabels'
import { visibleText } from '@/utils/visibleName'

// 盤點抽屜的檢查範圍：各檢查項的狀態、這次採用的特權群組、固定不檢查的項目
const props = defineProps({
  modelValue: { type: Array, default: () => [] },
  coverage: { type: Array, default: () => [] },
  fixedNotes: { type: Array, default: () => [] },
  privilegedGroups: { type: String, default: '' },
  canAdjustGroups: { type: Boolean, default: false },
  canManageExecutor: { type: Boolean, default: false },
})
const emit = defineEmits(['update:modelValue', 'goto'])

const groupsText = computed(() => {
  const names = String(props.privilegedGroups ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => visibleText(s))
  return names.length
    ? t('hostInventory.coverage.groups', { groups: names.join('、') })
    : t('hostInventory.coverage.groupsEmpty')
})
</script>

<style scoped>
.inv-coverage {
  margin-top: 16px;
}

.cov-list,
.cov-fixed {
  margin: 0 0 10px;
  padding-left: 18px;
  line-height: 1.8;
  font-size: 13px;
}

.cov-list li {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 10px;
}

.cov-list li.tone-success span {
  color: var(--ot-success);
}

.cov-list li.tone-warning span {
  color: var(--ot-warning);
}

.cov-list li.tone-danger span {
  color: var(--ot-danger);
}

.cov-list small {
  color: var(--ot-text-secondary);
}

.cov-groups {
  font-size: 13px;
}

h4 {
  margin: 12px 0 6px;
  font-size: 13px;
  color: var(--ot-text-secondary);
}
</style>
