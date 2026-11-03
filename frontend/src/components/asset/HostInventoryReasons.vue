<template>
  <span
    class="inv-reasons"
    data-test="inv-reasons"
  >
    <span
      v-if="!list.length"
      class="inv-reasons-none"
    >{{ $t('hostInventory.cell.none') }}</span>
    <template v-else>
      <span
        v-for="(r, i) in shown"
        :key="i"
        class="inv-reason"
        :class="{ 'is-muted': r.muted }"
        data-test="inv-reason"
      >
        <span>{{ labelOf(r) }}</span>
        <small
          v-if="r.bySudoRules"
          class="inv-reason-rules"
          data-test="inv-reason-rules"
        >{{ $t('hostInventory.cell.byRules') }}</small>
      </span>
      <el-tooltip
        v-if="rest.length"
        placement="top"
      >
        <template #content>
          <div
            v-for="(r, i) in rest"
            :key="i"
          >
            {{ labelOf(r) }}
          </div>
        </template>
        <el-tag
          size="small"
          effect="plain"
          data-test="inv-reason-more"
        >
          {{ $t('hostInventory.cell.moreReasons', { n: rest.length }) }}
        </el-tag>
      </el-tooltip>
    </template>
  </span>
</template>

<script setup>
// 特權原因標籤：群組名與別名來自主機，經 visibleName 可見化；依 sudo 規則判斷者另標小字。
import { computed } from 'vue'
import { t } from '@/i18n'
import { parseReason } from '@/utils/hostInventoryPresentation'
import { visibleText } from '@/utils/visibleName'

const props = defineProps({
  reasons: { type: Array, default: () => [] },
  max: { type: Number, default: 2 },
})

const list = computed(() => (props.reasons || []).map(parseReason))
const shown = computed(() => list.value.slice(0, props.max))
const rest = computed(() => list.value.slice(props.max))

function labelOf(r) {
  if (!r.known) return t('hostInventory.reason.unknown', { raw: visibleText(r.raw) })
  return t(`hostInventory.reason.${r.kind}`, { name: visibleText(r.name) })
}
</script>

<style scoped>
.inv-reasons {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px 6px;
}

.inv-reason {
  display: inline-flex;
  flex-direction: column;
  font-size: 13px;
  line-height: 1.4;
  color: var(--ot-text-primary);
}

.inv-reason.is-muted {
  color: var(--ot-text-disabled);
}

.inv-reason-rules {
  font-size: 11px;
  color: var(--ot-text-disabled);
}

.inv-reasons-none {
  color: var(--ot-text-disabled);
}
</style>
