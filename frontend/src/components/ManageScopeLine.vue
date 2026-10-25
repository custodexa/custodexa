<!--
  ManageScopeLine：頁首的「你可管理」範圍行。
  只做呈現：節點路徑由呼叫端從伺服器投影取出；不走節點樹、不用它過濾資料或決定動作可否。
  路徑可為名稱陣列（目前使用者資訊）或以「 / 」串接的字串（資產列表回應），一律以「›」連接。
-->
<template>
  <p
    class="manage-scope"
    data-test="manage-scope-line"
  >
    <strong>{{ t('manageScope.label') }}</strong>
    <span
      v-if="notAssigned"
      data-test="manage-scope-empty"
    >{{ t('manageScope.notAssigned') }}</span>
    <template v-else>
      <span
        v-for="(path, i) in shown"
        :key="i"
        data-test="manage-scope-node"
      >{{ path }}<template v-if="i < shown.length - 1">、</template></span>
      <button
        v-if="hasMore"
        type="button"
        class="more"
        data-test="manage-scope-more"
        @click="expanded = true"
      >
        {{ t('manageScope.more', { n: hiddenCount }) }}
      </button>
    </template>
  </p>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'

const LIMIT = 3
const props = defineProps({
  nodes: { type: Array, default: () => [] },
  notAssigned: { type: Boolean, default: false },
})

const { t } = useI18n()
const expanded = ref(false)

const toText = (p) => {
  const parts = Array.isArray(p) ? p : String(p ?? '').split(' / ')
  return parts.join(' › ')
}
const all = computed(() => props.nodes.map(toText))
const shown = computed(() => (expanded.value ? all.value : all.value.slice(0, LIMIT)))
const hasMore = computed(() => hiddenCount.value > 0)
const hiddenCount = computed(() => (expanded.value ? 0 : Math.max(0, all.value.length - LIMIT)))
</script>

<style scoped>
.manage-scope {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
.more {
  margin-left: var(--ot-space-xs);
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--ot-primary);
  cursor: pointer;
  font-size: inherit;
}
</style>
