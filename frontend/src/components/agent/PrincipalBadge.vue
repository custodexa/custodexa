<template>
  <span class="principal-badge">
    <span
      class="principal-badge__kind"
      :class="{ 'principal-badge__kind--agent': kind === 'agent' }"
      :title="kind === 'agent' ? t('agentPrincipals.agentExplained') : undefined"
      :aria-label="kind === 'agent' ? t('agentPrincipals.agentExplained') : undefined"
    >{{ t(kind === 'agent' ? 'agentPrincipals.agent' : kind === 'human' ? 'agentPrincipals.human' : 'agentPrincipals.unknown') }}</span>
    <span
      v-if="kind === 'agent' && showOwner"
      class="principal-badge__owner"
    >{{ t('agentPrincipals.ownerValue', { owner: ownerName || t('agentPrincipals.unavailable') }) }}</span>
  </span>
</template>
<script setup>
import { t } from '@/i18n'
// showOwner=false：負責人另處呈現（例如收進表格展開列）時不重複列，
// 首屏才不會整片都是次要文字
defineProps({ kind: { type: String, default: '' }, ownerId: { type: Number, default: null }, ownerName: { type: String, default: '' }, showOwner: { type: Boolean, default: true } })
</script>
<style scoped>
.principal-badge { display: inline-flex; flex-direction: column; gap: var(--ot-space-xs); font-size: var(--ot-font-size-sm); }
.principal-badge__kind { align-self: flex-start; border: 1px solid var(--ot-border); border-radius: var(--ot-radius-sm); padding: 0 var(--ot-space-xs); color: var(--ot-text-secondary); }
.principal-badge__kind--agent { color: var(--ot-info); }
.principal-badge__owner { color: var(--ot-text-secondary); overflow-wrap: anywhere; }
</style>
