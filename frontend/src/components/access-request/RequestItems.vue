<template>
  <div class="request-items">
    <article
      v-for="item in request.items || []"
      :key="item.id"
      class="request-items__row"
      data-test="request-item-state"
    >
      <strong>{{ item.asset_id === request.asset_id && request.asset?.name ? request.asset.name : t('common.assetRef', { id: item.asset_id }) }}</strong>
      <span>{{ !item.accounts?.length || item.accounts.includes('@ALL') ? t('multiRequest.allAccounts') : (item.accounts || []).join(t('common.listSeparator')) }}</span>
      <el-tag :type="item.status === 'approved' ? 'success' : item.status === 'pending' ? 'warning' : 'info'">
        {{ t(`multiRequest.state.${item.status}`) }}
      </el-tag>
      <span v-if="item.approved_duration_minutes">{{ t('common.minutesN', { n: item.approved_duration_minutes }) }}</span>
      <span v-if="item.revoked_at">{{ t('multiRequest.revokedAt', { time: formatDateTime(item.revoked_at) }) }}</span>
    </article>
  </div>
</template>
<script setup>
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
defineProps({ request: { type: Object, required: true } })
</script>
<style scoped>
.request-items { padding: var(--ot-space-md); }
.request-items__row { display: flex; flex-wrap: wrap; gap: var(--ot-space-md); padding: var(--ot-space-sm); border-bottom: 1px solid var(--ot-border-subtle); }
</style>
