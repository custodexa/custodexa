<template>
  <div class="request-items">
    <article
      v-for="item in request.items || []"
      :key="item.id"
      class="request-items__row"
      data-test="request-item-state"
    >
      <strong>{{ assetLabels[item.asset_id]?.name || t('common.assetRef', { id: item.asset_id }) }}</strong>
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
import { useAssetLabels } from '@/composables/useAssetLabels'
const props = defineProps({ request: { type: Object, required: true } })
// 第二項以後的資產名稱不在申請回傳裡，單靠 request.asset 只認得第一項，其餘退成
// 「資產 24」。名稱取得到就顯示，取不到才退回識別碼
const assetLabels = useAssetLabels(() => (props.request.items || []).map(item => ({
  id: item.asset_id,
  name: item.asset_name || item.asset?.name || (props.request.asset_id === item.asset_id ? props.request.asset?.name : ''),
})))
</script>
<style scoped>
.request-items { padding: var(--ot-space-md); }
.request-items__row { display: flex; flex-wrap: wrap; gap: var(--ot-space-md); padding: var(--ot-space-sm); border-bottom: 1px solid var(--ot-border-subtle); }
</style>
