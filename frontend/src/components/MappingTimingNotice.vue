<template>
  <div
    class="mapping-timing"
    data-test="mapping-timing-notice"
  >
    <p class="timing-heading">
      {{ $t('identityGroupMappings.timing.heading') }}
    </p>
    <p class="timing-line">
      <strong>{{ $t('identityGroupMappings.timing.manager.lead') }}</strong>
      {{ $t('identityGroupMappings.timing.manager.detail') }}
    </p>
    <p class="timing-line">
      <strong>{{ $t('identityGroupMappings.timing.external.lead') }}</strong>
    </p>
    <p class="observation-rule">
      {{ revalidationText }}
    </p>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { t } from '@/i18n'
import { getSecurityPolicies } from '@/api/securityPolicies'
import { can } from '@/composables/useCapabilities'
import { policyUnit } from '@/utils/policyFormat'

/**
 * 映射的角色何時變動：管理端的收回在儲存當下，外部目錄的變動在下次登入重算。
 * 重新驗證時限只有政策管理者讀得到；讀不到時顯示不帶值的通則句，
 * 不拿出廠預設冒充現值，也不寫成「一律保留」——超過時限會收回是真正的行為。
 */
const REVALIDATION_KEY = 'mapping_revalidation_hours'
const revalidationPolicy = ref(null)

const loadRevalidationLimit = async () => {
  revalidationPolicy.value = null
  if (!can('securitypolicy:manage')) return
  try {
    const result = await getSecurityPolicies()
    revalidationPolicy.value = (result.data || []).find((item) => item.key === REVALIDATION_KEY) || null
  } catch (error) {
    console.error('identity_group_mappings_revalidation_limit_failed', error)
  }
}

const revalidationText = computed(() => {
  const policy = revalidationPolicy.value
  const hours = policy ? Number.parseInt(policy.value, 10) : Number.NaN
  if (!Number.isInteger(hours) || hours < 0) return t('identityGroupMappings.revalidation.unknown')
  if (hours === 0) return t('identityGroupMappings.revalidation.unlimited')
  const unit = policyUnit(policy)
  return t('identityGroupMappings.revalidation.limited', { limit: unit ? `${hours} ${unit}` : String(hours) })
})

onMounted(loadRevalidationLimit)
defineExpose({ reload: loadRevalidationLimit })
</script>

<style scoped>
.mapping-timing {
  margin: var(--ot-space-sm) 0;
}
.timing-heading {
  margin: 0 0 var(--ot-space-xs);
  font-weight: 600;
  color: var(--ot-text-primary);
}
.timing-line,
.observation-rule {
  margin: var(--ot-space-xs) 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}
</style>
