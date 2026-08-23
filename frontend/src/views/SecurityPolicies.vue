<template>
  <div class="security-policies">
    <PageHeader
      :title="$t('menu.securityPolicies')"
      :description="$t('securityPolicies.description')"
    />

    <!-- 明文連線下的建議：本頁自己的協定是
         http，而「登入狀態僅在 https 連線保存」開著——使用者（含管理員自己）
         會每 15 分鐘被登出。語氣是建議不是警告：type="info"，列出兩條處置路徑，
         決定權在部署者。**系統不會自動改設定**，本頁唯一的寫入途徑仍是
         下方該政策項的開關加儲存 -->
    <el-alert
      v-if="insecureTransportHint"
      class="insecure-transport-alert"
      type="info"
      :title="$t('securityPolicies.insecureTransportTitle')"
      :closable="false"
      show-icon
    >
      <p class="insecure-transport-body">
        {{ $t('securityPolicies.insecureTransportBody') }}
      </p>
      <ol class="insecure-transport-options">
        <li>{{ $t('securityPolicies.insecureTransportOptionHttps') }}</li>
        <li>{{ $t('securityPolicies.insecureTransportOptionHttp') }}</li>
      </ol>
    </el-alert>

    <!-- 母頁總覽橫幅：全系統偏離總數＋分域列表；
         套用鈕僅動本頁鍵——其他域到各自頁面套用，避免改到未檢視頁的值 -->
    <PolicyPciBanner
      :loading="loading"
      :saving="saving"
      :is-dirty="isDirty"
      :deviation-count="totalDeviationCount"
      :ok-text="$t('securityPolicies.systemCompliant')"
      :deviation-text="$t('securityPolicies.systemDeviation', { n: totalDeviationCount }, totalDeviationCount)"
      :apply-label="$t('securityPolicies.applyPage')"
      :epayment-deviation-count="pageEPaymentDeviationCount"
      @apply="applyPagePCI"
      @apply-epayment="applyPageEPayment"
      @reset="resetForm"
      @save="save"
    >
      <template #extra>
        <div
          v-if="totalDeviationCount > 0"
          class="domain-breakdown"
        >
          <template
            v-for="domain in domainDeviations"
            :key="domain.id"
          >
            <span
              v-if="domain.id === 'security'"
              class="domain-item is-current"
            >{{ $t('securityPolicies.currentPageCount', { n: domain.count }) }}</span>
            <router-link
              v-else
              class="domain-item"
              :to="domain.route"
            >
              {{ domain.label }} {{ $t('securityPolicies.itemCount', { n: domain.count }) }}
            </router-link>
          </template>
        </div>
      </template>
    </PolicyPciBanner>

    <PolicyKeySections
      :sections="visibleSections"
      :form-values="formValues"
      :saved-values="savedValues"
      @update:value="(key, value) => (formValues[key] = value)"
    >
      <template #section-extra="{ section }">
        <!-- 跨欄位風險（TIMEOUT-1 方案 B）：設了協議閒置逾時但未設最長時長封頂時，
             tail -f/top 等監看類長連線因伺服器持續輸出而不受閒置逾時治理，須以
             最長時長作絕對上限中斷 -->
        <el-alert
          v-if="section.keys?.includes('session_max_minutes') && sessionCapRisk"
          class="section-risk"
          type="warning"
          :closable="false"
          show-icon
        >
          {{ $t('securityPolicies.sessionCapRiskAlert') }}
        </el-alert>
      </template>
    </PolicyKeySections>

    <SyslogForwardCard />
  </div>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import PageHeader from '@/components/PageHeader.vue'
import PolicyPciBanner from '@/components/PolicyPciBanner.vue'
import PolicyKeySections from '@/components/PolicyKeySections.vue'
import SyslogForwardCard from '@/components/SyslogForwardCard.vue'
import { usePolicyForm } from '@/composables/usePolicyForm'
import {
  POLICY_DOMAINS,
  POLICY_REFRESH_COOKIE_SECURE,
  SECURITY_SECTIONS,
  sectionKeys,
} from '@/constants/policyDomains'

const {
  loading,
  saving,
  policies,
  formValues,
  savedValues,
  totalDeviationCount,
  pageEPaymentDeviationCount,
  visibleSections,
  isDirty,
  loadPolicies,
  applyPagePCI,
  applyPageEPayment,
  resetForm,
  save,
  setRestExclude,
} = usePolicyForm(SECURITY_SECTIONS, { includeRest: true })

// 已歸其他域的鍵不落本頁「其他」區塊（它們在各自頁面呈現）
setRestExclude(
  POLICY_DOMAINS.filter((d) => d.id !== 'security').flatMap((d) =>
    sectionKeys(d.sections)
  )
)

// 分域偏離列表：以後端 compliant 旗標（已儲存狀態）計數，與
// deviation_count 同源——分域合計＝全系統總數。未歸域的鍵計入本頁
const domainDeviations = computed(() => {
  const assigned = new Set(
    POLICY_DOMAINS.flatMap((d) => sectionKeys(d.sections))
  )
  return POLICY_DOMAINS.map((domain) => {
    const keys = new Set(sectionKeys(domain.sections))
    const count = policies.value.filter(
      (p) =>
        p.compliant === false &&
        (keys.has(p.key) || (domain.id === 'security' && !assigned.has(p.key)))
    ).length
    return { ...domain, count }
  })
})

// 明文連線建議（決策 4）：兩個事實各取自最可靠的源——頁面協定只有前端知道
//（後端要知道同一件事只能猜標頭），生效值只有後端知道（隨政策清單供給）。
// 缺任一則提示要嘛漏報（不知生效值，關閉後的健康部署也彈）、要嘛誤報
//（不知協定，https 部署也彈）。
// 取 savedValues 而非 formValues：提示講的是這套部署此刻的實際行為，
// 不該隨編輯中的未儲存開關跳動；舊後端未提供本鍵時值為 undefined → 不顯示、不報錯
const insecureTransportHint = computed(
  () =>
    window.location.protocol === 'http:' &&
    savedValues.value[POLICY_REFRESH_COOKIE_SECURE] === true
)

// 跨欄位風險（TIMEOUT-1 方案 B）：協議閒置逾時已啟用（>0）但最長時長未封頂（=0）。
// 用 formValues 即時反映未儲存編輯；缺任一鍵（後端未提供）時不提示
const sessionCapRisk = computed(() => {
  const idle = formValues.value['session_idle_minutes']
  const max = formValues.value['session_max_minutes']
  if (idle == null || max == null) return false
  return Number(idle) > 0 && Number(max) === 0
})

onMounted(() => {
  loadPolicies()
})
</script>

<style scoped>
.insecure-transport-alert {
  margin-bottom: var(--ot-space-md);
}

.insecure-transport-body {
  margin: 0;
}

.insecure-transport-options {
  margin: var(--ot-space-xs) 0 0;
  padding-left: var(--ot-space-lg);
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.domain-breakdown {
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
  flex-wrap: wrap;
}

.domain-item {
  font-size: var(--ot-font-size-sm);
  color: var(--el-color-primary);
  text-decoration: none;
}

.domain-item.is-current {
  color: var(--ot-text-secondary);
}
</style>
