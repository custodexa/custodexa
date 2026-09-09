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

    <!-- 頁首列：生效政策組與本頁的套用、還原、儲存。
         套用僅動本頁鍵——其他域到各自頁面套用，避免改到未檢視頁的值 -->
    <PolicyGroupStrip
      :loading="loading"
      :saving="saving"
      :is-dirty="isDirty"
      :groups="groups"
      @apply="(command) => previewApply(command.mode, command.groupCode)"
      @reset="resetForm"
      @save="save"
    />

    <PolicyKeySections
      :sections="visibleSections"
      :form-values="formValues"
      :verdicts-by-key="verdictsByKey"
      :group-names="groupNames"
      :draft="isDraftVerdicts"
      :draft-status="draftStatus"
      @update:value="(key, value) => (formValues[key] = value)"
    >
      <template #section-extra="{ section }">
        <!-- 網頁會話絕對壽命設 0：會話沒有時間上界。角色由外部身分來源的群組
             成員資格決定時，來源側撤權要等到下次登入才生效，0 值等於把那個
             時效拉到無限長。語氣是警語不是阻擋——單機或不接外部來源的部署
             設 0 沒有這個問題，決定權在部署者 -->
        <el-alert
          v-if="section.keys?.includes('web_max_session_hours') && webSessionCapRisk"
          class="section-risk"
          type="warning"
          :closable="false"
          show-icon
        >
          {{ $t('securityPolicies.webSessionCapRiskAlert') }}
        </el-alert>
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

    <ApplyPreviewDialog
      v-model="previewVisible"
      :preview="previewData"
      :policies="pagePolicies"
      :page-title="$t('menu.securityPolicies')"
      :group-names="groupNames"
      :verdicts-by-key="verdictsByKey"
      @confirm="acceptPreview"
    />

    <SyslogForwardCard />
  </div>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import PageHeader from '@/components/PageHeader.vue'
import PolicyGroupStrip from '@/components/PolicyGroupStrip.vue'
import PolicyKeySections from '@/components/PolicyKeySections.vue'
import ApplyPreviewDialog from '@/components/ApplyPreviewDialog.vue'
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
  pagePolicies,
  groups,
  groupNames,
  formValues,
  savedValues,
  verdictsByKey,
  isDraftVerdicts,
  draftStatus,
  visibleSections,
  isDirty,
  previewVisible,
  previewData,
  loadPolicies,
  previewApply,
  acceptPreview,
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

// 網頁會話絕對壽命為 0（無上界）。用 formValues 即時反映未儲存編輯——
// 這一句要在按下儲存之前就出現，讓改成 0 的人當下就讀到後果；
// 後端未提供本鍵時值為 undefined → 不提示、不報錯
const webSessionCapRisk = computed(() => {
  const hours = formValues.value['web_max_session_hours']
  if (hours == null) return false
  return Number(hours) === 0
})

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

</style>
