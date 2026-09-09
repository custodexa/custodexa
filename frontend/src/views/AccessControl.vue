<template>
  <div class="access-control">
    <PageHeader
      :title="$t('menu.accessControl')"
      :description="$t('accessControl.description')"
    />

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
        <!-- 資料傳輸管控的邊界說明（data-transfer-control 7.2）：
             七項邊界必須可查閱，否則「開了 file_download_enabled=false 就等於
             資料出不去」的誤解會直接變成稽核事故。折疊呈現＝不擋日常操作，
             但任何時候點得開 -->
        <el-collapse
          v-if="section.keys?.includes('clipboard_send_enabled')"
          class="transfer-boundary"
        >
          <el-collapse-item :title="$t('transferBoundary.title')">
            <ol class="boundary-list">
              <li
                v-for="i in TRANSFER_BOUNDARY_COUNT"
                :key="i"
              >
                {{ $t(`transferBoundary.item${i}`) }}
              </li>
            </ol>
          </el-collapse-item>
        </el-collapse>
      </template>

      <template #section-footer="{ section }">
        <!-- 覆寫表格掛在「連線政策」區塊尾端（工作台主角）：
             全域預設列在上、資產覆寫在下，
             兩層關係一眼可視 -->
        <AssetPolicyTable
          v-if="section.keys?.includes('access_policy_default')"
          :global-policy="savedGlobalPolicy"
        />
      </template>
    </PolicyKeySections>

    <ApplyPreviewDialog
      v-model="previewVisible"
      :preview="previewData"
      :policies="pagePolicies"
      :page-title="$t('menu.accessControl')"
      :group-names="groupNames"
      :verdicts-by-key="verdictsByKey"
      @confirm="acceptPreview"
    />
  </div>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import PageHeader from '@/components/PageHeader.vue'
import PolicyGroupStrip from '@/components/PolicyGroupStrip.vue'
import PolicyKeySections from '@/components/PolicyKeySections.vue'
import ApplyPreviewDialog from '@/components/ApplyPreviewDialog.vue'
import AssetPolicyTable from '@/components/AssetPolicyTable.vue'
import { usePolicyForm } from '@/composables/usePolicyForm'
import { ACCESS_SECTIONS } from '@/constants/policyDomains'

// 條目數與規格條列一致；增刪條目時三語 key 必須同步
const TRANSFER_BOUNDARY_COUNT = 7

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
} = usePolicyForm(ACCESS_SECTIONS)

// 覆寫表格的「跟隨全域設定（目前：X）」以已儲存值為準——
// 未儲存的編輯還不是生效政策，不進文案（spec：全域變更「並儲存」後才更新）
const savedGlobalPolicy = computed(
  () => savedValues.value['access_policy_default'] || 'open'
)

onMounted(() => {
  loadPolicies()
})
</script>

<style scoped>
.access-control {
  /* MainLayout already provides padding via --ot-space-lg */
}

.transfer-boundary {
  margin-bottom: var(--ot-space-sm);
}

.boundary-list {
  margin: 0;
  padding-left: var(--ot-space-lg);
  font-size: var(--ot-font-size-sm);
  line-height: 1.7;
  color: var(--ot-text-secondary);
}
</style>
