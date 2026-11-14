<template>
  <div
    v-loading="loading"
    class="user-api-tokens"
    data-test="user-api-tokens"
  >
    <p class="uat-desc">
      {{ canRevoke ? $t('userDetail.apiTokens.desc', { user: username }) : $t('userDetail.apiTokens.descProtected', { user: username }) }}
    </p>

    <template v-if="loadFailed">
      <el-alert
        type="error"
        :closable="false"
        show-icon
        :title="$t('userDetail.apiTokens.loadFailed')"
        data-test="user-api-tokens-load-failed"
      />
      <div>
        <el-button
          data-test="user-api-tokens-reload"
          @click="load"
        >
          {{ $t('common.refresh') }}
        </el-button>
      </div>
    </template>

    <template v-else-if="loaded">
      <!-- 受保護帳號且檢視者不能撤銷時才說明原因；超級管理者或本人檢視時照常提供撤銷 -->
      <el-alert
        v-if="isProtected && !canRevoke"
        type="warning"
        :closable="false"
        show-icon
        :title="$t('userDetail.apiTokens.protectedTitle', { user: username })"
        :description="holder === 'security' ? $t('userDetail.apiTokens.protectedBodySecurity', { user: username }) : $t('userDetail.apiTokens.protectedBody', { user: username })"
        data-test="user-api-tokens-protected"
      />
      <!-- 帳號停用的提醒只對還沒失效的 token 有意義；全部失效後不再提 -->
      <el-alert
        v-if="!accountActive && revocable > 0"
        type="warning"
        :closable="false"
        show-icon
        :title="$t('userDetail.apiTokens.disabledTitle', { user: username })"
        :description="$t('userDetail.apiTokens.disabledBody')"
        data-test="user-api-tokens-disabled"
      />

      <ApiTokenList
        v-if="tokens.length"
        :tokens="tokens"
        mode="admin"
        :can-revoke="canRevoke"
        :account-disabled="!accountActive"
        @revoke="openRevoke"
      >
        <template #actions>
          <el-button
            v-if="canRevoke && revocable > 0"
            v-preview-write:delete
            type="danger"
            plain
            data-test="user-api-tokens-revoke-all"
            @click="openRevokeAll"
          >
            {{ $t('apiTokens.revokeAll.button') }}
          </el-button>
        </template>
      </ApiTokenList>
      <EmptyState
        v-else
        :title="$t('userDetail.apiTokens.empty', { user: username })"
        :icon="KeyRound"
        data-test="user-api-tokens-empty"
      />
    </template>

    <ApiTokenRevokeDialog
      v-model="revokeOpen"
      mode="admin"
      :token="revokeTarget"
      :all="revokeAll"
      :tokens="tokens"
      :owner-name="username"
      :submit="submitRevoke"
      @done="onRevoked"
      @failed="load"
    />
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { KeyRound } from 'lucide-vue-next'
import { t } from '@/i18n'
import { apiErrorSummary } from '@/api/redact'
import { getUserApiTokens, revokeAllUserApiTokens, revokeUserApiToken } from '@/api/apiTokens'
import { summarize } from '@/constants/apiTokens'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import EmptyState from '@/components/EmptyState.vue'
import ApiTokenList from '@/components/api-token/ApiTokenList.vue'
import ApiTokenRevokeDialog from '@/components/api-token/ApiTokenRevokeDialog.vue'

/**
 * 使用者詳情的 API token 分頁：管理者檢視此人建立的 API token 並可撤銷。
 * 能否撤銷、是否受保護、帳號是否啟用都取自 GET /users/:id/api-tokens。
 */
const props = defineProps({
  userId: { type: Number, required: true },
  username: { type: String, default: '' },
  // 受保護身分（super／security），只用來挑選說明文字
  holder: { type: String, default: '' },
})

const loading = ref(false)
const loaded = ref(false)
const loadFailed = ref(false)
const tokens = ref([])
const canRevoke = ref(false)
const isProtected = ref(false)
const accountActive = ref(true)
const revokeOpen = ref(false)
const revokeTarget = ref(null)
const revokeAll = ref(false)
let loadSeq = 0

const revocable = computed(() => summarize(tokens.value).revocable)

const load = async () => {
  const seq = ++loadSeq
  loading.value = true
  loadFailed.value = false
  try {
    const res = await getUserApiTokens(props.userId)
    if (seq !== loadSeq) return
    tokens.value = Array.isArray(res?.data) ? res.data : []
    canRevoke.value = res?.can_revoke === true
    isProtected.value = res?.protected === true
    accountActive.value = res?.account_active !== false
    loaded.value = true
  } catch (error) {
    if (seq !== loadSeq) return
    loadFailed.value = true
    console.error(...apiErrorSummary('user_api_token_list_failed', error))
  } finally {
    if (seq === loadSeq) loading.value = false
  }
}

const openRevoke = (token) => {
  revokeAll.value = false
  revokeTarget.value = token
  revokeOpen.value = true
}
const openRevokeAll = () => {
  revokeAll.value = true
  revokeTarget.value = null
  revokeOpen.value = true
}

const submitRevoke = (note) =>
  revokeAll.value
    ? revokeAllUserApiTokens(props.userId, note)
    : revokeUserApiToken(props.userId, revokeTarget.value.id, note)

const onRevoked = (res) => {
  if (revokeAll.value) {
    const n = Number.isFinite(res?.revoked) ? res.revoked : revocable.value
    ElMessage.success(t('apiTokens.msg.revokedAll', { n }))
  } else {
    ElMessage.success(t('apiTokens.msg.revoked', { name: revokeTarget.value?.name || '' }))
  }
  void load()
}

watch(() => props.userId, () => {
  loaded.value = false
  tokens.value = []
  void load()
})
onMounted(() => {
  void load()
})

defineExpose({ load })
</script>

<style scoped>
.user-api-tokens {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}
.uat-desc {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  line-height: 1.6;
}
</style>
