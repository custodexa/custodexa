<!--
  AuthzAccountScopeDialog：調整授權列的帳號範圍（asset-multi-account D5）。
  預設 `@ALL`（全部帳號，與多帳號維度引入前行為一致）；個別指定時綁 username
  字串而非 FK——授權客體可為節點，帳號卻是 per-asset 物件，「授權節點內的 root」
  只能以名字表達。username 建議清單僅為輸入輔助，非授權判定依據。
-->
<template>
  <el-dialog
    :model-value="modelValue"
    :title="$t('authorizations.accountScopeTitle')"
    width="560px"
    :close-on-click-modal="false"
    @update:model-value="(v) => emit('update:modelValue', v)"
    @open="onOpen"
  >
    <el-alert
      v-if="submitError"
      type="error"
      :closable="false"
      show-icon
      :title="submitError"
      class="authz-scope__alert"
    />
    <p class="authz-scope__target">
      {{ $t('authorizations.accountScopeTarget', { target: targetLabel }) }}
    </p>

    <el-radio-group
      v-model="mode"
      class="authz-scope__mode"
    >
      <el-radio value="all">
        {{ $t('authorizations.accountScopeAll') }}
      </el-radio>
      <el-radio value="named">
        {{ $t('authorizations.accountScopeNamed') }}
      </el-radio>
    </el-radio-group>

    <template v-if="mode === 'named'">
      <el-select
        v-model="usernames"
        multiple
        filterable
        allow-create
        default-first-option
        :reserve-keyword="false"
        :loading="suggestLoading"
        :placeholder="$t('authorizations.accountScopePlaceholder')"
        class="authz-scope__select"
      >
        <el-option
          v-for="name in suggestions"
          :key="name"
          :label="name"
          :value="name"
        />
      </el-select>
      <!-- 保留別名就近示警：按鈕同步 disabled，使用者才知道為何送不出去 -->
      <el-alert
        v-if="reservedUsernames.length > 0"
        type="warning"
        :closable="false"
        show-icon
        :title="$t('authorizations.accountScopeReserved', { names: reservedUsernames.join('、') })"
        class="authz-scope__reserved"
      />
      <p class="authz-scope__hint">
        {{ $t('authorizations.accountScopeHint') }}
      </p>
    </template>

    <template #footer>
      <el-button @click="emit('update:modelValue', false)">
        {{ $t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :loading="submitting"
        :disabled="mode === 'named' && (trimmedUsernames.length === 0 || reservedUsernames.length > 0)"
        @click="handleSubmit"
      >
        {{ $t('common.confirm') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { updateAuthorizationAccounts } from '@/api/authorizations'
import { getAssetList } from '@/api/assets'
import { listAssetAccounts } from '@/api/assetAccounts'
import { ACCOUNT_SCOPE_ALL, isAllAccountScope } from '@/constants/assetAccounts'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'

// 節點客體的建議來源上限：建議清單是輸入輔助不是完整性保證，
// 大節點全掃等於開啟數十個請求換一份下拉選單
const SUGGEST_ASSET_LIMIT = 10

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  // 授權列（含 id / asset_id / asset_name / asset_group_id / asset_group_name / accounts）
  row: { type: Object, default: null },
})
const emit = defineEmits(['update:modelValue', 'saved'])

const mode = ref('all')
const usernames = ref([])
const submitting = ref(false)
const submitError = ref('')
const suggestions = ref([])
const suggestLoading = ref(false)

const targetLabel = computed(
  () => props.row?.asset_group_name || props.row?.asset_name || '-'
)

// 送出值的唯一來源：按鈕 disabled 與 payload 同源，否則全空白輸入
// （`usernames.length===1` 但 trim 後為空）會送出空陣列吃後端 400
const trimmedUsernames = computed(() =>
  usernames.value.map((v) => v.trim()).filter(Boolean)
)

// allow-create 讓使用者可打任何字串，包含保留別名（對抗審查 MED-4）：
// 在「指定帳號」模式下送出 `@ALL` 會被後端展開成全部帳號——畫面說「指定」、
// 結果卻是「全部」，語義完全相反。後端已擋 `@` 前綴的 username，前端同步擋
// 並就近給訊息（`@` 為授權別名的保留前綴，不可能是真的帳號名）
const reservedUsernames = computed(() =>
  trimmedUsernames.value.filter((v) => v.startsWith('@'))
)

function onOpen() {
  submitError.value = ''
  const accounts = props.row?.accounts
  if (isAllAccountScope(accounts)) {
    mode.value = 'all'
    usernames.value = []
  } else {
    mode.value = 'named'
    usernames.value = [...accounts]
  }
  loadSuggestions()
}

// 建議清單＝授權客體範圍內資產的帳號 username 聯集（節點客體取子樹前 N 台）
async function loadSuggestions() {
  suggestions.value = []
  if (!props.row) return
  suggestLoading.value = true
  try {
    let assetIds = []
    if (props.row.asset_id) {
      assetIds = [props.row.asset_id]
    } else if (props.row.asset_group_id) {
      const resp = await getAssetList({
        node_id: props.row.asset_group_id,
        include_subtree: true,
        page: 1,
        page_size: SUGGEST_ASSET_LIMIT,
      })
      assetIds = (resp.data || []).map((a) => a.id)
    }
    const results = await Promise.allSettled(
      assetIds.map((id) => listAssetAccounts(id, { skipErrorToast: true }))
    )
    const names = new Set()
    for (const r of results) {
      if (r.status !== 'fulfilled') continue
      for (const account of r.value.data || []) names.add(account.username)
    }
    suggestions.value = [...names].sort()
  } catch (err) {
    // 建議清單缺席不擋輸入（allow-create 仍可自由輸入）
    console.warn('[AuthzAccountScopeDialog] 帳號建議清單載入失敗:', err)
  } finally {
    suggestLoading.value = false
  }
}

async function handleSubmit() {
  if (!props.row) return
  const accounts = mode.value === 'all' ? [ACCOUNT_SCOPE_ALL] : trimmedUsernames.value
  // 空清單語義上等於「誰都不能連」，後端以 400 明確拒收——前端不送出去換一則錯誤
  if (accounts.length === 0) return
  if (mode.value === 'named' && reservedUsernames.value.length > 0) {
    submitError.value = t('authorizations.accountScopeReserved', {
      names: reservedUsernames.value.join('、'),
    })
    return
  }
  submitting.value = true
  submitError.value = ''
  try {
    await updateAuthorizationAccounts(props.row.id, accounts)
    ElMessage.success(t('authorizations.accountScopeSaved'))
    emit('saved')
    emit('update:modelValue', false)
  } catch (err) {
    // 409 CONFLICT_TICKET_ACCOUNT_SCOPE_IMMUTABLE 等就近呈現：對話框保持開啟，
    // 使用者才看得到「為什麼這列改不動」（UI 已先擋 ticket 列，此為伺服端二道防線）
    submitError.value = resolveApiError(
      err.response?.data,
      err.response?.status,
      t('authorizations.accountScopeFailed')
    )
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.authz-scope__alert {
  margin-bottom: 12px;
}
.authz-scope__target {
  margin: 0 0 12px;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
.authz-scope__mode {
  margin-bottom: 12px;
}
.authz-scope__select {
  width: 100%;
}
.authz-scope__reserved {
  margin-top: 8px;
}
.authz-scope__hint {
  margin: 8px 0 0;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  line-height: 1.6;
}
</style>
