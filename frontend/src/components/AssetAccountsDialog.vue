<!--
  AssetAccountsDialog：資產帳號管理。
  自資產列表或資產編輯對話框進入；一個資產可有多個系統帳號，各自憑證加密存放。
  憑證只進不出——後端僅回 has_password／has_private_key 兩布林，此處絕不回填明文。
-->
<template>
  <el-dialog
    :model-value="modelValue"
    :title="$t('assetAccounts.title', { name: assetName })"
    width="680px"
    class="acct-mgr__dialog"
    :close-on-click-modal="false"
    @update:model-value="(v) => emit('update:modelValue', v)"
    @open="onOpen"
  >
    <el-alert
      v-if="protocol === 'k8s'"
      :title="$t('assetAccounts.k8sSingleAccount')"
      type="info"
      :closable="false"
      show-icon
      class="acct-mgr__alert"
    />
    <el-alert
      v-if="loadError"
      type="error"
      :closable="false"
      show-icon
      :title="$t('assetAccounts.loadFailed')"
      :description="loadError"
      class="acct-mgr__alert"
    />

    <div class="acct-mgr__bar">
      <el-button
        type="primary"
        size="small"
        :disabled="protocol === 'k8s' && accounts.length > 0"
        @click="openCreate"
      >
        <el-icon><Plus /></el-icon>
        {{ $t('assetAccounts.add') }}
      </el-button>
      <el-button
        size="small"
        :loading="loading"
        @click="load"
      >
        <el-icon><RefreshCw /></el-icon>
        {{ $t('common.refresh') }}
      </el-button>
    </div>

    <el-table
      v-loading="loading"
      :data="accounts"
      size="small"
      stripe
    >
      <el-table-column
        :label="$t('assetAccounts.colUsername')"
        min-width="170"
        show-overflow-tooltip
      >
        <template #default="{ row }">
          <el-tooltip
            v-if="row.is_default"
            :content="$t('assetAccounts.defaultTip')"
            placement="top"
          >
            <el-icon class="acct-mgr__star">
              <Star fill="currentColor" />
            </el-icon>
          </el-tooltip>
          <span class="acct-mgr__name">{{ row.username }}</span>
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('assetAccounts.colCredential')"
        width="110"
      >
        <template #default="{ row }">
          <el-tag
            :type="accountCredentialTagType(row)"
            size="small"
          >
            {{ accountCredentialLabel(row) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('assetAccounts.colPrivileged')"
        width="90"
      >
        <template #default="{ row }">
          <el-tag
            v-if="row.privileged"
            type="danger"
            size="small"
          >
            {{ $t('assetAccounts.privileged') }}
          </el-tag>
          <span v-else>-</span>
        </template>
      </el-table-column>
      <el-table-column
        prop="note"
        :label="$t('assetAccounts.colNote')"
        min-width="130"
        show-overflow-tooltip
      />
      <el-table-column
        :label="$t('common.actions')"
        width="190"
        fixed="right"
      >
        <template #default="{ row }">
          <el-button
            type="primary"
            size="small"
            link
            @click="openEdit(row)"
          >
            {{ $t('common.edit') }}
          </el-button>
          <el-button
            v-if="!row.is_default"
            type="warning"
            size="small"
            link
            @click="handleSetDefault(row)"
          >
            {{ $t('assetAccounts.setDefault') }}
          </el-button>
          <el-button
            type="danger"
            size="small"
            link
            @click="handleDelete(row)"
          >
            {{ $t('common.delete') }}
          </el-button>
        </template>
      </el-table-column>
      <template #empty>
        <EmptyState
          v-if="!loadError"
          :title="$t('assetAccounts.emptyTitle')"
          :hint="$t('assetAccounts.emptyHint')"
        />
        <span v-else />
      </template>
    </el-table>

    <template #footer>
      <el-button @click="emit('update:modelValue', false)">
        {{ $t('common.close') }}
      </el-button>
    </template>

    <!-- 帳號新增／編輯表單 -->
    <el-dialog
      :model-value="formVisible"
      :title="formMode === 'create' ? $t('assetAccounts.add') : $t('assetAccounts.editTitle')"
      width="560px"
      class="acct-mgr__dialog"
      append-to-body
      :close-on-click-modal="false"
      @update:model-value="(v) => (v ? (formVisible = true) : closeForm())"
    >
      <!-- 影響面明示（隱性權限擴張緩解）：新增帳號前先講清楚誰會因此多一個可選身分 -->
      <el-alert
        v-if="formMode === 'create' && impactLoaded"
        type="warning"
        :closable="false"
        show-icon
        :title="$t('assetAccounts.impactTitle', { users: impactUsers, groups: impactGroups })"
        :description="impactDescription"
        class="acct-mgr__alert"
      />

      <el-form
        ref="formRef"
        :model="form"
        :rules="formRules"
        label-position="top"
      >
        <el-form-item
          v-if="formMode === 'create'"
          :label="$t('assetAccounts.copyFrom')"
        >
          <el-select
            v-model="copyAssetId"
            filterable
            clearable
            :empty-values="[null, undefined]"
            :placeholder="$t('assetAccounts.copyAssetPlaceholder')"
            class="acct-mgr__copy-select"
            @change="onCopyAssetChange"
          >
            <el-option
              v-for="a in copyAssetOptions"
              :key="a.id"
              :label="a.name"
              :value="a.id"
            />
          </el-select>
          <el-select
            v-model="form.copy_from_account_id"
            :disabled="!copyAssetId"
            clearable
            :empty-values="[null, undefined]"
            :loading="copyAccountsLoading"
            :placeholder="$t('assetAccounts.copyAccountPlaceholder')"
            class="acct-mgr__copy-select"
            @change="onCopySourceChange"
          >
            <el-option
              v-for="a in copySourceAccounts"
              :key="a.id"
              :label="a.username"
              :value="a.id"
            />
          </el-select>
        </el-form-item>

        <el-form-item
          :label="$t('assetAccounts.colUsername')"
          prop="username"
        >
          <el-input
            v-model="form.username"
            :placeholder="$t('assetAccounts.usernamePlaceholder')"
          />
        </el-form-item>

        <el-alert
          v-if="form.copy_from_account_id"
          type="info"
          :closable="false"
          show-icon
          :title="$t('assetAccounts.copyCredentialNote')"
          class="acct-mgr__alert"
        />
        <template v-else>
          <el-form-item :label="$t('assetAccounts.password')">
            <el-input
              v-model="form.password"
              type="password"
              show-password
              autocomplete="new-password"
              :placeholder="formMode === 'edit' ? $t('assetAccounts.keepCredentialPlaceholder') : ''"
            />
          </el-form-item>
          <el-form-item :label="$t('assetAccounts.privateKey')">
            <el-input
              v-model="form.private_key"
              type="textarea"
              :rows="4"
              :placeholder="formMode === 'edit' ? $t('assetAccounts.keepCredentialPlaceholder') : ''"
            />
          </el-form-item>
        </template>

        <!-- 認證類型：憑證屬帳號，故此欄放帳號表單而非資產表單。
             1.0 只接受 sql；domain 保留選項但停用——後端收到 domain 直接 400，
             讓選項可見但不可選，比整個藏起來更能說明「尚未支援」 -->
        <el-form-item
          v-if="isDatabaseProtocol(protocol)"
          :label="$t('assets.authMethod')"
        >
          <el-select
            v-model="form.auth_method"
            class="acct-mgr__auth-select"
          >
            <el-option
              :label="$t('assets.authMethodSql')"
              value="sql"
            />
            <el-option
              :label="$t('assets.authMethodDomain')"
              value="domain"
              disabled
            />
          </el-select>
        </el-form-item>

        <el-form-item :label="$t('assetAccounts.colPrivileged')">
          <el-switch v-model="form.privileged" />
          <span class="acct-mgr__switch-hint">{{ $t('assetAccounts.privilegedHint') }}</span>
        </el-form-item>
        <el-form-item
          v-if="formMode === 'create' && accounts.length > 0"
          :label="$t('assetAccounts.setAsDefault')"
        >
          <el-switch v-model="form.is_default" />
        </el-form-item>
        <el-form-item :label="$t('assetAccounts.colNote')">
          <el-input
            v-model="form.note"
            maxlength="255"
            show-word-limit
          />
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="closeForm">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="submitting"
          @click="handleSubmit"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>
  </el-dialog>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, RefreshCw, Star } from 'lucide-vue-next'
import {
  listAssetAccounts,
  createAssetAccount,
  updateAssetAccount,
  deleteAssetAccount,
  setDefaultAssetAccount,
} from '@/api/assetAccounts'
import { getAssetList } from '@/api/assets'
import { getEffectiveUsers } from '@/api/authorizations'
import { accountCredentialLabel, accountCredentialTagType } from '@/constants/assetAccounts'
import { effectiveAccessNote } from '@/utils/keyDisplay'
import { isDatabaseProtocol } from '@/utils/protocol'
import EmptyState from '@/components/EmptyState.vue'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  assetId: { type: [Number, String], default: null },
  assetName: { type: String, default: '' },
  protocol: { type: String, default: '' },
})
const emit = defineEmits(['update:modelValue', 'changed'])

const accounts = ref([])
const loading = ref(false)
const loadError = ref('')

async function onOpen() {
  loadError.value = ''
  formVisible.value = false
  await load()
}

async function load() {
  if (!props.assetId) return
  loading.value = true
  try {
    const resp = await listAssetAccounts(props.assetId, { skipErrorToast: true })
    accounts.value = resp.data || []
    loadError.value = ''
  } catch (err) {
    loadError.value = resolveApiError(
      err.response?.data,
      err.response?.status,
      t('assetAccounts.loadFailed')
    )
    accounts.value = []
  } finally {
    loading.value = false
  }
}

// --- 表單 ---
const formVisible = ref(false)
const formMode = ref('create')
const formRef = ref(null)
const submitting = ref(false)
const editingId = ref(null)
const form = reactive({
  username: '',
  password: '',
  private_key: '',
  privileged: false,
  is_default: false,
  auth_method: 'sql',
  note: '',
  copy_from_account_id: null,
})

// computed：切語言時錯誤訊息跟著換（既有 Assets.vue 慣例）
const formRules = computed(() => ({
  username: [{ required: true, message: t('assetAccounts.usernameRequired'), trigger: 'blur' }],
}))

function resetForm() {
  form.username = ''
  form.password = ''
  form.private_key = ''
  form.privileged = false
  form.is_default = false
  form.auth_method = 'sql'
  form.note = ''
  form.copy_from_account_id = null
  copyAssetId.value = null
  copySourceAccounts.value = []
}

async function openCreate() {
  formMode.value = 'create'
  editingId.value = null
  resetForm()
  formVisible.value = true
  loadImpact()
  loadCopyAssets()
}

function openEdit(row) {
  formMode.value = 'edit'
  editingId.value = row.id
  resetForm()
  // 憑證刻意不回填（後端不回傳明文；空字串＝沿用既有）
  form.username = row.username
  form.privileged = !!row.privileged
  form.auth_method = row.auth_method || 'sql'
  form.note = row.note || ''
  formVisible.value = true
}

async function handleSubmit() {
  if (formRef.value) {
    try {
      await formRef.value.validate()
    } catch {
      return
    }
  }
  submitting.value = true
  try {
    if (formMode.value === 'create') {
      const payload = {
        username: form.username.trim(),
        privileged: form.privileged,
        is_default: form.is_default,
        note: form.note,
      }
      // 僅 DB 協議帶 auth_method；非 DB 協議不送，讓後端保持預設值
      if (isDatabaseProtocol(props.protocol)) payload.auth_method = form.auth_method
      if (form.copy_from_account_id) {
        payload.copy_from_account_id = form.copy_from_account_id
      } else {
        if (form.password) payload.password = form.password
        if (form.private_key) payload.private_key = form.private_key
      }
      await createAssetAccount(props.assetId, payload)
      ElMessage.success(t('assetAccounts.created'))
    } else {
      const payload = {
        username: form.username.trim(),
        privileged: form.privileged,
        note: form.note,
      }
      // 後端為指標欄位（nil＝不動），故非 DB 協議一律不帶
      if (isDatabaseProtocol(props.protocol)) payload.auth_method = form.auth_method
      // 空字串＝沿用既有憑證（後端語義），故僅在有輸入時送出
      if (form.password) payload.password = form.password
      if (form.private_key) payload.private_key = form.private_key
      await updateAssetAccount(props.assetId, editingId.value, payload)
      ElMessage.success(t('assetAccounts.updated'))
    }
    closeForm()
    emit('changed')
    await load()
  } catch (err) {
    // 全域攔截器已 toast（C10：頁內不重複）；對話框保持開啟供修正。
    // 只印機器碼與狀態——err 本體帶 config.data（本次送出的明文憑證）
    console.error(
      '[AssetAccountsDialog] 帳號寫入失敗:',
      err?.response?.status,
      err?.response?.data?.code
    )
  } finally {
    submitting.value = false
  }
}

// 關閉表單即清掉明文憑證：只隱藏對話框會讓
// form.password／form.private_key 續留在 reactive state，Vue DevTools 可讀。
// 沿用對新 KEK 明文的既有做法——**清元件狀態，
// 不承諾抹除 JS 記憶體**（字串不可變，舊值何時被 GC 回收不在我們控制內）
function closeForm() {
  formVisible.value = false
  form.password = ''
  form.private_key = ''
}

async function handleSetDefault(row) {
  try {
    await setDefaultAssetAccount(props.assetId, row.id)
    ElMessage.success(t('assetAccounts.defaultChanged'))
    emit('changed')
    await load()
  } catch (err) {
    console.error('[AssetAccountsDialog] 設為預設失敗:', err)
  }
}

async function handleDelete(row) {
  try {
    await ElMessageBox.confirm(
      t('assetAccounts.deleteConfirm', { username: row.username }),
      t('common.deleteConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )
  } catch {
    return // 使用者取消
  }
  try {
    await deleteAssetAccount(props.assetId, row.id)
    ElMessage.success(t('assetAccounts.deleted'))
    emit('changed')
    await load()
  } catch (err) {
    console.error('[AssetAccountsDialog] 刪除帳號失敗:', err)
  }
}

// --- 影響面：以既有有效權限查詢 API 推導，不新增後端路由 ---
const impactLoaded = ref(false)
const impactUsers = ref(0)
const impactGroups = ref(0)
// 角色隱含可及本資產者（admin/auditor）不在 users 內逐人列舉，只給摘要句；
// 漏掉它會讓 N/M 計數低估影響面，正是本區塊要緩解的「隱性權限擴張」盲區
const impactNote = ref('')

const impactDescription = computed(() =>
  impactNote.value
    ? `${t('assetAccounts.impactHint')}\n${impactNote.value}`
    : t('assetAccounts.impactHint')
)

async function loadImpact() {
  impactLoaded.value = false
  impactNote.value = ''
  if (!props.assetId) return
  try {
    const resp = await getEffectiveUsers(props.assetId)
    const users = resp.users || []
    impactNote.value = effectiveAccessNote(resp)
    impactUsers.value = users.length
    const groups = new Set()
    for (const u of users) {
      for (const p of u.paths || []) {
        if (p.via_group_id) groups.add(p.via_group_id)
      }
    }
    impactGroups.value = groups.size
    impactLoaded.value = true
  } catch (err) {
    // 影響面是提示而非閘門：查不到（非 admin、後端錯誤）就不顯示，不擋新增
    console.warn('[AssetAccountsDialog] 影響面查詢失敗:', err)
  }
}

// --- 從其他資產帳號複製（建號快捷）---
const copyAssetId = ref(null)
const copyAssets = ref([])
const copySourceAccounts = ref([])
const copyAccountsLoading = ref(false)

const copyAssetOptions = computed(() =>
  copyAssets.value.filter((a) => String(a.id) !== String(props.assetId))
)

async function loadCopyAssets() {
  if (copyAssets.value.length) return
  try {
    const resp = await getAssetList({ page: 1, page_size: 100 })
    copyAssets.value = resp.data || []
  } catch (err) {
    console.warn('[AssetAccountsDialog] 載入可複製資產失敗:', err)
  }
}

// latest-request-wins（專案慣例）：快速切換來源資產時，先發後到的回應
// 不得覆寫成上一個資產的帳號清單（會讓人挑到別台機器的帳號）
let copySourceSeq = 0

async function onCopyAssetChange(id) {
  const seq = ++copySourceSeq
  form.copy_from_account_id = null
  copySourceAccounts.value = []
  if (!id) return
  copyAccountsLoading.value = true
  try {
    const resp = await listAssetAccounts(id)
    if (seq !== copySourceSeq) return
    copySourceAccounts.value = resp.data || []
  } catch (err) {
    console.warn('[AssetAccountsDialog] 載入來源帳號失敗:', err)
  } finally {
    if (seq === copySourceSeq) copyAccountsLoading.value = false
  }
}

// 選定來源即帶出 username（顯式輸入仍可覆蓋——後端以顯式值優先）
function onCopySourceChange(id) {
  const source = copySourceAccounts.value.find((a) => a.id === id)
  if (source && !form.username.trim()) form.username = source.username
}
</script>

<style scoped>
.acct-mgr__alert {
  margin-bottom: 12px;
}
/* 影響面描述含角色隱含摘要句，以換行分段呈現 */
.acct-mgr__alert :deep(.el-alert__description) {
  white-space: pre-line;
}
.acct-mgr__bar {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}
.acct-mgr__star {
  color: var(--ot-warning, #d9a93e);
  margin-right: 4px;
  vertical-align: -2px;
}
.acct-mgr__name {
  font-family: var(--ot-font-mono, monospace);
}
.acct-mgr__copy-select {
  width: 100%;
}
.acct-mgr__auth-select {
  width: 100%;
}
.acct-mgr__copy-select + .acct-mgr__copy-select {
  margin-top: 8px;
}
.acct-mgr__switch-hint {
  margin-left: 10px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
</style>

<style>
/* 對話框限高（UI 走查）：新增帳號表單內容約 880px，1366x900 下
   取消／確定會被推出視窗外。body 限高捲動即可讓 footer 恆可見；
   對話框 teleport 到 body，scoped 樣式打不到，須全域 */
.acct-mgr__dialog .el-dialog__body {
  max-height: 62vh;
  overflow-y: auto;
}
</style>
