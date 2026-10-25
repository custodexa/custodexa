<!--
  AssetAccountRows：編輯資產抽屜內的帳號表。

  一個資產可以有多個登入身分，每個身分指向一筆憑證：共用（多台共用同一組秘密）
  或專用（只有這台在用）。表內直接完成新增、改預設、更正登記值、更換憑證、脫離共用與移除，
  不再另開對話框——原先要疊三層才做得到的事，在這裡是一列。

  「移除」與「脫離共用」是兩件事，畫面上必須分得出來：
  前者只解除這台的掛載，主機上的密碼不動；後者會登入這台改密，驗證通過才脫離。
-->
<template>
  <div class="account-rows">
    <div class="section-head">
      <h3 class="section-title">
        {{ t('assets.editDrawer.accountsTitle', { count: accounts.length }) }}
      </h3>
      <div class="section-actions">
        <span class="hint">{{ t('assets.editDrawer.accountsHint') }}</span>
        <el-button
          type="primary"
          size="small"
          :disabled="addDisabled"
          data-test="account-add"
          @click="openAdd"
        >
          <el-icon><Plus /></el-icon>
          {{ t('assets.editDrawer.addAccount') }}
        </el-button>
      </div>
    </div>

    <el-alert
      v-if="protocol === 'k8s'"
      :title="t('assetAccounts.k8sSingleAccount')"
      type="info"
      :closable="false"
      show-icon
      class="row-alert"
    />
    <el-alert
      v-if="loadError"
      type="error"
      :closable="false"
      show-icon
      :title="t('assetAccounts.loadFailed')"
      :description="loadError"
      class="row-alert"
    />

    <el-table
      v-loading="loading"
      :data="accounts"
      size="small"
      data-test="account-table"
    >
      <el-table-column
        :label="t('assetAccounts.colUsername')"
        min-width="110"
      >
        <template #default="{ row }">
          <el-icon
            v-if="row.is_default"
            class="default-star"
            :title="t('assetAccounts.defaultTip')"
          >
            <Star fill="currentColor" />
          </el-icon>
          <span class="mono">{{ row.username }}</span>
        </template>
      </el-table-column>
      <el-table-column
        :label="t('assetAccounts.colCredential')"
        min-width="124"
      >
        <template #default="{ row }">
          <!-- 引用的共用憑證不在檢視者的範圍內：伺服器已移除名稱與台數，這裡只標示事實 -->
          <el-tag
            v-if="row.credential_out_of_scope"
            size="small"
            type="info"
            effect="plain"
            :data-test="`account-out-of-scope-${row.id}`"
          >
            {{ t('assets.editDrawer.outOfScopeCredential') }}
          </el-tag>
          <span
            v-else
            class="cred-name"
            :data-test="`account-credential-${row.id}`"
          >{{ credentialName(row) }}</span>
          <el-tag
            v-if="row.shared_credential && !row.credential_out_of_scope"
            size="small"
            type="primary"
            effect="plain"
            :data-test="`account-shared-${row.id}`"
          >
            {{ t('assets.editDrawer.sharedTag', { count: row.binding_count || 1 }) }}
          </el-tag>
          <el-tag
            v-else-if="!row.credential_out_of_scope"
            size="small"
            type="info"
            effect="plain"
            :data-test="`account-dedicated-${row.id}`"
          >
            {{ t('enum.credentialScope.dedicated') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column
        :label="t('credentials.colSecretType')"
        width="70"
      >
        <template #default="{ row }">
          {{ accountCredentialLabel(row) }}
        </template>
      </el-table-column>
      <el-table-column
        :label="t('assetAccounts.colPrivileged')"
        width="60"
      >
        <template #default="{ row }">
          <el-tag
            v-if="row.privileged"
            size="small"
            type="warning"
            effect="plain"
          >
            {{ t('assetAccounts.privileged') }}
          </el-tag>
          <span v-else>—</span>
        </template>
      </el-table-column>
      <el-table-column
        :label="t('assets.editDrawer.colVersion')"
        width="92"
      >
        <template #default="{ row }">
          <span
            class="version"
            :data-test="`account-version-${row.id}`"
          >{{ versionText(row) }}</span>
        </template>
      </el-table-column>
      <!-- 操作欄給固定寬度而不是 min-width：參與彈性分配時，憑證名短到不換行的那一列
           會被其他欄吃掉寬度，第三、四個動作就落到抽屜可視範圍外（要橫捲才看得到） -->
      <el-table-column
        :label="t('common.actions')"
        width="264"
        class-name="actions-col"
      >
        <template #default="{ row }">
          <div class="row-actions">
            <span
              v-if="row.is_default"
              class="muted"
              :data-test="`account-is-default-${row.id}`"
            >{{ t('credentials.bindingDefault') }}</span>
            <el-button
              v-else
              link
              size="small"
              :data-test="`account-set-default-${row.id}`"
              @click="handleSetDefault(row)"
            >
              {{ t('assetAccounts.setDefault') }}
            </el-button>
            <el-button
              v-if="!row.shared_credential"
              link
              size="small"
              type="primary"
              :data-test="`account-edit-secret-${row.id}`"
              @click="openEditSecret(row)"
            >
              {{ t('assets.editDrawer.editSecret') }}
            </el-button>
            <!-- 共用憑證的登記值打錯時的更正：只改平台登記值、不碰主機，整組一併套用 -->
            <el-button
              v-else
              link
              size="small"
              type="primary"
              :disabled="rotationActive(row) || !!rowDenied(row, 'secret_fix')"
              :data-test="`account-secret-fix-${row.id}`"
              @click="openSecretFix(row)"
            >
              {{ secretFixLabel(row) }}
            </el-button>
            <!-- 專用列也能換憑證：把這台改掛到一筆共用憑證上是「這組秘密要跟別台一起管」
                 的唯一入口，只對共用列開放等於逼人先刪掉帳號再重加 -->
            <el-button
              link
              size="small"
              type="primary"
              :disabled="rotationActive(row) || !!rowDenied(row, 'rebind')"
              :data-test="`account-rebind-${row.id}`"
              @click="openRebind(row)"
            >
              {{ t('assets.editDrawer.rebind') }}
            </el-button>
            <el-button
              v-if="row.shared_credential"
              link
              size="small"
              type="warning"
              :disabled="rotationActive(row) || !!rowDenied(row, 'detach')"
              :data-test="`account-detach-${row.id}`"
              @click="openDetach(row)"
            >
              {{ t('assets.editDrawer.detach') }}
            </el-button>
            <el-button
              link
              size="small"
              type="danger"
              :disabled="!!rowDenied(row, 'remove')"
              :data-test="`account-remove-${row.id}`"
              @click="handleRemove(row)"
            >
              {{ t('assets.editDrawer.remove') }}
            </el-button>
          </div>
          <!-- 動作旗標由伺服器標示；不可操作的原因就地寫出，不靜默禁用 -->
          <div
            v-for="code in rowDeniedCodes(row)"
            :key="code"
            class="row-note"
            :data-test="`account-denied-${code}-${row.id}`"
          >
            {{ t(`credentials.actionReason.${code}`) }}
          </div>
          <div
            v-if="row.credential_out_of_scope"
            class="row-note"
            :data-test="`account-out-of-scope-note-${row.id}`"
          >
            {{ t('assets.editDrawer.outOfScopeNote') }}
          </div>
          <!-- 輪替進行中：同一個理由只寫一次，並說明它擋住哪些動作 -->
          <div
            v-if="rotationActive(row)"
            class="row-note"
            :data-test="`account-rotation-note-${row.id}`"
          >
            {{ t('assets.editDrawer.rotationActiveHint') }}
          </div>
          <!-- 展開列：更換憑證／編輯憑證就地完成，不另開對話框 -->
          <div
            v-if="rebindingId === row.id"
            class="inline-panel"
            :data-test="`account-rebind-panel-${row.id}`"
          >
            <CredentialPicker
              v-model="rebindCredentialId"
              :protocol="protocol"
              :windows-openssh="windowsOpenssh"
              :exclude-ids="mountedCredentialIds"
            />
            <!-- 後果依列型不同：專用憑證失去最後一個掛載會被回收，共用憑證只是少一台 -->
            <div
              class="hint"
              :data-test="`account-rebind-hint-${row.id}`"
            >
              {{ row.shared_credential
                ? t('assets.editDrawer.rebindHintShared')
                : t('assets.editDrawer.rebindHintDedicated') }}
            </div>
            <div class="inline-actions">
              <el-button
                type="primary"
                size="small"
                :loading="submitting"
                :disabled="!rebindCredentialId"
                data-test="account-rebind-submit"
                @click="submitRebind(row)"
              >
                {{ t('assets.editDrawer.rebindSubmit') }}
              </el-button>
              <el-button
                size="small"
                @click="rebindingId = null"
              >
                {{ t('common.cancel') }}
              </el-button>
            </div>
          </div>
          <div
            v-if="editingSecretId === row.id"
            class="inline-panel"
            :data-test="`account-edit-secret-panel-${row.id}`"
          >
            <el-input
              v-model="secretForm.password"
              type="password"
              show-password
              autocomplete="new-password"
              :placeholder="t('assetAccounts.keepCredentialPlaceholder')"
              data-test="account-secret-password"
            />
            <el-input
              v-if="protocol === 'ssh'"
              v-model="secretForm.private_key"
              type="textarea"
              :rows="2"
              :placeholder="t('assetAccounts.keepCredentialPlaceholder')"
              data-test="account-secret-private-key"
            />
            <div class="inline-actions">
              <el-switch v-model="secretForm.privileged" />
              <span class="hint">{{ t('assetAccounts.colPrivileged') }}</span>
              <el-button
                type="primary"
                size="small"
                :loading="submitting"
                data-test="account-secret-submit"
                @click="submitSecret(row)"
              >
                {{ t('common.confirm') }}
              </el-button>
              <el-button
                size="small"
                @click="closeSecret"
              >
                {{ t('common.cancel') }}
              </el-button>
            </div>
          </div>
        </template>
      </el-table-column>
      <template #empty>
        <EmptyState
          v-if="!loadError"
          :title="t('assetAccounts.emptyTitle')"
          :hint="t('assetAccounts.emptyHint')"
        />
        <span v-else />
      </template>
    </el-table>

    <!-- 新增帳號展開為表內一列（原「從其他資產帳號複製」由共用憑證取代） -->
    <AssetAccountAddRow
      v-if="adding"
      :asset-id="assetId"
      :asset-name="assetName"
      :protocol="protocol"
      :windows-openssh="windowsOpenssh"
      :exclude-ids="mountedCredentialIds"
      @added="onAdded"
      @cancel="adding = false"
    />

    <!-- 兩個動作的語義差別常駐在畫面上，不藏在確認框裡才看得到 -->
    <div
      class="semantics-hint"
      data-test="account-semantics-hint"
    >
      <div>{{ t('assets.editDrawer.removeHint') }}</div>
      <div>{{ t('assets.editDrawer.detachHint') }}</div>
      <div
        v-if="secretFixHint"
        data-test="account-semantics-secret-fix"
      >
        {{ secretFixHint }}
      </div>
    </div>

    <CredentialSecretFixDialog
      v-model="secretFixVisible"
      :credential-id="secretFixTarget ? secretFixTarget.credential_id : 0"
      :current-asset-id="assetId"
      @saved="onSecretFixed"
    />

    <CredentialDetachDialog
      v-model="detachVisible"
      :credential-id="detachTarget ? detachTarget.credential_id : 0"
      :credential-name="detachTarget ? credentialName(detachTarget) : ''"
      :binding-count="detachTarget ? detachTarget.binding_count || 1 : 0"
      :account-id="detachTarget ? detachTarget.id : 0"
      :asset-name="assetName"
      :username="detachTarget ? detachTarget.username : ''"
      :secret-type="detachTarget && detachTarget.has_private_key ? 'ssh_key' : 'password'"
      @detached="onDetached"
    />
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Plus, Star } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import {
  listAssetAccounts,
  updateAssetAccount,
  deleteAssetAccount,
  setDefaultAssetAccount,
} from '@/api/assetAccounts'
import { listCredentials, rebindAccountCredential } from '@/api/credentials'
import { accountCredentialLabel } from '@/constants/assetAccounts'
import { confirmDestructive } from '@/utils/confirm'
import { resolveApiError } from '@/api/error'
import EmptyState from '@/components/EmptyState.vue'
import AssetAccountAddRow from '@/components/asset/AssetAccountAddRow.vue'
import CredentialPicker from '@/components/credential/CredentialPicker.vue'
import CredentialDetachDialog from '@/components/credential/CredentialDetachDialog.vue'
import CredentialSecretFixDialog from '@/components/credential/CredentialSecretFixDialog.vue'
import { credentialSecretKind } from '@/constants/credentials'
import { deniedReason } from '@/utils/credentialActions'

const props = defineProps({
  assetId: { type: [Number, String], default: null },
  assetName: { type: String, default: '' },
  protocol: { type: String, default: '' },
  windowsOpenssh: { type: Boolean, default: false },
})

const emit = defineEmits(['changed'])

const { t } = useI18n()

const accounts = ref([])
const loading = ref(false)
const loadError = ref('')
const submitting = ref(false)
// 進行中輪替的憑證識別：來源是憑證清單的 rotation_active，不在此推導
const rotatingIds = ref(new Set())
// 憑證識別 → 現行版本序號，供逐列判斷就位版本是否落後
const currentVersions = ref(new Map())
// 憑證識別 → 共用憑證清單項（秘密型別與協定族），供「更正密碼／更正私鑰」選字
const sharedCredentials = ref(new Map())

const addDisabled = computed(
  () => adding.value || (props.protocol === 'k8s' && accounts.value.length > 0)
)

const mountedCredentialIds = computed(() =>
  accounts.value.map((row) => row.credential_id).filter(Boolean)
)

// 帳號列動作旗標（rebind、remove、secret_fix、detach），與寫入端點同一判定。
// 範圍外憑證的列沒有旗標時，更正與脫離一律不可執行（憑證管理需歸屬在範圍內）
const OUT_OF_SCOPE_BLOCKED = ['secret_fix', 'detach']
function rowDenied(row, key) {
  const code = deniedReason(row, key)
  if (code) return code
  if (row?.credential_out_of_scope && OUT_OF_SCOPE_BLOCKED.includes(key)
    && row.actions?.[key]?.allowed !== true) {
    return 'out_of_scope'
  }
  return ''
}
const rowDeniedCodes = (row) => {
  const codes = new Set()
  for (const key of ['rebind', 'remove', 'secret_fix', 'detach']) {
    const code = rowDenied(row, key)
    // 範圍外憑證列的 out_of_scope 已由專屬說明句涵蓋
    if (code && !(row?.credential_out_of_scope && code === 'out_of_scope')) codes.add(code)
  }
  return [...codes]
}

const credentialName = (row) => row.credential_name || row.username || ''

const rotationActive = (row) => rotatingIds.value.has(String(row.credential_id))

// 就位版本：共用憑證比對憑證的現行版本，落後即「待更新」；
// 專用憑證恆為單一掛載，其就位版本即現行版本
const versionText = (row) => {
  const versionNo = row.effective_version_no || 0
  if (!versionNo) return t('credentials.bindingNoVersion')
  const current = currentVersions.value.get(String(row.credential_id))
  const stale = row.shared_credential && current && current > versionNo
  const label = stale ? t('credentials.bindingStale') : t('credentials.bindingUpToDate')
  return `${label} · ${t('credentials.versionNo', { no: versionNo })}`
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

// 共用憑證的輪替狀態與現行版本只在憑證那一側說得準；查不到就不顯示，不擋任何動作
async function loadCredentialStates() {
  try {
    const resp = await listCredentials({ scope: 'shared' })
    const rotating = new Set()
    const versions = new Map()
    const shared = new Map()
    for (const item of resp?.data || []) {
      if (item.rotation_active) rotating.add(String(item.id))
      versions.set(String(item.id), item.current_version_no || 0)
      shared.set(String(item.id), item)
    }
    rotatingIds.value = rotating
    currentVersions.value = versions
    sharedCredentials.value = shared
  } catch (err) {
    console.warn('[AssetAccountRows] 載入憑證狀態失敗:', err)
  }
}

async function reload() {
  await load()
  await loadCredentialStates()
}

watch(() => props.assetId, reload)
onMounted(reload)

async function handleSetDefault(row) {
  try {
    await setDefaultAssetAccount(props.assetId, row.id)
    ElMessage.success(t('assetAccounts.defaultChanged'))
    emit('changed')
    await load()
  } catch (err) {
    console.error('[AssetAccountRows] 設為預設失敗:', err)
  }
}

// 移除只解除掛載：確認框把「主機上的密碼不動」寫出來，
// 與會改遠端的「脫離共用」明確分開
async function handleRemove(row) {
  try {
    await confirmDestructive(
      t('assets.editDrawer.removeMessage', { asset: props.assetName, username: row.username }),
      t('assets.editDrawer.removeTitle'),
      { confirmButtonText: t('assets.editDrawer.removeConfirm') }
    )
  } catch {
    return
  }
  try {
    await deleteAssetAccount(props.assetId, row.id)
    ElMessage.success(t('assets.editDrawer.removeDone'))
    emit('changed')
    await reload()
  } catch (err) {
    console.error('[AssetAccountRows] 移除帳號失敗:', err)
  }
}

// --- 脫離共用（改遠端；與憑證庫掛載列打同一支端點）---
const detachVisible = ref(false)
const detachTarget = ref(null)

function openDetach(row) {
  detachTarget.value = row
  detachVisible.value = true
}

async function onDetached() {
  emit('changed')
  await reload()
}

// --- 更換憑證（只能換成共用憑證，且沒有復原）---
const rebindingId = ref(null)
const rebindCredentialId = ref(null)

function openRebind(row) {
  closeSecret()
  rebindingId.value = row.id
  rebindCredentialId.value = null
}

async function submitRebind(row) {
  if (!rebindCredentialId.value) return
  submitting.value = true
  try {
    await rebindAccountCredential(props.assetId, row.id, rebindCredentialId.value)
    ElMessage.success(t('assets.editDrawer.rebindDone'))
    rebindingId.value = null
    emit('changed')
    await reload()
  } catch (err) {
    console.error('[AssetAccountRows] 更換憑證失敗:', err?.response?.status, err?.response?.data?.code)
  } finally {
    submitting.value = false
  }
}

// --- 編輯專用憑證的秘密（共用憑證的秘密由憑證庫整組寫入，此處不提供）---
const editingSecretId = ref(null)
const secretForm = reactive({ password: '', private_key: '', privileged: false })

function openEditSecret(row) {
  rebindingId.value = null
  editingSecretId.value = row.id
  secretForm.password = ''
  secretForm.private_key = ''
  secretForm.privileged = !!row.privileged
}

// 關閉即清掉明文：只隱藏面板會讓輸入值續留在元件狀態內
function closeSecret() {
  editingSecretId.value = null
  secretForm.password = ''
  secretForm.private_key = ''
}

async function submitSecret(row) {
  submitting.value = true
  try {
    const payload = { privileged: secretForm.privileged }
    if (secretForm.password) payload.password = secretForm.password
    if (secretForm.private_key) payload.private_key = secretForm.private_key
    await updateAssetAccount(props.assetId, row.id, payload)
    ElMessage.success(t('assetAccounts.updated'))
    closeSecret()
    emit('changed')
    // 更新回應的部分欄位不完整，一律重新取回再渲染
    await reload()
  } catch (err) {
    console.error('[AssetAccountRows] 更新帳號失敗:', err?.response?.status, err?.response?.data?.code)
  } finally {
    submitting.value = false
  }
}

// --- 更正共用憑證的登記值（不碰主機；與憑證庫詳情共用同一個對話框）---
const secretFixVisible = ref(false)
const secretFixTarget = ref(null)

// 憑證清單還沒回來時退回帳號列自己的旗標判斷型別
const rowSecretKind = (row) => {
  const cred = sharedCredentials.value.get(String(row.credential_id))
  if (cred) return credentialSecretKind(cred)
  return row.has_private_key ? 'ssh_key' : credentialSecretKind({ protocol_family: props.protocol })
}

const secretFixLabel = (row) =>
  t('credentials.secretFix.entry', { noun: t(`credentials.secretFix.noun.${rowSecretKind(row)}`) })

// 常駐說明只在有共用列時出現；表上同時有密碼型與金鑰型時兩個動作名都寫出來
const secretFixHint = computed(() => {
  const kinds = [...new Set(
    accounts.value.filter((row) => row.shared_credential).map(rowSecretKind)
  )]
  if (!kinds.length) return ''
  const actions = kinds
    .map((kind) => t('credentials.secretFix.actionQuoted', {
      entry: t('credentials.secretFix.entry', { noun: t(`credentials.secretFix.noun.${kind}`) }),
    }))
    .join(t('credentials.secretFix.actionSeparator'))
  const noun = kinds.length === 1
    ? t(`credentials.secretFix.noun.${kinds[0]}`)
    : t('credentials.secretFix.noun.mixed')
  return t('credentials.secretFix.drawerHint', { actions, noun })
})

function openSecretFix(row) {
  secretFixTarget.value = row
  secretFixVisible.value = true
}

async function onSecretFixed({ noun }) {
  ElMessage.success(t('credentials.secretFix.savedToast', { noun }))
  emit('changed')
  await reload()
}

// --- 新增帳號（表內一列）---
const adding = ref(false)

function openAdd() {
  adding.value = true
}

function closeAdd() {
  adding.value = false
}

async function onAdded() {
  adding.value = false
  emit('changed')
  await reload()
}

defineExpose({
  accounts,
  reload,
  openAdd,
  closeAdd,
  adding,
  openRebind,
  submitRebind,
  openDetach,
  openEditSecret,
  submitSecret,
  openSecretFix,
  secretFixVisible,
  secretFixTarget,
  handleRemove,
  handleSetDefault,
  rebindCredentialId,
  rotatingIds,
  versionText,
})
</script>

<style scoped>
.account-rows {
  width: 100%;
}

.section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-bottom: var(--ot-space-xs);
  border-bottom: 1px solid var(--el-border-color);
  margin-bottom: var(--ot-space-sm);
}

.section-title {
  margin: 0;
  font-size: var(--ot-font-size-md);
  font-weight: 600;
}

.section-actions {
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
}

.hint {
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
  line-height: 1.6;
}

.row-alert {
  margin-bottom: var(--ot-space-sm);
}

.default-star {
  color: var(--ot-warning, #d9a93e);
  margin-right: 4px;
  vertical-align: -2px;
}

.mono {
  font-family: var(--ot-font-mono, monospace);
}

.cred-name {
  margin-right: var(--ot-space-xs);
}

.version {
  color: var(--el-text-color-secondary);
}

/* 五個動作要在抽屜寬度內排成一列：按鈕間距只由 gap 決定，
   不再疊加 el-button 相鄰時的左邊距（疊加後最後一個動作會被推出表格可視範圍） */
.row-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.row-actions .el-button + .el-button {
  margin-left: 0;
}

/* 動作放不下就換行，不省略成「更換憑…」：被切掉的那兩個動作等於不存在 */
.account-rows :deep(.actions-col .cell) {
  white-space: normal;
  text-overflow: clip;
}

.muted {
  color: var(--el-text-color-placeholder);
  font-size: var(--ot-font-size-xs);
}

.row-note {
  margin-top: 4px;
  font-size: var(--ot-font-size-xs);
  color: var(--el-color-warning);
  line-height: 1.6;
}

.inline-panel {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  margin-top: var(--ot-space-xs);
  padding: var(--ot-space-sm);
  border: 1px solid var(--el-border-color);
  border-radius: var(--ot-radius-md, 6px);
  background: var(--el-fill-color-light);
}

.inline-actions {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}


.semantics-hint {
  margin-top: var(--ot-space-sm);
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
  line-height: 1.7;
}
</style>
