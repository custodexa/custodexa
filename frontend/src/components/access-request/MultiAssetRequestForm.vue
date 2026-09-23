<template>
  <el-form
    class="multi-request"
    label-position="top"
    data-test="multi-request"
    @submit.prevent="submit"
  >
    <h2>{{ t('multiRequest.title') }}</h2>
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
      data-test="request-error"
    />
    <el-form-item :label="t('multiRequest.executor')">
      <el-select
        v-model="executorId"
        :disabled="busy"
        @change="changeExecutor"
      >
        <el-option
          :label="t('multiRequest.self')"
          :value="0"
        />
        <el-option
          v-for="agent in agents"
          :key="agent.id"
          :label="agent.username"
          :value="agent.id"
          :disabled="!agent.active"
        />
      </el-select>
      <!-- 徽章與說明句各自起一行：直接放在 el-form-item 的 flex 列裡時，
           三者起點不同，讀起來像三個沒關係的東西 -->
      <div class="executor-meta">
        <PrincipalBadge
          v-if="executor"
          :kind="executor.kind"
          :owner-id="executor.owner_user_id"
          :owner-name="executor.owner_username"
        />
        <p
          v-if="executor"
          data-test="executor-relationship"
        >
          {{ t('multiRequest.relationship') }}
        </p>
        <p
          v-if="agentError"
          role="status"
        >
          {{ agentError }}
        </p>
      </div>
    </el-form-item>
    <el-form-item
      :label="t('common.requestReason')"
      required
    >
      <el-input
        v-model="reason"
        type="textarea"
        maxlength="1000"
        :disabled="busy"
      />
      <p data-test="reason-hint">
        {{ t('multiRequest.reasonHint') }}
      </p>
    </el-form-item>
    <el-form-item
      :label="t('multiRequest.minutes')"
      required
    >
      <el-input-number
        v-model="duration"
        :min="1"
        :precision="0"
        :disabled="busy"
      />
    </el-form-item>
    <article
      v-for="(item, index) in items"
      :key="item.key"
      class="request-item"
      data-test="request-item"
    >
      <h3>{{ t('multiRequest.item', { n: index + 1 }) }}</h3>
      <p
        v-if="item.error"
        role="alert"
        data-test="item-error"
      >
        {{ item.error }}
      </p>
      <el-form-item
        :label="t('common.asset')"
        required
      >
        <el-select
          :ref="el => { assetSelects[item.key] = el }"
          v-model="item.assetId"
          filterable
          remote
          :remote-method="searchAssets"
          :loading="searching"
          :disabled="busy"
          @change="loadAccounts(item)"
        >
          <el-option
            v-for="asset in assets"
            :key="asset.id"
            :value="asset.id"
            :label="asset.host ? t('multiRequest.assetOption', { name: asset.name, host: asset.host }) : asset.name"
          />
        </el-select>
      </el-form-item>
      <el-form-item
        :label="t('multiRequest.accounts')"
        required
      >
        <el-select
          :ref="el => { accountSelects[item.key] = el }"
          v-model="item.accounts"
          multiple
          automatic-dropdown
          :disabled="busy || !item.assetId || item.loading || !!item.loadError"
          :loading="item.loading"
        >
          <el-option
            v-if="!executorId"
            :label="t('multiRequest.allAccounts')"
            value="@ALL"
            :disabled="item.accounts.some(a => a !== '@ALL')"
          />
          <el-option
            v-for="account in item.options"
            :key="account.username"
            :value="account.username"
            :label="account.username"
            :disabled="item.accounts.includes('@ALL')"
          />
        </el-select>
      </el-form-item>
      <p v-if="executorId">
        {{ t('multiRequest.agentAccounts') }}
      </p>
      <p
        v-if="item.loading"
        role="status"
      >
        {{ t('multiRequest.accountsLoading') }}
      </p>
      <div v-else-if="item.loadError">
        <p role="alert">
          {{ item.loadError }}
        </p><el-button
          :disabled="busy"
          @click="loadAccounts(item)"
        >
          {{ t('common.refresh') }}
        </el-button>
      </div>
      <p v-else-if="item.assetId && !item.options.length">
        {{ t('multiRequest.accountsEmpty') }}
      </p>
      <el-button
        type="danger"
        plain
        :disabled="busy || items.length === 1"
        data-test="remove-item"
        @click="removeItem(item)"
      >
        {{ t('multiRequest.remove') }}
      </el-button>
    </article>
    <!-- 加項按鈕緊貼最後一項：它是「同一張單再加一台機器」，屬於項目區的動作，
         放在送出列裡要先掃過整份可送條件才看得到 -->
    <div class="request-add">
      <el-button
        :disabled="busy || items.length >= 20"
        data-test="add-item"
        @click="addItem(true)"
      >
        {{ t('multiRequest.add') }}
      </el-button>
    </div>
    <p
      v-if="assetError"
      role="alert"
    >
      {{ assetError }}
    </p>
    <p
      v-if="missingAccounts"
      role="status"
      data-test="missing-accounts"
    >
      {{ t('multiRequest.missingAccounts', { n: missingAccounts }) }}
    </p>
    <!-- 「還能不能送」：原本只能看按鈕是不是灰的，灰掉的理由要自己猜。
         把未達成的條件逐條列出，就不必試按一次才知道缺什麼 -->
    <ul
      v-if="blockers.length"
      class="request-blockers"
      data-test="submit-blockers"
    >
      <li
        v-for="blocker in blockers"
        :key="blocker"
      >
        {{ t(`multiRequest.blockers.${blocker}`) }}
      </li>
    </ul>
    <!-- 伺服器拒絕之後就不再是「可以送出」：綠字換成阻擋原因，與送出鈕同一可見區 -->
    <p
      v-else-if="serverRejected"
      class="request-rejected"
      role="alert"
      data-test="submit-rejected"
    >
      {{ t('multiRequest.serverRejected') }}
    </p>
    <p
      v-else
      class="request-ready"
      data-test="submit-ready"
    >
      {{ t('multiRequest.readyToSubmit') }}
    </p>
    <div class="request-actions">
      <el-button
        :disabled="busy"
        @click="emit('cancel')"
      >
        {{ t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :disabled="!valid"
        :loading="busy"
        data-test="submit-request"
        @click="submit"
      >
        {{ t('multiRequest.submit') }}
      </el-button>
    </div>
  </el-form>
</template>
<script setup>
import { ref, computed, nextTick, onMounted, onBeforeUnmount } from 'vue'
import { t } from '@/i18n'
import { getAssetList } from '@/api/assets'
import { listAssetAccounts } from '@/api/assetAccounts'
import { getMyAgents } from '@/api/agents'
import { createAccessRequest } from '@/api/accessRequests'
import { resolveApiError } from '@/api/error'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'
const emit = defineEmits(['created', 'cancel'])
const items = ref([]), agents = ref([]), assets = ref([])
// 帳號欄的元件參考：資產一選定就把游標移過去並展開選單，
// 「限定帳號」不必再自己找欄位、再點開一次
const accountSelects = {}
// 資產欄的元件參考：「再加一項」之後游標直接落在新項的資產選單，
// 不必自己捲下去再點一次
const assetSelects = {}
// 「誰來操作」上次的選擇：同一個人通常一直用同一個執行者，每次重選是白工
const EXECUTOR_MEMORY_KEY = 'custodexa.multiRequest.executorId'
const executorId = ref(0), reason = ref(''), duration = ref(60)
const busy = ref(false), searching = ref(false), error = ref(''), assetError = ref(''), agentError = ref('')
// 伺服器已經拒絕過這份內容：在使用者改掉被拒的內容之前，不得再宣稱可以送出。
// 以內容簽章判定，不用 watch——送出失敗時會寫入逐項錯誤，watch 會被自己的寫入清掉
const rejectedSignature = ref('')
let key = 0, searchVersion = 0, disposed = false
const executor = computed(() => agents.value.find(a => a.id === executorId.value))
const message = e => resolveApiError(e?.response?.data, e?.response?.status)
const missingAccounts = computed(() => items.value.filter(item => !item.accounts.length || (executorId.value && item.accounts.includes('@ALL'))).length)
// 條件與 valid 同一份述詞：兩邊各寫一次必然會漂移，漂移的後果是
// 按鈕灰著卻說「可以送出」
const blockers = computed(() => {
  const list = []
  if (!reason.value.trim()) list.push('reason')
  if (!Number.isInteger(duration.value) || duration.value <= 0) list.push('duration')
  if (!items.value.length || items.value.some(i => !i.assetId)) list.push('asset')
  const chosen = items.value.map(i => i.assetId).filter(Boolean)
  if (new Set(chosen).size !== chosen.length) list.push('duplicate')
  if (items.value.some(i => i.loading)) list.push('loading')
  if (items.value.some(i => i.loadError)) list.push('loadError')
  if (items.value.some(i => i.assetId && !i.loading && !i.loadError && !i.options.length)) list.push('noAccounts')
  if (items.value.some(i => i.assetId && !i.accounts.length)) list.push('accounts')
  if (executorId.value && items.value.some(i => i.accounts.includes('@ALL'))) list.push('agentAllAccounts')
  return list
})
const formSignature = computed(() => JSON.stringify({ reason: reason.value.trim(), duration: duration.value, executor: executorId.value, items: items.value.map(item => [item.assetId, [...item.accounts].sort()]) }))
const serverRejected = computed(() => !!rejectedSignature.value && rejectedSignature.value === formSignature.value)
const valid = computed(() => !busy.value && !!reason.value.trim() && Number.isInteger(duration.value) && duration.value > 0 && items.value.length > 0 && new Set(items.value.map(i => i.assetId).filter(Boolean)).size === items.value.length && items.value.every(i => i.assetId && !i.loading && !i.loadError && i.options.length && i.accounts.length && (!executorId.value || !i.accounts.includes('@ALL'))))
function addItem(focusNew = false) {
  if (items.value.length >= 20) return
  const added = { key: ++key, assetId: null, accounts: [], options: [], loading: false, loadError: '', error: '', version: 0 }
  items.value.push(added)
  if (focusNew) nextTick(() => { assetSelects[added.key]?.focus?.() })
}
function removeItem(item) { if (items.value.length > 1) { delete accountSelects[item.key]; delete assetSelects[item.key]; items.value = items.value.filter(i => i !== item) } }
function changeExecutor() { items.value.forEach(i => { i.accounts = i.accounts.filter(a => a !== '@ALL') }) }
async function searchAssets(search = '') {
  const version = ++searchVersion
  searching.value = true; assetError.value = ''
  try { const result = await getAssetList({ search: search || undefined, page: 1, page_size: 50, active: true }); if (!disposed && version === searchVersion) {
      const found = result.data || []
      const selectedIds = new Set(items.value.map(i => i.assetId))
      assets.value = [...assets.value.filter(a => selectedIds.has(a.id) && !found.some(v => v.id === a.id)), ...found]
    } }
  catch (e) { if (!disposed && version === searchVersion) assetError.value = message(e) }
  finally { if (!disposed && version === searchVersion) searching.value = false }
}
async function loadAccounts(item) {
  const version = ++item.version
  item.accounts = []; item.options = []; item.loadError = ''; item.loading = true
  try {
    const result = await listAssetAccounts(item.assetId, { skipErrorToast: true })
    if (!disposed && version === item.version) {
      item.options = result.data || []
      // 選完資產就把帳號範圍帶好：只有一個帳號時沒有別的可選，自己操作時預設
      // 全部帳號（可再改窄）。剩下真的要挑的情況才把游標送到帳號欄
      if (item.options.length === 1) item.accounts = [item.options[0].username]
      else if (item.options.length > 1 && !executorId.value) item.accounts = ['@ALL']
      if (item.options.length && !item.accounts.length) nextTick(() => { accountSelects[item.key]?.focus?.() })
    }
  }
  catch (e) { if (!disposed && version === item.version) item.loadError = t('multiRequest.accountsFailed') + ' ' + message(e) }
  finally { if (!disposed && version === item.version) item.loading = false }
}
async function submit() {
  if (!valid.value) return
  busy.value = true; error.value = ''; rejectedSignature.value = ''; items.value.forEach(item => { item.error = '' })
  const payload = { items: items.value.map(i => ({ asset_id: i.assetId, accounts: [...i.accounts] })), reason: reason.value.trim(), duration_minutes: duration.value }
  if (executorId.value) payload.executor_user_id = executorId.value
  try {
    const result = await createAccessRequest(payload, { skipErrorToast: true })
    rememberExecutor(executorId.value)
    if (!disposed) emit('created', result)
  }
  catch (e) { if (!disposed) {
    error.value = message(e)
    rejectedSignature.value = formSignature.value
    const data = e?.response?.data, index = data?.details?.item_index
    if (data?.code === 'VALIDATION_ACCOUNT_NOT_ON_ASSET' && Number.isInteger(index) && items.value[index]?.assetId === data.details.asset_id) items.value[index].error = message(e)
  } }
  finally { if (!disposed) busy.value = false }
}
function rememberExecutor(id) {
  // localStorage 在無痕或封鎖第三方儲存時會丟例外：記不住只是少一個便利，不該擋住送出
  try { window.localStorage?.setItem(EXECUTOR_MEMORY_KEY, String(id)) } catch { /* 記不住就算了 */ }
}
function recallExecutor() {
  // 沒存過要回 null 而不是 0：Number(null) 是 0，會被誤讀成「上次選了我自己」
  try { const raw = window.localStorage?.getItem(EXECUTOR_MEMORY_KEY); return raw == null ? null : Number(raw) } catch { return null }
}
// 預設「誰來操作」：先看上次選了誰（那個 agent 仍可用才算數），
// 否則名下只有一個可用 agent 時就直接帶入——只有一個選項還要人點一次是白工
function defaultExecutor() {
  const usable = agents.value.filter(agent => agent.active)
  const remembered = recallExecutor()
  if (remembered === 0) return 0
  if (Number.isInteger(remembered) && remembered > 0 && usable.some(agent => agent.id === remembered)) return remembered
  return usable.length === 1 ? usable[0].id : 0
}
addItem()
onMounted(async () => {
  searchAssets()
  // 自助建立關閉時仍可代名下既有 agent 開單：清單照列，只是沒有建立入口
  try {
    const result = await getMyAgents()
    if (!disposed) {
      agents.value = result.data || []
      executorId.value = defaultExecutor()
      changeExecutor()
    }
  }
  catch (e) { if (!disposed && e?.response?.data?.code !== 'RULE_AGENT_SELF_CREATE_DISABLED') agentError.value = message(e) }
})
onBeforeUnmount(() => { disposed = true; searchVersion++ })
</script>
<style scoped>
.multi-request { padding: var(--ot-space-lg); border: 1px solid var(--ot-border); border-radius: var(--ot-radius-lg); background: var(--ot-bg-surface); }
h2 { font-size: var(--ot-font-size-lg); font-weight: 600; }
h3 { font-size: var(--ot-font-size-lg); font-weight: 600; }
.request-item { margin: var(--ot-space-md) 0; padding: var(--ot-space-md); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-md); }
p { font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
/* 錯誤訊息不能跟說明句同一階灰字：讀者要先看到它 */
p[role="alert"] { color: var(--ot-danger); font-size: var(--ot-font-size-md); }
.executor-meta { display: flex; flex-direction: column; align-items: flex-start; gap: var(--ot-space-xs); width: 100%; }
.executor-meta p { margin: 0; }
/* 加項按鈕自成一個區塊：直接放在行內時，行框的殘餘高度會讓它與下一段的
   間距落在 48px，不在間距階上 */
.request-add { display: flex; margin: var(--ot-space-md) 0; }
.request-actions { position: sticky; bottom: 0; display: flex; flex-wrap: wrap; gap: var(--ot-space-sm); padding: var(--ot-space-sm) 0; background: var(--ot-bg-surface); }
/* 「還缺什麼」與「還有幾項沒選帳號」是要照著做的指示，不是背景說明：
   留在灰字階會和欄位說明混成一片，首屏讀起來整頁都是次要文字 */
.request-blockers { margin: var(--ot-space-sm) 0; padding-left: var(--ot-space-lg); font-size: var(--ot-font-size-md); color: var(--ot-text-primary); }
[data-test="missing-accounts"] { font-size: var(--ot-font-size-md); color: var(--ot-text-primary); }
[data-test="executor-relationship"] { color: var(--ot-text-primary); }
.request-ready { margin: var(--ot-space-sm) 0; font-size: var(--ot-font-size-sm); color: var(--ot-success); }
.request-rejected { margin: var(--ot-space-sm) 0; font-size: var(--ot-font-size-md); color: var(--ot-danger); }
</style>
