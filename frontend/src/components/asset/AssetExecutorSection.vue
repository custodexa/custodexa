<!--
  AssetExecutorSection：資產編輯抽屜內的「堡壘機專用帳號」區塊。

  區塊取值來自自己的讀取請求，不讀也不寫抽屜表單；動作按下即生效，與抽屜的「儲存」無關，
  成功後只 emit changed。沒有權限或範圍外（404）時整區不渲染。權限在目前使用者能力
  載入完成後才判斷，權限變化時重判；openKey 變動（抽屜重新開啟）時重新讀取並清掉
  上一次的短標與提示。動作完成後焦點回到觸發的按鈕或區塊標題。

  插槽契約：
  - login-status：已設定時渲染在資訊列之下、憑證庫一行之上。傳入值為唯讀的
    { assetId, executor, revision, protocol, windowsFamily, hostKeyRecorded, actions }。
    actions 的回呼：openPublicKey(anchorEl)、openReplace()、openSetupHelp(anchorEl)、
    reload()、openCredential()。會彈出內容的回呼接受錨點，回饋出現在觸發的按鈕旁。
  - setup-help-read-rule：轉傳給說明面板展開區的末尾；沒填時不留空白。
-->
<template>
  <section
    v-if="status !== 'hidden'"
    class="executor-section"
    data-focus="executor"
    data-test="executor-section"
  >
    <div class="section-head">
      <h3
        ref="titleRef"
        class="section-title"
        tabindex="-1"
        data-test="executor-title"
      >
        <Shield
          :size="16"
          aria-hidden="true"
          class="title-icon"
        />
        {{ t('assetExecutor.title') }}
      </h3>
      <el-tag
        size="small"
        type="info"
        effect="plain"
        data-test="executor-not-for-users"
      >
        <span class="tag-inner">
          <Ban
            :size="11"
            aria-hidden="true"
          />
          {{ t('assetExecutor.notForUsers') }}
        </span>
      </el-tag>
      <el-tag
        v-if="justTag"
        size="small"
        type="success"
        data-test="executor-just-tag"
      >
        {{ justTag === 'convert' ? t('assetExecutor.justConverted') : t('assetExecutor.justSet') }}
      </el-tag>
      <span
        v-if="isConfigured"
        class="head-actions"
      >
        <el-button
          v-if="executor.has_public_key"
          ref="pkBtnRef"
          size="small"
          data-test="executor-get-public-key"
          @click="openPublicKey(null)"
        >
          <KeyRound
            :size="13"
            aria-hidden="true"
            class="btn-icon"
          />
          {{ t('assetExecutor.getPublicKey') }}
        </el-button>
        <el-button
          v-preview-write
          size="small"
          data-test="executor-replace"
          @click="openReplace"
        >
          {{ t('assetExecutor.replace') }}
        </el-button>
        <el-button
          ref="clearBtnRef"
          v-preview-write
          size="small"
          type="danger"
          plain
          data-test="executor-clear"
          @click="openClear"
        >
          {{ t('assetExecutor.clear') }}
        </el-button>
      </span>
    </div>

    <template v-if="status === 'unsupported'">
      <p
        class="muted"
        data-test="executor-unsupported-purpose"
      >
        {{ t('assetExecutor.unconfiguredHint') }}
      </p>
      <div
        class="info-box"
        data-test="executor-unsupported"
      >
        <Info
          :size="14"
          aria-hidden="true"
          class="info-icon"
        />
        <span>{{ t('assetExecutor.unsupportedProtocol', { protocol: protocolLabel }) }}</span>
      </div>
    </template>

    <div
      v-else-if="status === 'error'"
      class="muted"
      data-test="executor-load-failed"
    >
      <span>{{ t('assetExecutor.loadFailed') }}</span>
      <el-button
        size="small"
        link
        type="primary"
        data-test="executor-reload"
        @click="reload"
      >
        {{ t('assetExecutor.reload') }}
      </el-button>
    </div>

    <p
      v-else-if="status === 'loading'"
      class="muted"
    >
      {{ t('common.loading') }}
    </p>

    <template v-else-if="status === 'ready' && !isConfigured">
      <p
        class="muted"
        data-test="executor-unconfigured"
      >
        {{ t('assetExecutor.unconfiguredHint') }}
      </p>
      <div
        class="row-actions"
        data-test="executor-row-actions"
      >
        <el-button
          v-preview-write
          type="primary"
          size="small"
          data-test="executor-set"
          @click="openSet"
        >
          {{ t('assetExecutor.set') }}
        </el-button>
        <el-button
          size="small"
          link
          type="primary"
          :aria-expanded="helpOpen ? 'true' : 'false'"
          data-test="executor-help-link"
          @click="helpOpen = !helpOpen"
        >
          {{ t('assetExecutor.howToPrepare') }}
        </el-button>
      </div>
    </template>

    <template v-else-if="isConfigured">
      <ExecutorInfoList :executor="executor" />

      <p
        v-if="outOfScope"
        class="muted"
        data-test="executor-out-of-scope-note"
      >
        {{ t('assetExecutor.outOfScopeNote') }}
      </p>

      <slot
        v-if="status === 'ready'"
        name="login-status"
        v-bind="slotProps"
      />

      <p
        v-if="credentialId"
        class="muted cred-line"
        data-test="executor-credential-line"
      >
        <span>{{ t('assetExecutor.credentialLead') }}</span>
        <a
          :href="`/credentials?credential=${credentialId}`"
          target="_blank"
          rel="noopener"
          data-test="executor-credential-link"
        >{{ t('assetExecutor.credentialLink') }}<ExternalLink
          :size="12"
          aria-hidden="true"
          class="link-icon"
        /></a>
      </p>

      <p
        v-if="convertedHint"
        class="muted"
        data-test="executor-converted-hint"
      >
        {{ t('assetExecutor.convertedRotateHint', { account: convertedHint }) }}
      </p>
    </template>

    <template
      v-for="n in notices"
      :key="n.id"
    >
      <!-- 完成句：精簡一行，細綠框白字 -->
      <ExecutorNoticeBox
        v-if="n.type === 'success'"
        class="notice"
        tone="success"
        :data-test="`executor-notice-${n.kind}`"
      >
        <p>{{ n.text }}</p>
      </ExecutorNoticeBox>
      <!-- 被擋與狀態已變：粗體首句＋說明句；狀態已變用重新整理圖示 -->
      <ExecutorNoticeBox
        v-else
        tone="warning"
        :icon="n.kind === 'state' ? RefreshCw : null"
        :title="n.head"
        :data-test="`executor-notice-${n.kind}`"
      >
        <p v-if="n.body">
          {{ n.body }}
        </p>
        <!-- 範圍外的共用憑證不回識別，使用者在憑證庫也看不到這筆，不給前往鈕（同憑證庫連結一行） -->
        <el-button
          v-if="n.openRotation && credentialId"
          size="small"
          type="primary"
          class="notice-action"
          data-test="executor-notice-open-rotation"
          @click="openCredential"
        >
          {{ t('assetExecutor.error.openRotation') }}
          <ExternalLink
            :size="12"
            aria-hidden="true"
            class="ext-icon"
          />
        </el-button>
      </ExecutorNoticeBox>
    </template>

    <!-- 說明面板：未設定時由「這個帳號要怎麼準備」展開；已設定時只經「設定方式」等入口展開，且不重複第一層句 -->
    <div
      v-if="helpOpen && status !== 'unsupported' && status !== 'loading'"
      class="help-area"
      data-test="executor-help-area"
    >
      <ExecutorSetupHelp
        expanded
        :hide-first="isConfigured"
      >
        <template
          v-if="$slots['setup-help-read-rule']"
          #read-rule
        >
          <slot name="setup-help-read-rule" />
        </template>
      </ExecutorSetupHelp>
    </div>

    <el-popover
      :visible="helpPopoverVisible"
      :virtual-ref="helpAnchor || undefined"
      virtual-triggering
      placement="bottom-start"
      :width="460"
      :teleported="false"
    >
      <div
        class="help-popover"
        data-test="executor-help-popover"
      >
        <h4
          ref="helpTitleRef"
          tabindex="-1"
        >
          {{ t('assetExecutor.howToPrepare') }}
        </h4>
        <ExecutorSetupHelp
          expanded
          :hide-first="isConfigured"
        >
          <template
            v-if="$slots['setup-help-read-rule']"
            #read-rule
          >
            <slot name="setup-help-read-rule" />
          </template>
        </ExecutorSetupHelp>
        <el-button
          size="small"
          link
          data-test="executor-help-popover-close"
          @click="closeHelpPopover"
        >
          {{ t('common.close') }}
        </el-button>
      </div>
    </el-popover>

    <ExecutorPublicKeyPanel
      v-if="isConfigured"
      v-model:visible="pkVisible"
      :asset-id="assetId"
      :account="executor.username"
      :anchor="pkAnchor"
      @unavailable="reload"
    />

    <ExecutorClearConfirm
      v-if="isConfigured"
      v-model:visible="clearVisible"
      :anchor="clearBtnEl"
      :asset-id="assetId"
      :executor="executor"
      :expected-account-id="loadedAccountId"
      @cleared="onCleared"
      @rotation-blocked="onClearRotationBlocked"
      @state-changed="onStateChanged({ action: 'clear' })"
    />

    <ExecutorSetupDialog
      v-model="dialogVisible"
      :mode="dialogMode"
      :asset-id="assetId"
      :asset-name="assetName"
      :windows-family="windowsFamily"
      :expected-account-id="loadedAccountId"
      :current="executor"
      @done="onDone"
      @applied="onApplied"
      @state-changed="onStateChanged"
      @rotation-blocked="onRotationBlocked"
      @closed="onDialogClosed"
    />

    <p
      v-if="status !== 'unsupported'"
      class="muted immediate"
      data-test="executor-immediate-note"
    >
      <Info
        :size="12"
        aria-hidden="true"
        class="info-icon"
      />
      {{ t('assetExecutor.immediateNote') }}
    </p>
  </section>
</template>

<script setup>
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { Ban, ExternalLink, Info, KeyRound, RefreshCw, Shield } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { can, useCapabilities } from '@/composables/useCapabilities'
import { useEscapeToClose } from '@/composables/useEscapeToClose'
import { getAssetExecutor } from '@/api/assetExecutor'
import { isExecutorProtocol } from '@/constants/assetExecutor'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import ExecutorSetupHelp from '@/components/asset/ExecutorSetupHelp.vue'
import ExecutorInfoList from '@/components/asset/ExecutorInfoList.vue'
import ExecutorPublicKeyPanel from '@/components/asset/ExecutorPublicKeyPanel.vue'
import ExecutorClearConfirm from '@/components/asset/ExecutorClearConfirm.vue'
import ExecutorSetupDialog from '@/components/asset/ExecutorSetupDialog.vue'
import ExecutorNoticeBox from '@/components/asset/ExecutorNoticeBox.vue'
import { splitLead } from '@/utils/splitLead'

const props = defineProps({
  assetId: { type: [Number, String], required: true },
  assetName: { type: String, default: '' },
  protocol: { type: String, default: '' },
  windowsFamily: { type: Boolean, default: false },
  hostKeyRecorded: { type: Boolean, default: false },
  // 抽屜每次開啟遞增；同一資產關閉再開也會變，藉此重新讀取並清掉上一次的短標與提示
  openKey: { type: Number, default: 0 },
})
const emit = defineEmits(['changed'])

const { t, te } = useI18n()

// 權限在能力載入完成後才判斷：新分頁直接開深連結時，/auth/me 可能比區塊掛載晚回來
const { ready: capsReady } = useCapabilities()
const canManage = computed(() => capsReady.value && can('asset:executor-manage'))

// hidden＝整區不渲染；unsupported／loading／error／ready
const status = ref('hidden')
const executor = ref({ configured: false })
const revision = ref(0)
const justTag = ref('')
const convertedHint = ref('')
const notices = ref([])
const helpOpen = ref(false)
const titleRef = ref(null)
let noticeSeq = 0

const isConfigured = computed(() => status.value === 'ready' && executor.value?.configured === true)
const loadedAccountId = computed(() => (isConfigured.value ? executor.value.account_id || 0 : 0))
// 協定顯示名照官方大小寫（MySQL、PostgreSQL 等）；未列的值原樣顯示
const protocolLabel = computed(() => {
  const p = props.protocol || ''
  const key = `assetExecutor.protocolLabel.${p}`
  return p && te(key) ? t(key) : p
})
const credential = computed(() => executor.value?.credential || {})
const outOfScope = computed(() => credential.value.credential_out_of_scope === true)
const credentialId = computed(() => (outOfScope.value ? 0 : credential.value.credential_id || 0))
function pushNotice(kind, type, text, extra = {}) {
  notices.value = [
    ...notices.value.filter((n) => n.kind !== kind),
    { id: ++noticeSeq, kind, type, text, ...splitLead(text), ...extra },
  ]
}
function clearNotices() {
  notices.value = []
  justTag.value = ''
  convertedHint.value = ''
}

async function load() {
  if (!canManage.value) {
    status.value = 'hidden'
    return
  }
  if (!isExecutorProtocol(props.protocol)) {
    status.value = 'unsupported'
    return
  }
  status.value = 'loading'
  try {
    const res = await getAssetExecutor(props.assetId)
    executor.value = res || { configured: false }
    status.value = 'ready'
  } catch (err) {
    status.value = err?.response?.status === 404 ? 'hidden' : 'error'
  }
}

// 重新讀取：遞增 revision 供插槽內容重讀
async function reload() {
  await load()
  revision.value += 1
}

// 換資產、換協定或抽屜重新開啟：關掉區塊內的彈出內容、清掉上一次的短標與提示，再重新讀取
function resetForReopen() {
  clearNotices()
  helpOpen.value = false
  helpPopoverVisible.value = false
  pkVisible.value = false
  clearVisible.value = false
  dialogVisible.value = false
}

onMounted(load)
watch(canManage, load)
watch(() => [props.assetId, props.protocol, props.openKey], () => {
  resetForReopen()
  reload()
})

const slotProps = computed(() => ({
  assetId: props.assetId,
  executor: executor.value,
  revision: revision.value,
  protocol: props.protocol,
  windowsFamily: props.windowsFamily,
  hostKeyRecorded: props.hostKeyRecorded,
  actions: { openPublicKey, openReplace, openSetupHelp, reload, openCredential },
}))

// 焦點：觸發的按鈕已不在畫面上（例如清除後「清除」消失）時落在區塊標題，不掉到頁面最上層
async function focusTitle() {
  await nextTick()
  titleRef.value?.focus?.()
}
function focusLost() {
  const el = document.activeElement
  return !el || el === document.body || !el.isConnected
}

// 設定／更換對話框
const dialogVisible = ref(false)
const dialogMode = ref('set')
function openSet() {
  dialogMode.value = 'set'
  dialogVisible.value = true
}
function openReplace() {
  dialogMode.value = 'replace'
  dialogVisible.value = true
}

// 前一個動作的短標與提示在下一個動作開始時消失
function beginAction() {
  clearNotices()
}

async function onDone({ kind }) {
  dialogVisible.value = false
  clearNotices()
  await reload()
  justTag.value = kind === 'convert' ? 'convert' : 'set'
  if (kind === 'convert' && executor.value?.username) convertedHint.value = executor.value.username
  emit('changed')
  await focusTitle()
}

// 平台產生金鑰成功、結果頁仍開著：設定已生效，背後區塊即時換成已設定（不搬焦點，焦點留在結果頁）
async function onApplied() {
  clearNotices()
  await reload()
  justTag.value = 'set'
  emit('changed')
}

// 對話框關閉動畫結束後，若焦點沒有回到任何元素（觸發鈕已因狀態改變而消失），落在區塊標題
function onDialogClosed() {
  if (focusLost()) focusTitle()
}

async function onStateChanged({ action }) {
  dialogVisible.value = false
  clearVisible.value = false
  const prev = loadedAccountId.value
  clearNotices()
  await reload()
  const verb = t(action === 'clear' ? 'assetExecutor.stateChanged.actionClear' : 'assetExecutor.stateChanged.actionReplace')
  if (action === 'set' && isConfigured.value) {
    pushNotice('state', 'warning', t('assetExecutor.stateChanged.alreadySet', { account: executor.value.username }))
  } else if (isConfigured.value && executor.value.account_id !== prev) {
    pushNotice('state', 'warning', t('assetExecutor.stateChanged.replaced', { action: verb, account: executor.value.username }))
  } else if (!isConfigured.value) {
    pushNotice('state', 'warning', t('assetExecutor.stateChanged.cleared', { action: verb }))
  }
  emit('changed')
  await focusTitle()
}

function onRotationBlocked() {
  dialogVisible.value = false
  clearNotices()
  pushNotice('rotation', 'warning', t('assetExecutor.error.replaceRotationActive'), { openRotation: true })
  focusTitle()
}

// 清除
const clearVisible = ref(false)
const clearBtnRef = ref(null)
const clearBtnEl = computed(() => clearBtnRef.value?.$el || null)

function openClear() {
  beginAction()
  clearVisible.value = true
}

async function onCleared(account) {
  clearVisible.value = false
  await reload()
  pushNotice('cleared', 'success', t('assetExecutor.clearDone', { account }))
  emit('changed')
  await focusTitle()
}

function onClearRotationBlocked() {
  clearVisible.value = false
  pushNotice('rotation', 'warning', t('assetExecutor.error.clearRotationActive'), { openRotation: true })
  focusTitle()
}

// 公鑰彈出框：錨點為觸發的按鈕，未傳時用頂端「取得公鑰」
const pkVisible = ref(false)
const pkBtnRef = ref(null)
const pkAnchor = ref(null)
function openPublicKey(anchorEl) {
  if (!isConfigured.value || !executor.value.has_public_key) return
  beginAction()
  pkAnchor.value = anchorEl || pkBtnRef.value?.$el || null
  pkVisible.value = false
  nextTick(() => {
    pkVisible.value = true
  })
}

// 設定方式：傳了錨點時以錨定彈出框顯示，未傳時展開區塊底部的面板
const helpPopoverVisible = ref(false)
const helpAnchor = ref(null)
const helpTitleRef = ref(null)
let helpReturnFocus = null
async function openSetupHelp(anchorEl) {
  if (anchorEl) {
    helpAnchor.value = anchorEl
    helpReturnFocus = anchorEl
    helpPopoverVisible.value = true
    await nextTick()
    helpTitleRef.value?.focus?.()
    return
  }
  helpOpen.value = true
  await nextTick()
  document.querySelector('[data-test="executor-help-area"]')?.scrollIntoView?.({ block: 'center' })
}
function closeHelpPopover() {
  helpPopoverVisible.value = false
  helpReturnFocus?.focus?.()
  helpReturnFocus = null
}
useEscapeToClose(() => helpPopoverVisible.value, closeHelpPopover)

function openCredential() {
  if (!credentialId.value) return
  window.open(`/credentials?credential=${credentialId.value}`, '_blank', 'noopener')
}

defineExpose({ reload, status, executor, revision, notices, justTag, openPublicKey, openReplace, openSetupHelp })
</script>

<style scoped>
.executor-section {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  margin-bottom: var(--ot-space-md);
  padding: var(--ot-space-md);
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.section-head {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.section-title {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin: 0;
}

/* 滑鼠操作後程式聚焦標題不畫框；鍵盤與深連結進來（:focus-visible）用全站焦點框 */
.section-title:focus:not(:focus-visible) {
  outline: none;
}

.section-title:focus-visible {
  border-radius: var(--ot-radius-sm);
  outline: 2px solid var(--ot-primary);
  outline-offset: 2px;
}

.title-icon {
  color: var(--ot-info);
}

.tag-inner {
  display: inline-flex;
  align-items: center;
  gap: 3px;
}

.head-actions {
  display: inline-flex;
  margin-left: auto;
}

.btn-icon {
  margin-right: 4px;
}

.row-actions {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.row-actions .el-button + .el-button {
  margin-left: 0;
}

.info-box {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-xs);
  padding: var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  background: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-md);
}

.info-icon {
  flex: none;
  margin-top: 2px;
  color: var(--ot-primary);
}

.muted {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.immediate {
  display: flex;
  align-items: center;
  gap: 4px;
}

.immediate .info-icon {
  margin-top: 0;
  color: var(--ot-text-secondary);
}

.cred-line {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ot-space-xs);
}

.cred-line a {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  color: var(--ot-primary);
  text-decoration: none;
}

.notice {
  padding: 6px var(--ot-space-sm);
}

.notice-action {
  margin-top: var(--ot-space-xs);
}

.ext-icon {
  margin-left: 4px;
}
</style>
