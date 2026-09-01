<template>
  <div class="external-identities">
    <!-- 本地身分與 IdP 自報值**分區呈現**（OA-5／design 行 68）：claim 快照完全由
         身分提供者端控制，低權使用者可把自己的 preferred_username 設成 admin。
         若與本地帳號混排，管理者會依假值判斷「這是誰」 -->
    <div class="local-identity">
      <div class="local-identity__main">
        <span class="local-identity__label">{{ $t('externalIdentities.localAccountLabel') }}</span>
        <span class="local-identity__value">{{ user.username }}</span>
        <el-tag
          size="small"
          effect="plain"
          :type="isExternalCredential ? 'warning' : 'success'"
        >
          {{ isExternalCredential
            ? $t('externalIdentities.externalCredentialTag')
            : $t('externalIdentities.localCredentialTag') }}
        </el-tag>
        <!-- 帳號啟用狀態就近顯示：「解除綁定並停用帳號」的
             結果只靠 3 秒 toast 呈現時，管理者無法自證剛才那一下是否真的生效 -->
        <el-tag
          class="local-identity__status"
          size="small"
          :type="isAccountDisabled ? 'danger' : 'success'"
        >
          {{ isAccountDisabled
            ? $t('externalIdentities.accountDisabledTag')
            : $t('externalIdentities.accountActiveTag') }}
        </el-tag>
      </div>
      <div class="local-identity__hint">
        {{ $t('externalIdentities.localAccountHint') }}
      </div>
    </div>

    <!-- claim 與解綁後果的警示只在**有身分可談**時出現：
         純本地帳號的畫面上沒有任何 claim 欄位、也沒有可解綁的對象，常駐警示
         只會訓練管理者略過警示，等真的要解綁時反而不看 -->
    <template v-if="identities.length > 0">
      <el-alert
        class="panel-alert"
        type="warning"
        :title="$t('externalIdentities.claimWarningTitle')"
        :description="$t('externalIdentities.claimWarningDesc')"
        :closable="false"
        show-icon
      />

      <!-- 解綁後果（UA-1：管理介面 SHALL 於確認前明示）。確認框內另有一次，
           此處常駐是為了讓管理者在按下按鈕**之前**就知道代價 -->
      <el-alert
        class="panel-alert"
        type="info"
        :title="$t('externalIdentities.unbindConsequenceTitle')"
        :description="$t('externalIdentities.unbindConsequenceDesc')"
        :closable="false"
        show-icon
      />
    </template>

    <!-- 載入失敗必須是**錯誤態**而非空態：空態等於斷言
         「此帳號沒有任何外部登入途徑」，管理者可能據此停掉本地密碼或刪帳號。
         此處**只留單行標題**：完整說明與「重試」放在表格空區的
         錯誤態——就在資料本該出現的位置。原本 alert 與 EmptyState 逐字相同，
         加上綁定卡片的第三段，一屏內講同一件事三次，只會訓練管理者略過警示 -->
    <el-alert
      v-if="loadError"
      class="panel-alert"
      type="error"
      :title="$t('externalIdentities.loadErrorTitle')"
      :closable="false"
      show-icon
    />

    <!-- 抽屜表格不使用 fixed 操作欄：1280 寬度下 fixed 浮層會
         蓋住「綁定時間」，時間戳被切一半在畫面上像資料損毀而非被截斷。
         欄寬預算：1280 視窗下抽屜可視寬約 1112px，
         下列欄寬總和 1070（140+120+150+180+150+150+180）必須守在該值內，
         且操作欄取三語最寬者定寬——ja「バインド解除」+「その他」在 150 裝不下，
         會上下相疊成誤點面。新增欄位前先重算這條加總 -->
    <el-table
      v-loading="loading"
      :data="identities"
      class="identity-table"
      stripe
    >
      <el-table-column
        :label="$t('externalIdentities.providerColumn')"
        min-width="140"
      >
        <template #default="{ row }">
          <el-tag
            size="small"
            type="info"
            effect="plain"
          >
            {{ row.provider_name || $t('externalIdentities.unknownProvider') }}
          </el-tag>
          <div class="cell-sub">
            {{ row.issuer }}
          </div>
        </template>
      </el-table-column>
      <!-- IdP 自報欄一律帶「自報」字樣與說明（防混淆約束，不是裝飾） -->
      <el-table-column min-width="120">
        <template #header>
          <el-tooltip
            :content="$t('externalIdentities.claimUsernameTooltip')"
            placement="top"
          >
            <span class="col-header-hint">{{ $t('externalIdentities.claimUsernameColumn') }}</span>
          </el-tooltip>
        </template>
        <template #default="{ row }">
          <span v-if="row.claim_username">{{ row.claim_username }}</span>
          <el-tag
            v-else
            size="small"
            type="info"
          >
            {{ $t('externalIdentities.claimAbsent') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column min-width="150">
        <template #header>
          <el-tooltip
            :content="$t('externalIdentities.claimEmailTooltip')"
            placement="top"
          >
            <span class="col-header-hint">{{ $t('externalIdentities.claimEmailColumn') }}</span>
          </el-tooltip>
        </template>
        <template #default="{ row }">
          <span v-if="row.claim_email">{{ row.claim_email }}</span>
          <el-tag
            v-else
            size="small"
            type="info"
          >
            {{ $t('externalIdentities.claimAbsent') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column min-width="180">
        <template #header>
          <el-tooltip
            :content="$t('externalIdentities.subjectTooltip')"
            placement="top"
          >
            <span class="col-header-hint">{{ $t('externalIdentities.subjectColumn') }}</span>
          </el-tooltip>
        </template>
        <template #default="{ row }">
          <div class="subject-cell">
            <code class="subject-value">{{ row.subject }}</code>
            <el-button
              class="subject-copy"
              size="small"
              link
              :aria-label="$t('externalIdentities.copy')"
              @click="copySubject(row.subject)"
            >
              <el-icon><Copy /></el-icon>
            </el-button>
          </div>
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('externalIdentities.lastLoginColumn')"
        width="150"
      >
        <template #default="{ row }">
          <span v-if="row.last_login_at">{{ formatDateTime(row.last_login_at) }}</span>
          <el-tag
            v-else
            size="small"
            type="info"
          >
            {{ $t('externalIdentities.neverLoggedIn') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('externalIdentities.boundAtColumn')"
        width="150"
      >
        <template #default="{ row }">
          {{ formatDateTime(row.created_at) }}
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('common.actions')"
        width="180"
      >
        <template #default="{ row }">
          <el-button
            type="danger"
            size="small"
            link
            :loading="isRowAction(row, 'unbind')"
            :disabled="busy"
            @click="handleUnbind(row)"
          >
            {{ $t('externalIdentities.unbind') }}
          </el-button>
          <!-- 「解除綁定並停用帳號」是 5.5 明列的第一級 admin 操作，必須常駐可達，
               但**不可**與一般解綁同色同權緊鄰：兩者字首相同、
               誤點代價是整個帳號被停用。收進「更多」選單並加分隔線，誤點面從
               「相鄰 12px」降為「需先展開選單再選 danger 項」 -->
          <el-dropdown
            class="row-more"
            trigger="click"
            placement="bottom-end"
            :disabled="busy"
            @command="(cmd) => handleRowCommand(cmd, row)"
          >
            <el-button
              size="small"
              link
              :loading="isRowAction(row, 'unbindAndDisable')"
              :disabled="busy"
            >
              {{ $t('common.more') }}<el-icon class="more-caret">
                <ChevronDown />
              </el-icon>
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <!-- 選單內僅此一項，不加 divided（會在選單頂端留一條懸空分隔線） -->
                <el-dropdown-item command="unbindAndDisable">
                  <span class="danger-item">{{ $t('externalIdentities.unbindAndDisable') }}</span>
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </template>
      </el-table-column>
      <template #empty>
        <EmptyState
          v-if="loadError"
          :title="$t('externalIdentities.loadErrorTitle')"
          :hint="$t('externalIdentities.loadErrorHint')"
          :icon="TriangleAlert"
        >
          <template #action>
            <el-button
              size="small"
              :loading="loading"
              @click="loadIdentities"
            >
              {{ $t('common.retry') }}
            </el-button>
          </template>
        </EmptyState>
        <EmptyState
          v-else
          :title="$t('externalIdentities.emptyTitle')"
          :hint="$t('externalIdentities.emptyHint')"
        />
      </template>
    </el-table>

    <!-- admin 顯式綁定：自助連結不在 v1 範圍，綁定一律由 admin 操作 -->
    <div class="bind-card">
      <div class="bind-card__title">
        {{ $t('externalIdentities.bindTitle') }}
      </div>
      <div class="bind-card__hint">
        {{ $t('externalIdentities.bindHint') }}
      </div>
      <el-form
        :inline="true"
        label-position="top"
        @submit.prevent
      >
        <el-form-item :label="$t('externalIdentities.bindProvider')">
          <el-select
            v-model="bindForm.providerId"
            class="bind-provider"
            :placeholder="$t('externalIdentities.bindProviderPlaceholder')"
          >
            <el-option
              v-for="p in providers"
              :key="p.id"
              :value="p.id"
              :label="p.enabled
                ? p.name
                : $t('externalIdentities.disabledProviderOption', {
                  name: p.name,
                  status: $t('common.disabled'),
                })"
            />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('externalIdentities.bindSubject')">
          <el-input
            v-model="bindForm.subject"
            class="bind-subject"
            maxlength="255"
            :placeholder="$t('externalIdentities.bindSubjectPlaceholder')"
          />
        </el-form-item>
        <el-form-item label=" ">
          <el-button
            type="primary"
            :loading="isAction('bind')"
            :disabled="bindDisabled"
            @click="handleBind"
          >
            {{ $t('externalIdentities.bindSubmit') }}
          </el-button>
        </el-form-item>
      </el-form>
      <!-- 送出值與輸入框不一致時必須先攤開：subject 大小寫
           敏感且不正規化，前端只去頭尾空白（貼上殘留空白遠比合法空白 subject
           常見），但「你打的」與「實際送的」不同時，管理者有權在送出前看到 -->
      <div
        v-if="trimmedSubjectNotice"
        class="bind-card__notice"
      >
        {{ trimmedSubjectNotice }}
      </div>
      <div
        v-if="loadError"
        class="bind-card__notice"
      >
        {{ $t('externalIdentities.stateUnknownHint') }}
      </div>
    </div>

    <!-- 帳號本體狀態過期：父層列表刷新失敗時，
         「具本地密碼／帳號啟用中」等標籤與轉換入口的顯隱都還是操作**之前**的
         舊值。此時再讓管理者依畫面判斷要不要轉換，等於拿舊事實做不可逆決定 -->
    <el-alert
      v-if="accountStateStale"
      class="panel-alert panel-alert--stale"
      type="warning"
      :title="$t('externalIdentities.accountStateStaleTitle')"
      :description="$t('externalIdentities.accountStateStaleHint')"
      :closable="false"
      show-icon
    />

    <!-- 改為僅外部登入（2.8 端點 d）：入口放在抽屜內而非使用者列——它的前提是
         「已有可用的外部身分」，該事實只有這個畫面看得到；在列表上開放等於邀請
         管理者對沒綁身分的帳號按下去，再由後端拒絕 -->
    <div class="external-only-card">
      <div class="bind-card__title">
        {{ $t('externalIdentities.externalOnlyTitle') }}
      </div>
      <div class="bind-card__hint">
        {{ $t('externalIdentities.externalOnlyHint') }}
      </div>
      <el-tag
        v-if="isExternalCredential"
        size="small"
        type="success"
        effect="plain"
      >
        {{ $t('externalIdentities.externalOnlyAlready') }}
      </el-tag>
      <template v-else>
        <el-button
          type="warning"
          :loading="isAction('externalOnly')"
          :disabled="externalOnlyDisabled"
          @click="handleExternalOnly"
        >
          {{ $t('externalIdentities.externalOnlySubmit') }}
        </el-button>
        <div
          v-if="!identities.length"
          class="bind-card__notice"
        >
          {{ $t('externalIdentities.externalOnlyNeedsIdentity') }}
        </div>
      </template>
    </div>
  </div>
</template>

<script setup>
/**
 * 使用者的外部身分管理（spec user-account-administration）。
 *
 * 五個刻意的設計約束，改動前請先讀 spec：
 *   1. claim 快照是 IdP 自報值，**與本地 username 分區並標示來源**，不得混排；
 *   2. 解綁的後果（該使用者全部工作階段登出）SHALL 於確認前明示；
 *   3. 「解綁後無登入途徑」由後端以 RULE_USER_LAST_LOGIN_PATH 拒絕——前端不自行
 *      預判擋下（判準涉及 LDAP 目錄帳號等本前端無從得知的條件），而是在被拒時
 *      就近提供「解除綁定並停用帳號」這條正當出路；
 *   4. 破壞性動作一次只准跑一個（單一 mutation 鎖），且確認框開著期間切換使用者
 *      即放棄該次操作——這兩件事錯了不會報錯，只會對錯的帳號執行；
 *   5. 載入失敗必須呈現錯誤態，不得退化成「此帳號沒有外部身分」的事實斷言。
 */
import { ref, reactive, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage } from 'element-plus'
import { Copy, ChevronDown, TriangleAlert } from 'lucide-vue-next'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime } from '@/utils/format'
import { confirmDestructive } from '@/utils/confirm'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import { apiErrorSummary } from '@/api/redact'
import {
  getExternalIdentities,
  bindExternalIdentity,
  unbindExternalIdentity,
  unbindExternalIdentityAndDisable,
  convertUserToExternalOnly,
} from '@/api/user'
import { getOIDCProviders } from '@/api/oidc'

const props = defineProps({
  user: {
    type: Object,
    required: true,
  },
  // 父層列表刷新失敗（Users.vue handleIdentitiesChanged）：帳號本體狀態
  //（external_credential／active）可能已經改變，但畫面上仍是操作前的舊值。
  // 此時必須停掉「再轉換一次」這條路
  accountStateStale: {
    type: Boolean,
    default: false,
  },
})

// changed 一律帶「這次變更的是哪個 user id」：本元件在
// 換人／卸載後仍可能收到成功回應並通知父層，父層若無從分辨是誰的變更，就會
// 拿舊操作去刷新目前抽屜的帳號狀態
const emit = defineEmits(['changed'])

const loading = ref(false)
const loadError = ref(false)
const identities = ref([])
const providers = ref([])

// 互斥鎖：**從開啟確認框到 reload 完成**都算佔用。
// 只在送出期間上鎖是不夠的——確認框是非同步的，兩個框可以同時開著，各自
// resolve 後交錯執行解綁與停用。busy 管互斥，mutation 只管 loading 指示，
// 兩者分離是為了不讓「確認框開著」把整張表的按鈕都停在轉圈
const busy = ref(false)
const mutation = ref(null)
const isAction = (action) => mutation.value?.action === action
const isRowAction = (row, action) =>
  mutation.value?.action === action && mutation.value?.id === row.id

// 請求世代：抽屜可在同一實例上換使用者，較慢返回的前一位
// 使用者結果會覆蓋當前清單，接著的解綁就會拿新 user id 配舊 identity id
const loadSeq = ref(0)

// —— 生命週期世代與鎖的所有權 ——
//
// 為什麼光比對 user id 不夠：ElMessageBox 的確認框被 teleport 到 body，**不隨
// 元件卸載而失效**。父層以 `:key="user.id"` 重掛面板時，舊實例被卸載但它開著的
// 確認框還在畫面上；使用者按下確認，舊實例的 handler 會繼續跑，而它閉包裡的
// `props.user` 停在舊值——`sameUser()` 因此回 true，操作照樣送出。抽屜此時顯示
// 的是另一個帳號，管理者無從察覺自己剛才停用了誰。
//
// 世代規則：user 變更與 onBeforeUnmount 各遞增一次；每個破壞性 handler 在進場時
// 取得一枚 token（同時記下當時世代），**每次 await 之後、送出請求之前、任何
// UI 副作用之前**都要重驗。
//
// 鎖的所有權：舊 handler 的 finally 不得改寫新世代的 busy／mutation。
// 切換使用者時只淘汰舊 owner，stale finally 因不再持有
// 所有權而變成 no-op，不會提前釋放新操作的鎖。
// lockOwner 刻意是普通變數而非 ref：以物件identity 判斷所有權，而 `ref()` 會把
// 物件深度包成 reactive proxy，`lockOwner.value === token` 永遠不成立
let generation = 0
let lockOwner = null

const invalidateGeneration = () => {
  generation += 1
  // 在途載入一併作廢（畫面寧可短暫空白也不顯示他人的身分）
  loadSeq.value += 1
  lockOwner = null
  busy.value = false
  mutation.value = null
}

const acquireLock = () => {
  if (busy.value) return null
  const token = { gen: generation }
  lockOwner = token
  busy.value = true
  return token
}

const ownsLock = (token) => token != null && lockOwner === token

const releaseLock = (token) => {
  if (!ownsLock(token)) return
  lockOwner = null
  busy.value = false
  mutation.value = null
}

const setMutation = (token, value) => {
  if (ownsLock(token)) mutation.value = value
}

// 生命週期判準（不涉及鎖）：世代未變且目標 user 仍是畫面上的 user。
// 非破壞性的非同步收尾（複製 subject 等）不持鎖，但同樣不得在「已經是別人」
// 的畫面上留下訊息
const sameLifecycle = (gen, userId) =>
  gen === generation && userId != null && userId === props.user?.id

// 單一有效性判準：仍持有鎖、世代未變、且目標 user 仍是畫面上的 user。
// 三者任一不成立即代表這次操作的前提已消失，必須就地放棄
const isCurrent = (token, userId) => ownsLock(token) && sameLifecycle(token.gen, userId)

// 換人／卸載後才按下舊確認框的破壞性按鈕：中止是對的，但**靜默**中止會讓
// 管理者以為已執行。沿用「已啟動流程才回饋」判準——按下
// 確認鈕已屬啟動，故給 info；第一層確認框的「取消」仍不給提示
const notifyAborted = () => ElMessage.info(t('externalIdentities.userSwitchedAborted'))

const bindForm = reactive({ providerId: null, subject: '' })

// 憑證是否由外部提供者管理：與 Users.vue 同一判定（external_credential 為權威，
// 缺欄時退回 is_ldap——LDAP 影子帳號同樣無本地密碼）
const isExternalCredential = computed(
  () =>
    props.user?.external_credential === true ||
    (props.user?.external_credential === undefined && props.user?.is_ldap === true)
)

// active 缺欄（舊後端或未帶該欄的呼叫端）時不假設已停用
const isAccountDisabled = computed(() => props.user?.active === false)

const trimmedSubject = computed(() => bindForm.subject.trim())
const trimmedSubjectNotice = computed(() =>
  trimmedSubject.value && trimmedSubject.value !== bindForm.subject
    ? t('externalIdentities.bindSubjectTrimmedNote', { subject: trimmedSubject.value })
    : ''
)

const bindDisabled = computed(() => (busy.value && !isAction('bind')) || loadError.value)
const externalOnlyDisabled = computed(
  () =>
    loadError.value ||
    props.accountStateStale ||
    identities.value.length === 0 ||
    (busy.value && !isAction('externalOnly'))
)

const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

const loadIdentities = async () => {
  const userId = props.user?.id
  if (!userId) return
  const seq = ++loadSeq.value
  loading.value = true
  loadError.value = false
  try {
    const res = await getExternalIdentities(userId)
    if (seq !== loadSeq.value) return
    identities.value = res?.data || []
  } catch (error) {
    if (seq !== loadSeq.value) return
    // 舊資料一律丟棄：把上一位使用者（或上一次成功）的清單留在畫面上，
    // 比空白更危險——它看起來像現況
    identities.value = []
    loadError.value = true
    logFailure('external_identity_list_failed', error)
  } finally {
    if (seq === loadSeq.value) loading.value = false
  }
}

const loadProviders = async () => {
  if (providers.value.length) return
  try {
    const res = await getOIDCProviders()
    providers.value = res?.data || []
  } catch (error) {
    logFailure('oidc_provider_list_failed', error)
  }
}

const reload = async () => {
  bindForm.providerId = null
  bindForm.subject = ''
  await Promise.all([loadIdentities(), loadProviders()])
}

// 解綁後果的**就地**說明：不預判後端裁決，只據實陳述此帳號的登入途徑現況。
// 「仍有本地密碼」與「憑證已外部化」是兩種完全不同的風險，混為一談等於沒說
const loginPathNote = () =>
  isExternalCredential.value
    ? t('externalIdentities.unbindNoLocalPasswordNote')
    : t('externalIdentities.unbindLocalPasswordNote')

const lastIdentityNote = () =>
  identities.value.length === 1 ? t('externalIdentities.unbindLastIdentityNote') : ''

const providerNameOf = (row) => row.provider_name || t('externalIdentities.unknownProvider')

// 逐段以單一空白接合（原本各段自帶尾空白，串出雙空白）
const joinSentences = (...parts) => parts.filter(Boolean).join(' ')

const confirmText = (row) =>
  joinSentences(
    t('externalIdentities.unbindConfirm', {
      name: props.user.username,
      provider: providerNameOf(row),
    }),
    lastIdentityNote(),
    loginPathNote()
  )

const unbindAndDisableText = (row) =>
  t('externalIdentities.unbindAndDisableConfirm', {
    name: props.user.username,
    provider: providerNameOf(row),
  })

const doUnbindAndDisable = async (row, userId, token) => {
  setMutation(token, { action: 'unbindAndDisable', id: row.id })
  try {
    // 送出前最後一次驗證（呼叫端已驗過，此處是原子出口的兜底）
    if (!isCurrent(token, userId)) return
    await unbindExternalIdentityAndDisable(userId, row.id)
    // 請求成功後才做 UI 副作用；期間若已換人／卸載，只讓父層重抓列表，
    // 不在「別人的畫面」上彈成功訊息（會被讀成剛剛停用的是這個帳號）
    if (!isCurrent(token, userId)) {
      emit('changed', userId)
      return
    }
    ElMessage.success(t('externalIdentities.unbindAndDisableDone'))
    emit('changed', userId)
    await loadIdentities()
  } catch (error) {
    logFailure('external_identity_unbind_disable_failed', error)
  } finally {
    setMutation(token, null)
  }
}

// 解綁被後端以「登入途徑歸零」拒絕時，直接把正當出路擺在同一個對話框裡。
// 只丟一句錯誤訊息會讓管理者卡死在「不能解綁、也不知道能做什麼」。
// 文案同時帶規則說明與完整後果：這個框的確認鍵會停用帳號，
// 不能只顯示「為什麼不能解綁」就要人按下去
const offerUnbindAndDisable = async (row, userId, token) => {
  try {
    await confirmDestructive(
      joinSentences(t('apiError.RULE_USER_LAST_LOGIN_PATH'), unbindAndDisableText(row)),
      t('externalIdentities.lastPathTitle'),
      {
        confirmButtonText: t('externalIdentities.unbindAndDisable'),
        cancelButtonText: t('common.cancel'),
      }
    )
  } catch {
    // 取消回饋只給**已啟動流程**的收尾：使用者已經按過
    // 「解除綁定」、被後端擋下、又在出路框按取消，畫面上什麼都沒變會被讀成
    // 「按鈕壞了」。第一層確認框的取消不給 toast——那是還沒開始的動作，
    // 每次取消都彈提示只會製造噪音
    if (isCurrent(token, userId)) ElMessage.info(t('externalIdentities.unbindNotCompleted'))
    return
  }
  if (!isCurrent(token, userId)) {
    notifyAborted()
    return
  }
  await doUnbindAndDisable(row, userId, token)
}

const handleUnbind = async (row) => {
  const token = acquireLock()
  if (!token) return
  const userId = props.user?.id
  try {
    try {
      await confirmDestructive(confirmText(row), t('externalIdentities.unbindTitle'), {
        confirmButtonText: t('externalIdentities.unbind'),
        cancelButtonText: t('common.cancel'),
      })
    } catch {
      return
    }
    if (!isCurrent(token, userId)) {
      notifyAborted()
      return
    }

    setMutation(token, { action: 'unbind', id: row.id })
    let lastLoginPath = false
    try {
      await unbindExternalIdentity(userId, row.id)
      if (!isCurrent(token, userId)) {
        emit('changed', userId)
        return
      }
      ElMessage.success(t('externalIdentities.unbound'))
      emit('changed', userId)
      await loadIdentities()
    } catch (error) {
      const data = error?.response?.data
      if (data?.code === 'RULE_USER_LAST_LOGIN_PATH') {
        lastLoginPath = true
      } else if (isCurrent(token, userId)) {
        // 全域 toast 對此端點已關閉（見 api/user.js），錯誤一律由此就近顯示
        ElMessage.error(resolveApiError(data, error?.response?.status))
        logFailure('external_identity_unbind_failed', error)
      } else {
        logFailure('external_identity_unbind_failed', error)
      }
    } finally {
      // 出路對話框開著期間不留 loading 轉圈（互斥仍由 busy 維持）
      setMutation(token, null)
    }
    if (lastLoginPath && isCurrent(token, userId)) {
      await offerUnbindAndDisable(row, userId, token)
    }
  } finally {
    releaseLock(token)
  }
}

const handleUnbindAndDisable = async (row) => {
  const token = acquireLock()
  if (!token) return
  const userId = props.user?.id
  try {
    try {
      await confirmDestructive(
        unbindAndDisableText(row),
        t('externalIdentities.unbindAndDisableTitle'),
        {
          confirmButtonText: t('externalIdentities.unbindAndDisable'),
          cancelButtonText: t('common.cancel'),
        }
      )
    } catch {
      return
    }
    if (!isCurrent(token, userId)) {
      notifyAborted()
      return
    }
    await doUnbindAndDisable(row, userId, token)
  } finally {
    releaseLock(token)
  }
}

const handleRowCommand = (command, row) => {
  if (command === 'unbindAndDisable') handleUnbindAndDisable(row)
}

const handleBind = async () => {
  if (busy.value) return
  // subject 大小寫敏感且不做正規化（依後端契約），前端同樣只去頭尾空白；
  // 實際送出值已於表單下方攤開（trimmedSubjectNotice）
  const subject = trimmedSubject.value
  if (!bindForm.providerId || !subject) {
    ElMessage.warning(t('externalIdentities.bindRequired'))
    return
  }
  // 同一帳號重複綁同一 provider+subject：後端回 409「已綁定至某個帳號」，
  // 但衝突對象就在同一畫面上，就近說清楚
  const duplicate = identities.value.some(
    (row) => row.provider_id === bindForm.providerId && row.subject === subject
  )
  if (duplicate) {
    ElMessage.warning(t('externalIdentities.bindDuplicateSelf'))
    return
  }
  const userId = props.user?.id
  const token = acquireLock()
  if (!token) return
  setMutation(token, { action: 'bind', id: null })
  try {
    if (!isCurrent(token, userId)) return
    await bindExternalIdentity(userId, bindForm.providerId, subject)
    if (!isCurrent(token, userId)) {
      emit('changed', userId)
      return
    }
    ElMessage.success(t('externalIdentities.bound'))
    bindForm.subject = ''
    emit('changed', userId)
    await loadIdentities()
  } catch (error) {
    // 綁定端點走全域 toast（錯誤碼譯文已備妥），此處只留去識別日誌
    logFailure('external_identity_bind_failed', error)
  } finally {
    releaseLock(token)
  }
}

const handleExternalOnly = async () => {
  if (busy.value || externalOnlyDisabled.value) return
  const token = acquireLock()
  if (!token) return
  const userId = props.user?.id
  try {
    try {
      await confirmDestructive(
        t('externalIdentities.externalOnlyConfirm', {
          name: props.user.username,
          identityCount: identities.value.length,
        }),
        t('externalIdentities.externalOnlyTitle'),
        {
          confirmButtonText: t('externalIdentities.externalOnlySubmit'),
          cancelButtonText: t('common.cancel'),
        }
      )
    } catch {
      return
    }
    if (!isCurrent(token, userId)) {
      notifyAborted()
      return
    }

    setMutation(token, { action: 'externalOnly', id: null })
    try {
      await convertUserToExternalOnly(userId)
      if (!isCurrent(token, userId)) {
        emit('changed', userId)
        return
      }
      ElMessage.success(t('externalIdentities.externalOnlyDone'))
      emit('changed', userId)
      await loadIdentities()
    } catch (error) {
      // 「尚未綁定身分」「最後一個本地管理員」都是規則拒絕，訊息本身即出路，
      // 必須就近顯示（全域 toast 已於 api/user.js 關閉）
      if (isCurrent(token, userId)) {
        ElMessage.error(resolveApiError(error?.response?.data, error?.response?.status))
      }
      logFailure('user_external_only_failed', error)
    } finally {
      setMutation(token, null)
    }
  } finally {
    releaseLock(token)
  }
}

// subject 是登入比對的真正依據，管理者常需貼到 IdP 端核對；不可用剪貼簿時
// 不靜默失敗（使用者會以為已複製而貼出空值）
// 剪貼簿 API 是非同步的：await 之後可能已經換人或卸載，此時的成功／失敗提示
// 會出現在別人的畫面上，被讀成「剛才複製的是這個帳號的
// subject」。不持鎖，故以生命週期世代判定
const copySubject = async (subject) => {
  const gen = generation
  const userId = props.user?.id
  try {
    await navigator.clipboard.writeText(subject)
    if (!sameLifecycle(gen, userId)) return
    ElMessage.success(t('externalIdentities.copied'))
  } catch {
    console.warn('clipboard_write_failed')
    if (!sameLifecycle(gen, userId)) return
    ElMessage.warning(t('externalIdentities.copyFailed'))
  }
}

watch(
  () => props.user?.id,
  (id, prev) => {
    if (id === prev) return
    // 切換使用者：立刻作廢在途請求、清單與鎖的所有權，畫面寧可短暫空白
    // 也不顯示他人的身分；舊 handler 的 finally 因失去所有權而變成 no-op
    invalidateGeneration()
    identities.value = []
    loadError.value = false
    if (id) reload()
  }
)

// 卸載同樣要遞增世代：父層以 `:key` 重掛時本實例會被卸載，
// 但它 teleport 到 body 的確認框還在畫面上；沒有這一行，之後按下的「確認」
// 會拿舊 user id 送出請求，而抽屜上顯示的已經是別人
onBeforeUnmount(invalidateGeneration)

onMounted(reload)

defineExpose({
  identities,
  providers,
  bindForm,
  loadError,
  busy,
  mutation,
  reload,
  loadIdentities,
  handleUnbind,
  handleUnbindAndDisable,
  handleRowCommand,
  handleBind,
  handleExternalOnly,
  copySubject,
  isExternalCredential,
})
</script>

<style scoped>
.local-identity {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  margin-bottom: var(--ot-space-md);
}

.local-identity__main {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  flex-wrap: wrap;
}

.local-identity__label {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.local-identity__value {
  font-weight: 600;
  font-size: var(--ot-font-size-md);
}

.local-identity__hint {
  margin-top: 6px;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.panel-alert {
  margin-bottom: var(--ot-space-md);
}

.identity-table {
  width: 100%;
}

/* Element Plus 的空白區文字預設只佔 50% 寬，長提示會在表格中央折成兩段
   並留下巨大空隙，看起來像壞掉 */
.identity-table :deep(.el-table__empty-text) {
  width: 100%;
  line-height: 1.6;
}

.col-header-hint {
  border-bottom: 1px dashed var(--ot-border-subtle);
  cursor: help;
}

.cell-sub {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  word-break: break-all;
  margin-top: 2px;
}

.subject-cell {
  display: flex;
  align-items: flex-start;
  gap: 4px;
}

.subject-value {
  word-break: break-all;
  font-size: var(--ot-font-size-xs);
}

.subject-copy {
  flex: none;
}

.more-caret {
  margin-left: 2px;
}

/* Element Plus 的按鈕間距靠相鄰選擇器 `.el-button + .el-button` 給，被
   `el-dropdown` 包住的按鈕不再是前一顆的相鄰兄弟，margin 直接失效——
   結果是紅色破壞性按鈕與「更多」觸發鈕的點擊熱區**貼在一起**（gap 0px），
   且 el-dropdown 預設 vertical-align: top 使兩者基線差 4px。
   這是誤點面，不是美觀問題 */
.row-more {
  margin-left: 12px;
  vertical-align: middle;
}

/* 選單內的破壞性項目與一般項目分色（配合 divided 分隔線） */
.danger-item {
  color: var(--el-color-danger);
}

.bind-card,
.external-only-card {
  margin-top: var(--ot-space-md);
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.bind-card__title {
  font-weight: 600;
  margin-bottom: 4px;
}

.bind-card__hint {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  margin-bottom: var(--ot-space-xs);
}

.bind-card__notice {
  margin-top: var(--ot-space-xs);
  color: var(--ot-warning, #e6a23c);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  word-break: break-all;
}

.bind-provider {
  width: 220px;
}

.bind-subject {
  width: 320px;
}
</style>
