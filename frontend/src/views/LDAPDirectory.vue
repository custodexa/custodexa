<template>
  <div
    ref="rootRef"
    class="ldap-directory"
  >
    <PageHeader
      :title="$t('menu.ldapDirectory')"
      :description="$t('ldapDirectory.headerDesc')"
    >
      <template #actions>
        <el-button
          v-if="configured"
          type="danger"
          plain
          :loading="deleting"
          @click="handleDelete"
        >
          {{ $t('ldapDirectory.deleteSettings') }}
        </el-button>
        <el-button
          :loading="loading"
          @click="refreshPage"
        >
          <el-icon><Refresh /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 解封能力前提：與 OIDC 頁同一條不變式（封印期只認本地 admin 憑證）。
         LDAP 使用者是 is_ldap 影子帳號、無本地密碼路徑，全員改走目錄登入同樣
         會使遇 KEK 重啟時無人能解封。文案與 OIDC 頁同源（none 態兩鍵直接共用），
         這是「同層兄弟頁可互相對照」在警示層的兌現 -->
    <el-alert
      v-if="localAdminState === 'none'"
      class="page-alert"
      type="error"
      :title="$t('oidcProviders.localAdminNoneTitle')"
      :description="$t('oidcProviders.localAdminNoneDesc')"
      :closable="false"
      show-icon
    />
    <el-alert
      v-else-if="localAdminState === 'unknown'"
      class="page-alert"
      type="warning"
      :title="$t('ldapDirectory.localAdminWarningTitle')"
      :description="$t('ldapDirectory.localAdminWarningDesc')"
      :closable="false"
      show-icon
    />

    <!-- 讀取失敗必須**真的**擋在表單之前（UI 審查 H3/H4）：原本只放一則 alert，
         但儲存鈕照樣可按——空白表單送出去，既存無 bind 密碼時就會把設定清空。
         警示本身不是閘門，閘門在下方 action-bar 的 :disabled。
         文案分工：狀態帶說「發生什麼事、怎麼復原」，本 alert 只說「我們替你停了
         什麼、為什麼」——原本兩者逐字相同，正是 OIDC 頁註解判過死刑的重複警示 -->
    <el-alert
      v-if="loadFailed"
      class="page-alert"
      type="error"
      :title="$t('ldapDirectory.loadFailedGuardTitle')"
      :description="$t('ldapDirectory.loadFailedGuardDesc')"
      :closable="false"
      show-icon
    />

    <!-- 狀態帶（未設定／已設定未啟用／已啟用／讀取失敗）：述說的是**已儲存**的
         狀態，不隨表單草稿變動——否則切一下開關就會顯示「已啟用」而實際未存 -->
    <div class="status-strip">
      <span class="status-strip__label">{{ $t('ldapDirectory.statusTitle') }}</span>
      <el-tag
        :type="statusTagType"
        effect="plain"
      >
        {{ statusLabel }}
      </el-tag>
      <span class="status-strip__hint">{{ statusHint }}</span>
      <!-- 已啟用且位址為明文 ldap://（UI 審查 M7）：warn 閘只在存檔那一刻確認過
           一次，之後回到本頁就再也看不到風險，於是本頁的頭條結論（綠色「已啟用」）
           與傳輸安全頁的判定（列入 at_risk_count）相反。不另開 alert——警示疲勞
           是本專案既有的教訓，狀態帶補一條風險說明即可 -->
      <span
        v-if="savedPlaintextRisk"
        class="status-strip__risk"
      >{{ $t('ldapDirectory.plaintextRisk') }}</span>
    </div>

    <el-form
      ref="formRef"
      v-loading="loading"
      :model="form"
      :rules="formRules"
      label-position="top"
    >
      <!-- 分區一：連線 -->
      <el-card class="section-card">
        <template #header>
          <div class="card-header">
            <span class="card-title">{{ $t('ldapDirectory.sectionConnection') }}</span>
            <span class="card-hint">{{ $t('ldapDirectory.sectionConnectionHint') }}</span>
          </div>
        </template>

        <el-form-item
          class="field-url"
          :label="$t('ldapDirectory.url')"
          prop="url"
        >
          <el-input
            v-model="form.url"
            :placeholder="$t('ldapDirectory.urlPlaceholder')"
            maxlength="255"
          />
          <div class="field-hint">
            {{ $t('ldapDirectory.urlHint') }}
          </div>
        </el-form-item>

        <el-form-item
          :label="$t('ldapDirectory.bindDn')"
          prop="bind_dn"
        >
          <el-input
            v-model="form.bind_dn"
            :placeholder="$t('ldapDirectory.bindDnPlaceholder')"
            maxlength="255"
          />
          <div class="field-hint">
            {{ $t('ldapDirectory.bindDnHint') }}
          </div>
        </el-form-item>

        <!-- write-only：讀取回應永不含密碼，只能覆寫不能檢視。
             留空＝沿用既存（與通知通道、OIDC 密鑰同一語義） -->
        <el-form-item
          class="field-bind-password"
          :label="$t('ldapDirectory.bindPassword')"
        >
          <el-input
            v-model="form.bind_password"
            type="password"
            show-password
            autocomplete="new-password"
            :disabled="form.clear_bind_password"
            :placeholder="bindPasswordPlaceholder"
          />
          <el-checkbox
            v-if="savedHasBindPassword"
            v-model="form.clear_bind_password"
            class="clear-secret"
          >
            {{ $t('ldapDirectory.clearBindPassword') }}
          </el-checkbox>
          <div
            v-if="form.clear_bind_password"
            class="field-warning"
          >
            {{ $t('ldapDirectory.clearBindPasswordHint') }}
          </div>
          <!-- 位址變更且未重供密碼：後端會以 400 拒絕（既有憑證不得隨新位址外送），
               這裡只是在按下儲存**之前**就講明，省一次來回。
               既存無密碼（草稿）時不提示——當下沒有憑證可被沿用，
               對「先存草稿再修正打錯的 URL」這條正常路徑加提示只是噪音 -->
          <div
            v-if="urlChangedNeedsPassword"
            class="field-warning"
          >
            {{ $t('ldapDirectory.urlChangedNeedPassword') }}
          </div>
        </el-form-item>

        <el-form-item :label="$t('ldapDirectory.skipTlsVerify')">
          <el-switch v-model="form.skip_tls_verify" />
          <!-- 警語恆顯示（非僅開啟時）：這個開關的後果是「bind 密碼可被中間人讀取」，
               在決定要不要打開之前就該讀到 -->
          <div class="field-warning">
            {{ $t('ldapDirectory.skipTlsVerifyWarning') }}
          </div>
        </el-form-item>
      </el-card>

      <!-- 分區二：使用者搜尋 -->
      <el-card class="section-card">
        <template #header>
          <div class="card-header">
            <span class="card-title">{{ $t('ldapDirectory.sectionSearch') }}</span>
            <span class="card-hint">{{ $t('ldapDirectory.sectionSearchHint') }}</span>
          </div>
        </template>

        <el-form-item
          :label="$t('ldapDirectory.baseDn')"
          prop="base_dn"
        >
          <el-input
            v-model="form.base_dn"
            :placeholder="$t('ldapDirectory.baseDnPlaceholder')"
            maxlength="255"
          />
        </el-form-item>

        <el-form-item
          :label="$t('ldapDirectory.userFilter')"
          prop="user_filter"
        >
          <el-input
            v-model="form.user_filter"
            :placeholder="$t('ldapDirectory.userFilterPlaceholder')"
            maxlength="255"
          />
          <div class="field-hint">
            {{ $t('ldapDirectory.userFilterHint') }}
          </div>
        </el-form-item>

        <div class="field-row">
          <el-form-item
            :label="$t('ldapDirectory.attrEmail')"
            prop="attr_email"
            class="field-row__item"
          >
            <el-input
              v-model="form.attr_email"
              :placeholder="$t('ldapDirectory.attrEmailPlaceholder')"
              maxlength="64"
            />
          </el-form-item>
          <el-form-item
            :label="$t('ldapDirectory.attrFullname')"
            prop="attr_fullname"
            class="field-row__item"
          >
            <el-input
              v-model="form.attr_fullname"
              :placeholder="$t('ldapDirectory.attrFullnamePlaceholder')"
              maxlength="64"
            />
          </el-form-item>
        </div>
      </el-card>

      <!-- 分區三：啟用與顯示名 -->
      <el-card class="section-card">
        <template #header>
          <div class="card-header">
            <span class="card-title">{{ $t('ldapDirectory.sectionEnable') }}</span>
            <span class="card-hint">{{ $t('ldapDirectory.sectionEnableHint') }}</span>
          </div>
        </template>

        <el-form-item
          :label="$t('ldapDirectory.name')"
          prop="name"
        >
          <el-input
            v-model="form.name"
            :placeholder="$t('ldapDirectory.namePlaceholder')"
            maxlength="100"
          />
        </el-form-item>

        <!-- 頁內啟用開關。**欄位不因停用而 disabled**：停用只代表「這份設定現在
             不參與登入」，不代表不能編輯——把欄位鎖起來會讓「先把設定填好再啟用」
             這條正常路徑走不通。必填驗證同樣僅於啟用時套用（與伺服端規則一致） -->
        <el-form-item
          class="field-enabled"
          :label="$t('ldapDirectory.enabled')"
        >
          <el-switch
            v-model="form.enabled"
            :active-text="$t('common.enabled')"
            :inactive-text="$t('common.disabled')"
          />
          <div class="field-hint">
            {{ $t('ldapDirectory.enabledHint') }}
          </div>
        </el-form-item>
      </el-card>
    </el-form>

    <el-alert
      v-if="formError"
      class="page-alert"
      type="error"
      :title="formError"
      :closable="false"
      show-icon
    />

    <div class="action-bar">
      <el-button
        :loading="testing"
        @click="handleTest"
      >
        {{ $t('ldapDirectory.test') }}
      </el-button>
      <!-- 讀取失敗**或讀取尚未回來**時停用（H3／輪 2 NEW-H1）：測試不寫入、
           留著可協助診斷，會覆蓋伺服端現況的只有儲存。
           `loading` 這一半是輪 2 補上的——action-bar 在 el-form 之外，
           v-loading 的遮罩蓋不到它，於是初次載入（或按了重新整理）期間儲存鈕
           照樣可按，而此時表單還是空白預設值：實測按下去會把伺服器上的
           name／url／bind_dn／base_dn 清成空字串，還回一個綠色「設定已儲存」。
           讀取失敗只是這條路徑的其中一種到達方式，慢也一樣到得了 -->
      <el-button
        type="primary"
        :loading="saving"
        :disabled="loadFailed || loading"
        @click="handleSave"
      >
        {{ $t('common.save') }}
      </el-button>
      <!-- 未儲存變更指示（輪 2 NEW-M4）：本頁是整頁表單，切選單／按重新整理都會
           靜默丟掉草稿，而姊妹的整頁設定表單（安全政策）有 isDirty 橫幅與重設鈕。
           這裡不攔導覽（全站無此慣例），但必須讓「還沒存」被看見 -->
      <span
        v-if="isDirty"
        class="action-bar__dirty"
      >{{ $t('ldapDirectory.unsavedChanges') }}</span>
      <span class="action-bar__hint">{{ $t('ldapDirectory.testHint') }}</span>
    </div>

    <!-- 連線測試結果：階梯是本端點存在的理由，故以分階段清單呈現而非單一成敗。
         ref + aria-live（UI 審查 M3）：測試最長 15 秒，期間唯一回饋是按鈕上的
         spinner；結果卡又長在頁尾，實測按下後畫面「毫無變化」（結果整片在摺線
         以下）。測完主動捲進視野，並讓輔助技術也讀得到 -->
    <el-card
      v-if="testError || testResult"
      ref="resultCardRef"
      class="section-card result-card"
      aria-live="polite"
    >
      <template #header>
        <div class="card-header">
          <span class="card-title">{{ $t('ldapDirectory.testResultTitle') }}</span>
        </div>
      </template>

      <!-- 結果與表單已不對應（輪 2 NEW-M3）：本頁的工作流是「先測後存」，
           結果卡因此會與使用者接下來的編輯並存。改完 URL 或 bind DN 後，
           上一輪那句綠色「連線測試通過」仍留在畫面上，讀起來像是在替**現在**
           這份設定背書。不清掉結果（診斷碼還要轉交），只聲明它已過期 -->
      <div
        v-if="testResultStale"
        class="field-warning result-stale"
      >
        {{ $t('ldapDirectory.testResultStale') }}
      </div>

      <!-- 測試「未執行」（驗證／傳輸閘／限流）與「跑完但失敗」是兩件事：
           前者沒有階梯可看，混在一起呈現會讓人以為撥號過了 -->
      <el-alert
        v-if="testError"
        type="error"
        :title="testError"
        :closable="false"
        show-icon
      />

      <template v-else>
        <!-- 三階皆過但命中 0 筆（輪 2 NEW-H2）：技術上每一階都成功，但這份設定
             **一個使用者都登不進來**——啟用後每一次目錄登入都會失敗。原本
             這件事只以次要灰字的「搜尋命中 0 筆」表達，頭條卻是綠色「通過」，
             使用者的合理反應是「綠的，過了」，然後去啟用。
             與 M5（屬性缺值）同一條規則：成功結果裡的壞消息不得與好消息同重 -->
        <el-alert
          :type="testHeadlineType"
          :title="testResult.success
            ? (noMatch ? $t('ldapDirectory.testPassedNoMatch') : $t('ldapDirectory.testSuccess'))
            : $t('ldapDirectory.testFailed', { stage: stageLabel(testResult.failed_stage) })"
          :closable="false"
          show-icon
        />

        <div
          v-if="testResult.target"
          class="result-meta"
        >
          {{ $t('ldapDirectory.target') }}: {{ testResult.target }}
        </div>

        <!-- 恆列三階（UI 審查 M2）：原本只 v-for 回應帶回來的階段，於是撥號失敗
             時整份清單只剩一行——分階段回報存在的理由就是讓人看出「走到哪一級、
             還差幾級」，把沒跑到的階段抽掉等於把這個資訊藏起來。
             TEST_STAGES 本就是前端閉集，不需後端配合 -->
        <ul class="stage-list">
          <li
            v-for="stage in stageRows"
            :key="stage.stage"
            class="stage-item"
            :class="`stage-item--${stage.state}`"
          >
            <el-icon class="stage-item__icon">
              <CircleCheck v-if="stage.state === 'ok'" />
              <CircleClose v-else-if="stage.state === 'fail'" />
              <Minus v-else />
            </el-icon>
            <span class="stage-item__name">{{ stageLabel(stage.stage) }}</span>
            <span class="stage-item__state">
              {{ $t(`ldapDirectory.${STAGE_STATE_KEYS[stage.state]}`) }}
            </span>
            <div
              v-if="stage.state === 'fail'"
              class="stage-item__reason"
            >
              {{ testCodeLabel(stage.code) }}
            </div>
          </li>
        </ul>

        <template v-if="testResult.success">
          <!-- 命中筆數走 vue-i18n 隱式複數（t(key, n)）：原本寫死 en 複數形，
               命中一筆時顯示「1 entries matched」 -->
          <div class="result-meta">
            {{ testResult.matched_at_least
              ? $t('ldapDirectory.matchedAtLeast', matchedCount)
              : $t('ldapDirectory.matched', matchedCount) }}
          </div>
          <!-- 命中 0 筆時不再另說「無命中項目，未取樣屬性」：那句與下方的後果
               警語講同一件事，重複的警示只會訓練管理者略過警示（H4 的教訓） -->
          <div
            v-if="noMatch"
            class="field-warning result-attr-warning"
          >
            {{ $t('ldapDirectory.noMatchConsequence') }}
          </div>
          <div
            v-else
            class="result-meta"
          >
            <template v-if="testResult.attr_sample && testResult.attr_sample.sampled">
              {{ $t('ldapDirectory.attrSampleTitle') }}:
              {{ $t('ldapDirectory.attrEmail') }} —
              <span :class="attrStateClass(testResult.attr_sample.email_present)">{{
                testResult.attr_sample.email_present
                  ? $t('ldapDirectory.attrPresent')
                  : $t('ldapDirectory.attrMissing') }}</span>
              /
              {{ $t('ldapDirectory.attrFullname') }} —
              <span :class="attrStateClass(testResult.attr_sample.fullname_present)">{{
                testResult.attr_sample.fullname_present
                  ? $t('ldapDirectory.attrPresent')
                  : $t('ldapDirectory.attrMissing') }}</span>
            </template>
            <template v-else>
              {{ $t('ldapDirectory.attrNotSampled') }}
            </template>
          </div>
          <!-- 屬性缺值的後果（UI 審查 M5）：原本「無值」與「測試目標」同色同重，
               在一片綠色的「測試通過」底下讀起來像中性資訊；但它的實際後果是
               自動建立的帳號會缺該欄位，且是靜默缺 -->
          <div
            v-if="attrSampleMissing"
            class="field-warning result-attr-warning"
          >
            {{ $t('ldapDirectory.attrMissingConsequence') }}
          </div>
        </template>

        <!-- 撥號失敗只有單一「無法連線」語義（不細分 DNS／逾時／拒絕／TLS）：
             這是刻意的收斂，粗分類原因只在伺服端日誌。除錯體驗由檢查清單補償 -->
        <div
          v-if="testResult.code === 'connect_failed'"
          class="result-checklist"
        >
          {{ $t('ldapDirectory.connectChecklist') }}
        </div>

        <!-- 診斷碼要被轉交給維運（說明自己就這麼寫），故必須可一鍵複製（UI 審查
             M4）——16 位十六進位手抄一定會出錯。說明另起一行（L7）：原本與碼
             擠在同一行，讀成一句 -->
        <div
          v-if="testResult.diagnostic_id"
          class="result-meta result-diagnostic"
        >
          <span class="result-diagnostic__line">
            {{ $t('ldapDirectory.diagnosticId') }}:
            <code>{{ testResult.diagnostic_id }}</code>
            <el-button
              type="primary"
              size="small"
              link
              @click="copyDiagnosticId"
            >
              {{ $t('common.copy') }}
            </el-button>
          </span>
          <span class="result-meta__hint">{{ $t('ldapDirectory.diagnosticIdHint') }}</span>
        </div>

        <div
          v-if="testResult.reused_stored_password"
          class="result-meta"
        >
          {{ $t('ldapDirectory.reusedStoredPassword') }}
        </div>
      </template>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive, computed, nextTick, onMounted, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh, CircleCheck, CircleClose, Minus } from '@element-plus/icons-vue'
import PageHeader from '@/components/PageHeader.vue'
import i18n, { t } from '@/i18n'
import { confirmDestructive } from '@/utils/confirm'
import { apiErrorSummary } from '@/api/redact'
import { resolveApiError } from '@/api/error'
import { riskLabel } from '@/utils/transportDisplay'
import { sameLdapEndpoint } from '@/utils/ldapUrl'
import {
  getLDAPDirectory,
  updateLDAPDirectory,
  deleteLDAPDirectory,
  testLDAPDirectory,
} from '@/api/ldapDirectory'
import { getLocalAdminCount } from '@/api/user'

// 階梯與階段碼是**資料不是錯誤訊息**（回應 body 的小寫字面值），故由前端以自有
// i18n 鍵查譯——與清冊 note_code 同一模式。閉集在此明列，未知值不顯示裸機器碼
const TEST_STAGES = ['dial', 'bind', 'search']
// 階段三態 → 顯示文案鍵（未執行是本次新增：見 stageRows）
const STAGE_STATE_KEYS = {
  ok: 'stagePassed',
  fail: 'stageFailed',
  skipped: 'stageNotRun',
}
const TEST_CODES = [
  'connect_failed',
  'egress_blocked',
  'bind_password_missing',
  'bind_failed',
  'search_failed',
  'stage_timeout',
]

// 傳輸閘的兩個既有機器碼（沿三通道共用契約，非本頁新造）
const GATE_ACK_REQUIRED = 'VALIDATION_TRANSMISSION_ACK_REQUIRED'
const GATE_STRICT_REJECT = 'VALIDATION_TRANSMISSION_STRICT_REJECT'

// 元件層日誌只留白名單欄位：本頁請求本文帶 bind 密碼
const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

// 未設定時的出廠預設：與伺服端 seed 的同組預設一致，讓「只填位址與帳號」
// 就是一份可用設定，而不是逼使用者自己查屬性名
const defaultForm = () => ({
  name: '',
  url: '',
  bind_dn: '',
  bind_password: '',
  clear_bind_password: false,
  base_dn: '',
  user_filter: '(uid=%s)',
  attr_email: 'mail',
  attr_fullname: 'cn',
  skip_tls_verify: false,
  enabled: false,
})

const loading = ref(false)
const loadFailed = ref(false)
const saving = ref(false)
const testing = ref(false)
const deleting = ref(false)
const formError = ref('')
const formRef = ref(null)
const rootRef = ref(null)

// 伺服端**已儲存**的事實（與表單草稿分離）：狀態帶、密碼 placeholder 與
// 位址變更提示三者都必須以此為基準，否則會把草稿當成現況
const configured = ref(false)
const savedURL = ref('')
const savedEnabled = ref(false)
const savedHasBindPassword = ref(false)

const testResult = ref(null)
const testError = ref('')
const resultCardRef = ref(null)
// 執行測試當下的表單快照：用來判斷畫面上的結果是否還對應現在的欄位值
const testedSnapshot = ref('')

// 本地管理員警示三態（與 OIDC 頁同語義）：ok 為初始值，載入中不閃警語
const localAdminState = ref('ok')

const form = reactive(defaultForm())

// 必填**僅於啟用時**套用（與伺服端條件式驗證一致）：停用是可暫存的草稿態，
// 對草稿強制必填等於不准存半成品
const requiredWhenEnabled = () => ({
  required: form.enabled,
  message: t('ldapDirectory.requiredWhenEnabled'),
  trigger: 'blur',
})

const formRules = computed(() => ({
  url: [requiredWhenEnabled()],
  bind_dn: [requiredWhenEnabled()],
  base_dn: [requiredWhenEnabled()],
  user_filter: [requiredWhenEnabled()],
  attr_email: [requiredWhenEnabled()],
  attr_fullname: [requiredWhenEnabled()],
}))

// 狀態帶在**第一次成功讀取之前**不得宣稱任何事實（輪 3）：原本 loading 期間
// configured 仍是初始值 false，於是整條狀態帶以全對比度寫著「尚未設定／尚無目錄
// 設定，目錄使用者無法登入」——而伺服器上可能正躺著一份已啟用的設定。
// v-loading 的遮罩只蓋 el-form，狀態帶在它之外，不帶任何載入線索。
// 這與 H5（OIDC 讀取失敗謊報「尚未設定」）是同一句假話換一條路徑：失敗與
// 「還沒讀到」都屬於「不知道」，不知道就不能斷言。
// loaded 一經置真即不再回退——重新整理期間顯示的是「上一次讀到的事實」，
// 那是陳舊而非虛構
const loaded = ref(false)

const status = computed(() => {
  if (loadFailed.value) return 'load_failed'
  if (!loaded.value) return 'loading'
  if (!configured.value) return 'unconfigured'
  return savedEnabled.value ? 'enabled' : 'disabled'
})

const STATUS_TAG_TYPES = {
  enabled: 'success',
  disabled: 'info',
  unconfigured: 'info',
  loading: 'info',
  load_failed: 'danger',
}
const statusTagType = computed(() => STATUS_TAG_TYPES[status.value] || 'info')
const statusLabel = computed(() => t(`ldapDirectory.status.${status.value}`))
const statusHint = computed(() => t(`ldapDirectory.statusHint.${status.value}`))

// 已儲存的位址是明文 ldap://（M7）：判的是**已儲存**值而非表單草稿——狀態帶
// 述說的一律是伺服端現況。未設定／讀取失敗時不判（沒有「現行連線」可言）
const savedPlaintextRisk = computed(
  () =>
    configured.value &&
    savedEnabled.value &&
    !loadFailed.value &&
    /^ldap:\/\//i.test(savedURL.value)
)

// bind 密碼 placeholder 三態（M1）：勾選清除後欄位雖然 disabled，原本仍寫著
// 「留空則不修改」——與正下方「儲存後既存密碼即被清除且無法還原」直接打臉
const bindPasswordPlaceholder = computed(() => {
  if (form.clear_bind_password) return t('ldapDirectory.bindPasswordClearPlaceholder')
  return savedHasBindPassword.value
    ? t('ldapDirectory.bindPasswordKeepPlaceholder')
    : t('ldapDirectory.bindPasswordPlaceholder')
})

// 恆列三階（M2）：回應未提及的階段＝沒跑到，標為未執行而非消失。
// 以閉集 TEST_STAGES 為骨架，回應中的未知階段一律忽略（不顯示裸機器碼）
const stageRows = computed(() => {
  const reported = new Map(
    (testResult.value?.stages || []).map((s) => [s.stage, s])
  )
  return TEST_STAGES.map((stage) => {
    const hit = reported.get(stage)
    if (!hit) return { stage, state: 'skipped', code: '' }
    return { stage, state: hit.ok ? 'ok' : 'fail', code: hit.code }
  })
})

// matched_count 缺欄或非數時退回 0，避免複數選支拿到 undefined
const matchedCount = computed(() =>
  Number.isFinite(testResult.value?.matched_count) ? testResult.value.matched_count : 0
)

const attrSampleMissing = computed(() => {
  const s = testResult.value?.attr_sample
  return Boolean(s?.sampled) && (!s.email_present || !s.fullname_present)
})

const attrStateClass = (present) => (present ? '' : 'attr-missing')

// 三階全過但一個都沒命中（輪 2 NEW-H2）：`matched_at_least` 為真代表撞到單次
// 上限（那是命中很多，不是沒命中），故必須排除
const noMatch = computed(
  () =>
    Boolean(testResult.value?.success) &&
    testResult.value.matched_at_least !== true &&
    matchedCount.value === 0
)

const testHeadlineType = computed(() => {
  if (!testResult.value?.success) return 'error'
  return noMatch.value ? 'warning' : 'success'
})

// 表單快照：JSON 字面比較就夠（欄位全為原始型別，鍵序由 defaultForm 固定）。
// bind_password 一併入內——打了字沒存也是未儲存的變更
const snapshotOf = () => JSON.stringify({ ...form })
// 最近一次「讀取成功／儲存成功」後的基準值
const savedSnapshot = ref(snapshotOf())
const isDirty = computed(() => snapshotOf() !== savedSnapshot.value)

// 畫面上的測試結果是否已與表單脫節（輪 2 NEW-M3）。
//
// **比較的是會影響測試結果的欄位，不是整份 payload**（輪 3）：原本拿
// `basePayload()` 全欄比較，於是切一下「啟用目錄登入」就跳出「請重新測試」——
// 但 `enabled` 對測試結果毫無影響（後端 ldap_directory_probe.go 的註解與程式碼
// 都寫明：驗證強制以 Enabled=true 計算、閘判定不受請求的 enabled 限縮，該欄
// 只入審計）。而「測通了 → 打開啟用 → 儲存」正是本頁最主要的動線，等於在使用者
// 做對事情的那一刻喊狼來了——重複而無謂的警示只會訓練管理者略過警示（H4 的教訓）。
// name 本就不在 basePayload 內，故無此問題
// 以「剔除清單」而非「納入清單」表述：日後 basePayload 新增欄位會自動納入比較，
// 誤差方向落在「多提醒一次」而非「該提醒卻沒提醒」
const TEST_UNAFFECTED_FIELDS = ['enabled']
const testSignature = () =>
  JSON.stringify(
    Object.fromEntries(
      Object.entries(basePayload()).filter(([key]) => !TEST_UNAFFECTED_FIELDS.includes(key))
    )
  )

const testResultStale = computed(
  () =>
    Boolean(testResult.value || testError.value) &&
    testedSnapshot.value !== '' &&
    testedSnapshot.value !== testSignature()
)

const stageLabel = (stage) =>
  TEST_STAGES.includes(stage) ? t(`ldapDirectory.stage.${stage}`) : stage || ''

const testCodeLabel = (code) =>
  TEST_CODES.includes(code) ? t(`ldapDirectory.testCode.${code}`) : t('ldapDirectory.testCodeUnknown')

// 位址變更且未重供密碼：伺服端會以 400 拒絕，此處只是提前提示。
// **既存無密碼時不提示**——當下沒有憑證可被沿用到新位址
const urlChangedNeedsPassword = computed(
  () =>
    configured.value &&
    savedHasBindPassword.value &&
    !sameLdapEndpoint(savedURL.value, form.url) &&
    !form.bind_password &&
    !form.clear_bind_password
)

const applyView = (view) => {
  const ok = view?.configured === true
  configured.value = ok
  savedURL.value = ok ? view.url || '' : ''
  savedEnabled.value = ok && view.enabled === true
  savedHasBindPassword.value = ok && view.has_bind_password === true

  const next = defaultForm()
  if (ok) {
    next.name = view.name || ''
    next.url = view.url || ''
    next.bind_dn = view.bind_dn || ''
    next.base_dn = view.base_dn || ''
    next.user_filter = view.user_filter || next.user_filter
    next.attr_email = view.attr_email || next.attr_email
    next.attr_fullname = view.attr_fullname || next.attr_fullname
    next.skip_tls_verify = view.skip_tls_verify === true
    next.enabled = view.enabled === true
  }
  Object.assign(form, next)
  // 表單已與伺服端一致，重設「未儲存變更」基準
  savedSnapshot.value = snapshotOf()
}

// 勾選「清除已保存的密碼」時一併清掉輸入框的值（輪 2 NEW-M2）：
// 欄位只是 disabled，先打字再勾選會讓 model 仍留著那串字，於是送出的 body
// 同時帶 bind_password 與 clear_bind_password，伺服端以 400
// 「不可同時填寫新的 bind 密碼與勾選清除密碼」拒絕——而畫面上的欄位是灰的，
// 使用者看不出自己「填了」什麼，也無法在不取消勾選的情況下清掉它
watch(
  () => form.clear_bind_password,
  (on) => {
    if (on) form.bind_password = ''
  }
)

// 註：「切掉啟用開關後必填錯誤仍在」曾被列為候選缺陷，實機 A／B 後排除——
// Element Plus 自己會在規則改變後收掉訊息，先前看到的殘留只是
// validateState 的 100ms debounce 加上觀察太早，不需要另外 clearValidate

const fetchDirectory = async () => {
  loading.value = true
  try {
    applyView(await getLDAPDirectory())
    loadFailed.value = false
    loaded.value = true
  } catch (error) {
    // 讀取失敗不清空表單：使用者可能正在編輯，靜默重置比顯示陳舊值更糟
    loadFailed.value = true
    logFailure('ldap_directory_load_failed', error)
  } finally {
    loading.value = false
  }
}

// 回應缺 count 欄位（非預期形狀）與請求失敗同義：狀態未知一律 fail-safe
const fetchLocalAdminState = async () => {
  try {
    const res = await getLocalAdminCount()
    const count = res?.count
    if (typeof count !== 'number') {
      localAdminState.value = 'unknown'
      return
    }
    localAdminState.value = count > 0 ? 'ok' : 'none'
  } catch (error) {
    localAdminState.value = 'unknown'
    logFailure('local_admin_count_failed', error)
  }
}

// 重新整理會以伺服端的值覆蓋整份表單——對有草稿的人而言就是「丟棄變更」，
// 但按鈕名字聽起來完全無害（輪 2 NEW-M4）。有未儲存變更時先問
const refreshPage = async () => {
  if (isDirty.value) {
    try {
      await ElMessageBox.confirm(
        t('ldapDirectory.discardChangesConfirm'),
        t('ldapDirectory.discardChangesTitle'),
        {
          confirmButtonText: t('ldapDirectory.discardChangesButton'),
          cancelButtonText: t('common.cancel'),
          type: 'warning',
        }
      )
    } catch {
      return
    }
  }
  fetchDirectory()
  fetchLocalAdminState()
}

// 測試與存檔共用的表單值（測的就是未儲存的當下值：先測後存）
const basePayload = () => ({
  url: form.url.trim(),
  bind_dn: form.bind_dn.trim(),
  bind_password: form.bind_password,
  clear_bind_password: form.clear_bind_password,
  base_dn: form.base_dn.trim(),
  user_filter: form.user_filter.trim(),
  attr_email: form.attr_email.trim(),
  attr_fullname: form.attr_fullname.trim(),
  skip_tls_verify: form.skip_tls_verify,
  enabled: form.enabled,
})

/**
 * 傳輸閘 warn 檔的確認迴圈（沿三通道共用契約）：後端回 400＋ACK_REQUIRED＋risks，
 * 使用者確認後帶 `risk_acknowledged: true` 重送。
 *
 * strict 檔位（STRICT_REJECT）**不進本迴圈**——重送無用，由呼叫端就地呈現。
 * @param {(acknowledged: boolean) => Promise} send
 * @param {string} confirmKey 風險確認文案的 i18n 鍵
 */
const withTransportGate = async (send, confirmKey) => {
  let acknowledged = false
  for (;;) {
    try {
      return await send(acknowledged)
    } catch (error) {
      const resp = error?.response
      if (resp?.status === 400 && resp.data?.code === GATE_ACK_REQUIRED && !acknowledged) {
        const risks = Array.isArray(resp.data.risks) ? resp.data.risks : []
        await ElMessageBox.confirm(
          t(confirmKey, {
            risks: risks.map((r) => riskLabel(r)).join(t('common.listSeparator')),
          }),
          t('connect.risksTitle'),
          {
            confirmButtonText: t('connect.risksConfirm'),
            cancelButtonText: t('common.cancel'),
            type: 'warning',
          }
        )
        acknowledged = true
        continue
      }
      throw error
    }
  }
}

// 欄位級 400 的定位：後端以 Meta 的 `field` 帶 wire 欄名（機器值），
// 前端查譯為欄位標籤後前綴於訊息——只說「欄位格式不正確」而不說哪一欄等於沒說
const describeApiError = (resp, fallbackKey) => {
  const message = resolveApiError(resp?.data, resp?.status, t(fallbackKey))
  const field = resp?.data?.field
  const labelKey = `ldapDirectory.fieldLabel.${field}`
  if (field && i18n.global.te(labelKey)) {
    return t('ldapDirectory.fieldErrorPrefix', { field: t(labelKey), message })
  }
  return message
}

/**
 * 驗證失敗時把第一個出問題的欄位捲進視野並取得焦點（輪 2 NEW-H3）。
 *
 * 動作列在三張分區卡之後，實測從頁尾按下儲存、驗證擋下時，**視窗內毫無變化**
 * ——沒有 toast、沒有頁面級警示，唯一的紅字在 350px 之上，焦點還留在按鈕上。
 * 使用者只會覺得按鈕壞了。這與 M3（測試結果在摺線以下）是同一種缺陷。
 * @param {Object} fields Element Plus validate() reject 帶回的無效欄位表
 */
const focusFirstInvalid = async (fields) => {
  const first = fields && typeof fields === 'object' ? Object.keys(fields)[0] : ''
  try {
    if (first) formRef.value?.scrollToField?.(first)
  } catch {
    // jsdom 等環境無 scrollIntoView：捲不動不該讓存檔流程整個爆掉
  }
  await nextTick()
  rootRef.value?.querySelector?.('.el-form-item.is-error input')?.focus?.()
}

const handleSave = async () => {
  formError.value = ''
  if (formRef.value) {
    let invalidFields = null
    const valid = await formRef.value.validate().catch((fields) => {
      invalidFields = fields
      return false
    })
    if (!valid) {
      await focusFirstInvalid(invalidFields)
      return
    }
  }

  saving.value = true
  try {
    const view = await withTransportGate(
      (acknowledged) =>
        updateLDAPDirectory(
          { ...basePayload(), name: form.name.trim(), risk_acknowledged: acknowledged },
          { skipErrorToast: true }
        ),
      'ldapDirectory.saveRiskConfirm'
    )
    applyView(view)
    loadFailed.value = false
    // PUT 的回應同樣是伺服端權威視圖：存檔成功後狀態帶已有事實可說
    loaded.value = true
    // 設定已改變，先前的測試結果不再對應現在的表單
    testResult.value = null
    testError.value = ''
    testedSnapshot.value = ''
    ElMessage.success(t('ldapDirectory.saved'))
  } catch (error) {
    // 非 axios 錯誤＝使用者於風險確認框按取消，不是失敗，不出錯誤態
    if (error?.response) {
      // strict 檔位拒存與拒測同源，但共用碼的通用譯文只把現象重述一次
      // （「設定含不安全傳輸」），沒有下一步；而**儲存才是主要動作**，被擋住的
      // 人多半先按儲存。與 handleTest 同樣就地給出路（UI 審查 H6）
      formError.value =
        error.response.data?.code === GATE_STRICT_REJECT
          ? t('ldapDirectory.saveStrictRejected')
          : describeApiError(error.response, 'ldapDirectory.saveFailed')
      logFailure('ldap_directory_save_failed', error)
    }
  } finally {
    saving.value = false
  }
}

// 測試結果捲進視野（M3）：結果卡在頁尾，實測按下測試後畫面可能毫無變化。
// block: 'nearest' 讓已在視野內時不亂跳
const revealTestResult = async () => {
  await nextTick()
  resultCardRef.value?.$el?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
}

const copyDiagnosticId = async () => {
  try {
    await navigator.clipboard.writeText(testResult.value?.diagnostic_id || '')
    ElMessage.success(t('ldapDirectory.diagnosticIdCopied'))
  } catch {
    ElMessage.warning(t('common.copyFailed'))
  }
}

const handleTest = async () => {
  formError.value = ''
  testError.value = ''
  testResult.value = null
  testing.value = true
  // 送出當下的值即本次結果所對應的設定（含使用者稍後可能再改的欄位）
  testedSnapshot.value = testSignature()
  try {
    testResult.value = await withTransportGate(
      (acknowledged) =>
        testLDAPDirectory(
          { ...basePayload(), risk_acknowledged: acknowledged },
          { skipErrorToast: true }
        ),
      'ldapDirectory.testRiskConfirm'
    )
  } catch (error) {
    const resp = error?.response
    if (!resp) return
    // strict 檔位連測試都拒（測試當下就會送出 bind 密碼，故不受表單啟用開關限縮）：
    // 共用碼的通用譯文說的是「拒絕儲存」，於測試路徑會讀成前後不一
    testError.value =
      resp.data?.code === GATE_STRICT_REJECT
        ? t('ldapDirectory.testStrictRejected')
        : describeApiError(resp, 'ldapDirectory.testFailedGeneric')
    logFailure('ldap_directory_test_failed', error)
  } finally {
    testing.value = false
    // 成敗都要捲：測試「未執行」（傳輸閘、限流）同樣是使用者在等的答案
    if (testResult.value || testError.value) revealTestResult()
  }
}

const handleDelete = async () => {
  try {
    await confirmDestructive(
      t('ldapDirectory.deleteConfirm'),
      t('common.deleteConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
      }
    )
  } catch {
    return
  }
  deleting.value = true
  try {
    await deleteLDAPDirectory()
    ElMessage.success(t('ldapDirectory.deleted'))
    testResult.value = null
    testError.value = ''
    testedSnapshot.value = ''
    formError.value = ''
    await fetchDirectory()
  } catch (error) {
    logFailure('ldap_directory_delete_failed', error)
  } finally {
    deleting.value = false
  }
}

onMounted(() => {
  fetchDirectory()
  // 與設定讀取獨立：任一方失敗不得吞掉另一方
  fetchLocalAdminState()
})
</script>

<style scoped>
.page-alert {
  margin-bottom: var(--ot-space-md);
}

.status-strip {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--ot-space-xs);
  margin-bottom: var(--ot-space-md);
}

.status-strip__label {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.status-strip__hint {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

/* 明文連線風險：與 hint 同尺寸但走警示色，且獨佔一行——接在 hint 後面同一行
   會被讀成同一句的補述，而它講的是相反方向的事 */
.status-strip__risk {
  width: 100%;
  color: var(--ot-warning, #e6a23c);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.section-card {
  margin-bottom: var(--ot-space-md);
}

.card-header {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 12px;
}

.card-title {
  font-weight: 600;
}

.card-hint {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

/* 兩欄併排：屬性名兩欄各自很短，各佔一整行只是把表單拉長 */
.field-row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-md);
}

.field-row__item {
  flex: 1 1 240px;
}

.field-hint {
  /* el-form-item 內容區是 flex，hint 不佔滿寬時會貼在控制項右側讀成同一句 */
  width: 100%;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  margin-top: 4px;
}

.field-warning {
  width: 100%;
  color: var(--ot-warning, #e6a23c);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  margin-top: 4px;
}

.clear-secret {
  width: 100%;
  margin-top: 4px;
}

.action-bar {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-md);
}

.action-bar__hint {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

/* 未儲存變更：與旁邊的中性提示同尺寸但走警示色，否則混在灰字裡等於沒說 */
.action-bar__dirty {
  color: var(--ot-warning, #e6a23c);
  font-size: var(--ot-font-size-xs);
}

/* 結果過期聲明置於結果卡最上方：它限定的是整張卡的可信度 */
.result-stale {
  margin-top: 0;
  margin-bottom: var(--ot-space-xs);
}

.stage-list {
  list-style: none;
  margin: var(--ot-space-sm) 0 0;
  padding: 0;
}

.stage-item {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--ot-space-xs);
  padding: 4px 0;
}

.stage-item--ok {
  color: var(--el-color-success);
}

.stage-item--fail {
  color: var(--el-color-danger);
}

/* 未執行：次要色。不可與失敗同色——「沒跑到」不是「失敗」 */
.stage-item--skipped {
  color: var(--ot-text-secondary);
}

.stage-item__name {
  color: var(--ot-text-primary);
}

.stage-item__state {
  font-size: var(--ot-font-size-xs);
}

.stage-item__reason {
  width: 100%;
  color: var(--el-color-danger);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.result-meta {
  margin-top: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

/* 診斷碼說明另起一行（L7）：原本與碼同一行，讀成「…c37e89a4a027118a 此碼同時…」 */
.result-diagnostic {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.result-diagnostic__line {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--ot-space-xs);
}

.result-diagnostic code {
  word-break: break-all;
}

/* 缺值的屬性與「有值」不得同色——它是這份成功結果裡唯一的壞消息 */
.attr-missing {
  color: var(--ot-warning, #e6a23c);
}

.result-attr-warning {
  margin-top: var(--ot-space-xs);
}

.result-checklist {
  margin-top: var(--ot-space-xs);
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}
</style>
