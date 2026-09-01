<template>
  <div class="oidc-providers">
    <PageHeader
      :title="$t('menu.oidcProviders')"
      :description="$t('oidcProviders.headerDesc')"
    >
      <template #actions>
        <el-button
          type="primary"
          @click="openCreateDialog"
        >
          <el-icon><Plus /></el-icon>
          {{ $t('oidcProviders.create') }}
        </el-button>
        <el-button @click="refreshPage">
          <el-icon><RefreshCw /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 解封能力前提：封印期只認本地 admin 憑證，全員切 SSO 會使遇 KEK
         重啟時無人能解封。**條件式**呈現——
         常駐警語在 count ≥ 1 時是純噪音，只會訓練管理者略過本頁警示區；
         部署前提的教育由 QUICKSTART／.env.example 承載。
         count = 0 才是實際已失能的狀態，升為 error 級；
         讀取失敗時 fail-safe 退回原通用警語（狀態未知不可靜默裝沒事） -->
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
      :title="$t('oidcProviders.localAdminWarningTitle')"
      :description="$t('oidcProviders.localAdminWarningDesc')"
      :closable="false"
      show-icon
    />

    <!-- 讀取失敗：原本 catch 只 log，畫面照常渲染 EmptyState，
         於是伺服器出錯時本頁**主動宣稱**「尚未設定任何 OIDC 提供者」——管理者
         合理推論是設定被刪了，接著去重建或查稽核日誌，全是白工。
         LDAP 頁在同一事件上已明確區分「讀取失敗」與「尚未設定」；同層的兩個
         身分來源頁不得在同一件事上給相反的答案 -->
    <el-alert
      v-if="loadFailed"
      class="page-alert"
      type="error"
      :title="$t('oidcProviders.loadFailedTitle')"
      :description="$t('oidcProviders.loadFailedDesc')"
      :closable="false"
      show-icon
    />

    <!-- 設定不完整（如未設 PUBLIC_BASE_URL）：這類 provider 不會出現在登入頁，
         必須在管理端說清楚，否則表現為「設定好了卻沒有按鈕」 -->
    <el-alert
      v-if="incompleteProviders.length > 0"
      class="page-alert"
      type="error"
      :title="$t('oidcProviders.incompleteTitle', { names: joinNames(incompleteProviders) })"
      :description="incompleteDescription"
      :closable="false"
      show-icon
    />

    <!-- 准入規則不合規：issuer 身分域是**現算**的，部署層移除某 issuer 的
         專屬宣告後，原本合法的規則會就地變成不合規——沒有任何寫入、也沒有任何
         錯誤回應，唯一症狀是「使用者突然無法自動供應而查不到原因」。故必須在
         管理端主動標示，且要說出成因。
         合併為單一 alert：一 provider 一條時，三個不合規
         就把表格推到摺線以下，且每條文案與列內 tooltip 逐字相同——重複的警示
         只會訓練管理者略過警示。成因細節留在列內徽章的 tooltip -->
    <el-alert
      v-if="nonCompliantProviders.length > 0"
      class="page-alert"
      type="error"
      :title="$t('oidcProviders.admissionIssueTitleAll', { names: nonCompliantNames })"
      :description="$t('oidcProviders.admissionIssueMergedDesc')"
      :closable="false"
      show-icon
    />

    <div class="list-card">
      <!-- 欄寬預算（與 Users.vue 同一條規則）——
           1280 視窗下本頁表格可視寬約 978px，下列宣告寬總和 930
           （46+70+200+150+240+112+112）守在該值內，表格不橫捲，
           因此**啟用開關不橫捲即可達**——它會推進憑證世代、重新啟用不復活，
           是本頁安全語義最重的控制項，不可藏在浮層後面。
           Issuer 收成名稱欄的副行、Client ID 與密鑰狀態收進展開列。
           新增欄位前先重算這條加總。 -->
      <el-table
        v-loading="loading"
        :data="providerList"
        style="width: 100%"
        stripe
      >
        <el-table-column
          type="expand"
          width="46"
        >
          <template #default="{ row }">
            <div class="row-detail">
              <div class="row-detail__item">
                <span class="row-detail__label">{{ $t('oidcProviders.issuer') }}</span>
                <span class="row-detail__value">{{ row.issuer }}</span>
              </div>
              <div class="row-detail__item">
                <span class="row-detail__label">{{ $t('oidcProviders.clientId') }}</span>
                <span class="row-detail__value">{{ row.client_id }}</span>
              </div>
              <div class="row-detail__item">
                <span class="row-detail__label">{{ $t('oidcProviders.secretColumn') }}</span>
                <span class="row-detail__value">
                  <el-tag
                    size="small"
                    effect="plain"
                    :type="row.has_secret ? 'success' : 'info'"
                  >
                    {{ row.has_secret
                      ? $t('oidcProviders.secretSet')
                      : $t('oidcProviders.secretUnset') }}
                  </el-tag>
                </span>
              </div>
            </div>
          </template>
        </el-table-column>
        <el-table-column
          prop="id"
          label="ID"
          width="70"
        />
        <el-table-column
          prop="name"
          :label="$t('common.name')"
          min-width="200"
        >
          <template #default="{ row }">
            <span>{{ row.name }}</span>
            <el-tag
              v-if="!row.config_complete"
              class="row-flag"
              type="danger"
              size="small"
              effect="plain"
            >
              {{ $t('oidcProviders.incompleteTag') }}
            </el-tag>
            <el-tooltip
              v-if="isNonCompliant(row)"
              :content="admissionIssueText(row.admission_issue)"
              placement="top"
            >
              <el-tag
                class="row-flag"
                type="danger"
                size="small"
              >
                {{ $t('oidcProviders.admissionIssueTag') }}
              </el-tag>
            </el-tooltip>
            <!-- issuer 收成副行：它是識別「這是哪個 IdP」的關鍵，不能只放展開列，
                 但獨立成欄要 240px，1280 下這一欄就是被浮層吞掉的那一欄 -->
            <el-tooltip
              :content="row.issuer"
              placement="top"
            >
              <div class="cell-sub">
                {{ row.issuer }}
              </div>
            </el-tooltip>
          </template>
        </el-table-column>
        <!-- Issuer 歸屬與**判定來源**：只顯示結果會讓「部署宣告打錯字
             而未生效」表現成「規則設定莫名被拒」，故來源與結果同列。
             欄寬 230：自述式標籤變長後，
             量測三語最長者為 en 的來源標籤「Not declared, defaults to shared」
             （198px）與「Dedicated to this organization」（186px），
             el-tag 不換行、超出即被儲存格無聲裁掉，故取 230（可用 206） -->
        <el-table-column
          :label="$t('oidcProviders.issuerKindColumn')"
          width="230"
        >
          <!-- 欄名自述但不足以承載後果：
               「共用 issuer 上純 Email 網域規則會被拒」是設定時才會撞上的規則，
               寫在表頭 tooltip 才在管理者判讀該欄時就讀得到 -->
          <template #header>
            <el-tooltip
              :content="$t('oidcProviders.issuerKindColumnTooltip')"
              placement="top"
              popper-class="col-header-tip"
            >
              <span class="col-header-hint">{{ $t('oidcProviders.issuerKindColumn') }}</span>
            </el-tooltip>
          </template>
          <template #default="{ row }">
            <el-space
              :size="4"
              wrap
            >
              <el-tag
                size="small"
                :type="row.issuer_kind === 'dedicated' ? 'success' : 'warning'"
              >
                {{ issuerKindLabel(row.issuer_kind) }}
              </el-tag>
              <el-tooltip
                :content="issuerKindSourceTooltip(row.issuer_kind_source)"
                placement="top"
              >
                <el-tag
                  size="small"
                  effect="plain"
                  :type="row.issuer_kind_source === 'unknown_default' ? 'warning' : 'info'"
                >
                  {{ issuerKindSourceLabel(row.issuer_kind_source) }}
                </el-tag>
              </el-tooltip>
            </el-space>
          </template>
        </el-table-column>
        <!-- 不合規時准入模式必須就地顯示「已停止」：
             橫向掃表格的管理者會把「依規則自動供應」讀成生效中，名稱旁的小徽章
             容易被略過，兩者並存等於畫面自相矛盾。
             欄寬：太窄裝不下三語的「模式＋（已停止）」，
             而 el-tag 是 inline-block，儲存格的 text-overflow 對它不生效——
             畫面上會出現一個紅色但寫著「依規則自動供應」的標籤，**無聲**丟掉
             「（已停止）」，等於回到修法前的自相矛盾狀態。280 取三語最長者
             （後量測為 ja「ルールに基づく自動作成
             （JIT）（停止中）」243px、en「Auto-provision by rules (JIT)
             (stopped)」236px）定寬；tooltip 與標籤內的省略號是兜底，任何
             未預期的長度都不會再無聲截斷 -->
        <el-table-column
          :label="$t('oidcProviders.admissionColumn')"
          width="280"
        >
          <!-- 「准入模式」是既有 zh 企業安全詞、名稱不改，語義改由表頭
               tooltip 承載：每次登入都重判、兩模式各自的後果 -->
          <template #header>
            <el-tooltip
              :content="$t('oidcProviders.admissionColumnTooltip')"
              placement="top"
              popper-class="col-header-tip"
            >
              <span class="col-header-hint">{{ $t('oidcProviders.admissionColumn') }}</span>
            </el-tooltip>
          </template>
          <template #default="{ row }">
            <el-tooltip
              :content="admissionModeCellLabel(row)"
              placement="top"
            >
              <el-tag
                class="admission-tag"
                size="small"
                effect="plain"
                :type="admissionTagType(row)"
              >
                {{ admissionModeCellLabel(row) }}
              </el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.status')"
          width="112"
        >
          <template #default="{ row }">
            <el-switch
              v-model="row.enabled"
              :loading="row._statusLoading"
              :aria-label="$t('oidcProviders.toggleAria', { name: row.name })"
              @change="handleEnabledChange(row)"
            />
          </template>
        </el-table-column>
        <!-- 操作欄**不再 fixed**：fixed 是浮在內容上的浮層，
             1280 下它蓋掉了准入模式、密鑰與**啟用開關**——正是本頁最該看見的三欄。
             欄寬總和已收在可視寬內，不橫捲就不需要 fixed -->
        <el-table-column
          :label="$t('common.actions')"
          width="112"
        >
          <template #default="{ row }">
            <el-button
              type="primary"
              size="small"
              link
              @click="openEditDialog(row)"
            >
              {{ $t('common.edit') }}
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
        <!-- 空狀態必須說得出「空是因為什麼」：讀取失敗時不得沿用
             「尚未設定任何提供者」——那是一句假的事實陳述。
             **讀取尚未回來時同樣不得說**：清單當下是空的，原因是還沒讀到，
             不是沒有設定；實測延遲 GET 期間畫面就寫著「尚未設定任何 OIDC 提供者」，
             與失敗態是同一句假話換一條路徑。載入中交由 v-loading 的遮罩與 spinner
             說明，本區塊保持沉默——不知道就不說 -->
        <template #empty>
          <EmptyState
            v-if="!loading"
            :title="loadFailed
              ? $t('oidcProviders.emptyLoadFailedTitle')
              : $t('oidcProviders.emptyTitle')"
            :hint="loadFailed
              ? $t('oidcProviders.emptyLoadFailedHint')
              : $t('oidcProviders.emptyHint')"
          />
        </template>
      </el-table>
    </div>

    <!-- 單頁 Modal 表單（不做多步精靈——欄位總量小，分步只增加來回） -->
    <el-dialog
      v-model="dialogVisible"
      :title="isEdit ? $t('oidcProviders.editTitle') : $t('oidcProviders.create')"
      width="640px"
      :close-on-click-modal="false"
    >
      <el-form
        ref="formRef"
        :model="form"
        :rules="formRules"
        label-position="top"
      >
        <el-form-item
          :label="$t('common.name')"
          prop="name"
        >
          <el-input
            v-model="form.name"
            maxlength="100"
            :placeholder="$t('oidcProviders.namePlaceholder')"
          />
        </el-form-item>

        <!-- issuer／client_id 是外部身分的鍵，建後不可變（後端亦強制，非僅前端停用）。
             停用輸入時必須說明原因，否則使用者只會看到「灰掉的欄位」 -->
        <el-form-item
          :label="$t('oidcProviders.issuer')"
          prop="issuer"
        >
          <el-tooltip
            :disabled="!isEdit"
            :content="$t('oidcProviders.immutableTooltip')"
            placement="top"
          >
            <el-input
              v-model="form.issuer"
              :disabled="isEdit"
              :placeholder="$t('oidcProviders.issuerPlaceholder')"
            />
          </el-tooltip>
          <div
            v-if="isEdit"
            class="field-hint"
          >
            {{ $t('oidcProviders.immutableTooltip') }}
          </div>
          <div
            v-if="azureMultiTenantWarning"
            class="field-warning"
          >
            {{ azureMultiTenantWarning }}
          </div>
        </el-form-item>

        <el-form-item
          :label="$t('oidcProviders.clientId')"
          prop="client_id"
        >
          <el-tooltip
            :disabled="!isEdit"
            :content="$t('oidcProviders.immutableTooltip')"
            placement="top"
          >
            <el-input
              v-model="form.client_id"
              :disabled="isEdit"
              :placeholder="$t('oidcProviders.clientIdPlaceholder')"
            />
          </el-tooltip>
        </el-form-item>

        <!-- write-only：讀取回應永不含密鑰的任何形式，故編輯時只能覆寫不能檢視 -->
        <el-form-item :label="$t('oidcProviders.clientSecret')">
          <el-input
            v-model="form.client_secret"
            type="password"
            show-password
            autocomplete="new-password"
            :placeholder="isEdit && hasSecret
              ? $t('oidcProviders.secretKeepPlaceholder')
              : $t('oidcProviders.secretPlaceholder')"
          />
          <div
            v-if="isEdit && form.client_secret"
            class="field-warning"
          >
            {{ $t('oidcProviders.secretRotateWarning') }}
          </div>
        </el-form-item>

        <el-form-item :label="$t('oidcProviders.scopes')">
          <el-checkbox-group v-model="form.scopeExtras">
            <el-checkbox value="profile">
              profile
            </el-checkbox>
            <el-checkbox value="email">
              email
            </el-checkbox>
          </el-checkbox-group>
          <div class="field-hint">
            {{ $t('oidcProviders.scopesHint') }}
          </div>
        </el-form-item>

        <!-- 准入模式與規則為表單一等公民，預設 prebound_only -->
        <el-form-item :label="$t('oidcProviders.admissionMode')">
          <el-radio-group v-model="form.admission_mode">
            <el-radio value="prebound_only">
              {{ $t('oidcProviders.admission.prebound_only') }}
            </el-radio>
            <el-radio value="jit_with_rules">
              {{ $t('oidcProviders.admission.jit_with_rules') }}
            </el-radio>
          </el-radio-group>
          <div class="field-hint">
            {{ $t(`oidcProviders.admissionHint.${form.admission_mode}`) }}
          </div>
          <!-- 「僅預先綁定」的效力**限制**（spec OA-4 SHALL 於管理介面明示）：
               它只檢查「身分是否已綁定」，故 IdP 端已刪除／停用的帳號進不來，
               但「帳號仍存續、組織歸屬已變更」（離職留帳號、轉調他租戶）不涵蓋。
               與下方的「切換語義」提示是兩件事，不可互相取代 -->
          <el-alert
            v-if="form.admission_mode === 'prebound_only'"
            class="inline-alert"
            type="info"
            :title="$t('oidcProviders.preboundLimitationTitle')"
            :description="$t('oidcProviders.preboundLimitationDesc')"
            :closable="false"
            show-icon
          />
          <el-alert
            v-if="preboundSwitchNotice"
            class="inline-alert"
            type="warning"
            :title="$t('oidcProviders.preboundSwitchTitle')"
            :description="preboundSwitchDesc"
            :closable="false"
            show-icon
          />
        </el-form-item>

        <template v-if="form.admission_mode === 'jit_with_rules'">
          <el-form-item :label="$t('oidcProviders.ruleTid')">
            <el-select
              v-model="form.rules.tid"
              multiple
              filterable
              allow-create
              default-first-option
              :reserve-keyword="false"
              class="rule-select"
              :placeholder="$t('oidcProviders.ruleListPlaceholder')"
            />
            <div class="field-hint">
              {{ $t('oidcProviders.ruleTidHint') }}
            </div>
          </el-form-item>
          <el-form-item :label="$t('oidcProviders.ruleHd')">
            <el-select
              v-model="form.rules.hd"
              multiple
              filterable
              allow-create
              default-first-option
              :reserve-keyword="false"
              class="rule-select"
              :placeholder="$t('oidcProviders.ruleListPlaceholder')"
            />
            <div class="field-hint">
              {{ $t('oidcProviders.ruleHdHint') }}
            </div>
          </el-form-item>
          <el-form-item :label="$t('oidcProviders.ruleEmailDomain')">
            <el-select
              v-model="form.rules.email_domain"
              multiple
              filterable
              allow-create
              default-first-option
              :reserve-keyword="false"
              class="rule-select"
              :placeholder="$t('oidcProviders.ruleListPlaceholder')"
            />
            <div class="field-hint">
              {{ $t('oidcProviders.ruleEmailDomainHint') }}
            </div>
          </el-form-item>
          <el-form-item :label="$t('oidcProviders.ruleEmailVerified')">
            <el-switch v-model="form.rules.email_verified" />
            <div class="field-hint">
              {{ $t('oidcProviders.ruleEmailVerifiedHint') }}
            </div>
          </el-form-item>
        </template>

        <el-form-item :label="$t('oidcProviders.forceShared')">
          <el-switch v-model="form.force_shared" />
          <div class="field-hint">
            {{ $t('oidcProviders.forceSharedHint') }}
          </div>
        </el-form-item>

        <el-form-item :label="$t('common.status')">
          <el-switch
            v-model="form.enabled"
            :active-text="$t('common.enabled')"
            :inactive-text="$t('common.disabled')"
          />
        </el-form-item>

        <el-alert
          v-if="formError"
          class="inline-alert"
          type="error"
          :title="formError"
          :closable="false"
          show-icon
        />
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="submitting"
          @click="submitForm"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Plus, RefreshCw } from 'lucide-vue-next'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { t } from '@/i18n'
import { confirmDestructive } from '@/utils/confirm'
import { apiErrorSummary } from '@/api/redact'
import {
  getOIDCProviders,
  createOIDCProvider,
  updateOIDCProvider,
  deleteOIDCProvider,
} from '@/api/oidc'
import { getLocalAdminCount } from '@/api/user'

// Azure 多租戶端點：discovery 的 issuer 字面帶 {tenantid} placeholder，
// 嚴格 issuer 比對必失敗（design 0.3 實查）。輸入當下就診斷，不等到登入才炸
const AZURE_MULTI_TENANT = /login\.microsoftonline\.com\/(common|organizations|consumers)(\/|$)/i

const ISSUER_KINDS = ['dedicated', 'shared']
const ISSUER_KIND_SOURCES = ['deploy_declared', 'builtin_list', 'admin_forced', 'unknown_default']
const ADMISSION_MODES = ['prebound_only', 'jit_with_rules']
const INCOMPLETE_HINTS = ['public_base_url_missing']
// 不合規成因機器碼（硬拷後端 service/oidc_provider_service.go:192 admissionIssueCode，
// 含其 default 分支的 invalid_rules）。未列於此者以通用文案呈現，不顯示裸機器碼
const ADMISSION_ISSUES = [
  'shared_needs_org_rule',
  'empty_rule_set',
  'consumer_tenant',
  'email_needs_verified',
  'unknown_rule',
  'invalid_rules',
]

// 元件層日誌只留白名單欄位：本頁請求本文帶 client_secret
const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

const loading = ref(false)
const loadFailed = ref(false)
const providerList = ref([])

// 本地管理員警示三態：
//   'ok'      讀到 count ≥ 1 → 不顯示（初始值刻意是 ok，載入中不閃警語）
//   'none'    讀到 count = 0 → error 級常駐警示
//   'unknown' 讀取失敗 → fail-safe 退回 warning 級通用警語
// 不用 count 數字本身做判斷：null／undefined 會被 `>= 1` 誤判為安全
const localAdminState = ref('ok')

const dialogVisible = ref(false)
const isEdit = ref(false)
const hasSecret = ref(false)
const submitting = ref(false)
const formError = ref('')
const formRef = ref(null)
// 進入編輯時的原始准入模式：用於「切為僅預先綁定」的語義提示
const originalAdmissionMode = ref('')
// 進入編輯時該 provider 的已綁定身分數：語義提示要給具體影響面
const editingIdentityCount = ref(null)

const emptyRules = () => ({ tid: [], hd: [], email_domain: [], email_verified: false })

const form = reactive({
  id: null,
  name: '',
  issuer: '',
  client_id: '',
  client_secret: '',
  scopeExtras: ['profile', 'email'],
  admission_mode: 'prebound_only',
  force_shared: false,
  enabled: true,
  rules: emptyRules(),
})

const formRules = computed(() => ({
  name: [{ required: true, message: t('oidcProviders.nameRequired'), trigger: 'blur' }],
  issuer: [
    { required: true, message: t('oidcProviders.issuerRequired'), trigger: 'blur' },
    {
      validator: (_rule, value, callback) => {
        if (!isEdit.value && value && !/^https:\/\//i.test(value.trim())) {
          callback(new Error(t('oidcProviders.issuerMustBeHttps')))
          return
        }
        callback()
      },
      trigger: 'blur',
    },
  ],
  client_id: [{ required: true, message: t('oidcProviders.clientIdRequired'), trigger: 'blur' }],
}))

const labelOf = (allowed, section, value) =>
  allowed.includes(value) ? t(`oidcProviders.${section}.${value}`) : value || '—'

const issuerKindLabel = (v) => labelOf(ISSUER_KINDS, 'issuerKind', v)
const issuerKindSourceLabel = (v) => labelOf(ISSUER_KIND_SOURCES, 'issuerKindSource', v)
const issuerKindSourceTooltip = (v) =>
  ISSUER_KIND_SOURCES.includes(v) ? t(`oidcProviders.issuerKindSourceHint.${v}`) : ''
const admissionModeLabel = (v) => labelOf(ADMISSION_MODES, 'admission', v)

const incompleteProviders = computed(() =>
  providerList.value.filter((p) => !p.config_complete).map((p) => p.name)
)

const incompleteDescription = computed(() => {
  const hint = providerList.value.find((p) => !p.config_complete)?.incomplete_hint
  return INCOMPLETE_HINTS.includes(hint)
    ? t(`oidcProviders.incompleteHint.${hint}`)
    : t('oidcProviders.incompleteHintGeneric')
})

// 只認**顯式的 false**：舊後端未回此欄時不可把全部 provider 標成不合規
const isNonCompliant = (row) => row?.admission_compliant === false

const nonCompliantProviders = computed(() => providerList.value.filter(isNonCompliant))

// 清單分隔符由語系決定：「、」是中日排版符號，英文介面應為逗號
const joinNames = (names) => names.join(t('common.listSeparator'))

const nonCompliantNames = computed(() => joinNames(nonCompliantProviders.value.map((p) => p.name)))

// 不合規時：模式文字補「已停止」，色階由 warning 降為 danger
const admissionModeCellLabel = (row) =>
  isNonCompliant(row)
    ? t('oidcProviders.admissionModeStopped', { mode: admissionModeLabel(row.admission_mode) })
    : admissionModeLabel(row.admission_mode)

const admissionTagType = (row) => {
  if (isNonCompliant(row)) return 'danger'
  return row.admission_mode === 'jit_with_rules' ? 'warning' : 'info'
}

const admissionIssueText = (issue) =>
  ADMISSION_ISSUES.includes(issue)
    ? t(`oidcProviders.admissionIssue.${issue}`)
    : t('oidcProviders.admissionIssueGeneric')

const azureMultiTenantWarning = computed(() =>
  AZURE_MULTI_TENANT.test(form.issuer || '') ? t('oidcProviders.azureMultiTenantWarning') : ''
)

// 由「規則模式」切回「僅預先綁定」：既有已綁定身分不受影響、未綁定者自此無法登入。
// 這是語義變更而非開關，須在送出前講明
const preboundSwitchNotice = computed(
  () =>
    isEdit.value &&
    originalAdmissionMode.value === 'jit_with_rules' &&
    form.admission_mode === 'prebound_only'
)

// 影響面要給**具體數字**：只說「既有身分不受影響」，管理者無從判斷這個切換
// 涉及幾個人。identity_count 缺欄時退回無數字版本（不假裝知道）
const preboundSwitchDesc = computed(() => {
  const n = editingIdentityCount.value
  return typeof n === 'number'
    ? t('oidcProviders.preboundSwitchDescCount', { count: n })
    : t('oidcProviders.preboundSwitchDesc')
})

const fetchProviders = async () => {
  loading.value = true
  try {
    const res = await getOIDCProviders()
    providerList.value = (res?.data || []).map((p) => ({ ...p, _statusLoading: false }))
    loadFailed.value = false
  } catch (error) {
    // 清單不清空：讀取失敗時把先前讀到的內容抹掉，等於把「曾經讀到什麼」也一起
    // 丟了；由 loadFailed 負責聲明畫面不代表現況（與 LDAP 頁同一決定）
    loadFailed.value = true
    logFailure('oidc_provider_list_failed', error)
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

// 手動重新整理同時重讀警示狀態：管理者在他處補建本地 admin 後回本頁按重新整理，
// 警示必須跟著消失，否則會被當成「修了也不會好」的假警報
const refreshPage = () => {
  fetchProviders()
  fetchLocalAdminState()
}

const resetForm = () => {
  form.id = null
  form.name = ''
  form.issuer = ''
  form.client_id = ''
  form.client_secret = ''
  form.scopeExtras = ['profile', 'email']
  form.admission_mode = 'prebound_only'
  form.force_shared = false
  form.enabled = true
  form.rules = emptyRules()
  formError.value = ''
}

const openCreateDialog = () => {
  isEdit.value = false
  hasSecret.value = false
  originalAdmissionMode.value = ''
  editingIdentityCount.value = null
  resetForm()
  dialogVisible.value = true
  formRef.value?.clearValidate()
}

// 規則 JSON 解析容錯：後端存的是字串，格式異常時不可讓整個對話框開不起來
const parseRules = (raw) => {
  const rules = emptyRules()
  if (!raw) return rules
  try {
    const parsed = JSON.parse(raw)
    rules.tid = Array.isArray(parsed.tid) ? parsed.tid : []
    rules.hd = Array.isArray(parsed.hd) ? parsed.hd : []
    rules.email_domain = Array.isArray(parsed.email_domain) ? parsed.email_domain : []
    rules.email_verified = parsed.email_verified === true
  } catch {
    console.warn('oidc_admission_rules_parse_failed')
  }
  return rules
}

const openEditDialog = (row) => {
  isEdit.value = true
  hasSecret.value = Boolean(row.has_secret)
  resetForm()
  form.id = row.id
  form.name = row.name
  form.issuer = row.issuer
  form.client_id = row.client_id
  form.scopeExtras = String(row.scopes || '')
    .split(/\s+/)
    .filter((s) => s && s !== 'openid')
  form.admission_mode = ADMISSION_MODES.includes(row.admission_mode)
    ? row.admission_mode
    : 'prebound_only'
  // DTO 不直接回 force_shared，由判定來源反推。唯一失真情形是「issuer 本就在
  // 內建共用清單」——此時來源恆為 builtin_list，開關顯示為關且送出會寫回 false，
  // 但該 issuer 本來就是共用，強制與否對 effective 判定無差別（只能收緊的開關對
  // 已經最緊的狀態是 no-op），故不影響准入把關
  form.force_shared = row.issuer_kind_source === 'admin_forced'
  form.enabled = row.enabled
  form.rules = parseRules(row.admission_rules)
  originalAdmissionMode.value = form.admission_mode
  editingIdentityCount.value =
    typeof row.identity_count === 'number' ? row.identity_count : null
  dialogVisible.value = true
  formRef.value?.clearValidate()
}

const buildRulesJSON = () => {
  const payload = {}
  const trimList = (list) => list.map((v) => String(v).trim()).filter(Boolean)
  if (form.rules.tid.length) payload.tid = trimList(form.rules.tid)
  if (form.rules.hd.length) payload.hd = trimList(form.rules.hd)
  if (form.rules.email_domain.length) payload.email_domain = trimList(form.rules.email_domain)
  if (form.rules.email_verified) payload.email_verified = true
  return JSON.stringify(payload)
}

const hasAnyRule = () =>
  form.rules.tid.length > 0 ||
  form.rules.hd.length > 0 ||
  form.rules.email_domain.length > 0 ||
  form.rules.email_verified

const submitForm = async () => {
  formError.value = ''
  if (formRef.value) {
    const valid = await formRef.value.validate().catch(() => false)
    if (!valid) return
  }
  // 自動供應必須有規則：後端亦拒，但就近擋下省一次來回
  if (form.admission_mode === 'jit_with_rules' && !hasAnyRule()) {
    formError.value = t('oidcProviders.rulesRequired')
    return
  }

  const payload = {
    name: form.name.trim(),
    scopes: ['openid', ...form.scopeExtras].join(' '),
    admission_mode: form.admission_mode,
    admission_rules: buildRulesJSON(),
    force_shared: form.force_shared,
    enabled: form.enabled,
  }
  if (!isEdit.value) {
    payload.issuer = form.issuer.trim()
    payload.client_id = form.client_id.trim()
  }
  // 留空即沿用既有密鑰（write-only 欄位的唯一可用語義）
  if (form.client_secret.trim()) {
    payload.client_secret = form.client_secret
  }

  submitting.value = true
  try {
    if (isEdit.value) {
      await updateOIDCProvider(form.id, payload)
      ElMessage.success(t('oidcProviders.updated'))
    } else {
      await createOIDCProvider(payload)
      ElMessage.success(t('oidcProviders.created'))
    }
    dialogVisible.value = false
    fetchProviders()
  } catch (error) {
    logFailure('oidc_provider_save_failed', error)
  } finally {
    submitting.value = false
  }
}

// 停用會推進憑證世代（既簽憑證永久失效，重新啟用不復活）——不可靜默切換
const handleEnabledChange = async (row) => {
  const next = row.enabled
  if (!next) {
    try {
      await confirmDestructive(
        t('oidcProviders.disableConfirm', { name: row.name }),
        t('oidcProviders.disableConfirmTitle'),
        {
          confirmButtonText: t('common.confirm'),
          cancelButtonText: t('common.cancel'),
        }
      )
    } catch {
      row.enabled = true
      return
    }
  }
  row._statusLoading = true
  try {
    await updateOIDCProvider(row.id, { name: row.name, enabled: next })
    ElMessage.success(next ? t('oidcProviders.enabled') : t('oidcProviders.disabled'))
    fetchProviders()
  } catch (error) {
    row.enabled = !next
    logFailure('oidc_provider_toggle_failed', error)
  } finally {
    row._statusLoading = false
  }
}

const handleDelete = async (row) => {
  try {
    await confirmDestructive(
      t('oidcProviders.deleteConfirm', { name: row.name }),
      t('common.deleteConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
      }
    )
  } catch {
    return
  }
  try {
    await deleteOIDCProvider(row.id)
    ElMessage.success(t('oidcProviders.deleted'))
    fetchProviders()
  } catch (error) {
    // 409（仍有外部身分關聯）由全域攔截器以 apiError 譯文提示
    logFailure('oidc_provider_delete_failed', error)
  }
}

onMounted(() => {
  fetchProviders()
  // 與 provider 清單獨立：任一方失敗不得吞掉另一方（警示的可靠性不依賴清單載入）
  fetchLocalAdminState()
})
</script>

<style scoped>
.page-alert {
  margin-bottom: var(--ot-space-md);
}

.list-card {
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-md);
}

.row-flag {
  margin-left: var(--ot-space-xs);
}

/* 帶說明的欄位標頭：虛線下標示可 hover 取得 tooltip（與 Users／UserExternalIdentities 同慣例） */
.col-header-hint {
  border-bottom: 1px dashed var(--ot-border-subtle);
  cursor: help;
}

/* 准入模式標籤：el-tag 是 inline-block，儲存格的
   text-overflow 對它不生效——超寬時直接被儲存格的 overflow:hidden 裁掉，
   畫面上沒有任何被截斷的線索。這裡讓標籤自己收在儲存格內並以省略號收尾，
   完整文字在 tooltip；欄寬已放到三語都裝得下，此為兜底 */
.admission-tag {
  max-width: 100%;
}

.admission-tag :deep(.el-tag__content) {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* issuer 副行：與名稱同讀，超長 URL 以省略號收尾（完整值在 tooltip 與展開列） */
.cell-sub {
  margin-top: 2px;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* 展開列：Issuer 全文、Client ID 與密鑰狀態 */
.row-detail {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: var(--ot-space-xs) var(--ot-space-md);
  padding: var(--ot-space-xs) var(--ot-space-md);
}

.row-detail__item {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  min-height: 28px;
}

.row-detail__label {
  flex: none;
  min-width: 72px;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.row-detail__value {
  word-break: break-all;
}

.field-hint {
  /* el-form-item 內容區是 flex，hint 不佔滿寬時會貼在 checkbox 右側，
     讀成「email + 提示文字」同一句 */
  width: 100%;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  margin-top: 4px;
}

.field-warning {
  color: var(--ot-warning, #e6a23c);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  margin-top: 4px;
}

.inline-alert {
  margin-top: var(--ot-space-xs);
}

.rule-select {
  width: 100%;
}
</style>

<style>
/* tooltip teleport 至 body，scoped 樣式打不到，須全域。
   表頭說明是完整句子，無上限時會拉成橫跨整個視窗的單行（讀不動）；
   限寬後才會折成可讀的段落 */
.col-header-tip {
  max-width: 460px;
  line-height: 1.6;
}
</style>
