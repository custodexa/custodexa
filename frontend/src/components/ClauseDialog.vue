<template>
  <el-dialog
    v-model="visible"
    :title="isEdit ? $t('clauseDialog.editTitle') : $t('clauseDialog.createTitle')"
    width="720px"
  >
    <el-form
      label-position="top"
      @submit.prevent
    >
      <el-form-item :label="$t('clauseDialog.clauseNoField')">
        <el-input
          v-model="form.clause_no"
          :disabled="isEdit"
          maxlength="64"
        />
        <div class="field-hint">
          {{ $t('clauseDialog.clauseNoHint') }}
        </div>
      </el-form-item>

      <el-form-item :label="$t('clauseDialog.titleField')">
        <el-input
          v-model="form.title"
          :placeholder="$t('clauseDialog.titlePlaceholder')"
          maxlength="300"
        />
      </el-form-item>

      <el-form-item :label="$t('clauseDialog.summaryField')">
        <el-input
          v-model="form.summary"
          type="textarea"
          :rows="2"
        />
      </el-form-item>

      <el-form-item :label="$t('clauseDialog.kindField')">
        <el-radio-group v-model="form.kind">
          <el-radio value="setting">
            {{ $t('clauseDialog.kindSetting') }}
          </el-radio>
          <el-radio value="self_attested">
            {{ $t('clauseDialog.kindSelfAttested') }}
          </el-radio>
        </el-radio-group>
        <div class="field-hint">
          {{ form.kind === 'setting'
            ? $t('clauseDialog.kindSettingHint')
            : $t('clauseDialog.kindSelfAttestedHint') }}
        </div>
      </el-form-item>

      <template v-if="form.kind === 'setting'">
        <div class="controls-label">
          {{ $t('clauseDialog.controlsField') }}
        </div>
        <div
          v-for="(row, index) in controls"
          :key="index"
          class="control-row"
        >
          <div class="control-fields">
            <el-select
              v-model="row.policy_key"
              filterable
              class="control-key"
              :placeholder="$t('clauseDialog.keyPlaceholder')"
              @change="loadDef(row)"
            >
              <el-option
                v-for="policy in selectableKeys"
                :key="policy.key"
                :label="settingLabel(policy.key)"
                :value="policy.key"
              />
            </el-select>

            <el-select
              v-model="row.comparator"
              class="control-comparator"
            >
              <el-option
                v-for="option in comparatorOptions(row)"
                :key="option.value"
                :label="option.label"
                :value="option.value"
              />
            </el-select>

            <el-input-number
              v-if="row.comparator !== 'review' && row.def && row.def.type === 'int'"
              v-model="row.expected_value"
              class="control-value"
              :controls-position="'right'"
            />
            <el-select
              v-else-if="row.comparator !== 'review' && row.def"
              v-model="row.expected_value"
              class="control-value"
            >
              <el-option
                v-for="option in valueOptions(row)"
                :key="option.value"
                :label="option.label"
                :value="option.value"
              />
            </el-select>

            <el-button
              text
              @click="removeControl(index)"
            >
              {{ $t('clauseDialog.removeControl') }}
            </el-button>
          </div>

          <p
            v-if="rowError(row)"
            class="control-error"
          >
            {{ rowError(row) }}
          </p>
          <p class="after-save">
            {{ $t('clauseDialog.afterSaveTitle') }}：{{ afterSaveText(row) }}
          </p>
        </div>

        <el-button
          text
          type="primary"
          @click="addControl"
        >
          {{ $t('clauseDialog.addControl') }}
        </el-button>
      </template>

      <p
        v-if="formError"
        class="form-error"
      >
        {{ formError }}
      </p>
    </el-form>

    <template #footer>
      <el-button @click="visible = false">
        {{ $t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :loading="saving"
        @click="submit"
      >
        {{ $t('common.save') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { getPolicyKeyDef, upsertPolicyClause } from '@/api/policyGroups'
import { previewCompliance } from '@/api/securityPolicies'
import { resolveApiError } from '@/api/error'
import { displayPolicyValue, resultLabel, settingLabel } from '@/utils/policyClauseText'
import { enumLabel } from '@/utils/policyFormat'

// 條文的新增與編輯。
//
// 要求欄的第一個選項是「有要求但不定值」，而且是預設值：條文寫的若是
// 「使用足夠強度之加密」這類語境式要求，系統不替它發明一個數字——發明出來的
// 門檻在報告上看起來和規範明定的一樣有出處，而它沒有。選了就不必填值。
//
// 值域檢查在送出前做一次，端點自己也會再驗一次。前面這一次不是為了省一趟往返，
// 是為了讓「不能填 9999」出現在那一格旁邊，而不是變成一則飄過去的錯誤通知。
//
// **「儲存後結果」不在前端算**：它打草稿判定端點，把正在編輯的這一項當成臨時
// 控制送過去，由後端用同一套比較器算。前端另算一份會與伺服器漂移，而分歧不會
// 有任何一處報錯——本檔在此之前就出現過「值域紅字說不能存，同一列卻預告儲存後
// 符合」這種畫面。前端只留輸入提示。

// 打端點前的去抖：數字欄每敲一下算一次是浪費，等使用者停手再問
const AFTER_SAVE_DEBOUNCE_MS = 300

// 尚未編號的新條文也要看得到結果。條號不影響判定（覆蓋以組代號與設定鍵為準），
// 這個代稱只出現在這一次唯讀的預覽請求裡，不會被寫進任何一張表
const DRAFT_CLAUSE_NO = 'draft'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  groupCode: { type: String, required: true },
  // 既有條文（編輯模式）；null＝新增
  clause: { type: Object, default: null },
  // 可選的設定鍵清單（政策列表的原形，至少含 key 與 type）
  policies: { type: Array, default: () => [] },
})

const emit = defineEmits(['update:modelValue', 'saved'])

const { t } = useI18n()

const emptyForm = () => ({ clause_no: '', title: '', summary: '', kind: 'setting' })

const form = ref(emptyForm())
const controls = ref([])
const saving = ref(false)
const formError = ref('')

const visible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value),
})

const isEdit = computed(() => !!props.clause)

// 自由文字型的鍵不可作為要求對象：沒有一種比較方式對一段文字是有意義的
const selectableKeys = computed(() => props.policies.filter((p) => p.type !== 'text'))

const newControl = () => ({
  policy_key: '',
  comparator: 'review',
  expected_value: '',
  def: null,
  // 儲存後結果的取得狀態：''（無）、'pending'、'ready'、'failed'
  afterSaveStatus: '',
  afterSaveVerdict: null,
  // 逐列的請求版本：只有最後一次送出的回應能寫進這一列
  afterSaveVersion: 0,
  afterSaveTimer: null,
})

const addControl = () => {
  controls.value.push(newControl())
}

const removeControl = (index) => {
  controls.value.splice(index, 1)
}

const loadDef = async (row) => {
  row.def = null
  if (!row.policy_key) return
  try {
    const res = await getPolicyKeyDef(row.policy_key)
    row.def = res.data || null
    // 換了鍵就換一套值域與可選值，舊的要求值留著只會變成另一個鍵上的錯值
    row.comparator = 'review'
    row.expected_value = ''
  } catch (error) {
    console.error('取得設定定義失敗:', error)
  }
}

const comparatorOptions = (row) => {
  const labels = {
    review: t('clauseDialog.comparatorReview'),
    min: t('clauseDialog.comparatorMin'),
    max: t('clauseDialog.comparatorMax'),
    equals: t('clauseDialog.comparatorEquals'),
  }
  const rest = (row.def?.comparators || []).filter((c) => c !== 'review')
  return ['review', ...rest].map((value) => ({ value, label: labels[value] || value }))
}

const valueOptions = (row) => {
  if (!row.def) return []
  if (row.def.type === 'bool') {
    return [
      { value: 'true', label: t('policyValue.on') },
      { value: 'false', label: t('policyValue.off') },
    ]
  }
  return (row.def.enum_order || []).map((value) => ({
    value,
    label: enumLabel({ key: row.def.key }, value),
  }))
}

// 上界為 0 的語義是「沿用共用上界」而不是「沒有上界」，故 0 一律不當成界線
const boundsOf = (def) => ({
  min: def?.min || 0,
  max: def?.max || 0,
})

const rowError = (row) => {
  if (!row.def || row.comparator === 'review') return ''
  if (row.expected_value === '' || row.expected_value === null) return ''
  if (row.def.type !== 'int') return ''
  const value = Number(row.expected_value)
  if (Number.isNaN(value)) return t('clauseDialog.valueRequired')
  const { min, max } = boundsOf(row.def)
  const outOfRange =
    (max && value > max) || (min && value < min && !(row.def.zero_disables && value === 0))
  if (!outOfRange) return ''
  return t('clauseDialog.outOfRange', { min, max: max || '—' })
}

// 這一列送去判定時的臨時控制。同組同鍵覆蓋既有控制，只影響那一次回應
const tempControlOf = (row) => ({
  group_code: props.groupCode,
  clause_no: form.value.clause_no.trim() || DRAFT_CLAUSE_NO,
  policy_key: row.policy_key,
  comparator: row.comparator,
  expected_value: row.comparator === 'review' ? '' : String(row.expected_value),
  reference_only: false,
})

// 值域錯誤或還沒填完的列不送判定，也不預告任何結果：端點會拒收這個值，
// 而「儲存後符合」與「這個值存不進去」不能同時出現在同一列上
const afterSaveEligible = (row) => {
  if (!row.policy_key || !row.def || row.def.type === 'text') return false
  if (rowError(row)) return false
  if (
    row.comparator !== 'review' &&
    (row.expected_value === '' || row.expected_value === null)
  ) {
    return false
  }
  return true
}

const fetchAfterSave = async (row) => {
  // 立即取問一次就取代排在後面的那一次去抖，否則兩趟往返會為同一個輸入各回一份
  if (row.afterSaveTimer) clearTimeout(row.afterSaveTimer)
  row.afterSaveTimer = null
  if (!afterSaveEligible(row)) {
    row.afterSaveStatus = ''
    return
  }
  row.afterSaveVersion += 1
  const version = row.afterSaveVersion
  row.afterSaveStatus = 'pending'
  try {
    const res = await previewCompliance({}, [tempControlOf(row)])
    if (version !== row.afterSaveVersion) return
    const verdict = (res.data?.verdicts || []).find(
      (v) => v.key === row.policy_key && v.group_code === props.groupCode
    )
    row.afterSaveVerdict = verdict || null
    row.afterSaveStatus = verdict ? 'ready' : 'unknown'
  } catch (error) {
    if (version !== row.afterSaveVersion) return
    row.afterSaveVerdict = null
    row.afterSaveStatus = 'failed'
    console.error('取得儲存後結果失敗:', error)
  }
}

const scheduleAfterSave = (row) => {
  row.afterSaveVersion += 1
  row.afterSaveVerdict = null
  if (row.afterSaveTimer) clearTimeout(row.afterSaveTimer)
  row.afterSaveTimer = null
  if (!afterSaveEligible(row)) {
    row.afterSaveStatus = ''
    return
  }
  row.afterSaveStatus = 'pending'
  row.afterSaveTimer = setTimeout(() => fetchAfterSave(row), AFTER_SAVE_DEBOUNCE_MS)
}

const afterSaveText = (row) => {
  if (!row.def) return t('clauseDialog.afterSaveUnknown')
  if (row.def.type === 'text') return t('clauseDialog.textKeyUnsupported')
  if (rowError(row)) return t('clauseDialog.afterSaveInvalid')
  if (row.afterSaveStatus === 'pending') return t('clauseDialog.afterSavePending')
  if (row.afterSaveStatus === 'failed') return t('clauseDialog.afterSaveFailed')
  if (row.afterSaveStatus !== 'ready' || !row.afterSaveVerdict) {
    return t('clauseDialog.afterSaveUnknown')
  }
  const verdict = row.afterSaveVerdict
  const current = displayPolicyValue(row.policy_key, verdict.current ?? row.def.value, {
    unit_key: verdict.unit_key || row.def.unit_key,
    unit: row.def.unit,
    zero_disables: verdict.zero_disables ?? row.def.zero_disables,
  })
  if (verdict.result === 'compliant') {
    return t('clauseDialog.afterSaveCompliant', { value: current })
  }
  if (verdict.result === 'deviating') {
    return t('clauseDialog.afterSaveDeviating', { value: current })
  }
  if (verdict.result === 'review') {
    return t('clauseDialog.afterSaveReview', { value: current })
  }
  // 後端另有結果碼時原樣說出來，不歸到符合或偏離任一邊
  return `${resultLabel(verdict.result)}（${current}）`
}

// 鍵、比較方式與要求值任一改變就重問一次；狀態欄位刻意不進簽章，
// 否則寫入結果本身會再觸發一輪
const controlSignatures = computed(() =>
  controls.value.map(
    (row) =>
      `${row.policy_key}|${row.comparator}|${row.expected_value}|${row.def ? row.def.key : ''}`
  )
)

watch(controlSignatures, (next, prev = []) => {
  controls.value.forEach((row, index) => {
    if (next[index] === prev[index]) return
    scheduleAfterSave(row)
  })
})

const payloadControls = () => {
  if (form.value.kind !== 'setting') return []
  return controls.value.map((row) => ({
    policy_key: row.policy_key,
    comparator: row.comparator,
    // 不定值不帶值：帶了會被端點擋下，而且那個值在報告上會被讀成規範給的門檻
    expected_value: row.comparator === 'review' ? '' : String(row.expected_value),
    reference_only: false,
  }))
}

const validate = () => {
  if (!form.value.clause_no.trim()) return t('clauseDialog.clauseNoRequired')
  if (!form.value.title.trim()) return t('clauseDialog.titleRequired')
  if (form.value.kind !== 'setting') return ''
  if (controls.value.length === 0) return t('clauseDialog.controlsRequired')
  const keys = new Set()
  for (const row of controls.value) {
    if (!row.policy_key) return t('clauseDialog.keyRequired')
    if (keys.has(row.policy_key)) return t('clauseDialog.duplicateKey')
    keys.add(row.policy_key)
    if (rowError(row)) return rowError(row)
    if (
      row.comparator !== 'review' &&
      (row.expected_value === '' || row.expected_value === null)
    ) {
      return t('clauseDialog.valueRequired')
    }
  }
  return ''
}

const submit = async () => {
  formError.value = validate()
  if (formError.value) return
  saving.value = true
  try {
    await upsertPolicyClause(
      props.groupCode,
      form.value.clause_no.trim(),
      {
        title: form.value.title.trim(),
        summary: form.value.summary,
        kind: form.value.kind,
        controls: payloadControls(),
      },
      { skipErrorToast: true }
    )
    emit('saved')
    visible.value = false
  } catch (error) {
    formError.value = resolveApiError(error?.response?.data, error?.response?.status)
  } finally {
    saving.value = false
  }
}

const reset = async () => {
  formError.value = ''
  if (!props.clause) {
    form.value = emptyForm()
    controls.value = [newControl()]
    return
  }
  form.value = {
    clause_no: props.clause.clause_no,
    title: props.clause.title,
    summary: props.clause.summary || '',
    kind: props.clause.kind || 'setting',
  }
  controls.value = (props.clause.controls || []).map((control) => ({
    ...newControl(),
    policy_key: control.policy_key,
    comparator: control.comparator,
    expected_value: control.expected_value,
  }))
  if (controls.value.length === 0) controls.value = [newControl()]
  // 回填後仍要取定義：值域與目前值是「儲存後結果」的輸入，
  // 而編輯的人最需要知道的就是改了之後會變成什麼
  for (const row of controls.value) {
    if (!row.policy_key) continue
    const comparator = row.comparator
    const expected = row.expected_value
    await loadDef(row)
    row.comparator = comparator
    row.expected_value = expected
  }
}

watch(
  () => props.modelValue,
  (opened) => {
    if (opened) {
      reset()
      return
    }
    // 關掉之後不再去問結果：對話框已經不在畫面上，那趟往返沒有讀者
    controls.value.forEach((row) => {
      if (row.afterSaveTimer) clearTimeout(row.afterSaveTimer)
      row.afterSaveTimer = null
      row.afterSaveVersion += 1
    })
  }
)

defineExpose({
  form,
  controls,
  isEdit,
  selectableKeys,
  comparatorOptions,
  loadDef,
  addControl,
  submit,
  fetchAfterSave,
  scheduleAfterSave,
})
</script>

<style scoped>
.field-hint {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  line-height: 1.6;
}

.controls-label {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  margin-bottom: var(--ot-space-xs);
}

.control-row {
  padding: var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  margin-bottom: var(--ot-space-sm);
}

.control-fields {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}

.control-key {
  min-width: 220px;
}

.control-comparator {
  min-width: 200px;
}

.control-value {
  min-width: 140px;
}

.control-error,
.form-error {
  margin: var(--ot-space-xs) 0 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-danger);
}

.after-save {
  margin: var(--ot-space-xs) 0 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
</style>
