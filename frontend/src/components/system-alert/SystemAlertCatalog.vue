<template>
  <div
    class="system-alert-catalog"
    data-test="system-alert-catalog"
  >
    <el-alert
      type="info"
      :closable="false"
      show-icon
      class="catalog-intro"
      :title="$t('systemAlerts.catalog.intro')"
    />
    <el-alert
      v-if="!canAdjust"
      type="warning"
      :closable="false"
      show-icon
      class="catalog-intro"
      data-test="catalog-readonly"
      :title="$t('systemAlerts.catalog.readonlyHint')"
    />

    <div
      v-loading="loading"
      class="catalog-body"
    >
      <template v-if="groups.length">
        <section
          v-for="group in groups"
          :key="group.key"
          class="catalog-group"
          :data-test="`catalog-group-${group.key}`"
        >
          <h3 class="catalog-group__title">
            {{ groupLabel(group.key) }}
          </h3>
          <table class="catalog-table">
            <thead>
              <tr>
                <th>{{ $t('systemAlerts.catalog.columnType') }}</th>
                <th>{{ $t('systemAlerts.catalog.columnDefault') }}</th>
                <th>{{ $t('systemAlerts.catalog.columnEffective') }}</th>
                <th v-if="hasRecent">
                  {{ $t('systemAlerts.catalog.columnRecent') }}
                </th>
                <th v-if="canAdjust" />
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="row in group.rows"
                :key="row.key"
                :data-test="`catalog-row-${row.key}`"
              >
                <td>
                  <div class="catalog-type__name">
                    {{ typeName(row.key) }}
                  </div>
                  <div class="catalog-type__desc">
                    {{ typeDescription(row.key) }}
                  </div>
                </td>
                <td>
                  <el-tag
                    size="small"
                    :type="tagType(row.default_severity)"
                    effect="plain"
                  >
                    {{ levelLabel(row.default_severity) }}
                  </el-tag>
                </td>
                <td>
                  <el-tag
                    size="small"
                    :type="tagType(row.effective_severity)"
                  >
                    {{ levelLabel(row.effective_severity) }}
                  </el-tag>
                  <el-tag
                    v-if="row.adjusted"
                    size="small"
                    type="info"
                    class="catalog-adjusted"
                    :data-test="`catalog-adjusted-${row.key}`"
                  >
                    {{ $t('systemAlerts.catalog.adjusted') }}
                  </el-tag>
                </td>
                <td
                  v-if="hasRecent"
                  :data-test="`catalog-recent-${row.key}`"
                >
                  {{ row.recent_30d === undefined ? '' : $t('systemAlerts.catalog.recentCount', { count: row.recent_30d }) }}
                </td>
                <td v-if="canAdjust">
                  <el-button
                    link
                    type="primary"
                    :data-test="`catalog-adjust-${row.key}`"
                    @click="openAdjust(row)"
                  >
                    {{ $t('systemAlerts.catalog.adjust') }}
                  </el-button>
                </td>
              </tr>
            </tbody>
          </table>
        </section>
        <p
          class="catalog-total"
          data-test="catalog-total"
        >
          {{ $t('systemAlerts.catalog.total', { count: types.length }) }}
        </p>
      </template>
      <EmptyState
        v-else-if="!loading"
        :title="$t('systemAlerts.catalog.empty')"
      />
    </div>

    <!-- 只有調分級一個動作：沒有停用開關，也沒有刪除入口 -->
    <el-dialog
      v-model="dialogVisible"
      :title="$t('systemAlerts.catalog.dialogTitle')"
      width="520px"
      data-test="catalog-dialog"
    >
      <template v-if="editing">
        <div class="catalog-type__name">
          {{ typeName(editing.key) }}
        </div>
        <div class="catalog-type__desc catalog-dialog__desc">
          {{ typeDescription(editing.key) }}
        </div>
        <el-form label-position="top">
          <el-form-item :label="$t('systemAlerts.catalog.dialogLevelLabel')">
            <el-radio-group
              v-model="selected"
              class="catalog-levels"
            >
              <el-radio
                v-for="level in LEVELS"
                :key="level"
                :value="level"
                :data-test="`catalog-level-${level}`"
              >
                <strong>{{ levelLabel(level) }}</strong>
                <span class="catalog-level__hint">{{ $t(`systemAlerts.catalog.option${level[0].toUpperCase()}${level.slice(1)}`) }}</span>
              </el-radio>
            </el-radio-group>
          </el-form-item>
        </el-form>
        <p
          class="catalog-dialog__note"
          data-test="catalog-dialog-note"
        >
          {{ $t('systemAlerts.catalog.dialogNote') }}
        </p>
      </template>
      <template #footer>
        <el-button @click="dialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="saving"
          data-test="catalog-save"
          @click="save"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import EmptyState from '@/components/EmptyState.vue'
import { getSystemAlertTypes, updateSystemAlertSeverity } from '@/api/systemAlerts'
import { can } from '@/composables/useCapabilities'
import { resolveApiError } from '@/api/error'
import { t } from '@/i18n'

const LEVELS = ['high', 'medium', 'low']
const TAG_TYPES = { high: 'danger', medium: 'warning', low: 'info' }
// 後端分組鍵（snake）→ 前端 i18n 鍵（camel）。登錄新增分組時兩邊一起補。
const GROUP_I18N = {
  address_transport: 'addressTransport',
  secret: 'secret',
  identity_privilege: 'identityPrivilege',
  security_settings: 'securitySettings',
  notification: 'notification',
}

const types = ref([])
const loading = ref(false)
const dialogVisible = ref(false)
const editing = ref(null)
const selected = ref('high')
const saving = ref(false)

// 由 can() 決定唯讀或可調（後端才是強制點）
const canAdjust = computed(() => can('systemalert:manage'))
// 筆數欄只在後端有帶時顯示（呼叫者沒有稽核檢視時整欄缺席）
const hasRecent = computed(() => types.value.some((r) => r.recent_30d !== undefined))

const groups = computed(() => {
  const order = []
  const byKey = {}
  for (const row of types.value) {
    if (!byKey[row.group]) {
      byKey[row.group] = { key: row.group, rows: [] }
      order.push(byKey[row.group])
    }
    byKey[row.group].rows.push(row)
  }
  return order
})

const groupLabel = (key) => (GROUP_I18N[key] ? t(`systemAlerts.groups.${GROUP_I18N[key]}`) : key)
const typeName = (key) => t(`systemAlerts.types.${key}.name`)
const typeDescription = (key) => t(`systemAlerts.types.${key}.description`)
const levelLabel = (level) => (LEVELS.includes(level) ? t(`enum.alertLevel.${level}`) : level)
const tagType = (level) => TAG_TYPES[level] || 'info'

const load = async () => {
  loading.value = true
  try {
    const resp = await getSystemAlertTypes()
    const list = resp?.types ?? resp?.data?.types
    types.value = Array.isArray(list) ? list : []
  } catch {
    types.value = []
    ElMessage.error(t('systemAlerts.catalog.loadFailed'))
  } finally {
    loading.value = false
  }
}

const openAdjust = (row) => {
  editing.value = row
  selected.value = row.effective_severity
  dialogVisible.value = true
}

const save = async () => {
  if (!editing.value) return
  saving.value = true
  try {
    await updateSystemAlertSeverity(editing.value.key, selected.value, { skipErrorToast: true })
    ElMessage.success(t('systemAlerts.catalog.saved'))
    dialogVisible.value = false
    await load()
  } catch (err) {
    const resp = err?.response
    ElMessage.error(resolveApiError(resp?.data, resp?.status, t('systemAlerts.catalog.loadFailed')))
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.catalog-intro {
  margin-bottom: var(--ot-space-md);
}

.catalog-group {
  margin-bottom: var(--ot-space-lg);
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.catalog-group__title {
  margin: 0 0 var(--ot-space-sm);
  font-size: 15px;
}

.catalog-table {
  width: 100%;
  border-collapse: collapse;
}

.catalog-table th,
.catalog-table td {
  padding: var(--ot-space-sm) var(--ot-space-md);
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.catalog-table th {
  font-weight: 500;
  color: var(--ot-text-secondary);
  font-size: 13px;
}

.catalog-type__name {
  font-weight: 500;
}

.catalog-type__desc {
  color: var(--ot-text-secondary);
  font-size: 13px;
}

.catalog-adjusted {
  margin-left: var(--ot-space-xs);
}

.catalog-total {
  color: var(--ot-text-secondary);
  font-size: 13px;
}

.catalog-levels {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--ot-space-sm);
}

.catalog-level__hint {
  margin-left: var(--ot-space-sm);
  color: var(--ot-text-secondary);
}

.catalog-dialog__desc {
  margin-bottom: var(--ot-space-md);
}

.catalog-dialog__note {
  color: var(--ot-text-secondary);
  font-size: 13px;
}
</style>
