<template>
  <table
    v-if="rows.length"
    class="inv-table"
    data-test="inv-table"
  >
    <caption
      class="inv-caption"
      data-test="inv-caption"
    >
      {{ $t('hostInventory.caption.host', { name: assetName }) }}
    </caption>
    <thead>
      <tr>
        <th scope="col">
          {{ $t('hostInventory.col.account') }}
        </th>
        <th scope="col">
          {{ $t('hostInventory.col.uid') }}
        </th>
        <th scope="col">
          {{ $t('hostInventory.col.reasons') }}
        </th>
        <th scope="col">
          {{ $t('hostInventory.col.login') }}
        </th>
        <th scope="col">
          {{ $t('hostInventory.col.managed') }}
        </th>
        <th scope="col">
          {{ $t('hostInventory.col.state') }}
        </th>
        <th
          v-if="showActions"
          scope="col"
        >
          {{ $t('hostInventory.col.actions') }}
        </th>
      </tr>
    </thead>
    <tbody>
      <tr
        v-for="f in rows"
        :key="f.id"
        :class="{ 'is-gone': !f.present }"
        data-test="inv-row"
      >
        <td>
          <div class="inv-cell-name">
            <HostInventoryName :value="f.username" />
            <el-tooltip
              v-if="f.uid_conflict"
              :content="$t('hostInventory.cell.uidConflictTip')"
              placement="top"
            >
              <el-tag
                size="small"
                type="warning"
                effect="plain"
                data-test="badge-conflict"
              >
                {{ $t('hostInventory.cell.uidConflict') }}
              </el-tag>
            </el-tooltip>
            <el-button
              link
              size="small"
              :title="$t('hostInventory.cell.copy')"
              :aria-label="$t('hostInventory.cell.copy')"
              data-test="inv-copy"
              @click="copyName(f)"
            >
              <Copy
                :size="13"
                aria-hidden="true"
              />
            </el-button>
          </div>
        </td>
        <td :class="{ 'is-uid0': String(f.uid) === '0' }">
          {{ f.uid }}
        </td>
        <td>
          <HostInventoryReasons :reasons="f.privileged_reasons" />
        </td>
        <td>
          <span
            :title="$t('hostInventory.cell.loginNote')"
          >{{ f.login_capable ? $t('hostInventory.cell.canLogin') : $t('hostInventory.cell.cannotLogin') }}</span>
        </td>
        <td>
          <span
            :class="f.managed ? 'ok' : f.privileged ? 'warn' : 'muted'"
            data-test="inv-managed"
          >{{ f.managed ? $t('hostInventory.cell.managed') : $t('hostInventory.cell.unmanaged') }}</span>
        </td>
        <td>
          <el-tooltip
            v-if="f.status === 'ignored'"
            :content="ignoredTip(f)"
            placement="top"
          >
            <el-tag
              size="small"
              type="info"
              data-test="badge-ignored"
            >
              {{ $t('hostInventory.cell.ignored') }}
            </el-tag>
          </el-tooltip>
          <el-tooltip
            v-if="!f.present"
            :content="$t('hostInventory.cell.goneTip', { time: fmt(f.last_seen_at) })"
            placement="top"
          >
            <el-tag
              size="small"
              type="info"
              effect="plain"
              data-test="badge-gone"
            >
              {{ $t('hostInventory.cell.gone') }}
            </el-tag>
          </el-tooltip>
          <el-tooltip
            v-if="f.incomplete"
            :content="$t('hostInventory.cell.incompleteTip')"
            placement="top"
          >
            <el-tag
              size="small"
              type="warning"
              effect="plain"
              data-test="badge-incomplete"
            >
              {{ $t('hostInventory.cell.incomplete') }}
            </el-tag>
          </el-tooltip>
        </td>
        <td v-if="showActions">
          <div class="inv-actions">
            <el-tooltip
              v-if="showManage && !f.managed && f.present"
              :disabled="canManage"
              :content="$t('hostInventory.action.manageDenied')"
              placement="top"
            >
              <span>
                <el-button
                  v-preview-write
                  link
                  type="primary"
                  size="small"
                  :disabled="!canManage"
                  data-test="inv-manage"
                  @click="emit('manage', f)"
                >
                  {{ $t('hostInventory.action.manage') }}
                </el-button>
              </span>
            </el-tooltip>
            <el-button
              v-if="canDiscover && f.status === 'open' && f.privileged"
              v-preview-write
              link
              size="small"
              data-test="inv-ignore"
              @click="emit('ignore', f)"
            >
              {{ $t('hostInventory.action.ignore') }}
            </el-button>
            <el-popconfirm
              v-if="canDiscover && f.status === 'ignored'"
              :title="$t('hostInventory.reopen.confirm', { name: visibleText(f.username) })"
              :confirm-button-text="$t('hostInventory.reopen.ok')"
              :cancel-button-text="$t('hostInventory.reopen.cancel')"
              width="280"
              @confirm="emit('reopen', f)"
            >
              <template #reference>
                <el-button
                  v-preview-write
                  link
                  size="small"
                  data-test="inv-reopen"
                >
                  {{ $t('hostInventory.action.reopen') }}
                </el-button>
              </template>
            </el-popconfirm>
          </div>
        </td>
      </tr>
    </tbody>
  </table>
  <div
    v-else
    class="inv-empty"
    data-test="inv-empty"
  >
    <template v-if="filter === 'needs'">
      <p>{{ $t('hostInventory.empty.needs') }}</p>
      <p class="inv-empty-hint">
        {{ $t('hostInventory.empty.needsHint') }}
      </p>
      <p
        v-if="partial"
        class="inv-empty-warn"
        data-test="inv-empty-partial"
      >
        {{ $t('hostInventory.empty.partialExtra') }}
      </p>
    </template>
    <p v-else>
      {{ $t('hostInventory.empty.other') }}
    </p>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { ElMessage } from 'element-plus'
import { Copy } from 'lucide-vue-next'
import { t } from '@/i18n'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import { formatDateTime } from '@/utils/format'
import { visibleText } from '@/utils/visibleName'
import HostInventoryName from './HostInventoryName.vue'
import HostInventoryReasons from './HostInventoryReasons.vue'

// 盤點抽屜的結果表格與空狀態。
// 納管只給持主機帳號盤點權限點者（showManage），可不可做再看該台的「管理帳號」（canManage）；
// 忽略與重新開啟看該台的盤點旗標（canDiscover）。
const props = defineProps({
  rows: { type: Array, default: () => [] },
  filter: { type: String, default: 'needs' },
  partial: { type: Boolean, default: false },
  assetName: { type: String, default: '' },
  canDiscover: { type: Boolean, default: false },
  canManage: { type: Boolean, default: false },
  showManage: { type: Boolean, default: false },
})
const emit = defineEmits(['manage', 'ignore', 'reopen'])

const showActions = computed(() => props.canDiscover || props.showManage)

function fmt(v) {
  return v ? formatDateTime(v) : ''
}
function ignoredTip(f) {
  return t('hostInventory.cell.ignoredTip', { reason: f.ignore_reason || '', by: f.ignored_by_name || '', time: fmt(f.ignored_at) })
}
async function copyName(f) {
  try {
    await navigator.clipboard.writeText(f.username)
    ElMessage.success(t('hostInventory.cell.copied'))
  } catch {
    // 剪貼簿不可用時不打擾使用者
  }
}
</script>

<style scoped>
.inv-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

/* 表格標題只給輔助技術讀，畫面上不佔位 */
.inv-caption {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.inv-table th {
  text-align: left;
  padding: 8px 6px;
  font-weight: 500;
  color: var(--ot-text-secondary);
  border-bottom: 1px solid var(--ot-border);
}

.inv-table td {
  padding: 8px 6px;
  vertical-align: top;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.inv-table tr.is-gone {
  opacity: 0.55;
}

.inv-cell-name {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
}

.is-uid0 {
  color: var(--ot-danger);
  font-weight: 600;
}

.ok {
  color: var(--ot-success);
}

.warn {
  color: var(--ot-warning);
}

.muted {
  color: var(--ot-text-secondary);
}

.inv-actions {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}

.inv-empty {
  padding: 24px 8px;
  text-align: center;
  color: var(--ot-text-secondary);
}

.inv-empty-hint {
  font-size: 13px;
  color: var(--ot-text-disabled);
}

.inv-empty-warn {
  color: var(--ot-warning);
  font-size: 13px;
}
</style>
