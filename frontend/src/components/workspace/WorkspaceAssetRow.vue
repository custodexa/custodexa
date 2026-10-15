<template>
  <div
    class="asset-item"
    :class="{
      'is-gated': gated,
      'is-view-only': state === 'view_only',
      'is-selected': selected,
    }"
    :style="{ paddingLeft: indent + 'px' }"
    :data-access-state="state"
    :data-asset-id="asset.id"
    :aria-label="asset.name"
    role="button"
    tabindex="0"
    @click="emit('activate', asset, $event)"
    @keydown.enter.space.prevent="emit('activate', asset, $event)"
  >
    <el-tooltip
      :content="protocolFullName(asset.protocol)"
      placement="top"
      :enterable="false"
      :show-after="300"
    >
      <el-icon
        class="asset-proto"
        :class="'asset-proto--' + protoKind"
        :data-proto-kind="protoKind"
        role="img"
        :aria-label="protocolFullName(asset.protocol)"
      >
        <component :is="PROTOCOL_ICONS[protoKind]" />
      </el-icon>
    </el-tooltip>
    <!-- 名稱是選錯資產的唯一防線：截斷保住尾碼，提示給全名與主機位址；
         提示放列的右側，不蓋住上下的分組。搜尋命中主機位址時標出命中片段 -->
    <el-tooltip
      placement="right"
      popper-class="asset-tip-popper"
      :enterable="false"
      :show-after="300"
      :disabled="tipDisabled"
    >
      <template #content>
        <div
          class="asset-tip__name"
          data-test="asset-tip-name"
        >
          {{ asset.name }}
        </div>
        <div
          v-if="hostSegments.length"
          class="asset-tip__host"
          data-test="asset-tip-host"
        >
          <template
            v-for="(seg, i) in hostSegments"
            :key="i"
          >
            <mark
              v-if="seg.hit"
              class="asset-tip__hit"
              data-test="asset-tip-hit"
            >{{ seg.text }}</mark>
            <span v-else>{{ seg.text }}</span>
          </template>
        </div>
      </template>
      <span
        :ref="nameRef"
        class="asset-item-name"
        :data-row-key="rowKey"
        data-test="asset-name"
      >{{ label }}</span>
    </el-tooltip>
    <span
      v-if="state === 'view_only'"
      class="asset-state-chip"
      data-test="state-view-only"
    >{{ $t('workspace.stateViewOnly') }}</span>
    <el-tooltip
      v-else-if="STATE_ICONS[state]"
      :content="stateTip"
      placement="top"
      :enterable="false"
    >
      <el-icon
        class="asset-state"
        :class="'asset-state--' + state"
        role="img"
        :aria-label="stateTip"
        data-test="state-icon"
      >
        <component :is="STATE_ICONS[state]" />
      </el-icon>
    </el-tooltip>
    <!-- 查詢主控台入口：只對三種 SQL 方言出現，與整列同一組存取狀態判準。
         只在列被停留、取得焦點或為選中列時出現，未出現時不佔名稱寬度 -->
    <el-tooltip
      v-if="isDBConsoleProtocol(asset.protocol)"
      :content="$t('workspace.openConsole')"
      placement="top"
      :enterable="false"
    >
      <button
        type="button"
        class="asset-item-console"
        :aria-label="$t('workspace.openConsole')"
        data-test="console-entry"
        @click.stop="emit('console', asset, $event)"
        @keydown.enter.space.stop
      >
        <el-icon><Database /></el-icon>
      </button>
    </el-tooltip>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { Database, Lock, Clock, Pencil, SquareTerminal, Monitor, Container } from 'lucide-vue-next'
import { t } from '@/i18n'
import { isDBConsoleProtocol, protocolIconKind, protocolFullName } from '@/utils/protocol'
import { hostLineSegments } from './highlight'

const props = defineProps({
  asset: { type: Object, required: true },
  rowKey: { type: String, required: true },
  depth: { type: Number, default: 0 },
  // 依名稱欄寬度截斷後的顯示文字
  label: { type: String, default: '' },
  // assetEntryState 五態之一
  state: { type: String, default: 'open' },
  gated: { type: Boolean, default: false },
  selected: { type: Boolean, default: false },
  // 說明框開啟時停用名稱提示，避免疊在說明框上
  tipDisabled: { type: Boolean, default: false },
  // 已去頭尾空白的搜尋關鍵字；空字串＝不標命中
  searchTerm: { type: String, default: '' },
  // 名稱欄元素回呼（供寬度量測）
  nameRef: { type: Function, default: null },
})

const emit = defineEmits(['activate', 'console'])

const PROTOCOL_ICONS = { terminal: SquareTerminal, desktop: Monitor, database: Database, container: Container }
const STATE_ICONS = { pending: Clock, approval: Lock, reason: Pencil }
const STATE_TIP_KEYS = {
  pending: 'workspace.statePendingTip',
  approval: 'workspace.stateApprovalTip',
  reason: 'workspace.stateReasonTip',
  view_only: 'workspace.stateViewOnlyTip',
}

const protoKind = computed(() => protocolIconKind(props.asset.protocol))
const stateTip = computed(() => (STATE_TIP_KEYS[props.state] ? t(STATE_TIP_KEYS[props.state]) : ''))
const indent = computed(() => (props.depth === 0 ? 8 : 4 + props.depth * 14 + 6))

const hostText = computed(() => {
  const { host, port } = props.asset
  if (!host) return ''
  return port ? `${host}:${port}` : String(host)
})

// 提示第二行：主機位址，命中片段另標
const hostSegments = computed(() => {
  const host = hostText.value
  if (!host) return []
  return hostLineSegments(t('workspace.hostAddress', { host }), host, props.searchTerm)
})
</script>

<style scoped>
.asset-item {
  position: relative;
  display: flex;
  align-items: center;
  gap: 8px;
  height: 30px;
  padding-right: 8px;
  border-radius: var(--ot-radius-sm);
  cursor: pointer;
  color: var(--ot-terminal-fg);
}

.asset-item:hover {
  background: var(--ot-bg-hover);
}

.asset-item:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: -2px;
}

/* 選中列（目前分頁的資產，或說明框所指的列） */
.asset-item.is-selected {
  background: var(--ot-bg-active);
}

.asset-item.is-selected::before {
  content: '';
  position: absolute;
  left: 0;
  top: 4px;
  bottom: 4px;
  width: 3px;
  border-radius: 2px;
  background: var(--ot-primary);
}

.asset-proto {
  flex-shrink: 0;
  font-size: 16px;
  color: var(--ot-text-secondary);
}

.asset-item-name {
  flex: 1;
  min-width: 0;
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* 不發簽發的列：游標不暗示可直接連線（點了會出說明） */
.asset-item.is-gated {
  cursor: help;
}

/* 僅檢視：名稱淡化 */
.asset-item.is-view-only .asset-item-name,
.asset-item.is-view-only .asset-proto {
  opacity: 0.55;
}

.asset-state {
  flex-shrink: 0;
  font-size: 14px;
  color: var(--ot-text-secondary);
}

.asset-state--pending {
  color: var(--ot-warning);
}

.asset-state-chip {
  flex-shrink: 0;
  padding: 0 6px;
  font-size: 11px;
  line-height: 18px;
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-sm);
  color: var(--ot-text-secondary);
  white-space: nowrap;
}

/* 主控台鈕：平時 display:none 不佔名稱寬度 */
.asset-item-console {
  display: none;
  flex-shrink: 0;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  padding: 0;
  border: 1px solid transparent;
  border-radius: var(--ot-radius-sm);
  background: transparent;
  color: var(--ot-primary);
  cursor: pointer;
  font-size: 14px;
}

.asset-item:hover .asset-item-console,
.asset-item:focus-within .asset-item-console,
.asset-item.is-selected .asset-item-console {
  display: inline-flex;
}

.asset-item-console:hover,
.asset-item-console:focus-visible {
  border-color: var(--ot-primary);
  background: var(--ot-primary-dim);
}
</style>

<style>
/* 側欄名稱提示（teleport 到 body，不受 scoped 影響）：第一行全名、第二行主機位址 */
.asset-tip-popper {
  line-height: 1.6;
}

.asset-tip-popper .asset-tip__name {
  font-weight: 600;
}

/* 搜尋命中片段：底色標記，文字色沿用提示框 */
.asset-tip-popper .asset-tip__hit {
  padding: 0 1px;
  border-radius: 2px;
  background: color-mix(in srgb, var(--ot-warning) 45%, transparent);
  color: inherit;
}
</style>
