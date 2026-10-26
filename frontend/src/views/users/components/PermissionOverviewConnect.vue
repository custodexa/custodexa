<template>
  <section
    class="po-col"
    data-test="po-connect"
  >
    <header class="po-col__head">
      <h3>{{ $t('permissionOverview.connect.title') }}</h3>
      <span class="po-col__sub">{{ $t('permissionOverview.connect.subtitle') }}</span>
    </header>

    <p
      v-if="!connection.available"
      class="po-note"
      data-test="po-connect-unavailable"
    >
      {{ $t('permissionOverview.connect.unavailable') }}
    </p>

    <template v-else>
      <p
        v-if="overrideText"
        class="po-note"
        :data-test="`po-connect-${connection.role_override}`"
      >
        {{ overrideText }}
      </p>

      <p
        v-if="isEmpty"
        class="po-note"
        data-test="po-connect-empty"
      >
        {{ $t('permissionOverview.connect.empty') }}
      </p>

      <article
        v-for="(item, idx) in items"
        :key="idx"
        class="po-item"
        data-test="po-item"
      >
        <div class="po-item__head">
          <span
            class="po-item__title"
            data-test="po-item-title"
          >{{ item.title }}</span>
          <el-tag
            size="small"
            :type="item.permission === 'connect' ? 'success' : 'info'"
            data-test="po-item-level"
          >
            {{ item.level }}
          </el-tag>
        </div>
        <p
          class="po-item__meta"
          data-test="po-item-meta"
        >
          <span>{{ $t('permissionOverview.connect.assetCount', { n: item.visible }) }}</span>
          <span v-if="item.detail">{{ item.via }}</span>
          <span v-if="item.detail">{{ item.validity }}</span>
          <span
            v-if="item.policy"
            data-test="po-item-policy"
          >{{ item.policy }}</span>
        </p>
        <p
          v-if="item.alsoManage"
          class="po-item__manage"
          data-test="po-item-also-manage"
        >
          {{ item.alsoManage }}
        </p>
        <p
          v-if="item.managed > 0"
          class="po-item__notice"
          data-test="po-item-address-notice"
        >
          {{ $t('permissionOverview.connect.addressNotice', { name: username }) }}
        </p>
        <el-button
          v-if="item.detail"
          link
          type="primary"
          data-test="po-item-why-toggle"
          @click="toggle(idx)"
        >
          {{ $t('permissionOverview.why.toggle') }}
        </el-button>
        <ul
          v-if="item.detail && open[idx]"
          class="po-why"
          data-test="po-item-why"
        >
          <li>{{ item.via }}</li>
          <li>{{ item.account }}</li>
          <li>{{ item.validity }}</li>
        </ul>
      </article>

      <p
        v-for="(row, ri) in manageOnly"
        :key="`m${ri}`"
        class="po-note"
        data-test="po-manage-only"
      >
        {{ row }}
      </p>

      <p
        v-if="outOfScope > 0"
        class="po-note"
        data-test="po-out-of-scope"
      >
        {{ $t('permissionOverview.connect.outOfScope', { n: outOfScope }) }}
      </p>
    </template>
  </section>
</template>

<script setup>
import { computed, reactive } from 'vue'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { accountText, policyText, validityText, viaText } from '@/utils/permissionOverviewPresentation'

/**
 * 能連線到哪裡（右欄）：項目、台數、也能管理的標示都取自回應，不在前端推算。
 * 看不到的授權記錄只給等級與台數；回應不帶的欄位這裡也不補。
 */
const props = defineProps({
  connection: { type: Object, required: true },
  // 範圍外資產台數（回應頂層欄位，登錄固定欄名）
  outOfScopeCount: { type: Number, default: 0 },
  username: { type: String, default: '' },
})

const open = reactive({})
const toggle = (idx) => {
  open[idx] = !open[idx]
}

// 內建身分隱含的連線摘要：值域由伺服器給（admin、auditor），這裡只對應成白話
const OVERRIDE_KEYS = { admin: 'permissionOverview.identity.superAdminConnect', auditor: 'permissionOverview.identity.auditorConnect' }
const overrideText = computed(() => (OVERRIDE_KEYS[props.connection.role_override] ? t(OVERRIDE_KEYS[props.connection.role_override]) : ''))

// 沒有任何項目、也沒有隱含身分摘要或「只能管理」列時，明說這一欄為什麼是空的
const isEmpty = computed(
  () => !overrideText.value && items.value.length === 0 && (props.connection.manage_only || []).length === 0,
)

const outOfScope = computed(() => Number(props.outOfScopeCount) || 0)

const alsoManageText = (item) => {
  if (!(item.managed_asset_count > 0)) return ''
  if (item.managed_asset_count === item.visible_asset_count) return t('permissionOverview.connect.alsoManage')
  return t('permissionOverview.connect.alsoManagePartial', { n: item.managed_asset_count })
}

const itemTitle = (item) => {
  if (item.kind === 'undisclosed_authorization') {
    return t('permissionOverview.connect.undisclosed', { n: item.visible_asset_count })
  }
  if (item.kind === 'approver_scope') {
    return t('permissionOverview.connect.approverScope', { n: item.visible_asset_count })
  }
  return item.target?.name || ''
}

const items = computed(() =>
  (props.connection.items || []).map((item) => {
    const detail = item.kind === 'authorization'
    return {
      permission: item.permission,
      level: t(`permissionOverview.connect.level.${item.permission === 'connect' ? 'connect' : 'view'}`),
      title: itemTitle(item),
      visible: item.visible_asset_count,
      managed: item.managed_asset_count,
      detail,
      via: detail ? viaText(item.via) : '',
      validity: detail ? validityText(item.validity, formatDateTime) : '',
      account: detail ? accountText(item.account_scope) : '',
      policy: detail ? policyText(item.access_policy) : '',
      alsoManage: alsoManageText(item),
    }
  }),
)

const manageOnly = computed(() =>
  (props.connection.manage_only || []).map((row) =>
    t('permissionOverview.connect.manageOnly', { path: row.node_path, n: row.asset_count, name: props.username }),
  ),
)
</script>

<style scoped>
.po-col {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  min-width: 0;
}

.po-col__head {
  display: flex;
  align-items: baseline;
  gap: var(--ot-space-sm);
}

.po-col__head h3 {
  margin: 0;
}

.po-col__sub {
  color: var(--ot-text-secondary);
  font-size: 13px;
}

.po-note {
  margin: 0;
  color: var(--ot-text-secondary);
}

.po-item {
  border: 1px solid var(--ot-border-subtle);
  border-radius: 6px;
  padding: var(--ot-space-md);
}

.po-item__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
}

.po-item__title {
  font-weight: 600;
  overflow-wrap: anywhere;
}

.po-item__meta {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-sm);
  margin: var(--ot-space-xs) 0 0;
  color: var(--ot-text-secondary);
  font-size: 13px;
}

.po-item__manage {
  margin: var(--ot-space-xs) 0 0;
  font-weight: 600;
}

.po-item__notice {
  margin: var(--ot-space-xs) 0 0;
  color: var(--ot-text-secondary);
  font-size: 13px;
}

.po-why {
  margin: var(--ot-space-xs) 0 0;
  padding: var(--ot-space-sm) var(--ot-space-md);
  background: var(--ot-fill-subtle, rgba(127, 127, 127, 0.08));
  border-radius: 4px;
  font-size: 13px;
  list-style: none;
}
</style>
