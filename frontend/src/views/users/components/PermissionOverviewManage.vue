<template>
  <section
    class="po-col"
    data-test="po-manage"
  >
    <header class="po-col__head">
      <h3>{{ $t('permissionOverview.manage.title') }}</h3>
      <span class="po-col__sub">{{ $t('permissionOverview.manage.subtitle') }}</span>
    </header>

    <p
      v-if="identity.super_admin"
      class="po-note"
      data-test="po-identity-super"
    >
      {{ $t('permissionOverview.identity.superAdmin') }}
    </p>
    <p
      v-if="identity.auditor"
      class="po-note"
      data-test="po-identity-auditor"
    >
      {{ $t('permissionOverview.identity.auditor') }}
    </p>

    <article
      v-for="(card, idx) in cards"
      :key="idx"
      class="po-card"
      data-test="po-card"
    >
      <h4 class="po-card__title">
        {{ card.title }}
      </h4>
      <p
        class="po-card__scope"
        data-test="po-card-scope"
      >
        <span class="po-card__label">{{ $t('permissionOverview.card.scopeLabel') }}</span>
        <span>{{ card.scopeText }}</span>
        <span v-if="card.assetCount !== null">・{{ $t('permissionOverview.card.assetCount', { n: card.assetCount }) }}</span>
      </p>
      <p
        v-for="(note, ni) in card.inactive"
        :key="`i${ni}`"
        class="po-card__warn"
        data-test="po-card-inactive"
      >
        {{ note }}
      </p>

      <dl
        v-if="card.hasEntries"
        class="po-entries"
      >
        <template
          v-for="g in card.groups"
          :key="g.id"
        >
          <dt
            :class="`po-entries__label po-entries__label--${g.id}`"
            :data-test="`po-entries-${g.id}`"
          >
            {{ $t(`roles.summary.${g.id}`) }}
          </dt>
          <dd>{{ g.names }}</dd>
        </template>
      </dl>
      <p
        v-else
        class="po-card__empty"
        data-test="po-card-no-entries"
      >
        {{ $t('permissionOverview.card.noEntries') }}
      </p>

      <div class="po-card__actions">
        <el-button
          link
          type="primary"
          data-test="po-why-toggle"
          @click="toggle(idx, 'why')"
        >
          {{ $t('permissionOverview.why.toggle') }}
        </el-button>
        <el-button
          link
          type="primary"
          data-test="po-detail-toggle"
          @click="toggle(idx, 'detail')"
        >
          {{ $t('permissionOverview.detail.toggle') }}
        </el-button>
      </div>

      <ul
        v-if="open[`${idx}:why`]"
        class="po-why"
        data-test="po-why"
      >
        <li
          v-for="(line, li) in card.why"
          :key="li"
        >
          <span class="po-why__scope">{{ line.scope }}</span>
          <span class="po-why__sentence">{{ line.sentence }}</span>
        </li>
      </ul>

      <div
        v-if="open[`${idx}:detail`]"
        class="po-detail"
        data-test="po-detail"
      >
        <div
          v-for="(d, di) in card.detail"
          :key="di"
          class="po-detail__row"
        >
          <span class="po-detail__scope">{{ d.scope }}</span>
          <span v-if="d.names.length">{{ d.names.join($t('common.listSeparator')) }}</span>
          <span
            v-else
            class="po-card__empty"
          >{{ $t('permissionOverview.detail.empty') }}</span>
          <p
            v-for="(ine, ii) in d.ineffective"
            :key="ii"
            class="po-detail__ineffective"
          >
            {{ ine }}
          </p>
        </div>
      </div>

      <div
        v-if="card.ineffectiveReasons.length"
        class="po-ineffective"
        data-test="po-ineffective"
      >
        <strong>{{ $t('permissionOverview.ineffective.title') }}</strong>
        <p
          v-for="(r, ri) in card.ineffectiveReasons"
          :key="ri"
        >
          {{ r }}
        </p>
      </div>
    </article>

    <div
      v-if="ineffectiveSources.length"
      class="po-card po-card--ineffective"
      data-test="po-ineffective-sources"
    >
      <strong>{{ $t('permissionOverview.ineffective.title') }}</strong>
      <p
        v-for="(s, si) in ineffectiveSources"
        :key="si"
      >
        {{ s }}
      </p>
    </div>

    <p
      v-if="identity.approver"
      class="po-note"
      data-test="po-identity-approver"
    >
      {{ $t('permissionOverview.identity.approver') }}
      <router-link
        v-if="canOpenApproverScopes"
        to="/approver-scopes"
        data-test="po-approver-link"
      >
        {{ $t('permissionOverview.identity.approverLink') }}
      </router-link>
    </p>
  </section>
</template>

<script setup>
import { computed, reactive } from 'vue'
import { t } from '@/i18n'
import { canEnter, ENTRY_RULES } from '@/router/entryRules'
import {
  ENTRY_GROUPS,
  entryName,
  ineffectiveReasonText,
  permissionName,
  roleName,
  scopeNotApplicable,
  scopeParts,
  sourceSentences,
} from '@/utils/permissionOverviewPresentation'

/**
 * 能管理什麼（左欄）：一個角色一張卡，欄位全取自回應的 management；
 * 範圍、來源、入口分組與台數都由伺服器給，這裡只轉成白話。
 */
const props = defineProps({
  management: { type: Object, required: true },
  // 角色列表（id → 定義），只用來決定全系統範圍寫「全系統」或「不適用」
  roleDefs: { type: Map, default: () => new Map() },
})

const open = reactive({})
const toggle = (idx, kind) => {
  const k = `${idx}:${kind}`
  open[k] = !open[k]
}

const identity = computed(() => props.management.identity || {})
const canOpenApproverScopes = computed(() => canEnter(ENTRY_RULES['/approver-scopes']))

const sourceByRef = computed(() => {
  const map = new Map()
  for (const s of props.management.sources || []) map.set(s.source_ref, s)
  return map
})

const joinList = (parts) => parts.join(t('common.listSeparator'))

const cardTitle = (binding, sources) => {
  if (binding.role) return roleName(binding.role)
  const kind = sources[0]?.kind
  return kind === 'agent_fixed' ? t('permissionOverview.identity.agent') : t('permissionOverview.identity.compatDefault')
}

const cards = computed(() =>
  (props.management.bindings || []).map((binding) => {
    const sources = (binding.source_refs || []).map((r) => sourceByRef.value.get(r)).filter(Boolean)
    const na = scopeNotApplicable(binding.role, props.roleDefs, identity.value.super_admin === true)
    const parts = sources.map((s) => scopeParts(s.scope, { notApplicable: na }))
    const scopeText = joinList([...new Set(parts.map((p) => p.text))])
    const entries = binding.entries || {}
    const groups = ENTRY_GROUPS.map((id) => ({ id, ids: entries[id] || [] }))
      .filter((g) => g.ids.length)
      .map((g) => ({ id: g.id, names: joinList(g.ids.map(entryName)) }))
    return {
      title: cardTitle(binding, sources),
      scopeText,
      assetCount: binding.manageable_asset_count ?? null,
      inactive: parts.map((p) => p.inactive).filter(Boolean),
      groups,
      hasEntries: groups.length > 0,
      why: sources.flatMap((s, i) =>
        sourceSentences(s).map((sentence) => ({ scope: parts[i].text, sentence })),
      ),
      detail: sources.map((s, i) => ({
        scope: parts[i].text,
        names: (s.effective_permissions || []).map(permissionName),
        ineffective: (s.ineffective || []).map((x) => `${permissionName(x.permission)}：${ineffectiveReasonText(x.reason)}`),
      })),
      ineffectiveReasons: [...new Set(sources.flatMap((s) => (s.ineffective || []).map((x) => ineffectiveReasonText(x.reason))))],
    }
  }),
)

const ineffectiveSources = computed(() =>
  (props.management.ineffective_sources || []).map((s) => {
    const who = s.role ? roleName(s.role) : ''
    const reason = ineffectiveReasonText(s.reason)
    return who ? `${who}：${reason}` : reason
  }),
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

.po-card {
  border: 1px solid var(--ot-border-subtle);
  border-radius: 6px;
  padding: var(--ot-space-md);
  background: var(--ot-surface, transparent);
}

.po-card__title {
  margin: 0 0 var(--ot-space-xs);
}

.po-card__scope {
  margin: 0;
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-xs);
}

.po-card__label {
  color: var(--ot-text-secondary);
}

.po-card__warn {
  margin: var(--ot-space-xs) 0 0;
  color: var(--ot-warning, #b26a00);
  font-size: 13px;
}

.po-card__empty {
  margin: var(--ot-space-xs) 0 0;
  color: var(--ot-text-secondary);
}

.po-entries {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: var(--ot-space-xs) var(--ot-space-md);
  margin: var(--ot-space-sm) 0 0;
}

.po-entries dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.po-entries__label {
  font-weight: 600;
}

.po-card__actions {
  display: flex;
  gap: var(--ot-space-md);
  margin-top: var(--ot-space-xs);
}

.po-why,
.po-detail {
  margin: var(--ot-space-xs) 0 0;
  padding: var(--ot-space-sm);
  background: var(--ot-fill-subtle, rgba(127, 127, 127, 0.08));
  border-radius: 4px;
  font-size: 13px;
}

.po-why {
  list-style: none;
}

.po-why li,
.po-detail__row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-sm);
}

.po-why__scope,
.po-detail__scope {
  font-weight: 600;
}

.po-detail__ineffective {
  flex-basis: 100%;
  margin: 0;
  color: var(--ot-text-secondary);
}

.po-ineffective {
  margin-top: var(--ot-space-sm);
  color: var(--ot-text-secondary);
  font-size: 13px;
}

.po-ineffective p,
.po-card--ineffective p {
  margin: var(--ot-space-xs) 0 0;
}
</style>
