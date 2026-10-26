<template>
  <section
    v-if="canViewAssets"
    class="po-probe"
    data-test="po-probe"
  >
    <h3>{{ $t('permissionOverview.probe.title') }}</h3>
    <el-select
      v-model="assetId"
      filterable
      remote
      clearable
      reserve-keyword
      :remote-method="search"
      :loading="searching"
      :placeholder="$t('permissionOverview.probe.placeholder')"
      class="po-probe__select"
      data-test="po-probe-select"
      @change="probe"
    >
      <el-option
        v-for="a in options"
        :key="a.id"
        :label="a.name"
        :value="a.id"
      />
    </el-select>

    <p
      v-if="notFound"
      class="po-probe__msg"
      data-test="po-probe-not-found"
    >
      {{ $t('permissionOverview.probe.notFound') }}
    </p>

    <div
      v-else-if="result"
      class="po-probe__cells"
    >
      <div
        class="po-probe__cell"
        data-test="po-probe-manage"
      >
        <strong>{{ result.manage.allowed ? $t('permissionOverview.probe.manageYes') : $t('permissionOverview.probe.manageNo') }}</strong>
        <p
          v-for="(g, i) in manageLines"
          :key="i"
        >
          {{ g }}
        </p>
        <p v-if="!result.manage.allowed">
          {{ $t('permissionOverview.probe.manageNoReason') }}
        </p>
      </div>
      <div
        class="po-probe__cell"
        data-test="po-probe-connect"
      >
        <strong v-if="!result.connect.available">{{ $t('permissionOverview.probe.connectUnavailable') }}</strong>
        <template v-else>
          <strong>{{ result.connect.allowed ? $t('permissionOverview.probe.connectYes') : $t('permissionOverview.probe.connectNo') }}</strong>
          <p v-if="overrideText">
            {{ overrideText }}
          </p>
          <p
            v-for="(l, i) in connectLines"
            :key="i"
          >
            {{ l }}
          </p>
          <p v-if="!result.connect.allowed">
            {{ $t('permissionOverview.probe.connectNoReason') }}
          </p>
          <router-link
            v-if="!result.connect.allowed && canOpenAuthorizations"
            to="/authorizations"
            data-test="po-probe-batch-link"
          >
            {{ $t('permissionOverview.probe.batchLink') }}
          </router-link>
        </template>
      </div>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { t } from '@/i18n'
import { can } from '@/composables/useCapabilities'
import { canEnter, ENTRY_RULES } from '@/router/entryRules'
import { getAssetList } from '@/api/assets'
import { PROBE_NOT_FOUND, probePermissionAsset } from '@/api/permissionOverview'
import { formatDateTime } from '@/utils/format'
import {
  roleName,
  scopeNotApplicable,
  scopeParts,
  validityText,
  viaText,
} from '@/utils/permissionOverviewPresentation'

/**
 * 查一台資產：輸入建議取自檢視者自己的資產列表（不帶 authorized_only，要看得到管理範圍內的資產），
 * 選定後問伺服器能否管理、能否連線；兩格結果直接用回應，不在前端判斷。
 */
const props = defineProps({
  userId: { type: Number, required: true },
  roleDefs: { type: Map, default: () => new Map() },
})

const canViewAssets = computed(() => can('asset:view'))
const canOpenAuthorizations = computed(() => canEnter(ENTRY_RULES['/authorizations']))

const assetId = ref(null)
const options = ref([])
const searching = ref(false)
const result = ref(null)
const notFound = ref(false)
let probeSeq = 0

const search = async (keyword) => {
  searching.value = true
  try {
    const res = await getAssetList({ search: keyword || undefined, page: 1, page_size: 20 })
    options.value = Array.isArray(res?.data) ? res.data : []
  } catch {
    options.value = []
  } finally {
    searching.value = false
  }
}

onMounted(() => {
  if (canViewAssets.value) search('')
})

const errorCode = (e) => {
  const body = e?.response?.data
  return (body && typeof body.error === 'object' ? body.error?.code : body?.code) || ''
}

const probe = async (id) => {
  const seq = ++probeSeq
  result.value = null
  notFound.value = false
  if (!id) return
  try {
    const res = await probePermissionAsset(props.userId, id)
    if (seq === probeSeq) result.value = res
  } catch (e) {
    if (seq !== probeSeq) return
    if (errorCode(e) === PROBE_NOT_FOUND) notFound.value = true
  }
}

const OVERRIDE_KEYS = { admin: 'permissionOverview.identity.superAdminConnect', auditor: 'permissionOverview.identity.auditorConnect' }
const overrideText = computed(() => {
  const key = OVERRIDE_KEYS[result.value?.connect?.role_override]
  return key ? t(key) : ''
})

const manageLines = computed(() =>
  (result.value?.manage?.grants || []).map((g) => {
    const na = scopeNotApplicable(g.role, props.roleDefs, false)
    return t('permissionOverview.probe.manageBy', {
      role: roleName(g.role) || t('permissionOverview.identity.compatDefault'),
      scope: scopeParts(g.scope, { notApplicable: na }).text,
    })
  }),
)

const connectLines = computed(() =>
  (result.value?.connect?.items || [])
    .filter((i) => i.kind === 'authorization')
    .map((i) =>
      t('permissionOverview.probe.connectBy', {
        target: i.target?.name || '',
        via: viaText(i.via),
        validity: validityText(i.validity, formatDateTime),
      }),
    ),
)
</script>

<style scoped>
.po-probe {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: 6px;
}

.po-probe h3 {
  margin: 0;
}

.po-probe__select {
  max-width: 420px;
}

.po-probe__msg {
  margin: 0;
  color: var(--ot-text-secondary);
}

.po-probe__cells {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: var(--ot-space-md);
}

.po-probe__cell {
  padding: var(--ot-space-sm) var(--ot-space-md);
  background: var(--ot-fill-subtle, rgba(127, 127, 127, 0.08));
  border-radius: 4px;
}

.po-probe__cell p {
  margin: var(--ot-space-xs) 0 0;
  font-size: 13px;
  color: var(--ot-text-secondary);
}
</style>
