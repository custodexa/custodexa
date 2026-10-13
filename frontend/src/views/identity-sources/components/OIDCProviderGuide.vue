<template>
  <section
    class="provider-guide"
    data-test="provider-guide"
    :data-provider="provider"
  >
    <header class="provider-guide__head">
      <span class="provider-guide__title">
        {{ $t('identitySources.oidc.guide.title', { provider: $t(`identitySources.oidc.provider.${provider}`) }) }}
      </span>
      <button
        type="button"
        class="provider-guide__toggle"
        data-test="provider-guide-toggle"
        :aria-expanded="open ? 'true' : 'false'"
        @click="$emit('update:open', !open)"
      >
        {{ open ? $t('identitySources.collapse') : $t('identitySources.expand') }}
      </button>
    </header>

    <div
      v-if="open"
      class="provider-guide__body"
    >
      <p
        v-if="spec.intro"
        class="provider-guide__intro"
      >
        {{ $t('identitySources.oidc.guide.otherIntro') }}
      </p>

      <dl class="provider-guide__fields">
        <div
          v-for="field in spec.fields"
          :key="field"
          class="provider-guide__field"
          :data-test="`guide-field-${field}`"
        >
          <dt>{{ $t(`identitySources.oidc.guide.field.${field}`) }}</dt>
          <dd>{{ $t(`identitySources.oidc.guide.${provider}.${field}`) }}</dd>
        </div>
      </dl>

      <!-- 完整步驟：依欄位分組、各組預設收合；「其他 OIDC」只有系統要求，不設本段 -->
      <div
        v-if="spec.groups.length"
        class="provider-guide__steps"
        data-test="guide-full-steps"
      >
        <div class="provider-guide__steps-title">
          {{ $t('identitySources.oidc.guide.fullSteps') }}
        </div>
        <div
          v-for="group in spec.groups"
          :key="group.key"
          class="provider-guide__group"
        >
          <button
            type="button"
            class="provider-guide__group-toggle"
            :data-test="`guide-step-group-${group.key}`"
            :aria-expanded="openGroups[group.key] ? 'true' : 'false'"
            @click="toggleGroup(group.key)"
          >
            <el-icon class="provider-guide__chevron">
              <ChevronDown v-if="openGroups[group.key]" />
              <ChevronRight v-else />
            </el-icon>
            <span class="provider-guide__group-title">{{ $t(`identitySources.oidc.guide.stepGroup.${group.key}`) }}</span>
            <span class="provider-guide__count">{{ $t('identitySources.oidc.guide.stepCount', { n: group.steps.length }) }}</span>
          </button>
          <ol
            v-if="openGroups[group.key]"
            class="provider-guide__list"
          >
            <li
              v-for="n in group.steps"
              :key="n"
            >
              {{ $t(`identitySources.oidc.guide.steps.${provider}.s${n}`) }}
            </li>
          </ol>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup>
// 提供者取值說明：逐欄一到兩句，下方為依欄位分組、預設收合的完整步驟。
// 文案只採有提供者官方文件或本系統行為為依據的句子
import { computed, reactive, watch } from 'vue'
import { ChevronDown, ChevronRight } from 'lucide-vue-next'

const range = (from, to) => Array.from({ length: to - from + 1 }, (_, i) => from + i)

// 步驟編號對回說明稿的句號；缺號是查無官方依據而不入文案的句子
const GUIDES = {
  entra: {
    intro: false,
    fields: ['issuer', 'clientId', 'secret', 'redirect', 'admission', 'groups', 'restrict'],
    groups: [
      { key: 'create', steps: range(1, 5) },
      { key: 'issuer', steps: range(6, 8) },
      { key: 'clientId', steps: [9, 10] },
      { key: 'secret', steps: [11, 12, 13, 14, 16, 17] },
      { key: 'redirect', steps: range(18, 24) },
      { key: 'entraTid', steps: range(25, 27) },
      { key: 'entraGroups', steps: range(28, 33) },
      { key: 'entraRestrict', steps: range(35, 40) },
    ],
  },
  google: {
    intro: false,
    fields: ['issuer', 'clientId', 'secret', 'redirect', 'admission', 'groups', 'restrict'],
    groups: [
      { key: 'create', steps: range(1, 4) },
      { key: 'googleClient', steps: range(5, 8) },
      { key: 'googleIssuerClientId', steps: [9, 10] },
      { key: 'secret', steps: [11, 12, 13, 15] },
      { key: 'googleHd', steps: [16, 17, 19, 20] },
      { key: 'googleGroups', steps: range(21, 23) },
    ],
  },
  other: {
    intro: true,
    fields: ['issuer', 'clientIdSecret', 'redirect', 'flow', 'scopes', 'groups'],
    groups: [],
  },
}

const props = defineProps({
  provider: { type: String, required: true },
  open: { type: Boolean, default: true },
})

defineEmits(['update:open'])

const spec = computed(() => GUIDES[props.provider] || GUIDES.other)

const openGroups = reactive({})
const toggleGroup = (key) => {
  openGroups[key] = !openGroups[key]
}

// 換提供者時各組回到收合：同名分組（Issuer、Client Secret）的內容已換了一家
watch(
  () => props.provider,
  () => {
    for (const key of Object.keys(openGroups)) openGroups[key] = false
  }
)
</script>

<style scoped>
.provider-guide {
  margin-bottom: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.provider-guide__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-sm) var(--ot-space-md);
}

.provider-guide__title {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.provider-guide__toggle {
  flex-shrink: 0;
  border: 0;
  background: transparent;
  color: var(--ot-text-secondary);
  font: inherit;
  font-size: var(--ot-font-size-xs);
  cursor: pointer;
}

/* 內容多時在面板內捲動，不把右欄撐得比表單還長 */
.provider-guide__body {
  max-height: calc(100vh - 220px);
  overflow-y: auto;
  padding: 0 var(--ot-space-md) var(--ot-space-md);
  border-top: 1px solid var(--ot-border-subtle);
}

.provider-guide__intro {
  margin: var(--ot-space-sm) 0 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.provider-guide__fields {
  margin: 0;
}

.provider-guide__field {
  padding: var(--ot-space-sm) 0;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.provider-guide__field dt {
  font-weight: 600;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}

.provider-guide__field dd {
  margin: 2px 0 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.7;
  overflow-wrap: anywhere;
}

.provider-guide__steps {
  margin-top: var(--ot-space-md);
}

.provider-guide__steps-title {
  margin-bottom: var(--ot-space-xs);
  font-weight: 600;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}

.provider-guide__group {
  border-top: 1px solid var(--ot-border-subtle);
}

.provider-guide__group-toggle {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  width: 100%;
  padding: 6px 4px;
  border: 0;
  background: transparent;
  color: var(--ot-text-primary);
  font: inherit;
  font-size: var(--ot-font-size-sm);
  text-align: left;
  cursor: pointer;
}

.provider-guide__chevron {
  color: var(--ot-text-secondary);
}

.provider-guide__group-title {
  flex: 1;
  font-weight: 600;
}

.provider-guide__count {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.provider-guide__list {
  margin: 0 0 var(--ot-space-sm);
  padding-left: 36px;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.7;
  overflow-wrap: anywhere;
}
</style>
