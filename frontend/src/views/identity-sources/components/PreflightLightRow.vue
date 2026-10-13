<template>
  <div
    class="light"
    :data-test="`preflight-light-${light.key}`"
    :data-state="light.state"
  >
    <component
      :is="ICONS[light.state]"
      class="light__icon"
      :class="`light__icon--${light.state}`"
    />
    <div class="light__body">
      <div
        v-if="light.label"
        class="light__label"
      >
        {{ $t(light.label) }}
      </div>
      <div
        class="light__text"
        data-test="preflight-light-text"
      >
        {{ $t(light.text.key, light.text.params) }}
      </div>
      <template v-if="light.list">
        <div class="light__hint">
          {{ $t(light.list.head) }}
        </div>
        <ul class="light__list">
          <li
            v-for="item in light.list.items"
            :key="item"
          >
            {{ $t(item) }}
          </li>
        </ul>
      </template>
      <dl
        v-if="light.compare"
        class="light__compare"
      >
        <template
          v-for="row in light.compare"
          :key="row.label"
        >
          <dt>{{ $t(row.label) }}</dt>
          <dd class="light__mono">
            {{ row.value }}
          </dd>
        </template>
      </dl>
      <div
        v-if="light.hint"
        class="light__hint"
      >
        {{ $t(light.hint.key, light.hint.params) }}
      </div>
      <div
        v-if="light.sub"
        class="light__hint"
      >
        {{ $t(light.sub.key) }}
      </div>
      <div
        v-if="light.note"
        class="light__note"
        data-test="preflight-light-note"
      >
        {{ $t(light.note.key) }}
      </div>
    </div>
    <div class="light__side">
      <span
        class="light__word"
        :class="`light__word--${light.state}`"
        data-test="preflight-light-word"
      >{{ $t(light.word) }}</span>
      <el-button
        v-if="light.action === 'rediscover'"
        size="small"
        :loading="discovering"
        data-test="preflight-rediscover"
        @click="$emit('rediscover')"
      >
        {{ $t('identitySources.preflight.rediscover') }}
      </el-button>
    </div>
  </div>
</template>

<script setup>
import { CircleCheck, TriangleAlert, CircleDashed, CircleMinus } from 'lucide-vue-next'

// 圖示形狀與狀態詞一起表達燈號，不只靠顏色
const ICONS = { ok: CircleCheck, warn: TriangleAlert, gray: CircleDashed, neutral: CircleMinus }

defineProps({
  light: { type: Object, required: true },
  discovering: { type: Boolean, default: false },
})
defineEmits(['rediscover'])
</script>

<style scoped>
.light {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-sm) 0;
  border-top: 1px solid var(--ot-border-subtle);
  font-size: var(--ot-font-size-sm);
}
.light__icon { width: 16px; height: 16px; margin-top: 3px; flex-shrink: 0; }
.light__icon--ok, .light__word--ok { color: var(--ot-success); }
.light__icon--warn, .light__word--warn { color: var(--ot-warning); }
.light__icon--gray, .light__icon--neutral { color: var(--ot-text-secondary); }
.light__body { flex: 1; min-width: 0; line-height: 1.6; }
.light__label { font-weight: 600; color: var(--ot-text-primary); }
.light__text, .light__hint { color: var(--ot-text-secondary); font-size: var(--ot-font-size-xs); }
.light__side { display: flex; flex-direction: column; align-items: flex-end; gap: var(--ot-space-xs); }
.light__word {
  padding: 0 6px;
  border: 1px solid currentColor;
  border-radius: var(--ot-radius-sm);
  font-size: var(--ot-font-size-xs);
  line-height: 20px;
  white-space: nowrap;
  color: var(--ot-text-secondary);
}
.light__note { color: var(--ot-warning); font-size: var(--ot-font-size-xs); }
.light__list { margin: 2px 0; padding-left: 1.2em; color: var(--ot-text-secondary); font-size: var(--ot-font-size-xs); }
.light__compare {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 4px var(--ot-space-sm);
  margin: 4px 0;
  font-size: var(--ot-font-size-xs);
}
.light__compare dt { color: var(--ot-text-secondary); }
.light__compare dd { margin: 0; }
.light__mono { font-family: var(--ot-font-mono); word-break: break-all; }
</style>
