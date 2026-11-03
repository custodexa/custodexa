<template>
  <span
    class="inv-name"
    data-test="inv-name"
    :title="shownText"
  >
    <bdi class="inv-name-text"><template
      v-for="(seg, i) in parsed.segments"
      :key="i"
    ><span
      v-if="seg.escaped"
      class="inv-name-esc"
      data-test="inv-name-esc"
    >{{ seg.text }}</span><template v-else>{{ seg.text }}</template></template></bdi>
    <template v-if="badges">
      <el-tooltip
        v-if="parsed.hasEscaped"
        :content="$t('hostInventory.cell.hiddenCharsTip')"
        placement="top"
      >
        <el-tag
          size="small"
          type="warning"
          effect="plain"
          data-test="badge-hidden"
        >
          {{ $t('hostInventory.cell.hiddenChars') }}
        </el-tag>
      </el-tooltip>
      <el-tooltip
        v-if="parsed.hasNonAscii"
        :content="$t('hostInventory.cell.nonAsciiTip')"
        placement="top"
      >
        <el-tag
          size="small"
          type="info"
          effect="plain"
          data-test="badge-nonascii"
        >
          {{ $t('hostInventory.cell.nonAscii') }}
        </el-tag>
      </el-tooltip>
    </template>
  </span>
</template>

<script setup>
// 主機傳回的名稱：不可見與易混淆字元可見化，以文字節點渲染（不用 HTML 插值），
// 容器隔離文字方向，名稱不影響相鄰文字的排列。
import { computed } from 'vue'
import { visibleName, visibleText } from '@/utils/visibleName'

const props = defineProps({
  value: { type: String, default: '' },
  badges: { type: Boolean, default: true },
})

const parsed = computed(() => visibleName(props.value))
const shownText = computed(() => visibleText(props.value))
</script>

<style scoped>
.inv-name {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
  min-width: 0;
  unicode-bidi: isolate;
}

.inv-name-text {
  font-family: var(--ot-font-mono);
  font-size: 13px;
  max-width: 240px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  unicode-bidi: isolate;
}

.inv-name-esc {
  background: var(--ot-bg-active);
  color: var(--ot-warning);
  border-radius: var(--ot-radius-sm);
  padding: 0 2px;
}
</style>
