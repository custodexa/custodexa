<template>
  <span
    class="source-cell"
    data-test="source-cell"
  >
    <!--
      無位址時是**顯式的未知**，不是空白格。空白格會被讀成「來源是空的」
      或「這一欄還沒載入」，而三種原因（系統發起、寫入當下無法解析、
      所屬連線已不存在）對稽核的意義完全不同——標籤後掛原因
    -->
    <el-tooltip
      v-if="!address"
      :content="reasonText"
      placement="top"
      popper-class="source-cell-tip"
    >
      <el-tag
        size="small"
        type="info"
        class="source-unknown"
        data-test="source-unknown"
      >
        {{ $t('auditorWorkbench.events.clientIpUnknown') }}
      </el-tag>
    </el-tooltip>

    <!-- 有位址：等寬字（位址要能逐段對齊比對）。人／資產樞紐下是深連結——
         一鍵以該位址開新調查並保留當前時間窗與類別；位址樞紐下自身位址
         不加連結（連到自己不是導覽） -->
    <el-tooltip
      v-else
      :content="tipText"
      placement="top"
      popper-class="source-cell-tip"
    >
      <router-link
        v-if="link"
        :to="link"
        class="source-addr is-link"
        data-test="source-link"
      >{{ address }}</router-link>
      <span
        v-else
        class="source-addr"
        data-test="source-addr"
      >{{ address }}</span>
    </el-tooltip>
  </span>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

// 時間軸與表格檢視共用的來源位址格（auditor-workbench 來源位址維度）。
// 兩處各寫一份會讓「未知」的三種原因、位址語義說明與深連結行為在兩個
// 畫面上分岔——那正是稽核最不能承受的分岔。

const props = defineProps({
  // 後端顯式回 null（不設 omitempty）：null／空字串一律視為未知
  address: { type: String, default: null },
  // system｜unresolvable｜session_missing（僅無位址時有值）
  reason: { type: String, default: '' },
  // 事件類別，決定位址的**語義**（建線當下／該筆請求／所屬連線建線當下）
  eventType: { type: String, default: '' },
  // 位址樞紐深連結；null＝不加連結（位址樞紐下、或無位址）
  link: { type: Object, default: null },
})

const { t, te } = useI18n()

// 位址的取樣時刻依類別而不同，且這件事**必須逐格說明**：
// 指令、告警、剪貼簿本身沒有位址欄，顯示的是所屬連線建線當下的來源，
// 把它讀成「這筆指令當下的來源」會得出錯誤的結論
const SCOPE_BY_TYPE = {
  session: 'session',
  audit_log: 'request',
  file_transfer: 'request',
  command: 'viaSession',
  alert: 'viaSession',
  clipboard: 'viaSession',
}

const reasonText = computed(() => {
  const key = `auditorWorkbench.events.clientIpReason.${props.reason}`
  // 後端日後新增原因碼時顯示碼本身，不吞資訊也不假裝知道原因
  return te(key) ? t(key) : props.reason || t('auditorWorkbench.events.clientIpUnknown')
})

const tipText = computed(() => {
  const scope = SCOPE_BY_TYPE[props.eventType]
  const scopeText = scope ? t(`auditorWorkbench.events.clientIpScope.${scope}`) : ''
  if (!props.link) return scopeText
  const linkText = t('auditorWorkbench.events.pivotLink')
  return scopeText ? `${scopeText}\n${linkText}` : linkText
})
</script>

<style scoped>
.source-cell {
  display: inline-flex;
  align-items: center;
}

.source-addr {
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.source-addr.is-link {
  color: var(--ot-primary);
  text-decoration: none;
}

.source-addr.is-link:hover {
  text-decoration: underline;
}

.source-unknown {
  font-size: var(--ot-font-size-xs);
}
</style>

<style>
/* tooltip popper 掛在 body 下，scoped 樣式構不著（同 clipboard-note-tip 做法） */
.source-cell-tip {
  max-width: 360px;
  line-height: 1.6;
  /* 語義說明與深連結提示各自成行（內容以 \n 分行） */
  white-space: pre-line;
}
</style>
