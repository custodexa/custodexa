<template>
  <div class="preservice-page">
    <div class="preservice-lang">
      <slot name="lang" />
    </div>
    <div class="preservice-grid">
      <!-- 左欄先於右欄是**契約而非排版偏好**：i18n spec 要求遺失警語在文件順序上
           位於任何表單之前，摺為單欄時也由此順序承擔（故樣式不得用 order 改寫） -->
      <aside class="preservice-left">
        <slot name="left" />
        <!-- 狀態訊息的固定版位：成立的排進來，不成立的整條不存在。
             改版前它們插在表單之前，一多就把表單推到半頁以下 -->
        <div class="status-messages">
          <div
            v-for="message in messages"
            :key="message.key"
            class="status-message"
            :class="`is-${message.tone}`"
          >
            <span class="status-dot" />
            <div class="status-message-body">
              <p class="status-message-title">
                {{ message.title }}
              </p>
              <p
                v-if="message.text"
                class="status-message-text"
              >
                {{ message.text }}
              </p>
              <ol
                v-if="message.steps"
                class="status-message-steps"
              >
                <li
                  v-for="step in message.steps"
                  :key="step"
                >
                  {{ step }}
                </li>
              </ol>
              <p
                v-if="message.note"
                class="status-message-note"
              >
                {{ message.note }}
              </p>
            </div>
          </div>
        </div>
      </aside>
      <section
        class="preservice-right"
        :class="[rightClass, { 'is-danger': tone === 'danger' }]"
      >
        <slot name="right" />
      </section>
    </div>
  </div>
</template>

<script setup>
// 服務前頁面（服務尚未上線時操作者看得到的全頁畫面）的共同版面：
// 左欄只放「現在什麼狀態、什麼不能弄丟」，右欄只放「唯一要做的事」。
//
// 這個切分解掉的是改版前的痛點：狀態訊息與表單同欄時，訊息一多就把表單推到
// 半頁以下，而讀者正在處理中斷、只會跳著看。兩欄之後，訊息的出現與消失
// 不會動到右欄表單的版位。

defineProps({
  // 右欄外框語氣。'danger' 用於「這次輸入不可逆」的動作（初始化解封），
  // 只表語意，不作品牌強調
  tone: {
    type: String,
    default: 'default',
    validator: (v) => ['default', 'danger'].includes(v),
  },
  // 供頁面掛自己的狀態旗標與測試錨點（版面本身不認得這些類名）
  rightClass: {
    type: [String, Array, Object],
    default: '',
  },
  // 成立中的狀態訊息（{ key, tone: 'warning'|'danger', title, text?, steps?, note? }）。
  // 由版面持有版位、頁面只給內容：這樣「訊息增減不影響右欄」是結構保證，
  // 不是每個頁面各自遵守的約定
  messages: {
    type: Array,
    default: () => [],
  },
})
</script>

<style scoped>
.preservice-page {
  position: relative;
  min-height: 100vh;
  box-sizing: border-box;
  padding: var(--ot-space-xl) 40px;
  background: var(--el-bg-color-page);
}

/* 語言切換：封印期本頁是唯一可達頁面，切換入口固定在右上（同 Login.vue 的版位） */
.preservice-lang {
  position: absolute;
  top: var(--ot-space-lg);
  right: var(--ot-space-lg);
}

.preservice-grid {
  max-width: 960px;
  margin: 0 auto;
  display: grid;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  gap: 20px;
}

.preservice-left,
.preservice-right {
  box-sizing: border-box;
  padding: var(--ot-space-lg);
  border-radius: var(--ot-radius-lg);
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color);
  display: flex;
  flex-direction: column;
}

.preservice-left {
  grid-column: span 5;
  gap: var(--ot-space-md);
}

.preservice-right {
  grid-column: span 7;
  gap: 14px;
}

/* 不可逆的動作：外框加重並外暈。危險色只表語意 */
.preservice-right.is-danger {
  border: 2px solid var(--el-color-danger);
  box-shadow: 0 0 0 4px var(--el-color-danger-light-9);
}

/* 一則都不成立時整塊不佔空間（版位仍在，只是沒有內容） */
.status-messages {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
}

.status-messages:empty {
  display: none;
}

.status-message {
  display: flex;
  gap: var(--ot-space-sm);
  align-items: flex-start;
  font-size: var(--ot-font-size-sm);
  line-height: 1.5;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-top: 6px;
  flex-shrink: 0;
  background: var(--el-color-warning);
}

.status-message.is-danger .status-dot {
  background: var(--el-color-danger);
}

.status-message-body {
  min-width: 0;
}

.status-message-title {
  margin: 0;
  font-weight: 600;
}

.status-message-text,
.status-message-note {
  margin: 2px 0 0;
  color: var(--el-text-color-secondary);
}

.status-message-steps {
  margin: 4px 0 0;
  padding-left: 20px;
  color: var(--el-text-color-secondary);
}

@media (max-width: 900px) {
  .preservice-page {
    padding: var(--ot-space-lg) var(--ot-space-md);
  }

  .preservice-grid {
    grid-template-columns: 1fr;
  }

  .preservice-left,
  .preservice-right {
    grid-column: auto;
  }
}
</style>
