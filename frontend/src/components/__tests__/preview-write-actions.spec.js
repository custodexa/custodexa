import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import { nextTick } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import ElementPlus from 'element-plus'
import PageHeader from '../PageHeader.vue'
import SourceDetailLayout from '@/views/identity-sources/components/SourceDetailLayout.vue'
import { previewWrite } from '@/directives/previewWrite'
import i18n from '@/i18n'
import { applyPreviewResponse, beginPreviewRequest, cancelPreview } from '@/composables/useRolePreview'
import { resetCapabilities } from '@/composables/useCapabilities'
import { readFileSync } from 'node:fs'
import { parse as parseSfc } from '@vue/compiler-sfc'
import inventoryMap from './preview-inventory-map.json'

enableAutoUnmount(afterEach)

const t = (k) => i18n.global.t(k)

const enter = (entryStates = []) => {
  applyPreviewResponse(beginPreviewRequest(), {
    role: { id: 7, name: 'R7' },
    previewable: true,
    permissions: ['asset:view'],
    entry_states: entryStates,
  })
}

beforeEach(() => {
  resetCapabilities()
})
afterEach(() => {
  cancelPreview()
})

describe('寫入動作標記指令', () => {
  const Probe = {
    props: { arg: { type: String, default: '' } },
    emits: ['go'],
    directives: { previewWrite },
    template: `
      <div>
        <button data-test="plain" v-preview-write @click="$emit('go','plain')">x</button>
        <button data-test="create" v-preview-write:create @click="$emit('go','create')">x</button>
        <button data-test="ticket" v-preview-write:ticket @click="$emit('go','ticket')">x</button>
        <button data-test="unmarked" @click="$emit('go','unmarked')">x</button>
      </div>`,
  }

  it('覆蓋存在時帶標記的按鈕為 disabled，說明句依新增類、一般類、票證類，點擊不觸發處理函式', async () => {
    enter()
    const w = mount(Probe)
    await nextTick()
    const expectMsg = { plain: 'rolePreview.disabledAction', create: 'rolePreview.disabledCreate', ticket: 'rolePreview.disabledTicket' }
    for (const [id, key] of Object.entries(expectMsg)) {
      const btn = w.get(`[data-test="${id}"]`)
      expect(btn.attributes('disabled')).toBeDefined()
      expect(btn.attributes('aria-description')).toBe(t(key))
      await btn.trigger('click')
    }
    expect(w.emitted('go')).toBeUndefined()
    expect(w.get('[data-test="plain"]').attributes('aria-description')).toBe('預覽中不能執行這個操作。持有這個角色的人可以使用。')
    expect(w.get('[data-test="create"]').attributes('aria-description')).toBe('預覽中不能新增。持有這個角色的人可以使用。')
    expect(w.get('[data-test="ticket"]').attributes('aria-description')).toBe('預覽中不能連線或播放錄影。持有這個角色的人可以使用。')
    await w.get('[data-test="unmarked"]').trigger('click')
    expect(w.emitted('go')).toEqual([['unmarked']])
  })

  it('覆蓋不存在時渲染結果與未加指令的同一按鈕相同，點擊照常觸發', async () => {
    const marked = mount(Probe)
    const bare = mount({ emits: ['go'], template: '<button data-test="plain" @click="$emit(\'go\',\'plain\')">x</button>' })
    expect(marked.get('[data-test="plain"]').html()).toBe(bare.get('[data-test="plain"]').html())
    await marked.get('[data-test="create"]').trigger('click')
    expect(marked.emitted('go')).toEqual([['create']])
  })

  it('預覽中途離開後恢復原狀', async () => {
    enter()
    const w = mount(Probe)
    await nextTick()
    expect(w.get('[data-test="plain"]').attributes('disabled')).toBeDefined()
    cancelPreview()
    await nextTick()
    const btn = w.get('[data-test="plain"]')
    expect(btn.attributes('disabled')).toBeUndefined()
    expect(btn.attributes('aria-description')).toBeUndefined()
    await btn.trigger('click')
    expect(w.emitted('go')).toEqual([['plain']])
  })

  it('停用的 el-button 也不觸發 click', async () => {
    enter()
    const onClick = vi.fn()
    const w = mount(
      {
        directives: { previewWrite },
        methods: { onClick },
        template: '<el-button v-preview-write:create data-test="eb" @click="onClick">新增</el-button>',
      },
      { global: { plugins: [ElementPlus] } }
    )
    await nextTick()
    await w.get('[data-test="eb"]').trigger('click')
    expect(onClick).not.toHaveBeenCalled()
    expect(w.get('[data-test="eb"]').attributes('aria-description')).toBe(t('rolePreview.disabledCreate'))
  })

  it('預覽中各變體的 el-button 帶停用外觀 class，離開預覽後與未加指令的同一按鈕相同', async () => {
    const variants = [
      { type: 'primary' },
      { type: 'default' },
      { type: 'primary', text: true },
      { type: 'danger', plain: true },
    ]
    for (const v of variants) {
      const attrs = Object.entries(v).map(([k, val]) => (val === true ? k : `${k}="${val}"`)).join(' ')
      const marked = mount(
        { directives: { previewWrite }, template: `<el-button ${attrs} v-preview-write data-test="m">x</el-button>` },
        { global: { plugins: [ElementPlus] } }
      )
      const bare = mount(
        { template: `<el-button ${attrs} data-test="m">x</el-button>` },
        { global: { plugins: [ElementPlus] } }
      )
      expect(marked.get('button').classes()).not.toContain('is-disabled')
      enter()
      await nextTick()
      expect(marked.get('button').classes()).toContain('is-disabled')
      expect(marked.get('button').attributes('data-preview-disabled')).toBeDefined()
      cancelPreview()
      await nextTick()
      expect(marked.get('button').classes()).toEqual(bare.get('button').classes())
      expect(marked.get('button').attributes('data-preview-disabled')).toBeUndefined()
      expect(marked.html()).toBe(bare.html())
    }
  })

  it('本來就停用的 el-button 離開預覽後仍保有停用 class', async () => {
    const w = mount(
      { directives: { previewWrite }, template: '<el-button disabled v-preview-write>x</el-button>' },
      { global: { plugins: [ElementPlus] } }
    )
    enter()
    await nextTick()
    cancelPreview()
    await nextTick()
    expect(w.get('button').classes()).toContain('is-disabled')
  })

  it('滑過與聚焦時說明卡出現在按鈕正下方，不再用原生 title', async () => {
    enter()
    const w = mount(Probe, { attachTo: document.body })
    await nextTick()
    const btn = w.get('[data-test="plain"]')
    expect(btn.attributes('title')).toBeUndefined()
    const el = btn.element
    el.getBoundingClientRect = () => ({ left: 40, right: 120, top: 100, bottom: 130, width: 80, height: 30 })
    document.dispatchEvent(new MouseEvent('mousemove', { clientX: 60, clientY: 110, bubbles: true }))
    const card = document.querySelector('[data-test="preview-hint-card"]')
    expect(card.hidden).toBe(false)
    expect(card.textContent).toContain(t('rolePreview.disabledAction'))
    expect(card.style.top).toBe('136px')
    expect(card.style.left).toBe('120px')
    document.dispatchEvent(new MouseEvent('mousemove', { clientX: 500, clientY: 500, bubbles: true }))
    expect(card.hidden).toBe(true)
    el.dispatchEvent(new Event('focus'))
    expect(card.hidden).toBe(false)
    el.dispatchEvent(new Event('blur'))
    expect(card.hidden).toBe(true)
    w.unmount()
  })
})

describe('頁首唯讀標示與說明', () => {
  const mountAt = async (path, props = {}, slots = {}) => {
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:p(.*)*', component: { template: '<div />' } }] })
    router.push(path)
    await router.isReady()
    return mount(PageHeader, { props: { title: '標題', description: '既有說明', ...props }, slots, global: { plugins: [ElementPlus, router] } })
  }
  const states = [
    { entry: 'credentials', path: '/credentials', state: 'read' },
    { entry: 'policy_groups', path: '/policy-groups', state: 'read' },
    { entry: 'assets', path: '/assets', state: 'manage' },
    { entry: 'roles', path: '/roles', state: 'available' },
  ]

  it('目前頁為 read：出現唯讀標示與通用說明，既有頁面說明仍在', async () => {
    enter(states)
    const w = await mountAt('/credentials')
    expect(w.get('[data-test="preview-readonly-tag"]').text()).toBe(t('roles.state.read'))
    expect(w.get('[data-test="preview-readonly-note"]').text()).toBe('這個角色只能檢視，看不到新增、編輯與刪除。')
    expect(w.text()).toContain('既有說明')
  })

  it('頁面自有唯讀說明時（政策組）只有標示，沒有通用說明', async () => {
    enter(states)
    const w = await mountAt('/policy-groups', { ownReadonlyNote: true })
    expect(w.find('[data-test="preview-readonly-tag"]').exists()).toBe(true)
    expect(w.find('[data-test="preview-readonly-note"]').exists()).toBe(false)
  })

  it('不用頁首元件的身分來源詳情頁：唯讀時同樣標示並說明', async () => {
    enter([{ entry: 'identity_sources', path: '/identity-sources', state: 'read' }])
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:p(.*)*', component: { template: '<div />' } }] })
    router.push('/identity-sources/ldap/3')
    await router.isReady()
    const w = mount(SourceDetailLayout, { props: { title: 'X', typeLabel: 'LDAP' }, global: { plugins: [ElementPlus, router], stubs: { 'router-link': true } } })
    expect(w.get('[data-test="preview-readonly-tag"]').text()).toBe(t('roles.state.read'))
    expect(w.get('[data-test="preview-readonly-note"]').text()).toBe('這個角色只能檢視，看不到新增、編輯與刪除。')
  })

  it('manage、available 與無覆蓋時都不標示', async () => {
    enter(states)
    for (const path of ['/assets', '/roles']) {
      const w = await mountAt(path)
      expect(w.find('[data-test="preview-readonly-tag"]').exists()).toBe(false)
      expect(w.find('[data-test="preview-readonly-note"]').exists()).toBe(false)
    }
    cancelPreview()
    const w = await mountAt('/credentials')
    expect(w.find('[data-test="preview-readonly-tag"]').exists()).toBe(false)
  })
})

// ── 寫入動作盤點比對：每個觸發元素都要帶標記 ─────────────────────────────
// 對照表由盤點逐列人工對到模板元素；這裡逐元素檢查標記存在，並確認三批合計列數。
const EXPECTED_ROWS = {
  '3.8': [2, 3, 8, 9, 26, 27, 28, 29, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 53, 54, 55, 56, 59, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 88, 110, 113, 150, 151, 152, 153, 154, 155],
  '3.9': [1, 18, 19, 20, 21, 48, 49, 72, 89, 138, 139, 140, 141, 142, 161],
  '3.10': [6, 7, 13, 15, 16, 17, 22, 23, 24, 25, 93, 94, 95, 96, 97, 98, 99, 102, 103, 104, 105, 106, 107, 108, 109, 111, 112, 114, 115, 116, 117, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 132, 133, 134, 135, 137, 146, 147, 159, 160, 162, 163, 164, 165, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 179, 180, 181, 182, 183],
}
// 非模板元素的觸發（載入邏輯、傳 prop）：以來源片段確認
const SOURCE_CHECKS = [
  { batch: '3.8', rows: [151], file: 'src/views/SessionDetail.vue', mustContain: ['if (previewActive.value) return', 'preview-recording-disabled'] },
  { batch: '3.8', rows: [], file: 'src/views/Assets.vue', mustContain: [':node-drag-disabled="previewActive"'] },
  { batch: '3.8', rows: [], file: 'src/views/Dashboard.vue', mustContain: ['<UpgradeGuidanceCard v-if="!previewActive" />'] },
]

const walk = (node, visit) => {
  if (!node) return
  if (node.type === 1) visit(node)
  for (const child of node.children || []) if (child && typeof child === 'object') walk(child, visit)
}

const elementsMatching = (file, pattern) => {
  const src = readFileSync(file, 'utf8')
  const { descriptor } = parseSfc(src)
  const rx = new RegExp(pattern)
  const found = []
  walk(descriptor.template.ast, (el) => {
    if (el.props.some((p) => rx.test(p.loc.source))) found.push(el)
  })
  return found
}

describe('寫入動作盤點比對', () => {
  for (const batch of Object.keys(EXPECTED_ROWS)) {
    const entries = inventoryMap.filter((e) => e.batch === batch)
    const checks = SOURCE_CHECKS.filter((c) => c.batch === batch)

    it(`${batch}：每個對照的觸發元素都帶 v-preview-write，種類相符`, () => {
      const problems = []
      for (const e of entries) {
        const els = elementsMatching(`src/${e.file}`, e.match)
        if (!els.length) problems.push(`${e.file} ${e.match} 找不到元素`)
        for (const el of els) {
          // 下拉選單項目不是單一根節點，指令無法掛上；改用包裝元件，由它在內層元素帶指令
          if (el.tag === 'PreviewDropdownItem') {
            const kindProp = el.props.find((p) => p.type === 6 && p.name === 'kind')
            if ((kindProp ? kindProp.value.content : 'plain') !== e.kind) problems.push(`${e.file} ${e.match} 種類不符`)
            continue
          }
          const dir = el.props.find((p) => p.type === 7 && p.name === 'preview-write')
          if (!dir) problems.push(`${e.file} ${e.match} 未標記`)
          else if ((dir.arg ? dir.arg.content : 'plain') !== e.kind) problems.push(`${e.file} ${e.match} 種類不符`)
        }
      }
      expect(problems).toEqual([])
    })

    it(`${batch}：來源片段檢查`, () => {
      for (const c of checks) {
        const src = readFileSync(c.file, 'utf8')
        for (const text of c.mustContain) expect(src, `${c.file} 缺 ${text}`).toContain(text)
      }
    })

    it(`${batch}：對照列等於盤點的加標記、開對話框入口、簽發票證類（${EXPECTED_ROWS[batch].length} 列），未標記 0`, () => {
      const covered = new Set([...entries.flatMap((e) => e.rows), ...checks.flatMap((c) => c.rows)])
      const expected = new Set(EXPECTED_ROWS[batch])
      expect([...expected].filter((r) => !covered.has(r))).toEqual([])
      expect([...covered].filter((r) => !expected.has(r))).toEqual([])
    })
  }

  it('三批合計列數等於盤點 1.2 四類之和（150 列）', () => {
    const total = Object.values(EXPECTED_ROWS).reduce((n, rows) => n + rows.length, 0)
    expect(total).toBe(150)
  })
})
