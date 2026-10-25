import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import WorkspaceAssetSidebar from '../workspace/WorkspaceAssetSidebar.vue'
import { getAssetList } from '@/api/assets'
import { resetCapabilities } from '@/composables/useCapabilities'
import { grantFor } from '@/composables/__tests__/capabilityFixtures'

// 工作區左側資產側欄：寬度、每列版面、分組樹與搜尋、存取狀態標示、全量載入。
// 與分頁的互動（點擊開分頁、說明框不發簽發、重新整理不重建分頁）在 Workspace.spec.js

enableAutoUnmount(afterEach)

vi.mock('@/api/assets', () => ({
  getAssetList: vi.fn().mockResolvedValue({ data: [], total: 0 }),
}))

// 列表首次載入由外層頁面在掛載時觸發；單獨掛載側欄時由此代為觸發
const mountSidebar = (props = {}) => {
  const wrapper = mount(WorkspaceAssetSidebar, { props, global: { plugins: [ElementPlus] } })
  wrapper.vm.loadAssets()
  return wrapper
}

// 停留在名稱上，等提示框出現（show-after 300ms），回傳提示框元素
const hoverTip = async (row) => {
  await row.find('[data-test="asset-name"]').trigger('mouseenter')
  await new Promise((r) => setTimeout(r, 350))
  await flushPromises()
  const poppers = [...document.body.querySelectorAll('.asset-tip-popper')]
    .filter((el) => el.style.display !== 'none')
  return poppers[poppers.length - 1]
}

// 可控的 ResizeObserver：測試主動送出量測結果
const roInstances = []
class ResizeObserverStub {
  constructor(cb) {
    this.cb = cb
    this.els = new Set()
    roInstances.push(this)
  }
  observe(el) { this.els.add(el) }
  unobserve(el) { this.els.delete(el) }
  disconnect() { this.els.clear() }
}
const fireResize = (match, width) => {
  for (const ro of roInstances) {
    const entries = [...ro.els]
      .filter(match)
      .map((el) => ({ target: el, contentRect: { width, height: 20 } }))
    if (entries.length) ro.cb(entries)
  }
}

const sidebarStyleWidth = (wrapper) => wrapper.find('.workspace-sidebar').attributes('style') || ''

const resetSidebarEnv = () => {
  vi.clearAllMocks()
  localStorage.clear()
  resetCapabilities()
  grantFor(['user'])
  roInstances.length = 0
}

const withAssets = (list) => getAssetList.mockResolvedValue({ data: list, total: list.length })

describe('WorkspaceAssetSidebar 寬度', () => {
  beforeEach(() => {
    resetSidebarEnv()
    withAssets([{ id: 1, name: 'ssh-a', protocol: 'ssh', active: true }])
  })

  const drag = async (wrapper, from, to) => {
    await wrapper.find('[data-test="sidebar-resizer"]').trigger('pointerdown', { clientX: from, button: 0 })
    window.dispatchEvent(new MouseEvent('pointermove', { clientX: to }))
    window.dispatchEvent(new MouseEvent('pointerup', { clientX: to }))
    await flushPromises()
  }

  it('預設 280；拖曳後寬度寫入儲存，重新掛載讀回', async () => {
    const wrapper = mountSidebar()
    await flushPromises()
    expect(sidebarStyleWidth(wrapper)).toContain('width: 280px')

    await drag(wrapper, 280, 400)
    expect(sidebarStyleWidth(wrapper)).toContain('width: 400px')
    expect(localStorage.getItem('custodexa.workspace.sidebarWidth')).toBe('400')
    wrapper.unmount()

    const again = mountSidebar()
    await flushPromises()
    expect(sidebarStyleWidth(again)).toContain('width: 400px')
  })

  it('超出 480 夾到 480、低於 200 夾到 200', async () => {
    const wrapper = mountSidebar()
    await flushPromises()
    await drag(wrapper, 280, 2000)
    expect(sidebarStyleWidth(wrapper)).toContain('width: 480px')
    expect(localStorage.getItem('custodexa.workspace.sidebarWidth')).toBe('480')
    await drag(wrapper, 480, 0)
    expect(sidebarStyleWidth(wrapper)).toContain('width: 200px')
  })

  it.each(['garbage', '9999', '10', ''])('儲存值為 %j 時用預設 280', async (raw) => {
    localStorage.setItem('custodexa.workspace.sidebarWidth', raw)
    const wrapper = mountSidebar()
    await flushPromises()
    expect(sidebarStyleWidth(wrapper)).toContain('width: 280px')
  })

  it('儲存讀取丟例外時不影響掛載，退回預設', async () => {
    const spy = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    const wrapper = mountSidebar()
    await flushPromises()
    expect(sidebarStyleWidth(wrapper)).toContain('width: 280px')
    spy.mockRestore()
  })
})

describe('WorkspaceAssetSidebar 每列版面與名稱', () => {
  const ROWS = [
    { id: 1, name: 'ssh-a', protocol: 'ssh', host: '10.0.0.1', port: 22, active: true },
    { id: 2, name: 'win-a', protocol: 'rdp', host: '10.0.0.2', port: 3389, active: true },
    { id: 3, name: 'mysql-101-r-01.acme.internal.example', protocol: 'mysql', host: '10.20.5.23', port: 3306, active: true },
    { id: 4, name: 'k8s-a', protocol: 'k8s', host: '10.0.0.4', active: true },
    { id: 5, name: 'pg-a', protocol: 'postgres', active: true },
    { id: 6, name: 'mssql-a', protocol: 'mssql', active: true },
    { id: 7, name: 'redis-a', protocol: 'redis', active: true },
  ]

  beforeEach(() => {
    resetSidebarEnv()
    withAssets(ROWS)
    vi.stubGlobal('ResizeObserver', ResizeObserverStub)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  const rowOf = (wrapper, id) => wrapper.find(`.asset-item[data-asset-id="${id}"]`)

  it('列首為協定類別圖示，列上不再有協定文字徽章', async () => {
    const wrapper = mountSidebar()
    await flushPromises()
    const kindOf = (id) => rowOf(wrapper, id).find('.asset-proto').attributes('data-proto-kind')
    expect(kindOf(1)).toBe('terminal')
    expect(kindOf(2)).toBe('desktop')
    expect(kindOf(3)).toBe('database')
    expect(kindOf(4)).toBe('container')
    expect(rowOf(wrapper, 3).find('.asset-proto').attributes('aria-label')).toBe('MySQL 資料庫')
    // 舊版的大寫協定徽章（el-tag）不得再出現
    expect(wrapper.findAll('.asset-item .el-tag')).toHaveLength(0)
    expect(wrapper.findAll('.asset-item').some((r) => /\b(SSH|RDP|MYSQL|K8S)\b/.test(r.text()))).toBe(false)
  })

  it('主控台鈕只在 mysql／postgres／mssql 出現，為無文字圖示鈕並帶提示文字', async () => {
    const wrapper = mountSidebar()
    await flushPromises()
    const withConsole = ROWS.filter((r) => rowOf(wrapper, r.id).find('[data-test="console-entry"]').exists())
      .map((r) => r.protocol)
    expect(withConsole.sort()).toEqual(['mssql', 'mysql', 'postgres'])
    const btn = rowOf(wrapper, 3).find('[data-test="console-entry"]')
    expect(btn.text().trim()).toBe('')
    expect(btn.attributes('aria-label')).toBe('開啟查詢主控台')
    const tips = wrapper.findAllComponents({ name: 'ElTooltip' }).map((c) => c.props('content'))
    expect(tips.filter((c) => c === '開啟查詢主控台')).toHaveLength(3)
  })

  it('名稱依名稱欄寬度截斷、拖窄後重算；提示含全名與主機位址；aria-label 為全名', async () => {
    const wrapper = mountSidebar()
    await flushPromises()
    const name = () => rowOf(wrapper, 3).find('[data-test="asset-name"]').text()
    const isName = (el) => el.classList?.contains('asset-item-name')

    // 量測前不截斷
    expect(name()).toBe('mysql-101-r-01.acme.internal.example')

    fireResize(isName, 400)
    await flushPromises()
    expect(name()).toBe('mysql-101-r-01.acme.internal.example')

    // 名稱欄變窄（約 20 字）：主機名完整、網域從尾端省略
    fireResize(isName, 140)
    await flushPromises()
    expect(name()).toBe('mysql-101-r-01.acme…')
    expect(name()).toContain('…')

    const tip = await hoverTip(rowOf(wrapper, 3))
    expect(tip.querySelector('[data-test="asset-tip-name"]').textContent.trim())
      .toBe('mysql-101-r-01.acme.internal.example')
    expect(tip.textContent).toContain('10.20.5.23:3306')
    expect(rowOf(wrapper, 3).attributes('aria-label')).toBe('mysql-101-r-01.acme.internal.example')
  })
})

describe('WorkspaceAssetSidebar 分組樹與搜尋', () => {
  const TREE = [
    { id: 1, name: 'm-1', protocol: 'mysql', host: '10.1.0.1', node_paths: ['prod / mysql'], active: true },
    { id: 2, name: 'm-2', protocol: 'mysql', host: '10.1.0.2', node_paths: ['prod / mysql'], active: true },
    { id: 3, name: 'm-3', protocol: 'mysql', host: '10.1.0.3', node_paths: ['prod / mysql'], active: true },
    { id: 4, name: 'r-1', protocol: 'redis', host: '10.20.5.4', node_paths: ['prod / redis'], active: true },
    { id: 5, name: 'es-uat', protocol: 'ssh', host: '10.30.0.5', node_paths: ['uat / elk'], active: true },
  ]

  beforeEach(() => {
    resetSidebarEnv()
    withAssets(TREE)
  })

  const nodes = (wrapper) =>
    wrapper.findAll('[data-test="asset-node"]').map((n) => [
      n.find('.asset-node-name').text(),
      Number(n.find('[data-test="node-count"]').text()),
    ])
  const assetNames = (wrapper) => wrapper.findAll('.asset-item').map((r) => r.attributes('aria-label'))
  const nodeEl = (wrapper, key) => wrapper.find(`[data-test="asset-node"][data-node-key="${key}"]`)

  it('分層樹附子樹台數；首次只展開第一層', async () => {
    const wrapper = mountSidebar()
    await flushPromises()
    expect(nodes(wrapper)).toEqual([
      ['prod', 4], ['mysql', 3], ['redis', 1], ['uat', 1], ['elk', 1],
    ])
    // 第二層節點預設收合：其下資產不渲染
    expect(assetNames(wrapper)).toEqual([])
    expect(nodeEl(wrapper, 'prod').attributes('aria-expanded')).toBe('true')
    expect(nodeEl(wrapper, 'prod / mysql').attributes('aria-expanded')).toBe('false')
  })

  it('多歸屬資產在兩個節點各出現一次', async () => {
    withAssets([
      ...TREE,
      { id: 9, name: 'zabbix', protocol: 'ssh', node_paths: ['prod / mysql', 'uat / elk'], active: true },
    ])
    localStorage.setItem('custodexa.workspace.expandedNodes', JSON.stringify(['prod', 'prod / mysql', 'uat', 'uat / elk']))
    const wrapper = mountSidebar()
    await flushPromises()
    expect(assetNames(wrapper).filter((n) => n === 'zabbix')).toHaveLength(2)
    expect(nodes(wrapper)).toContainEqual(['mysql', 4])
    expect(nodes(wrapper)).toContainEqual(['elk', 2])
  })

  it('收合後重新掛載維持收合', async () => {
    const wrapper = mountSidebar()
    await flushPromises()
    await nodeEl(wrapper, 'prod').trigger('click')
    expect(nodes(wrapper).map((n) => n[0])).toEqual(['prod', 'uat', 'elk'])
    wrapper.unmount()

    const again = mountSidebar()
    await flushPromises()
    expect(nodes(again).map((n) => n[0])).toEqual(['prod', 'uat', 'elk'])
    expect(nodeEl(again, 'prod').attributes('aria-expanded')).toBe('false')
  })

  it('全部未分組時不顯示樹頭，直接列資產', async () => {
    withAssets([
      { id: 1, name: 'a', protocol: 'ssh', active: true },
      { id: 2, name: 'b', protocol: 'ssh', node_paths: [], active: true },
    ])
    const wrapper = mountSidebar()
    await flushPromises()
    expect(wrapper.findAll('[data-test="asset-node"]')).toHaveLength(0)
    expect(assetNames(wrapper)).toEqual(['a', 'b'])
  })

  it('以主機位址片段搜得資產；無命中節點不渲染；台數改為符合數', async () => {
    const wrapper = mountSidebar()
    await flushPromises()
    await wrapper.find('.sidebar-search input').setValue('10.20.5')
    await flushPromises()
    expect(assetNames(wrapper)).toEqual(['r-1'])
    expect(nodes(wrapper)).toEqual([['prod', 1], ['redis', 1]])
  })

  it('以節點名搜得該節點下全部資產（資產名不含關鍵字也列出）', async () => {
    const wrapper = mountSidebar()
    await flushPromises()
    await wrapper.find('.sidebar-search input').setValue('MySQL')
    await flushPromises()
    expect(assetNames(wrapper)).toEqual(['m-1', 'm-2', 'm-3'])
    expect(nodes(wrapper)).toEqual([['prod', 3], ['mysql', 3]])
  })

  it('完全無命中顯示空狀態；清空後回到搜尋前的展開狀態', async () => {
    const wrapper = mountSidebar()
    await flushPromises()
    await nodeEl(wrapper, 'uat').trigger('click')
    const before = { nodes: nodes(wrapper), assets: assetNames(wrapper) }
    const saved = localStorage.getItem('custodexa.workspace.expandedNodes')

    await wrapper.find('.sidebar-search input').setValue('oracle')
    await flushPromises()
    expect(wrapper.find('.asset-empty').text()).toBe('沒有符合的資產')
    await wrapper.find('.sidebar-search input').setValue('m-')
    await flushPromises()
    expect(assetNames(wrapper)).toEqual(['m-1', 'm-2', 'm-3'])

    await wrapper.find('.sidebar-search input').setValue('')
    await flushPromises()
    expect({ nodes: nodes(wrapper), assets: assetNames(wrapper) }).toEqual(before)
    expect(localStorage.getItem('custodexa.workspace.expandedNodes')).toBe(saved)
  })
})

describe('WorkspaceAssetSidebar 存取狀態標示', () => {
  const STATES = [
    { id: 30, name: 'view-a', protocol: 'ssh', permission: 'view', access_state: '', active: true },
    { id: 31, name: 'pending-a', protocol: 'mysql', permission: 'connect', access_state: 'pending', active: true },
    { id: 32, name: 'approval-a', protocol: 'mysql', permission: 'connect', access_state: 'approval_required', active: true },
    { id: 33, name: 'reason-a', protocol: 'mysql', permission: 'connect', access_state: 'reason_required', active: true },
    { id: 34, name: 'open-a', protocol: 'ssh', permission: 'connect', access_state: 'connectable', active: true },
  ]

  beforeEach(() => {
    resetSidebarEnv()
    withAssets(STATES)
  })

  const rowOf = (wrapper, id) => wrapper.find(`.asset-item[data-asset-id="${id}"]`)

  it('列上標示：僅檢視文字、審核中時鐘、需審核鎖、需填理由提示', async () => {
    const wrapper = mountSidebar()
    await flushPromises()
    expect(rowOf(wrapper, 30).find('[data-test="state-view-only"]').text()).toBe('僅檢視')
    expect(rowOf(wrapper, 30).classes()).toContain('is-view-only')
    expect(rowOf(wrapper, 31).find('.asset-state--pending').exists()).toBe(true)
    expect(rowOf(wrapper, 32).find('.asset-state--approval').exists()).toBe(true)
    expect(rowOf(wrapper, 33).find('.asset-state--reason').attributes('aria-label')).toBe('連線時需填理由')
    expect(rowOf(wrapper, 34).find('[data-test="state-icon"]').exists()).toBe(false)
  })
})

describe('WorkspaceAssetSidebar 列表全量載入', () => {
  beforeEach(() => {
    resetSidebarEnv()
  })

  const pageOf = (start, count) =>
    Array.from({ length: count }, (_, i) => ({ id: start + i, name: `h-${start + i}`, protocol: 'ssh', active: true }))

  it('total=250 逐頁抓 3 次、列表 250 筆', async () => {
    getAssetList.mockImplementation(({ page }) =>
      Promise.resolve({ data: pageOf((page - 1) * 100 + 1, page < 3 ? 100 : 50), total: 250 })
    )
    const wrapper = mountSidebar()
    await flushPromises()
    expect(getAssetList).toHaveBeenCalledTimes(3)
    expect(getAssetList.mock.calls.map((c) => c[0])).toEqual([
      { page: 1, page_size: 100, authorized_only: true },
      { page: 2, page_size: 100, authorized_only: true },
      { page: 3, page_size: 100, authorized_only: true },
    ])
    expect(wrapper.vm.assets).toHaveLength(250)
    expect(wrapper.findAll('.asset-item')).toHaveLength(250)
    expect(wrapper.find('[data-test="list-notice"]').exists()).toBe(false)
  })

  it('翻頁中出現重複 id 只留一筆', async () => {
    getAssetList.mockImplementation(({ page }) =>
      Promise.resolve({ data: page === 1 ? pageOf(1, 100) : pageOf(100, 100), total: 200 })
    )
    const wrapper = mountSidebar()
    await flushPromises()
    expect(getAssetList).toHaveBeenCalledTimes(2)
    expect(wrapper.vm.assets).toHaveLength(199)
    expect(new Set(wrapper.vm.assets.map((a) => a.id)).size).toBe(199)
  })

  it('每頁皆滿且 total 極大時於 200 頁停止並提示列表不完整', async () => {
    getAssetList.mockImplementation(() => Promise.resolve({ data: pageOf(1, 100), total: 1e9 }))
    const wrapper = mountSidebar()
    await flushPromises()
    expect(getAssetList).toHaveBeenCalledTimes(200)
    expect(wrapper.find('[data-test="list-notice"]').text()).toContain('列表未完整載入')
  })

  it('重新整理失敗時保留舊列表並提示', async () => {
    withAssets([{ id: 1, name: 'ssh-a', protocol: 'ssh', active: true }])
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapper = mountSidebar()
    await flushPromises()
    getAssetList.mockRejectedValueOnce(new Error('boom'))
    await wrapper.find('[data-test="refresh-assets"]').trigger('click')
    await flushPromises()
    expect(wrapper.vm.assets.map((a) => a.name)).toEqual(['ssh-a'])
    expect(wrapper.find('[data-test="list-notice"]').text()).toContain('上次載入')
    errSpy.mockRestore()
  })
})

describe('WorkspaceAssetSidebar 提示框標出搜尋命中的主機位址片段', () => {
  const HOSTS = [
    { id: 1, name: 'prod-es-data-03', protocol: 'ssh', host: '10.20.5.23', port: 22, active: true },
    { id: 2, name: 'm-1', protocol: 'mysql', host: '10.1.0.1', port: 3306, active: true },
  ]

  beforeEach(() => {
    resetSidebarEnv()
    withAssets(HOSTS)
  })

  const rowOf = (wrapper, id) => wrapper.find(`.asset-item[data-asset-id="${id}"]`)
  const search = async (wrapper, term) => {
    await wrapper.find('.sidebar-search input').setValue(term)
    await flushPromises()
  }

  it('以位址片段搜尋時，提示框只把位址中命中的那段標出來', async () => {
    const wrapper = mountSidebar()
    await flushPromises()
    await search(wrapper, '10.20.5')
    const tip = await hoverTip(rowOf(wrapper, 1))
    const host = tip.querySelector('[data-test="asset-tip-host"]')
    expect(host.textContent).toBe('主機位址 10.20.5.23:22')
    const hits = [...host.querySelectorAll('[data-test="asset-tip-hit"]')].map((el) => el.textContent)
    expect(hits).toEqual(['10.20.5'])
    expect(host.querySelector('mark').tagName).toBe('MARK')
    // 名稱行不標
    expect(tip.querySelector('[data-test="asset-tip-name"] mark')).toBeNull()
  })

  it('關鍵字不分大小寫，標記保留原字樣；位址內出現多次全部標出', async () => {
    withAssets([{ id: 9, name: 'gw', protocol: 'ssh', host: 'GW-a.gw.local', active: true }])
    const wrapper = mountSidebar()
    await flushPromises()
    await search(wrapper, 'gw')
    const tip = await hoverTip(rowOf(wrapper, 9))
    const hits = [...tip.querySelectorAll('[data-test="asset-tip-hit"]')].map((el) => el.textContent)
    expect(hits).toEqual(['GW', 'gw'])
    expect(tip.querySelector('[data-test="asset-tip-host"]').textContent).toBe('主機位址 GW-a.gw.local')
  })

  it('只因名稱命中或沒有關鍵字時，提示框不標任何片段', async () => {
    const wrapper = mountSidebar()
    await flushPromises()
    let tip = await hoverTip(rowOf(wrapper, 2))
    expect(tip.querySelector('[data-test="asset-tip-hit"]')).toBeNull()
    expect(tip.textContent).toContain('10.1.0.1:3306')

    await search(wrapper, 'm-1')
    tip = await hoverTip(rowOf(wrapper, 2))
    expect(tip.querySelector('[data-test="asset-tip-hit"]')).toBeNull()
    expect(tip.querySelector('[data-test="asset-tip-host"]').textContent).toBe('主機位址 10.1.0.1:3306')
  })

  it('提示框以文字節點切段渲染，不使用 v-html', () => {
    const source = readFileSync(join(process.cwd(), 'src/components/workspace/WorkspaceAssetRow.vue'), 'utf8')
    expect(source).not.toMatch(/v-html/)
    expect(source).toMatch(/hostLineSegments/)
  })
})
