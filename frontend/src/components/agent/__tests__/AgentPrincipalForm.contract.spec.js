import { describe, it, expect, vi, afterEach } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AgentPrincipalForm from '../AgentPrincipalForm.vue'

// 管理端建立 agent 的前後端契約：表單經 API 客戶端實際送出的 body，
// 必須與後端 handler 測試使用的同一份 fixture 逐鍵相等
// （backend/internal/api/testdata/agent_create_payload.json，
// 後端側為 backend/internal/api/agent_create_contract_test.go）。
// 只 mock 最底層的 request，讓表單的組裝與 agents.js 補上的 kind 都真的走過。
// 前端 payload 一改，本案例即紅，直到 fixture 同步——而 fixture 一改，
// 後端測試會以新形狀重新驗收建立結果。
//
// fixture 由 docker-compose.dev.yml 以唯讀掛載送進前端容器（/repo 慣例）；
// 無掛載時該案例 skip 並印出原因——純前端環境讀不到後端原始碼。

const request = vi.hoisted(() => vi.fn())
vi.mock('@/api/request', () => ({ default: request }))
enableAutoUnmount(afterEach)

const fixtureName = 'agent_create_payload.json'
const fixturePath = [
  join(process.cwd(), '../backend/internal/api/testdata', fixtureName),
  join(process.cwd(), '../../backend/internal/api/testdata', fixtureName),
  join('/repo/backend/internal/api/testdata', fixtureName),
].find((p) => existsSync(p))

if (!fixturePath) {
  // eslint-disable-next-line no-console
  console.warn(
    '[AgentPrincipalForm.contract] 共用 fixture 不可讀，跳過契約案例。' +
      '開發環境請確認 docker-compose.dev.yml 已掛載 backend/internal/api/testdata 至 /repo'
  )
}

describe('建立 agent 的送出內容與後端 fixture 一致', () => {
  it.skipIf(!fixturePath)('表單送出的 body 逐鍵等於共用 fixture', async () => {
    const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'))
    // fixture 讀成空物件時 toEqual 仍可能對上——先鎖住形狀
    expect(Object.keys(fixture).length, 'fixture 載入後沒有任何鍵').toBeGreaterThan(0)
    expect(fixture.kind).toBe('agent')

    const owner = { id: fixture.owner_user_id, username: 'owner', kind: 'human', active: true }
    request.mockImplementation((config) =>
      Promise.resolve(config.method === 'get' ? { data: [owner], total: 1 } : { data: { id: 99 } })
    )
    const w = mount(AgentPrincipalForm, { global: { plugins: [ElementPlus] } })
    await flushPromises()
    w.vm.username = `  ${fixture.username}  `
    w.vm.ownerId = fixture.owner_user_id
    await w.get('[data-test="agent-submit"]').trigger('click')
    await flushPromises()

    const posts = request.mock.calls.map(([config]) => config).filter((c) => c.method === 'post')
    expect(posts).toHaveLength(1)
    expect(posts[0].url).toBe('/users')
    expect(posts[0].data).toEqual(fixture)
    expect(w.emitted('created')).toHaveLength(1)
  })
})
