import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import PrincipalBadge from '../agent/PrincipalBadge.vue'
describe('PrincipalBadge', () => {
  it('agent 主體輸出文字徽章與負責人', () => {
    const w = mount(PrincipalBadge, { props: { kind: 'agent', ownerId: 9, ownerName: 'carol' } })
    expect(w.text()).toContain('AI agent')
    expect(w.text()).toContain('負責人：carol')
    w.unmount()
  })
  it('類型只看後端欄位不看名稱', () => {
    const human = mount(PrincipalBadge, { props: { kind: 'human', ownerName: 'agent-bot' } })
    expect(human.text()).toBe('人類')
    const agent = mount(PrincipalBadge, { props: { kind: 'agent', ownerId: 9 } })
    expect(agent.text()).toContain('AI agent')
    expect(agent.text()).toContain('#9')
    human.unmount(); agent.unmount()
  })
  it('移除顏色後語義仍可讀', () => {
    const w = mount(PrincipalBadge, { props: { kind: 'agent', ownerName: 'carol' } })
    w.findAll('*').forEach(node => { node.element.removeAttribute('class'); node.element.removeAttribute('style') })
    expect(w.text()).toBe('AI agent負責人：carol')
    w.unmount()
  })
})
