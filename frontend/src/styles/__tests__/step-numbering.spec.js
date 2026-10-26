// el-steps 的步驟號不得畫在圓框內：全站覆寫在 dark-theme.css，涵蓋所有 el-step。
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { mount } from '@vue/test-utils'
import ElementPlus, { ElSteps, ElStep } from 'element-plus'
import { h } from 'vue'

const css = readFileSync(join(process.cwd(), 'src/styles/dark-theme.css'), 'utf8')

function block(selector) {
  const idx = css.indexOf(`\n${selector} {`)
  if (idx < 0) throw new Error(`selector ${selector} not found`)
  return css.slice(idx, css.indexOf('}', idx))
}

describe('el-step numbering', () => {
  it('renders the step number inside .el-step__icon.is-text, which has no circular frame', () => {
    const w = mount(
      {
        render: () =>
          h(ElSteps, { active: 1, finishStatus: 'success' }, () => [
            h(ElStep, { title: 'a' }),
            h(ElStep, { title: 'b' }),
          ]),
      },
      { global: { plugins: [ElementPlus] } }
    )
    const icons = w.findAll('.el-step__icon.is-text')
    expect(icons.length).toBe(2)
    // 未完成步驟：數字文字節點由 ::after 補點
    expect(w.findAll('.el-step__icon-inner:not(.is-status)')[0].text()).toMatch(/^\d+$/)

    const frame = block('.el-step__icon.is-text')
    expect(frame).toMatch(/border:\s*0\s*;/)
    expect(frame).toMatch(/border-radius:\s*0\s*;/)
    expect(frame).not.toMatch(/50%/)
    expect(css).toMatch(/\.el-step__icon-inner:not\(\.is-status\)::after\s*\{\s*content:\s*'\.'/)
    w.unmount()
  })
})
