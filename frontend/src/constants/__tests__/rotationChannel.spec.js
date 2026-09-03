// 改密通道值域與導出：
// 值域硬拷後端 internal/model/asset_rotation_channel.go；有效通道的推導規則
// 必須與後端 EffectiveRotationChannel 同向（空字串：ssh → posix_ssh，其餘 → none），
// 否則改密計劃的資產下拉會漏列或誤列。
import { describe, it, expect } from 'vitest'
import {
  ROTATION_CHANNEL_VALUES,
  WINRM_SCHEME_VALUES,
  WINRM_TLS_MODE_VALUES,
  WINRM_DEFAULT_PORTS,
  effectiveRotationChannel,
  isRotatableAsset,
  rotationChannelText,
  rotationChannelTagType,
} from '../rotationChannel'

describe('改密通道值域（硬拷後端）', () => {
  it('通道、連線方式、憑證驗證模式三組值域與後端常數一致', () => {
    expect(ROTATION_CHANNEL_VALUES).toEqual(['posix_ssh', 'windows_winrm', 'windows_ssh', 'none'])
    expect(WINRM_SCHEME_VALUES).toEqual(['http', 'https'])
    expect(WINRM_TLS_MODE_VALUES).toEqual(['system', 'ca', 'insecure'])
    expect(WINRM_DEFAULT_PORTS).toEqual({ http: 5985, https: 5986 })
  })
})

describe('有效通道推導', () => {
  it.each([
    [{ protocol: 'rdp', effective_rotation_channel: 'windows_winrm' }, 'windows_winrm'],
    [{ protocol: 'rdp', rotation_channel: 'windows_ssh' }, 'windows_ssh'],
    [{ protocol: 'ssh' }, 'posix_ssh'],
    [{ protocol: 'ssh', rotation_channel: '' }, 'posix_ssh'],
    [{ protocol: 'rdp' }, 'none'],
    [{ protocol: 'vnc' }, 'none'],
    [undefined, 'none'],
  ])('%o → %s', (asset, expected) => {
    expect(effectiveRotationChannel(asset)).toBe(expected)
  })

  it('列表投影的 effective_rotation_channel 優先於本地推導', () => {
    expect(effectiveRotationChannel({ protocol: 'ssh', effective_rotation_channel: 'none' })).toBe('none')
  })

  it('只有有效通道非 none 的資產可進改密計劃', () => {
    expect(isRotatableAsset({ protocol: 'ssh' })).toBe(true)
    expect(isRotatableAsset({ protocol: 'rdp', effective_rotation_channel: 'windows_winrm' })).toBe(true)
    expect(isRotatableAsset({ protocol: 'rdp', effective_rotation_channel: 'none' })).toBe(false)
    expect(isRotatableAsset({ protocol: 'rdp' })).toBe(false)
    expect(isRotatableAsset({ protocol: 'mysql' })).toBe(false)
  })
})

describe('通道顯示', () => {
  it('WinRM 附連線方式，其餘取 enum 譯文，none 為空字串（zh-TW 為源）', () => {
    expect(
      rotationChannelText({ protocol: 'rdp', effective_rotation_channel: 'windows_winrm', winrm_scheme: 'https' })
    ).toBe('WinRM · HTTPS')
    expect(
      rotationChannelText({ protocol: 'rdp', effective_rotation_channel: 'windows_winrm', winrm_scheme: 'http' })
    ).toBe('WinRM · HTTP')
    expect(rotationChannelText({ protocol: 'rdp', effective_rotation_channel: 'windows_ssh' })).toBe(
      'SSH → PowerShell'
    )
    expect(rotationChannelText({ protocol: 'ssh' })).toBe('POSIX SSH')
    expect(rotationChannelText({ protocol: 'rdp' })).toBe('')
  })

  it('tag 色與傳輸階梯的風險鍵同向：http 與 insecure 走 warning，其餘 info', () => {
    const winrm = (extra) => ({ protocol: 'rdp', effective_rotation_channel: 'windows_winrm', ...extra })
    expect(rotationChannelTagType(winrm({ winrm_scheme: 'http' }))).toBe('warning')
    expect(rotationChannelTagType(winrm({ winrm_scheme: 'https', winrm_tls_mode: 'insecure' }))).toBe('warning')
    expect(rotationChannelTagType(winrm({ winrm_scheme: 'https', winrm_tls_mode: 'system' }))).toBe('info')
    expect(rotationChannelTagType(winrm({ winrm_scheme: 'https', winrm_tls_mode: 'ca' }))).toBe('info')
    expect(rotationChannelTagType({ protocol: 'ssh' })).toBe('info')
    expect(rotationChannelTagType({ protocol: 'rdp', effective_rotation_channel: 'windows_ssh' })).toBe('info')
  })
})
