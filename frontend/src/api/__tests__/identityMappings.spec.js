import { describe, it, expect, vi } from 'vitest'
import {
  getRoleMappings, getUserGroupMappings, createUserGroupMapping,
  updateUserGroupMapping, deleteUserGroupMapping, getExternalGroups,
  updateExternalGroupNote,
  getUserGroupMappingUsage,
} from '../identitySources'
import { replaceUserGroupMembers } from '../userGroups'

const requestMock = vi.fn(() => Promise.resolve({ data: [] }))
vi.mock('../request', () => ({ default: (options) => requestMock(options) }))

describe('外部群組映射 API 契約', () => {
  it('角色、使用者群組與共用字典各走明確路由', async () => {
    await getRoleMappings('oidc', 3)
    await getUserGroupMappings('oidc', 3)
    await createUserGroupMapping('oidc', 3, { match_value: 'ops', user_group_id: 8 })
    await updateUserGroupMapping('oidc', 3, 4, { enabled: false })
    await deleteUserGroupMapping('oidc', 3, 4)
    await getExternalGroups('oidc', 3)
    await updateExternalGroupNote('oidc', 3, 9, 'Operations')
    await getUserGroupMappingUsage('oidc', 3, 8)
    expect(requestMock.mock.calls.map(([x]) => `${x.method} ${x.url}`)).toEqual([
      'get /identity-sources/oidc/3/role-mappings',
      'get /identity-sources/oidc/3/user-group-mappings',
      'post /identity-sources/oidc/3/user-group-mappings',
      'put /identity-sources/oidc/3/user-group-mappings/4',
      'delete /identity-sources/oidc/3/user-group-mappings/4',
      'get /identity-sources/oidc/3/external-groups',
      'put /identity-sources/oidc/3/external-groups/9',
      'get /identity-sources/oidc/3/user-group-usage/8',
    ])
  })

  it('成員穿梭框只提交手動名單', async () => {
    requestMock.mockClear()
    await replaceUserGroupMembers(8, [2, 5])
    expect(requestMock).toHaveBeenCalledWith({
      url: '/user-groups/8/members',
      method: 'put',
      data: { manual_user_ids: [2, 5] },
    })
  })
})
