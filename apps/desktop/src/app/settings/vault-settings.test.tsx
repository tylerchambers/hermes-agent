import type { VaultItem } from '@hermes/shared'
import { QueryClientProvider } from '@tanstack/react-query'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { deferred } from '@/test/deferred'
import { stubResizeObserver } from '@/test/jsdom'

const { requestGateway, requestGatewayForAgent } = vi.hoisted(() => ({
  requestGateway: vi.fn(),
  requestGatewayForAgent: vi.fn()
}))

// The panel routes every RPC through the owner (connection, profile) socket (never the ambient
// gateway); the mock receives (method, params) after the connectionId + profile arguments.
vi.mock('@/store/gateway', async importActual => ({
  ...(await importActual<Record<string, unknown>>()),
  requestGatewayForAgent: (...args: [null | string, string, string, Record<string, unknown>?, ...unknown[]]) => {
    requestGatewayForAgent(...args)

    return requestGateway(args[2], args[3] ?? {})
  }
}))

import { queryClient } from '@/lib/query-client'
import { $connection, $gatewayState } from '@/store/session'

import { VaultSettings } from './vault-settings'

stubResizeObserver()

const renderVault = (route = '/settings?tab=vault') =>
  render(
    <MemoryRouter initialEntries={[route]}>
      <QueryClientProvider client={queryClient}>
        <VaultSettings />
      </QueryClientProvider>
    </MemoryRouter>
  )

const LOGIN_ITEM = {
  id: 'vault_abc123',
  kind: 'login',
  label: 'GitHub work',
  origin: 'https://github.com',
  created_at: '2026-08-01T12:00:00+00:00',
  identifier: 'me@example.com',
  identifier_type: 'email'
}

beforeEach(() => {
  requestGateway.mockReset()
  requestGatewayForAgent.mockReset()
  queryClient.clear()
  $connection.set(null)
  $gatewayState.set('open')
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('VaultSettings', () => {
  // Two connections both serving `default` (this device + a remote gateway): a bare profile
  // name would resolve onto the PRIMARY socket and the panel would show the other machine's
  // vault (#94811). The RPC must name the connection the panel claims to show.
  it('routes every vault RPC through the active connection, not a bare profile name', async () => {
    requestGateway.mockResolvedValue({ items: [] })
    $connection.set({ connectionId: 'this-device', mode: 'local' } as never)
    renderVault()

    await waitFor(() => expect(requestGateway).toHaveBeenCalledWith('vault.list', {}))
    expect(requestGatewayForAgent).toHaveBeenCalledWith(
      'this-device',
      expect.any(String),
      'vault.list',
      {},
      undefined,
      undefined,
      { spawnPriority: 'foreground' }
    )
  })

  it('opens the Add dialog pre-filled from deep-link query params (never secrets)', async () => {
    requestGateway.mockResolvedValue({ items: [] })
    renderVault('/settings?tab=vault&kind=login&label=github&origin=https://github.com')

    await waitFor(() => expect(screen.getByLabelText('Label')).toBeTruthy())
    expect((screen.getByLabelText('Label') as HTMLInputElement).value).toBe('github')
    expect((screen.getByLabelText('Site origin') as HTMLInputElement).value).toBe('https://github.com')
    // The password field always starts empty — a secret can never arrive via link.
    expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('')
  })

  it('validates the origin before submitting a login item', async () => {
    requestGateway.mockResolvedValue({ items: [] })
    renderVault()

    fireEvent.click(await screen.findByRole('button', { name: 'Add' }))
    fireEvent.change(screen.getByLabelText('Label'), { target: { value: 'x' } })
    fireEvent.change(screen.getByLabelText('Site origin'), { target: { value: 'not-a-url' } })
    fireEvent.change(screen.getByLabelText('Identifier'), { target: { value: 'me@example.com' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(screen.getByText('Enter a valid URL like https://example.com.')).toBeTruthy())
    expect(requestGateway).not.toHaveBeenCalledWith('vault.add', expect.anything())
  })

  it('deletes an item through the confirm dialog', async () => {
    requestGateway.mockImplementation(async (method: string) =>
      method === 'vault.list' ? { items: [LOGIN_ITEM] } : { removed: true }
    )
    renderVault()

    await waitFor(() => expect(screen.getByText('GitHub work')).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: 'Remove saved item' }))
    await waitFor(() => expect(screen.getByText('Delete this item?')).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))

    await waitFor(() => expect(requestGateway).toHaveBeenCalledWith('vault.remove', { id: 'vault_abc123' }))
  })

  it('unlocks a password manager from Settings; the master password leaves only via vault.unlock', async () => {
    const sources = [
      {
        name: 'onepassword',
        display_name: '1Password',
        enabled: true,
        needs_unlock: true,
        unlocked: false,
        installed: true
      },
      {
        name: 'bitwarden',
        display_name: 'Bitwarden',
        enabled: false,
        needs_unlock: true,
        unlocked: false,
        installed: false
      }
    ]

    requestGateway.mockImplementation(async (method: string) => {
      if (method === 'vault.list') {
        // An external item has no delete affordance; its manager is shown as a source badge instead.
        return { items: [{ ...LOGIN_ITEM, id: 'op:xyz', label: 'GitHub via 1Password', backend: 'onepassword' }] }
      }

      if (method === 'vault.sources') {
        return { sources: sources.map(source => ({ ...source })) }
      }

      if (method === 'vault.unlock') {
        sources[0] = { ...sources[0], unlocked: true }

        return { unlocked: true }
      }

      return {}
    })
    renderVault()

    await waitFor(() => expect(screen.getByText('GitHub via 1Password')).toBeTruthy())
    expect(screen.queryByRole('button', { name: 'Remove saved item' })).toBeNull()
    // A manager that isn't installed has nothing to switch (detection is automatic); the installed one can be unlocked.
    expect(screen.queryByRole('switch', { name: 'Bitwarden' })).toBeNull()
    expect(screen.getByRole('switch', { name: '1Password' })).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Unlock' }))
    await waitFor(() => expect(screen.getByText('Unlock 1Password')).toBeTruthy())

    fireEvent.change(screen.getByPlaceholderText('Master password'), { target: { value: 'correct horse' } })
    fireEvent.click(
      screen.getByRole('button', { name: 'Unlock' }).closest('form')!.querySelector('button[type=submit]')!
    )

    await waitFor(() =>
      expect(requestGateway).toHaveBeenCalledWith('vault.unlock', { name: 'onepassword', password: 'correct horse' })
    )
    await waitFor(() => expect(screen.getByText('Unlocked')).toBeTruthy())
    expect(screen.queryByPlaceholderText('Master password')).toBeNull()
    expect(screen.getByRole('button', { name: 'Lock' })).toBeTruthy()
  })

  it('refreshes password-manager detection when the page is reopened', async () => {
    let installed = false
    requestGateway.mockImplementation(async (method: string) => {
      if (method === 'vault.sources') {
        return {
          sources: [
            {
              name: 'onepassword',
              display_name: '1Password',
              enabled: false,
              needs_unlock: true,
              unlocked: false,
              installed
            }
          ]
        }
      }

      return { items: [] }
    })

    const first = renderVault()
    await screen.findByText('Not detected')
    first.unmount()

    installed = true
    renderVault()

    await waitFor(() => expect(screen.getByRole('switch', { name: '1Password' })).toBeTruthy())
    expect(requestGateway.mock.calls.filter(([method]) => method === 'vault.sources')).toHaveLength(2)
  })

  it('refreshes password-manager detection after remounting while the gateway is closed', async () => {
    let installed = false
    requestGateway.mockImplementation(async (method: string) => {
      if (method === 'vault.sources') {
        return {
          sources: [
            {
              name: 'onepassword',
              display_name: '1Password',
              enabled: false,
              needs_unlock: true,
              unlocked: false,
              installed
            }
          ]
        }
      }

      return { items: [] }
    })

    const first = renderVault()
    await screen.findByText('Not detected')
    first.unmount()

    installed = true
    $gatewayState.set('closed')
    renderVault()
    act(() => $gatewayState.set('open'))

    await waitFor(() => expect(screen.getByRole('switch', { name: '1Password' })).toBeTruthy())
    expect(requestGateway.mock.calls.filter(([method]) => method === 'vault.sources')).toHaveLength(2)
  })

  it('roundtrips explicit grants through refetch, resets consent, and preserves a failed revocation draft', async () => {
    let items: VaultItem[] = []
    let rejectRevocation = true
    requestGateway.mockImplementation(async (method: string, params: Record<string, unknown>) => {
      if (method === 'gateway.capabilities') {
        return { vault_origin_rules: true }
      }

      if (method === 'vault.sources') {
        return { sources: [] }
      }

      if (method === 'vault.list') {
        return { items: items.map(item => ({ ...item })) }
      }

      if (method === 'vault.add') {
        expect(params.allowed_origins).toEqual(['https://github.com/login', 'https://www.github.com/login'])
        expect(params.wildcard_origins).toEqual(['https://*.github.com'])
        // The authoritative read returns canonical origins, not the submitted URL paths.
        items = [
          {
            ...LOGIN_ITEM,
            backend: 'local',
            allowed_origins: ['https://github.com', 'https://www.github.com'],
            wildcard_origins: ['https://*.github.com']
          }
        ]

        return { id: LOGIN_ITEM.id }
      }

      if (method === 'vault.update_origins') {
        expect(params).toEqual({
          id: LOGIN_ITEM.id,
          origin: 'https://github.com',
          allowed_origins: ['https://github.com'],
          wildcard_origins: []
        })

        if (rejectRevocation) {
          rejectRevocation = false
          throw new Error('Vault is locked')
        }

        items = [{ ...LOGIN_ITEM, backend: 'local', allowed_origins: ['https://github.com'], wildcard_origins: [] }]

        return { id: LOGIN_ITEM.id }
      }

      throw new Error(`Unexpected method: ${method}`)
    })
    renderVault()
    fireEvent.click(await screen.findByRole('button', { name: 'Add' }))
    await screen.findByLabelText(/^Additional exact origins/)

    for (const [label, value] of [
      ['Label', 'GitHub work'],
      ['Site origin', 'https://github.com/login'],
      [/^Additional exact origins/, ' https://www.github.com/login \n'],
      [/^Wildcard origins/, 'https://*.github.com'],
      ['Identifier', 'me@example.com'],
      ['Password', 'private-password']
    ] as const) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } })
    }

    const consentName = 'I trust every matching subdomain to receive this password.'
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByRole('checkbox', { name: consentName }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByLabelText('Password')).toBeNull())
    expect(await screen.findByText('https://www.github.com')).toBeTruthy()
    expect(screen.getByText('https://*.github.com')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: 'Edit origins' }))
    expect((screen.getByLabelText('Site origin') as HTMLInputElement).value).toBe('https://github.com')
    expect((screen.getByLabelText(/^Additional exact origins/) as HTMLTextAreaElement).value).toBe(
      'https://www.github.com'
    )
    expect(screen.getByRole('checkbox', { name: consentName }).getAttribute('aria-checked')).toBe('false')
    fireEvent.click(screen.getByRole('checkbox', { name: consentName }))
    fireEvent.change(screen.getByLabelText(/^Wildcard origins/), { target: { value: 'https://*.other.example' } })
    expect(screen.getByRole('checkbox', { name: consentName }).getAttribute('aria-checked')).toBe('false')
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByRole('checkbox', { name: consentName }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    fireEvent.click(screen.getByRole('button', { name: 'Edit origins' }))
    expect((screen.getByLabelText(/^Wildcard origins/) as HTMLTextAreaElement).value).toBe('https://*.github.com')
    expect(screen.getByRole('checkbox', { name: consentName }).getAttribute('aria-checked')).toBe('false')

    fireEvent.change(screen.getByLabelText(/^Additional exact origins/), { target: { value: '' } })
    fireEvent.change(screen.getByLabelText(/^Wildcard origins/), { target: { value: '' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Vault is locked')).toBeTruthy()
    expect((screen.getByLabelText(/^Additional exact origins/) as HTMLTextAreaElement).value).toBe('')
    expect((screen.getByLabelText(/^Wildcard origins/) as HTMLTextAreaElement).value).toBe('')
    expect(requestGateway.mock.calls.filter(([method]) => method === 'vault.update_origins')).toHaveLength(1)
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByLabelText('Site origin')).toBeNull())
    await waitFor(() => expect(screen.queryByText('https://www.github.com')).toBeNull())
    expect(screen.queryByText('https://*.github.com')).toBeNull()
    expect(screen.getByText('https://github.com')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Edit origins' }))
    expect((screen.getByLabelText(/^Additional exact origins/) as HTMLTextAreaElement).value).toBe('')
    expect((screen.getByLabelText(/^Wildcard origins/) as HTMLTextAreaElement).value).toBe('')
    expect(screen.queryByRole('checkbox', { name: consentName })).toBeNull()
  })

  it.each(['absent', 'false', 'unconfirmed'] as const)(
    'keeps single-origin adds usable with %s origin-rule support and the previous add contract',
    async capability => {
      let saved = false
      requestGateway.mockImplementation(async (method: string, params: Record<string, unknown>) => {
        if (method === 'gateway.capabilities') {
          if (capability === 'unconfirmed') {
            return deferred<unknown>().promise
          }

          return capability === 'false' ? { vault_origin_rules: false } : {}
        }

        if (method === 'vault.sources') {
          return { sources: [] }
        }

        if (method === 'vault.list') {
          return { items: saved ? [LOGIN_ITEM] : [] }
        }

        if (method === 'vault.add') {
          // Previous VaultAddParams rejects unknown fields, even empty grant arrays.
          if (Object.keys(params).some(key => !['kind', 'label', 'origin', 'secret'].includes(key))) {
            throw new Error('Unexpected add parameter')
          }

          saved = true

          return { id: LOGIN_ITEM.id }
        }

        throw new Error(`Unexpected method: ${method}`)
      })
      renderVault()
      fireEvent.click(await screen.findByRole('button', { name: 'Add' }))

      for (const [label, value] of [
        ['Label', 'GitHub work'],
        ['Site origin', 'https://github.com'],
        ['Identifier', 'me@example.com'],
        ['Password', 'private-password']
      ]) {
        fireEvent.change(screen.getByLabelText(label), { target: { value } })
      }

      expect(screen.queryByLabelText(/^Additional exact origins/)).toBeNull()
      expect(screen.queryByLabelText(/^Wildcard origins/)).toBeNull()
      fireEvent.click(screen.getByRole('button', { name: 'Save' }))
      await waitFor(() => expect(screen.queryByLabelText('Password')).toBeNull())
      expect(await screen.findByText('GitHub work')).toBeTruthy()
      expect(screen.getByText('https://github.com')).toBeTruthy()
      expect(screen.queryByRole('button', { name: 'Edit origins' })).toBeNull()
      expect(requestGateway.mock.calls.filter(([method]) => method === 'vault.add')).toHaveLength(1)
      expect(requestGateway).toHaveBeenCalledWith('gateway.capabilities', {})
    }
  )
})
