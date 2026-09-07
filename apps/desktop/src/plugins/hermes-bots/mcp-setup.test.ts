/**
 * RFC 9207 iss relay: beginOAuth() must forward the iss value returned by
 * mcpOauth.wait() through the mcp.servers.oauth.callback RPC payload so the
 * TUI gateway can propagate it to the MCP SDK.
 */

import type * as HermesSdk from '@hermes/plugin-sdk'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  notify: vi.fn(),
  request: vi.fn()
}))

vi.mock('@hermes/plugin-sdk', async importOriginal => {
  const original = await importOriginal<typeof HermesSdk>()

  return {
    ...original,
    Button: ({ children, onClick }: { children?: React.ReactNode; onClick?: () => void }) =>
      // biome-ignore lint: test stub
      <button onClick={onClick}>{children}</button>,
    host: {
      ...original.host,
      notify: mocks.notify,
      request: mocks.request
    },
    Input: () => null,
    useI18n: () => ({ t: { common: { cancel: 'Cancel' } } })
  }
})

// mcp-setup.tsx reads _mcpRpcSupported from module scope; reset between tests
// via vi.resetModules() (already isolated by vi.mock boundary).

const callbackPayloads: Record<string, unknown>[] = []

function makeMcpOauthBridge(
  result: { code: null | string; error: null | string; iss: null | string; state: null | string }
) {
  return {
    cancel: vi.fn().mockResolvedValue(undefined),
    listen: vi.fn().mockResolvedValue({ id: 'lst-1', redirectUri: 'http://127.0.0.1:59001/callback' }),
    wait: vi.fn().mockResolvedValue(result)
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  callbackPayloads.length = 0
  Element.prototype.scrollIntoView = () => undefined
  Element.prototype.hasPointerCapture = () => false
  Element.prototype.releasePointerCapture = () => undefined
  Element.prototype.setPointerCapture = () => undefined
})

afterEach(() => {
  cleanup()
  // Remove bridge so tests don't bleed state.
  if (typeof window !== 'undefined' && window.hermesDesktop) {
    // @ts-expect-error test teardown
    delete window.hermesDesktop.mcpOauth
  }
})

function setupRequestMock(sessionId = 'sess-rfc9207') {
  mocks.request.mockImplementation(async (method: string, params: Record<string, unknown>) => {
    if (method === 'mcp.servers.list') {
      return { servers: [] }
    }

    if (method === 'mcp.servers.add') {
      return {}
    }

    if (method === 'mcp.servers.oauth.start') {
      return { auth_url: 'https://accounts.example.com/auth', session_id: sessionId }
    }

    if (method === 'mcp.servers.oauth.callback') {
      callbackPayloads.push(structuredClone(params ?? {}))

      return { ok: true }
    }

    if (method === 'mcp.servers.oauth.poll') {
      return { status: 'approved' }
    }

    return {}
  })
}

describe('RFC 9207 iss relay via mcpOauth.wait', () => {
  it('includes iss in oauth.callback payload when the redirect carries it', async () => {
    setupRequestMock()

    const bridge = makeMcpOauthBridge({
      code: 'code-abc',
      error: null,
      iss: 'https://accounts.google.com',
      state: 'state-xyz'
    })

    // @ts-expect-error injecting test bridge
    window.hermesDesktop = { mcpOauth: bridge, openExternal: vi.fn() }

    vi.resetModules()
    const { McpSetupButton } = await import('./mcp-setup')

    render(
      <McpSetupButton
        entry={{ auth: 'oauth', fromCatalog: true, installed: false, name: 'google-workspace' }}
        profile="test-profile"
      />
    )

    // Wait for the feature-detect probe to resolve (mcp.servers.list).
    await waitFor(() => expect(mocks.request).toHaveBeenCalledWith('mcp.servers.list', {}))

    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }))

    await waitFor(() => expect(callbackPayloads).toHaveLength(1))

    expect(callbackPayloads[0]).toMatchObject({
      code: 'code-abc',
      iss: 'https://accounts.google.com',
      name: 'google-workspace',
      profile: 'test-profile',
      session_id: 'sess-rfc9207',
      state: 'state-xyz'
    })
  })

  it('omits iss from oauth.callback payload when the redirect carries no iss', async () => {
    setupRequestMock('sess-no-iss')

    const bridge = makeMcpOauthBridge({
      code: 'code-def',
      error: null,
      iss: null,
      state: 'state-2'
    })

    // @ts-expect-error injecting test bridge
    window.hermesDesktop = { mcpOauth: bridge, openExternal: vi.fn() }

    vi.resetModules()
    const { McpSetupButton } = await import('./mcp-setup')

    render(
      <McpSetupButton
        entry={{ auth: 'oauth', fromCatalog: false, installed: true, name: 'plain-server' }}
        profile="profile-b"
      />
    )

    await waitFor(() => expect(mocks.request).toHaveBeenCalledWith('mcp.servers.list', {}))

    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }))

    await waitFor(() => expect(callbackPayloads).toHaveLength(1))

    // null iss → `null || undefined` → key absent from payload.
    expect(callbackPayloads[0]).not.toHaveProperty('iss')
    expect(callbackPayloads[0]).toMatchObject({
      code: 'code-def',
      name: 'plain-server',
      profile: 'profile-b',
      session_id: 'sess-no-iss',
      state: 'state-2'
    })
  })
})
