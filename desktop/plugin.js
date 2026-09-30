// Desktop half of the cloudflare-ai-gateway provider: Access sign-in without a terminal.
//
// The backend (dashboard/plugin_api.py + the provider's token source) owns the Access
// exchange and the grant. This half only opens the sign-in page on THIS machine
// (ctx.os.openExternal) and shows state: a status-bar chip, palette commands, and toasts
// when a turn needs sign-in or a sign-in finishes.
import { host, PALETTE_AREA, STATUSBAR_AREAS } from '@hermes/plugin-sdk'
import { useSyncExternalStore } from 'react'
import { jsx } from 'react/jsx-runtime'

const ID = 'cloudflare-ai-gateway'
const EVENT = `plugin.${ID}.`

let status = null
const listeners = new Set()
const setStatus = next => {
  status = next
  listeners.forEach(fn => fn())
}
const subscribe = fn => {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

function label(s) {
  if (!s) return 'Cloudflare'
  if (s.pending) return 'Cloudflare: finish sign-in'
  return s.signed_in ? 'Cloudflare ✓' : 'Cloudflare: sign in'
}

function detail(s) {
  if (!s) return 'Cloudflare AI Gateway'
  if (s.signed_in && s.session_expires_at) {
    return `Signed in to ${s.base_url} until ${new Date(s.session_expires_at * 1000).toLocaleString()}`
  }
  return s.last_error || `Sign in to ${s.base_url} with Cloudflare Access`
}

export default {
  id: ID,
  name: 'Cloudflare AI Gateway',
  register(ctx) {
    const opened = new Set()
    // One toast slot for the whole sign-in story: each notify with this id replaces the previous
    // one, so "Signed in" clears the sticky "sign-in required" warning (the SDK has no dismiss).
    const TOAST = `${ID}:sign-in`
    let warning = false
    const toast = input => {
      warning = input.kind === 'warning' || input.kind === 'error'
      host.notify({ id: TOAST, ...input })
    }
    const signedIn = () => toast({ kind: 'success', title: 'Signed in to Cloudflare', message: 'A waiting message continues automatically.' })

    const refresh = () =>
      ctx
        .rest('/status')
        .then(s => {
          setStatus(s)
          // Safety net for a missed completion event: never leave the warning up once signed in.
          if (warning && s?.signed_in && !s?.pending) signedIn()
        })
        .catch(() => setStatus(null))

    const open = url => {
      if (!url || opened.has(url)) return
      opened.add(url)
      void ctx.os.openExternal(url)
    }

    const signIn = async () => {
      try {
        const s = await ctx.rest('/sign-in', { method: 'POST' })
        setStatus(s)
        opened.delete(s.browser_url) // an explicit click always reopens
        open(s.browser_url)
        toast({ kind: 'info', title: 'Cloudflare sign-in', message: 'Finish signing in in your browser.' })
      } catch (error) {
        host.notifyError(error, 'Could not start Cloudflare sign-in')
      }
    }

    const signOut = async () => {
      try {
        setStatus(await ctx.rest('/sign-out', { method: 'POST' }))
        host.notify({ kind: 'info', message: 'Signed out of Cloudflare AI Gateway.' })
      } catch (error) {
        host.notifyError(error, 'Could not sign out')
      }
    }

    ctx.onEvent(EVENT + 'signin.required', ({ payload }) => {
      open(payload?.browser_url)
      void refresh()
      toast({
        kind: 'warning',
        title: 'Cloudflare sign-in required',
        message: 'Your Cloudflare session ended. Finish signing in in your browser; your message will continue.',
        action: { label: 'Open sign-in page', onClick: () => void ctx.os.openExternal(payload?.browser_url) }
      })
    })

    ctx.onEvent(EVENT + 'signin.completed', () => {
      signedIn()
      void refresh()
    })

    ctx.onEvent(EVENT + 'signin.failed', ({ payload }) => {
      void refresh()
      toast({
        kind: 'error',
        title: 'Cloudflare sign-in failed',
        message: payload?.message || 'Sign-in did not complete.',
        action: { label: 'Try again', onClick: () => void signIn() }
      })
    })

    function Chip() {
      const s = useSyncExternalStore(subscribe, () => status)
      if (s?.mode === 'token') return null // API-token gateway: nothing to sign in to
      return jsx('button', {
        type: 'button',
        title: detail(s),
        className: 'px-1.5 text-[0.6875rem] text-(--ui-text-tertiary) hover:text-(--ui-text-secondary)',
        onClick: () => void (s?.signed_in && !s?.pending ? refresh() : signIn()),
        children: label(s)
      })
    }

    ctx.registerMany([
      { id: 'status', area: STATUSBAR_AREAS.right, order: 125, render: () => jsx(Chip, {}) },
      {
        id: 'sign-in',
        area: PALETTE_AREA,
        data: { id: `${ID}.sign-in`, label: 'Cloudflare AI Gateway: Sign in', keywords: ['cloudflare', 'access', 'login'], run: () => void signIn() }
      },
      {
        id: 'sign-out',
        area: PALETTE_AREA,
        data: { id: `${ID}.sign-out`, label: 'Cloudflare AI Gateway: Sign out', keywords: ['cloudflare', 'access', 'logout'], run: () => void signOut() }
      }
    ])

    void refresh()
    ctx.setInterval(() => void refresh(), 60_000)
    ctx.setInterval(() => void (warning && refresh()), 5_000) // clear a stale warning quickly
  }
}
