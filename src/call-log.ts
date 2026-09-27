// The AAuth call log (@aauth/call-log): one `aauth.call` record per call this
// resource answers (/authorize, /api/demo). Its agents are browsers, which do
// not log, so the record written here is the only one of each call; it makes
// no calls to other AAuth roles itself (issuer key discovery is not one).
// Records go where every event goes, by the queue to Freezer, and the monitor
// shows them.
import type { Context } from 'hono'
import { callLogMiddleware, tokenize, type CallLogHost, type ContextLike } from '@aauth/call-log'
import { emit } from './events'
import type { Env } from './types'

type HonoEnv = { Bindings: Env }

const executionCtx = (c: Context<HonoEnv>): { waitUntil(p: Promise<unknown>): void } | undefined => {
  try {
    return c.executionCtx
  } catch {
    return undefined
  }
}

/** The host for a call this resource answers. */
export const calleeHost = (c: Context<HonoEnv>): CallLogHost => {
  const ctx = executionCtx(c)
  return {
    origin: c.env.ORIGIN,
    role: 'resource',
    // tokenize once more over the whole record: a resource token inside a parsed
    // AAuth-Requirement (the auth-token challenge) is a string 0.1.0 leaves as is.
    log: (record) => emit(c, { ...(tokenize(record) as Record<string, unknown>), event: record.event }),
    defer: ctx ? (p) => ctx.waitUntil(p) : undefined,
  }
}

// Not calls between AAuth roles: the package's defaults (metadata, JWKS,
// health), plus this Worker's agent-provider routes — the browser agent
// bootstrapping its own agent token is not a call the monitor maps (its party
// map has no agent-provider circle).
const skip = (request: Request): boolean => {
  if (request.method === 'OPTIONS' || request.method === 'HEAD') return true
  const path = new URL(request.url).pathname
  return path.startsWith('/.well-known/') || path === '/health' || path === '/openapi.json' || path === '/bootstrap' || path === '/refresh' || path === '/agent/forget'
}

export const callLog = async (c: Context<HonoEnv>, next: () => Promise<void>) => {
  // A view of the context: Hono's `executionCtx` getter throws where there is
  // none, and the package reads it as a plain property.
  const view: ContextLike = {
    req: c.req,
    get res() {
      return c.res
    },
    executionCtx: executionCtx(c),
  }
  return callLogMiddleware(calleeHost(c), { skip })(view, next)
}
