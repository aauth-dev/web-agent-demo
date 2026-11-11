// Key discovery. Every key this Worker looks up goes through one
// @hellocoop/httpsig key resolver on one store: the PS's keys for a person
// token at /authorize and an auth token at /api/demo (iss + dwk → metadata →
// jwks_uri → JWKS), and a signer's keys under the jwks_uri scheme, which
// httpsig's verify() resolves before the route rejects the scheme. The
// resolver holds the policy of draft-hardt-httpbis-signature-key §Caching
// and Performance: a 5 s fetch timeout, a one-minute refetch floor that also
// holds after a failed fetch, one refresh on an unknown kid, max-age honored
// down to the floor and capped at one hour. The store is per isolate and
// bounded: its keys are URLs taken from requests not yet verified.
import type { Context } from 'hono'
import {
  BoundedTtlCache,
  createKeyResolver,
  type KeyFetchEvent,
  type KeyResolver,
  type KeyStoreEntry,
} from '@hellocoop/httpsig'
import { emit } from './events'
import type { Env } from './types'

type HonoEnv = { Bindings: Env }

const keyStore = new BoundedTtlCache<KeyStoreEntry>(500)

// Test seam: drop every cached document and every refetch-floor entry.
export function clearKeyCache(): void {
  keyStore.clear()
}

/**
 * The key resolver for one request. Every metadata and JWKS fetch it makes
 * is emitted as `aauth.playground.key_fetch` with the reason for the fetch.
 * Resolvers share the store, so the cache and the refetch floor hold across
 * requests.
 */
export function keyResolverFor(c: Context<HonoEnv>): KeyResolver {
  return createKeyResolver({
    store: keyStore,
    onFetch: (event: KeyFetchEvent) =>
      emit(c, {
        event: 'aauth.playground.key_fetch',
        level: event.ok ? 30 : 40,
        msg: `${event.doc} fetch ${event.ok ? 'ok' : 'failed'} (${event.reason}): ${event.url}`,
        route: new URL(c.req.url).pathname,
        ...event,
      }),
  })
}
