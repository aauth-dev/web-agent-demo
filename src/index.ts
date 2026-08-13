import { Hono } from 'hono'
import type { Context } from 'hono'
import { cors } from 'hono/cors'
import type { Env } from './types'
import {
  verifySigJwt,
  verifySigHwk,
  psJwksVerifier,
  verifyPersonToken,
} from './httpsig-verify'
import {
  importSigningKey,
  getPublicJWK,
  signJWT,
  generateJTI,
  computeJwkThumbprint,
  sanitizeCnfJwk,
} from './crypto'
import { generateAgentLocal } from './agent-local'
import { emit, emitVerifyFailed } from './events'

type HonoEnv = { Bindings: Env }

const app = new Hono<HonoEnv>()

// Legacy host redirect — playground.aauth.dev is the old hostname; all
// production traffic should be served from web-agent.aauth.dev. We keep
// the legacy route bound to this worker (see wrangler.toml) so existing
// links 301 to the new host with path + query preserved.
app.use('*', async (c, next) => {
  const url = new URL(c.req.url)
  if (url.hostname === 'playground.aauth.dev') {
    url.hostname = 'web-agent.aauth.dev'
    return c.redirect(url.toString(), 301)
  }
  await next()
})

app.use('*', cors())

// Catch every unhandled exception, emit a structured error event with
// a stack trace, and return a clean 500. Without this, unprotected KV
// and crypto calls would bubble to Hono's default 500 with no context.
app.onError((err, c) => {
  const error = err instanceof Error ? err : new Error(String(err))
  emit(c, {
    event: 'aauth.unhandled_error',
    level: 50,
    msg: error.message,
    route: new URL(c.req.url).pathname,
    method: c.req.method,
    error_name: error.name,
    error_message: error.message,
    error_stack: error.stack,
  })
  return c.json({ error: 'internal error' }, 500)
})

// Helper: extract the error message from a Hono Response built by one
// of the verify helpers, without consuming the response body that's
// about to be returned to the caller.
async function readVerifyError(res: Response): Promise<string | undefined> {
  try {
    const body = (await res.clone().json()) as { error?: string }
    return body?.error
  } catch {
    return undefined
  }
}

// ── Resource scope metadata ──
//
// Resource scopes describe operations an agent can perform at this resource
// (the playground, wearing its resource hat). Only these values are defined
// by the resource itself.
const SCOPE_DESCRIPTIONS: Record<string, string> = {
  'playground.demo': 'Run the playground demo endpoint',
}

// Identity scopes defined by the Person Server (aauth-claims-plan v3
// §4.2 AAUTH_SUPPORTED_SCOPES + OIDC `profile` composite). These flow
// through resource_token.scope unchanged — the PS classifies them at
// /aauth/token time and releases claim values onto the auth_token.
//
// Why accept them here: v3 carries identity + resource scopes together
// in a single resource_token.scope string (the previous split across
// bootstrap/authorize is gone). The resource still validates its own
// scopes against SCOPE_DESCRIPTIONS, but must pass identity scopes
// through rather than 400'ing on them.
const PS_IDENTITY_SCOPES: Set<string> = new Set([
  'openid',
  'profile',
  'name',
  'nickname',
  'given_name',
  'family_name',
  'preferred_username',
  'picture',
  'email',
  'phone',
  'ethereum',
  'discord',
  'twitter',
  'github',
  'gitlab',
  'bio',
  'banner',
  'recovery',
  'mastodon',
  'instagram',
  'verified_name',
  'existing_name',
  'existing_username',
  'tenant_sub',
  'org',
  'groups',
  'roles',
])

// KV TTL for the (jkt → name) and (name → jkt) mappings. 90 days lets the
// same browser ephemeral keep its agent local-part across visits without
// growing the namespace forever — once a key is gone, the local-part is
// freed for re-use on a future enrollment.
const AGENT_NAME_TTL_SECONDS = 60 * 60 * 24 * 90

// ── Well-known endpoints ──

app.get('/.well-known/aauth-agent.json', (c) => {
  const origin = c.env.ORIGIN
  return c.json({
    issuer: origin,
    jwks_uri: `${origin}/.well-known/jwks.json`,
    client_name: c.env.AGENT_NAME,
    name: c.env.AGENT_NAME,
    logo_uri: c.env.AGENT_LOGO_URI ?? `${origin}/logo.svg`,
    bootstrap_endpoint: `${origin}/bootstrap`,
    refresh_endpoint: `${origin}/refresh`,
    callback_endpoint: `${origin}/callback`,
    login_endpoint: `${origin}/login`,
    localhost_callback_allowed: true,
  })
})

app.get('/.well-known/aauth-resource.json', (c) => {
  const origin = c.env.ORIGIN
  return c.json({
    issuer: origin,
    jwks_uri: `${origin}/.well-known/jwks.json`,
    name: c.env.AGENT_NAME,
    description:
      'Sample protected API for the AAuth web agent playground, used to demonstrate the end-to-end authorization flow.',
    logo_uri: c.env.AGENT_LOGO_URI ?? `${origin}/logo.svg`,
    authorization_endpoint: `${origin}/authorize`,
    scope_descriptions: SCOPE_DESCRIPTIONS,
  })
})

app.get('/.well-known/jwks.json', async (c) => {
  const publicJwk = await getPublicJWK(c.env.SIGNING_KEY)
  return c.json({ keys: [publicJwk] })
})

// ── Bootstrap ──
//
// Per draft-hardt-aauth-bootstrap, the agent provider issues an agent
// token directly: the agent generates a signing key, signs the request
// with sig=hwk, and the AP returns a token bound to that key. No PS
// involvement at this stage — the PS binds the agent to a person lazily,
// on the agent's first three-party flow.
//
// This endpoint maintains a stored mapping (jkt ↔ agent local-part) in
// KV so that the same browser ephemeral always resolves to the same
// `aauth:local@host` identifier on repeat calls. A new key gets a new
// local-part — no per-user identity is involved.

app.post('/bootstrap', async (c) => {
  const verifyRes = await verifySigHwk(c)
  if (verifyRes instanceof Response) {
    emitVerifyFailed(c, 'sig_hwk_failed', { detail: await readVerifyError(verifyRes) })
    return verifyRes
  }

  let body: { ps?: string }
  try {
    body = verifyRes.rawBody.length ? JSON.parse(verifyRes.rawBody) : {}
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400)
  }

  if (body.ps) {
    try {
      const psUrl = new URL(body.ps)
      if (psUrl.protocol !== 'https:') return c.json({ error: 'ps must be HTTPS' }, 400)
    } catch {
      return c.json({ error: 'invalid ps URL' }, 400)
    }
  }

  const host = new URL(c.env.ORIGIN).hostname

  // Look up an existing local-part for this thumbprint, or mint a fresh one.
  // Both directions are stored so /refresh can resolve a name from the
  // same key on a return visit. A fresh key always gets a fresh name —
  // we never re-use a local-part across distinct keys.
  let agentLocal = await c.env.WEBAUTHN_KV.get(`agent:name:${verifyRes.jkt}`)
  const fresh = !agentLocal
  if (!agentLocal) {
    agentLocal = generateAgentLocal()
    await c.env.WEBAUTHN_KV.put(`agent:name:${verifyRes.jkt}`, agentLocal, { expirationTtl: AGENT_NAME_TTL_SECONDS })
    await c.env.WEBAUTHN_KV.put(`agent:key:${agentLocal}`, verifyRes.jkt, { expirationTtl: AGENT_NAME_TTL_SECONDS })
  }

  const aauthSub = `aauth:${agentLocal}@${host}`
  const token = await mintAgentToken(c.env, {
    aauthSub,
    psUrl: body.ps,
    jwk: verifyRes.publicJwk,
  })

  emit(c, {
    event: 'aauth.agent_token.minted',
    msg: fresh ? 'bootstrap: minted token for new agent' : 'bootstrap: minted token for existing agent',
    route: '/bootstrap',
    agent_sub: aauthSub,
    agent_jkt: verifyRes.jkt,
    ps: body.ps,
    fresh,
  })

  return c.json(token)
})

// ── Refresh ──
//
// The agent signs with the same hwk key that's recorded against its
// local-part. We look up the name by thumbprint, mint a fresh token
// bound to the same key, and return it. No key rotation — the agent's
// durable key is unchanged across refreshes (per the bootstrap draft's
// web-app refresh pattern).

app.post('/refresh', async (c) => {
  const verifyRes = await verifySigHwk(c)
  if (verifyRes instanceof Response) {
    emitVerifyFailed(c, 'sig_hwk_failed', { detail: await readVerifyError(verifyRes) })
    return verifyRes
  }

  let body: { ps?: string }
  try {
    body = verifyRes.rawBody.length ? JSON.parse(verifyRes.rawBody) : {}
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400)
  }

  const agentLocal = await c.env.WEBAUTHN_KV.get(`agent:name:${verifyRes.jkt}`)
  if (!agentLocal) {
    emitVerifyFailed(c, 'refresh_unknown_agent', { agent_jkt: verifyRes.jkt })
    return c.json({ error: 'agent not enrolled — bootstrap first' }, 404)
  }

  const host = new URL(c.env.ORIGIN).hostname
  const aauthSub = `aauth:${agentLocal}@${host}`
  const token = await mintAgentToken(c.env, {
    aauthSub,
    psUrl: body.ps,
    jwk: verifyRes.publicJwk,
  })

  emit(c, {
    event: 'aauth.agent_token.minted',
    msg: 'refresh: re-minted token for existing agent',
    route: '/refresh',
    agent_sub: aauthSub,
    agent_jkt: verifyRes.jkt,
    ps: body.ps,
  })

  return c.json(token)
})

// ── Agent forget ──
//
// Drops the (jkt ↔ local-part) mapping so the next /bootstrap with the
// same key mints a fresh local-part. Lets the playground's Reset button
// fully reset the demo's identity instead of carrying the prior name
// across a "fresh start". Authenticated by sig=hwk — only the holder of
// the key can release its name.
app.post('/agent/forget', async (c) => {
  const verifyRes = await verifySigHwk(c)
  if (verifyRes instanceof Response) {
    emitVerifyFailed(c, 'sig_hwk_failed', { detail: await readVerifyError(verifyRes) })
    return verifyRes
  }

  const agentLocal = await c.env.WEBAUTHN_KV.get(`agent:name:${verifyRes.jkt}`)
  await c.env.WEBAUTHN_KV.delete(`agent:name:${verifyRes.jkt}`)
  if (agentLocal) await c.env.WEBAUTHN_KV.delete(`agent:key:${agentLocal}`)

  const host = new URL(c.env.ORIGIN).hostname
  emit(c, {
    event: 'aauth.agent_forget',
    msg: 'agent identity forgotten',
    route: '/agent/forget',
    agent_sub: agentLocal ? `aauth:${agentLocal}@${host}` : undefined,
    agent_jkt: verifyRes.jkt,
    had_existing: !!agentLocal,
  })

  return c.json({ ok: true })
})

// ── Token minting helper ──

async function mintAgentToken(
  env: Env,
  args: { aauthSub: string; psUrl?: string; jwk: JsonWebKey }
): Promise<{ agent_token: string; agent_id: string; expires_in: number; ps?: string }> {
  const origin = env.ORIGIN
  const privateKey = await importSigningKey(env.SIGNING_KEY)
  const publicJwk = await getPublicJWK(env.SIGNING_KEY)
  const now = Math.floor(Date.now() / 1000)

  // alg is the fully-specified `Ed25519`, not the polymorphic `EdDSA`
  // (draft-hardt-oauth-aauth-protocol §Signature Algorithms).
  const agentHeader = { alg: 'Ed25519', typ: 'aa-agent+jwt', kid: publicJwk.kid }
  const agentPayload: Record<string, unknown> = {
    iss: origin,
    dwk: 'aauth-agent.json',
    sub: args.aauthSub,
    jti: generateJTI(),
    cnf: { jwk: sanitizeCnfJwk(args.jwk) },
    iat: now,
    exp: now + 3600,
  }
  if (args.psUrl) agentPayload.ps = args.psUrl
  const agentToken = await signJWT(agentHeader, agentPayload, privateKey)

  return {
    agent_token: agentToken,
    agent_id: args.aauthSub,
    expires_in: 3600,
    ...(args.psUrl ? { ps: args.psUrl } : {}),
  }
}

// ── Authorization (resource token issuance) ──
//
// Under AAuth -11 the agent presents a PERSON token here, not its agent
// token: a resource MUST have verified a person token before it issues a
// resource token (draft-hardt-oauth-aauth-protocol §Resource Access and
// Resource Tokens). The person token's `iss` IS the person server, so the
// request body carries only `scope` — there is no `ps` parameter to
// believe or disbelieve, and the identity written into the resource token
// is PS-asserted rather than agent-asserted.

// 401 challenge for a request that presented no person token. The agent
// gets one from its PS's person_token_endpoint and retries
// (§Person Token Required).
function personTokenRequired(c: Context<HonoEnv>) {
  return c.json({ error: 'person token required' }, 401, {
    'AAuth-Requirement': 'requirement=person-token',
  })
}

app.post('/authorize', async (c) => {
  const ourJwk = await getPublicJWK(c.env.SIGNING_KEY)
  const origin = c.env.ORIGIN

  // No Signature-Key at all: nothing to verify, so challenge rather than
  // reject — the agent can satisfy this by fetching a person token.
  if (!c.req.header('Signature-Key')) {
    emitVerifyFailed(c, 'person_token_missing', { detail: 'no Signature-Key header' })
    return personTokenRequired(c)
  }

  // sig=jwt;jwt=<person_token>. verifySigJwt proves the caller holds the
  // key named in the presented JWT's cnf; the person token's own
  // signature and claims are checked below.
  //
  // An agent token where a person token belongs is the "absent" case
  // rather than an error: the agent holds the wrong credential and needs
  // to be told which one this endpoint wants, so the typ mismatch becomes
  // the requirement=person-token challenge.
  let challenged = false
  const verifyRes = await verifySigJwt(c, {
    accept: ['person'],
    onTypMismatch: (ctx, typ) => {
      challenged = true
      emitVerifyFailed(ctx, 'person_token_missing', {
        detail: `presented typ ${typ ?? 'none'}`,
      })
      return personTokenRequired(ctx as Context<HonoEnv>)
    },
  })
  if (verifyRes instanceof Response) {
    // The challenge already logged its own reason; anything else that
    // came back is a signature failure.
    if (!challenged) {
      emitVerifyFailed(c, 'sig_jwt_failed', { detail: await readVerifyError(verifyRes) })
    }
    return verifyRes
  }

  let person: Awaited<ReturnType<typeof verifyPersonToken>>
  try {
    person = await verifyPersonToken(verifyRes.innerJwt, {
      aud: origin,
      callerJkt: verifyRes.callerJkt,
    })
  } catch (err) {
    const detail = (err as Error).message
    emitVerifyFailed(c, 'person_token_invalid', { detail, caller_jkt: verifyRes.callerJkt })
    return c.json({ error: 'invalid_person_token', detail }, 400)
  }

  const personPayload = person.payload
  const psMetadata = person.psMetadata
  const psMetadataUrl = person.psMetadataUrl

  let body: { scope: string }
  try {
    body = JSON.parse(verifyRes.rawBody) as { scope: string }
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400)
  }

  if (!body.scope) {
    return c.json({ error: 'missing required field: scope' }, 400)
  }

  // resource_token.scope is the combined identity + resource string the
  // PS will classify at its auth_token_endpoint. The resource validates
  // its own scopes (SCOPE_DESCRIPTIONS) and lets PS-known identity scopes
  // pass through; anything else is a typo / spoofing attempt.
  const requestedScopes = body.scope.trim().split(/\s+/).filter(Boolean)
  const unknown = requestedScopes.filter(
    (s) => !(s in SCOPE_DESCRIPTIONS) && !PS_IDENTITY_SCOPES.has(s),
  )
  if (unknown.length > 0) {
    return c.json({ error: 'invalid_scope', unknown }, 400)
  }

  // The PS metadata was fetched during person-token key discovery. We
  // still need `issuer` (the resource token's audience in three-party) and
  // `auth_token_endpoint` — renamed from `token_endpoint` in -11 — which
  // the agent reads out of the response to place its token request.
  if (!psMetadata.issuer || !psMetadata.auth_token_endpoint || !psMetadata.jwks_uri) {
    return c.json({
      error: 'PS metadata missing required fields (issuer, auth_token_endpoint, jwks_uri)',
      ps_metadata: psMetadata,
    }, 502)
  }

  // Mint the resource token. It carries no agent identifier: `agent_jkt`
  // binds it to the agent's key, and `ps`/`sub`/`person_token_jti` name
  // the person and the exact person token this authorization rests on
  // (§Resource Token Structure).
  const agentJkt = await computeJwkThumbprint(
    (personPayload.cnf as { jwk: JsonWebKey }).jwk
  )

  const privateKey = await importSigningKey(c.env.SIGNING_KEY)

  const now = Math.floor(Date.now() / 1000)
  const rtHeader = {
    alg: 'Ed25519',
    typ: 'aa-resource+jwt',
    kid: ourJwk.kid,
  }
  const rtPayload: Record<string, unknown> = {
    iss: origin,
    dwk: 'aauth-resource.json',
    aud: psMetadata.issuer as string,
    jti: generateJTI(),
    ps: personPayload.iss as string,
    sub: personPayload.sub as string,
    person_token_jti: personPayload.jti as string,
    agent_jkt: agentJkt,
    scope: body.scope,
    iat: now,
    // 5 minutes, but never past the person token this rests on. The
    // person token is itself clamped to the mission's expires_at, so
    // this transitively keeps a mission-scoped resource token from
    // outliving its mission.
    exp: Math.min(now + 300, personPayload.exp as number),
  }
  // REQUIRED when the person token carried one, copied unchanged — the
  // PS re-reads it off the person token it issued, so dropping it here
  // would be detected as mission stripping.
  if (typeof personPayload.mission_s256 === 'string') {
    rtPayload.mission_s256 = personPayload.mission_s256
  }
  // Likewise copied when present. §Resource Token Verification step 6 has
  // the PS check ps, sub, mission_s256 AND tenant against the person token
  // it issued, "rejecting the resource token on any mismatch or omission"
  // — so dropping a tenant the person token carried makes every resource
  // token we mint for an org-affiliated person unredeemable.
  if (typeof personPayload.tenant === 'string') {
    rtPayload.tenant = personPayload.tenant
  }

  const resourceToken = await signJWT(rtHeader, rtPayload, privateKey)

  emit(c, {
    event: 'aauth.resource_token.minted',
    msg: 'resource_token minted for agent',
    route: '/authorize',
    agent_jkt: agentJkt,
    caller_jkt: verifyRes.callerJkt,
    requested_scope: body.scope,
    granted_scope: body.scope,
    ps: personPayload.iss,
    ps_issuer: psMetadata.issuer,
    person_token_jti: personPayload.jti,
    mission_s256: personPayload.mission_s256,
  })

  return c.json({
    ps_metadata: psMetadata,
    ps_metadata_url: psMetadataUrl,
    resource_token: resourceToken,
    resource_token_decoded: rtPayload,
  })
})

// ── Resource API: /api/demo ──
//
// The resource endpoint gated by `playground.demo`. An agent calls this with
// an auth_token issued by the PS; we verify the token, check the scope, and
// echo back a greeting using identity claims the PS placed on the token.
// Keeps the demo honest — the user sees a scope go end-to-end and actually
// gate something, rather than hanging unused in a consent screen.
app.get('/api/demo', async (c) => {
  // sig=jwt;jwt=<auth_token>. httpSigVerify extracts auth_token.cnf.jwk
  // from Signature-Key and verifies the RFC 9421 signature — proving
  // possession of the ephemeral. psJwksVerifier fetches the auth_token's
  // issuer JWKS (the PS) and verifies the token's own JWT signature.
  //
  // accept is auth only. A person token from the same PS carries the same
  // iss, dwk, aud, sub and cnf and would pass every other check here —
  // but it asserts identity, not authorization, and this endpoint is
  // gated on scope. §Person Token Verification: "A recipient MUST reject
  // an aa-person+jwt wherever an auth token is required."
  const origin = c.env.ORIGIN
  const verifyRes = await verifySigJwt(c, {
    accept: ['auth'],
    verifyInner: psJwksVerifier(),
  })
  if (verifyRes instanceof Response) {
    emitVerifyFailed(c, 'sig_jwt_failed', { detail: await readVerifyError(verifyRes) })
    return verifyRes
  }

  const payload = verifyRes.innerPayload as Record<string, unknown>
  if (payload.aud !== origin) {
    emitVerifyFailed(c, 'auth_token_aud_mismatch', {
      aud_actual: payload.aud,
      aud_expected: origin,
      caller_jkt: verifyRes.callerJkt,
    })
    return c.json({ error: 'auth_token aud mismatch' }, 401)
  }

  const scopeStr = typeof payload.scope === 'string' ? payload.scope : ''
  const scopes = scopeStr.split(/\s+/).filter(Boolean)
  if (!scopes.includes('playground.demo')) {
    emitVerifyFailed(c, 'insufficient_scope', {
      required: 'playground.demo',
      granted: scopes,
      caller_jkt: verifyRes.callerJkt,
    })
    return c.json({ error: 'insufficient_scope', required: 'playground.demo', granted: scopes }, 403)
  }

  const name = (payload.name as string) || (payload.given_name as string) || 'friend'

  emit(c, {
    event: 'aauth.demo_call',
    msg: 'demo endpoint called successfully',
    route: '/api/demo',
    agent_sub: payload.act ? (payload.act as { sub?: string }).sub : payload.sub,
    auth_token_sub: payload.sub,
    caller_jkt: verifyRes.callerJkt,
    scope: scopeStr,
    iss: payload.iss,
  })

  return c.json({
    hello: name,
    granted_scopes: scopes,
    identity_claims_present: {
      name: typeof payload.name === 'string',
      email: typeof payload.email === 'string',
      picture: typeof payload.picture === 'string',
    },
  })
})

export default app
