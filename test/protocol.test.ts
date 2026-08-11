import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// client/protocol.js is the source bundled by esbuild into public/protocol.js.
// Extract pure helpers (parseInteractionHeader, decodeJWTPayloadBrowser) by
// evaluating just the function declarations in a Node sandbox.
function extractFn(name: string): Function {
  const source = readFileSync(
    resolve(__dirname, '../client/protocol.js'),
    'utf-8'
  )
  // Match `function name(...) { ... }` up to its matching closing brace at column 0.
  const re = new RegExp(`function ${name}\\b[\\s\\S]*?\\n\\}\\n`, 'm')
  const match = source.match(re)
  if (!match) throw new Error(`Could not extract function ${name}`)
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function(`${match[0]}\nreturn ${name};`)()
}

// The deferred-response poll loop resolves its narration by template —
// copy(`${copyPrefix}.ps_pending_longpoll.label_template`) and friends —
// so a missing key renders as `undefined` in the log rather than throwing.
// Pin every prefix the loop can be driven with.
describe('deferred-poll narration keys', () => {
  const LOG_TEXT = JSON.parse(
    readFileSync(resolve(__dirname, '../public/log-text.json'), 'utf-8')
  )
  const at = (path: string) =>
    path.split('.').reduce<any>((o, k) => (o == null ? undefined : o[k]), LOG_TEXT)

  // 'person_token' drives the person-token leg, 'authorize' the whoami
  // auth-token leg, 'notes' the notes auth-token leg.
  for (const prefix of ['person_token', 'authorize', 'notes']) {
    it(`resolves every key the poll loop reads for prefix "${prefix}"`, () => {
      for (const key of [
        'ps_pending_longpoll.label_template',
        'ps_pending_longpoll.label_resolved_template',
        'ps_pending_longpoll.description',
        'ps_consent_prompt.label',
        'authorization_denied.label',
        'authorization_timed_out.label',
      ]) {
        expect(at(`${prefix}.${key}`), `${prefix}.${key}`).toBeTypeOf('string')
      }
    })
  }

  it('has the person-token request, received, and resumed-consent copy', () => {
    for (const key of [
      'person_token.request.label_template',
      'person_token.request.label_resolved_template',
      'person_token.request.label_error_network_template',
      'person_token.request.description',
      'person_token.received.label',
      'person_token.received.description',
      'person_token.authorization_granted.label',
      'person_token_resumed.ps_consent_prompt.label',
      'person_token_resumed.ps_consent_prompt.description',
    ]) {
      expect(at(key), key).toBeTypeOf('string')
    }
  })
})

describe('parseInteractionHeader', () => {
  const parse = extractFn('parseInteractionHeader') as (h: string) => Record<string, string>

  it('parses requirement, url, and code', () => {
    const result = parse('requirement=interaction; url="https://ps.example/i"; code="ABCD1234"')
    expect(result).toEqual({
      requirement: 'interaction',
      url: 'https://ps.example/i',
      code: 'ABCD1234',
    })
  })

  it('strips surrounding double quotes from values', () => {
    const result = parse('foo="bar"')
    expect(result.foo).toBe('bar')
  })

  it('keeps unquoted values as-is', () => {
    const result = parse('requirement=interaction')
    expect(result.requirement).toBe('interaction')
  })

  it('skips parts without an equals sign', () => {
    const result = parse('requirement=interaction; garbage; url="https://x"')
    expect(result).toEqual({
      requirement: 'interaction',
      url: 'https://x',
    })
  })

  it('returns an empty object for empty input', () => {
    expect(parse('')).toEqual({})
  })
})

describe('decodeJWTPayloadBrowser', () => {
  const decode = extractFn('decodeJWTPayloadBrowser') as (jwt: string) => unknown

  it('decodes a standard JWT payload', () => {
    // header={"alg":"none"}; payload={"sub":"abc","n":1}; sig=""
    const jwt = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhYmMiLCJuIjoxfQ.'
    expect(decode(jwt)).toEqual({ sub: 'abc', n: 1 })
  })

  it('returns null for malformed input', () => {
    expect(decode('not-a-jwt')).toBeNull()
  })

  it('handles base64url with - and _ characters', () => {
    // Payload: {"x":"a-b_c"} - which contains chars that base64url uses.
    const payload = Buffer.from('{"x":"a-b_c"}').toString('base64url')
    const jwt = `h.${payload}.s`
    expect(decode(jwt)).toEqual({ x: 'a-b_c' })
  })
})
