import { createHmac } from 'node:crypto'

import test from 'ava'
import { WebhookVerificationError } from 'svix'

import { SeamInvalidWebhookPayloadError } from './seam-invalid-webhook-payload-error.js'
import { SeamWebhook } from './seam-webhook.js'

const secret = `whsec_${Buffer.from('secret'.repeat(4)).toString('base64')}`

// Signs a payload the way svix does, so these tests exercise the real
// verification path rather than stubbing it out.
const signedHeaders = (
  payload: string,
  { id = 'msg_1', timestamp = Math.floor(Date.now() / 1000) } = {},
): Record<string, string> => {
  const key = Buffer.from(secret.replace('whsec_', ''), 'base64')
  const signature = createHmac('sha256', key)
    .update(`${id}.${timestamp}.${payload}`)
    .digest('base64')
  return {
    'svix-id': id,
    'svix-timestamp': String(timestamp),
    'svix-signature': `v1,${signature}`,
  }
}

const webhook = new SeamWebhook(secret)

const verify = (payload: string, headers?: Record<string, string>): unknown =>
  webhook.verify(payload, headers ?? signedHeaders(payload))

test('SeamWebhook: constructor', (t) => {
  t.truthy(new SeamWebhook('1234'))
})

test('SeamWebhook: returns a known event', (t) => {
  const payload = JSON.stringify({
    event_id: 'event_1',
    event_type: 'access_code.created',
    access_code_id: 'access_code_1',
  })

  const event = verify(payload) as Record<string, unknown>

  t.is(event['event_type'], 'access_code.created')
  t.is(event['access_code_id'], 'access_code_1')
})

test('SeamWebhook: returns an event type this SDK does not know', (t) => {
  const payload = JSON.stringify({
    event_id: 'event_1',
    event_type: 'future.thing',
    future_field: { nested: true },
  })

  const event = verify(payload) as Record<string, unknown>

  t.is(event['event_type'], 'future.thing')
  t.deepEqual(event['future_field'], { nested: true })
})

test('SeamWebhook: rejects a bad signature', (t) => {
  const payload = JSON.stringify({
    event_id: 'event_1',
    event_type: 'access_code.created',
  })

  t.throws(() => verify(payload, signedHeaders('a different payload')), {
    instanceOf: WebhookVerificationError,
  })
})

test('SeamWebhook: rejects a stale timestamp', (t) => {
  const payload = JSON.stringify({
    event_id: 'event_1',
    event_type: 'access_code.created',
  })
  const stale = Math.floor(Date.now() / 1000) - 60 * 60

  t.throws(
    () => verify(payload, signedHeaders(payload, { timestamp: stale })),
    {
      instanceOf: WebhookVerificationError,
    },
  )
})

// A signed but unreadable body is permanently unreadable: the sender is
// genuinely Seam, so retrying can never help. It must not look like a
// verification failure, which is the signal to retry.
for (const [label, payload] of [
  ['not JSON', '{not json'],
  ['a JSON array', '[1, 2]'],
  ['a JSON null', 'null'],
  ['a JSON string', '"hello"'],
  ['an object that is not an event', JSON.stringify({ hello: 'world' })],
  ['an event with no event_type', JSON.stringify({ event_id: 'event_1' })],
  [
    'an event with a non-string event_type',
    JSON.stringify({ event_id: 'e', event_type: 42 }),
  ],
] as const) {
  test(`SeamWebhook: rejects ${label} as an invalid payload`, (t) => {
    t.throws(() => verify(payload), {
      instanceOf: SeamInvalidWebhookPayloadError,
    })
  })
}
