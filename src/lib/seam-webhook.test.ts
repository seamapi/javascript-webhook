import test from 'ava'
import { Webhook } from 'svix'

import {
  isSeamInvalidWebhookPayloadError,
  SeamInvalidWebhookPayloadError,
} from './seam-invalid-webhook-payload-error.js'
import { SeamWebhook } from './seam-webhook.js'

const secret = 'MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'

const eventPayload = JSON.stringify({
  event_id: '11111111-1111-1111-1111-111111111111',
  event_type: 'device.connected',
  workspace_id: '22222222-2222-2222-2222-222222222222',
  device_id: '33333333-3333-3333-3333-333333333333',
  created_at: '2026-08-27T00:00:00.000Z',
  occurred_at: '2026-08-27T00:00:00.000Z',
})

const signHeaders = (
  payload: string,
  { msgId = 'msg_1', timestamp = new Date(), signingSecret = secret } = {},
): Record<string, string> => ({
  'svix-id': msgId,
  'svix-timestamp': Math.floor(timestamp.getTime() / 1000).toString(),
  'svix-signature': new Webhook(signingSecret).sign(msgId, timestamp, payload),
})

test('SeamWebhook: constructor', (t) => {
  t.truthy(new SeamWebhook('1234'))
})

test('SeamWebhook: verifies and parses a signed event', (t) => {
  const webhook = new SeamWebhook(secret)

  const event = webhook.verify(eventPayload, signHeaders(eventPayload))

  t.is(event.event_type, 'device.connected')
  t.is(event.event_id, '11111111-1111-1111-1111-111111111111')
})

test('SeamWebhook: accepts mixed case headers', (t) => {
  const webhook = new SeamWebhook(secret)
  const headers = Object.fromEntries(
    Object.entries(signHeaders(eventPayload)).map(([key, value]) => [
      key.toUpperCase(),
      value,
    ]),
  )

  t.is(webhook.verify(eventPayload, headers).event_type, 'device.connected')
})

test('SeamWebhook: a tampered payload fails verification', (t) => {
  const webhook = new SeamWebhook(secret)
  const headers = signHeaders(eventPayload)
  const tampered = eventPayload.replace(
    'device.connected',
    'device.disconnected',
  )

  const error = t.throws(() => webhook.verify(tampered, headers))

  t.false(isSeamInvalidWebhookPayloadError(error))
  t.regex(error?.message ?? '', /No matching signature/)
})

test('SeamWebhook: a wrong secret fails verification', (t) => {
  const webhook = new SeamWebhook(secret)
  const headers = signHeaders(eventPayload, {
    signingSecret: 'WrongQ9r8GKYqrTwjUPD8ILPZIo2LaLa',
  })

  const error = t.throws(() => webhook.verify(eventPayload, headers))

  t.regex(error?.message ?? '', /No matching signature/)
})

test('SeamWebhook: an expired timestamp fails verification', (t) => {
  const webhook = new SeamWebhook(secret)
  const headers = signHeaders(eventPayload, {
    timestamp: new Date(Date.now() - 60 * 60 * 1000),
  })

  const error = t.throws(() => webhook.verify(eventPayload, headers))

  t.regex(error?.message ?? '', /too old/)
})

for (const missing of ['svix-id', 'svix-timestamp', 'svix-signature']) {
  test(`SeamWebhook: a missing ${missing} header fails verification`, (t) => {
    const webhook = new SeamWebhook(secret)
    const { [missing]: _, ...headers } = signHeaders(eventPayload)

    const error = t.throws(() => webhook.verify(eventPayload, headers))

    t.false(isSeamInvalidWebhookPayloadError(error))
    t.regex(error?.message ?? '', /Missing required headers/)
  })
}

test('SeamWebhook: a signed but unparseable payload is not forgery', (t) => {
  const webhook = new SeamWebhook(secret)
  const payload = '{"event_id": "trailing-comma",}'

  const error = t.throws(() => webhook.verify(payload, signHeaders(payload)), {
    instanceOf: SeamInvalidWebhookPayloadError,
  })

  t.regex(error?.message ?? '', /not valid JSON/)
  t.truthy(error?.cause)
})

for (const payload of ['null', '[1]', '42', '"event"', '{}']) {
  test(`SeamWebhook: a signed non-event payload ${payload} is not forgery`, (t) => {
    const webhook = new SeamWebhook(secret)

    const error = t.throws(
      () => webhook.verify(payload, signHeaders(payload)),
      {
        instanceOf: SeamInvalidWebhookPayloadError,
      },
    )

    t.regex(error?.message ?? '', /did not contain a Seam event/)
  })
}

test('SeamWebhook: an unknown event type still parses', (t) => {
  const webhook = new SeamWebhook(secret)
  const payload = JSON.stringify({
    event_id: '11111111-1111-1111-1111-111111111111',
    event_type: 'future.event_type',
  })

  // event_type is a closed union of known types, so widen it to assert
  // that an unrecognized type still round-trips.
  const event: { event_type?: string | undefined } = webhook.verify(
    payload,
    signHeaders(payload),
  )

  t.is(event.event_type, 'future.event_type')
})
