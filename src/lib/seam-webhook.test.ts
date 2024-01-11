import test from 'ava'

import { SeamWebhook } from './seam-webhook.js'

test('SeamWebhook: constructor', (t) => {
  t.truthy(new SeamWebhook('1234'))
})
