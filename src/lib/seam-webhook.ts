import type { SeamEvent } from '@seamapi/types'
import { Webhook } from 'svix'

export class SeamWebhook {
  readonly #webhook: Webhook

  constructor(secret: string) {
    this.#webhook = new Webhook(secret)
  }

  verify(payload: string, headers: Record<string, string>): SeamEvent {
    return this.#webhook.verify(payload, headers) as SeamEvent
  }
}
