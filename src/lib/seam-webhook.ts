import type { SeamEvent } from '@seamapi/http/connect'
import { Webhook, WebhookVerificationError } from 'svix'

import { SeamInvalidWebhookPayloadError } from './seam-invalid-webhook-payload-error.js'

export class SeamWebhook {
  readonly #webhook: Webhook

  constructor(secret: string) {
    this.#webhook = new Webhook(secret)
  }

  /**
   * Verifies an incoming webhook request and returns the event it carries.
   *
   * @throws {WebhookVerificationError} When the signature does not match.
   * @throws {SeamInvalidWebhookPayloadError} When the signature matches
   * but the body is not a Seam event.
   */
  verify(payload: string, headers: Record<string, string>): SeamEvent {
    const normalizedHeaders = Object.fromEntries(
      Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]),
    )

    let data: unknown

    try {
      data = this.#webhook.verify(payload, normalizedHeaders)
    } catch (error) {
      if (error instanceof WebhookVerificationError) throw error

      throw new SeamInvalidWebhookPayloadError(
        `The verified webhook payload is not valid JSON: ${getErrorMessage(error)}`,
        { cause: error },
      )
    }

    if (!isSeamEvent(data)) {
      throw new SeamInvalidWebhookPayloadError(
        'The verified webhook payload did not contain a Seam event',
      )
    }

    return data
  }
}

const isSeamEvent = (data: unknown): data is SeamEvent =>
  typeof data === 'object' &&
  data !== null &&
  'event_id' in data &&
  typeof data.event_id === 'string' &&
  'event_type' in data &&
  typeof data.event_type === 'string'

const getErrorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error)
