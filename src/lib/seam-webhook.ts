import type { SeamEvent } from '@seamapi/http/connect'
import { Webhook } from 'svix'

import { SeamInvalidWebhookPayloadError } from './seam-invalid-webhook-payload-error.js'

export class SeamWebhook {
  readonly #webhook: Webhook

  constructor(secret: string) {
    this.#webhook = new Webhook(secret)
  }

  /**
   * Verify and parse an incoming HTTP webhook request.
   *
   * @throws {SeamWebhookVerificationError} When the signature does not match.
   *   Respond with an error status so the sender retries.
   * @throws {SeamInvalidWebhookPayloadError} When the signature matches but the
   *   body is not a Seam event. The body will never become readable, so report
   *   it rather than letting the sender retry.
   */
  verify(payload: string, headers: Record<string, string>): SeamEvent {
    const normalizedHeaders = Object.fromEntries(
      Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]),
    )

    let verified: unknown
    try {
      verified = this.#webhook.verify(payload, normalizedHeaders)
    } catch (error) {
      // svix JSON.parses after the signature checks out, so a SyntaxError here
      // is a genuinely-from-Seam body that is permanently unreadable, not a
      // failed verification.
      if (error instanceof SyntaxError) {
        throw new SeamInvalidWebhookPayloadError(
          `The verified webhook payload is not valid JSON: ${error.message}`,
        )
      }
      throw error
    }

    if (!isSeamEvent(verified)) {
      throw new SeamInvalidWebhookPayloadError(
        'The verified webhook payload did not contain a Seam event',
      )
    }

    return verified
  }
}

const isSeamEvent = (value: unknown): value is SeamEvent => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }

  const { event_id: eventId, event_type: eventType } = value as Record<
    string,
    unknown
  >

  return typeof eventId === 'string' && typeof eventType === 'string'
}
