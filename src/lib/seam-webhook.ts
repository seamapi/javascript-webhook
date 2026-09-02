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
   * @throws {SeamInvalidWebhookPayloadError} When it does but the body is not an event.
   */
  verify(payload: string, headers: Record<string, string>): VerifiedSeamEvent {
    const normalizedHeaders = Object.fromEntries(
      Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]),
    )

    let verified: unknown
    try {
      verified = this.#webhook.verify(payload, normalizedHeaders)
    } catch (error) {
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

    // Non-enumerable: JSON.stringify(event) must not embed a copy of itself.
    Object.defineProperty(verified, 'raw_json', {
      value: () => payload,
      enumerable: false,
    })

    return verified as VerifiedSeamEvent
  }
}

/** A verified event, plus the payload it was parsed from. */
export type VerifiedSeamEvent = SeamEvent & {
  raw_json: () => string
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
