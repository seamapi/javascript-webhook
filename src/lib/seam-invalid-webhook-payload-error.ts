/**
 * Thrown when a payload is correctly signed but is not a Seam event.
 *
 * Unlike {@link SeamWebhookVerificationError}, retrying it can never help.
 */
export class SeamInvalidWebhookPayloadError extends Error {
  override readonly name = 'SeamInvalidWebhookPayloadError'

  constructor(message: string) {
    super(message)
    Object.setPrototypeOf(this, SeamInvalidWebhookPayloadError.prototype)
  }
}
