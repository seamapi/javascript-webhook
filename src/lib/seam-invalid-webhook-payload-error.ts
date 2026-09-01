/**
 * Thrown when a payload carries a valid signature but cannot be read as a Seam
 * event.
 *
 * Kept distinct from {@link SeamWebhookVerificationError}: a verification
 * failure means the sender may not be Seam, so the right response is an error
 * status that makes it retry. This error means the sender *is* Seam and the body
 * will never become readable, so retrying can only repeat the failure. Report it
 * instead.
 */
export class SeamInvalidWebhookPayloadError extends Error {
  override readonly name = 'SeamInvalidWebhookPayloadError'

  constructor(message: string) {
    super(message)
    Object.setPrototypeOf(this, SeamInvalidWebhookPayloadError.prototype)
  }
}
