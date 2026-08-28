/**
 * Thrown when a webhook payload passes signature verification
 * but cannot be read as a Seam event.
 *
 * Verification has already succeeded by this point, so the payload is
 * genuinely from Seam and will never become readable. Report it as a bug
 * instead of letting the sender retry it, and do not treat it as forgery.
 */
export class SeamInvalidWebhookPayloadError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'SeamInvalidWebhookPayloadError'
  }
}

export const isSeamInvalidWebhookPayloadError = (
  error: unknown,
): error is SeamInvalidWebhookPayloadError =>
  error instanceof SeamInvalidWebhookPayloadError
