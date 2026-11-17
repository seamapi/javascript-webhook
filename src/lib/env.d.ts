declare global {
  namespace NodeJS {
    interface ProcessEnv {
      SEAM_WEBHOOK_SECRET?: string
    }
  }
}

export {}
