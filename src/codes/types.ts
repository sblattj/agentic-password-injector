// Shared shapes for one-time-code sources (`fill_sms_code`, `fill_email_code`).
//
// A source returns raw messages; the CODE is pulled out by `extract.ts` and is
// never returned from a tool. Nothing in a CodeMessage may be logged or put in
// an error message: a body can carry the code, and a sender can carry PII.

export interface CodeMessage {
  /** When the message arrived, ms since the Unix epoch. */
  at: number;
  /** Phone number / short code / email address of the sender. */
  sender: string;
  /** Plain-text body (email: subject + "\n" + text body). */
  body: string;
}

export interface CodeSource {
  readonly kind: "sms" | "email";
  /**
   * Incoming messages that arrived at or after `sinceMs`, newest first.
   * Throws `CdpError` with ONE of the fixed codes below, never anything else:
   * - `messages_access_denied`: chat.db could not be opened (Full Disk Access).
   * - `email_source_unavailable`: no email source configured.
   * - `email_source_error`: configured, but the fetch or token refresh failed.
   * - `source_error`: any other fault.
   * The error MESSAGE is fixed text: no path contents, no body, no token.
   */
  fetchSince(sinceMs: number): Promise<CodeMessage[]>;
}
