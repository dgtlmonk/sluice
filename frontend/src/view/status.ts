/**
 * Status 0 means no HTTP response was ever sent (a CONNECT the client closed,
 * or a proxy failure before any answer). 0 is not a status code, so it shows
 * as an em dash; the reason is in the detail pane's strip.
 */
export function statusText(status: number): string {
  return status === 0 ? '\u2014' : String(status)
}
