/**
 * Incremental Server-Sent Events decoder.
 *
 * Network reads cut a stream at arbitrary byte offsets: inside a UTF-8
 * character, between the `\r` and `\n` of a line break, or in the middle of a
 * multi-line event. {@link SseDecoder} buffers across reads and yields an
 * event only once its terminating blank line has arrived; {@link SseDecoder.finish}
 * flushes an event the stream ended without terminating.
 */

/** One dispatched event. */
export interface SseEvent {
  /** The `event:` field, when the event named one. */
  event?: string;
  /** The `data:` lines, joined with `\n`. */
  data: string;
  /** The last `id:` seen on the stream so far. */
  id?: string;
}

/**
 * Decodes a byte stream into {@link SseEvent}s. Accepts `\r\n`, `\n` and `\r`
 * line breaks, skips `:` comment lines, and ignores unknown fields.
 */
export class SseDecoder {
  private readonly text = new TextDecoder();
  private line = "";
  private afterCr = false;
  private data: string | undefined;
  private event: string | undefined;
  private lastId: string | undefined;

  /** Absorb one network read and return the events it completed. */
  push(chunk: Uint8Array): SseEvent[] {
    return this.consume(this.text.decode(chunk, { stream: true }));
  }

  /** End of stream: process an unterminated last line and dispatch its event. */
  finish(): SseEvent[] {
    const out = this.consume(this.text.decode());
    if (this.line.length > 0) this.endLine(out);
    this.dispatch(out);
    return out;
  }

  private consume(s: string): SseEvent[] {
    const out: SseEvent[] = [];
    for (const ch of s) {
      const afterCr = this.afterCr;
      this.afterCr = false;
      if (afterCr && ch === "\n") continue;
      if (ch === "\n") {
        this.endLine(out);
      } else if (ch === "\r") {
        this.endLine(out);
        this.afterCr = true;
      } else {
        this.line += ch;
      }
    }
    return out;
  }

  private endLine(out: SseEvent[]): void {
    const line = this.line;
    this.line = "";
    if (line.length === 0) {
      this.dispatch(out);
      return;
    }
    if (line.startsWith(":")) return;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "data") {
      this.data = this.data === undefined ? value : `${this.data}\n${value}`;
    } else if (field === "event") {
      this.event = value;
    } else if (field === "id" && !value.includes("\0")) {
      this.lastId = value;
    }
  }

  private dispatch(out: SseEvent[]): void {
    const event = this.event;
    this.event = undefined;
    if (this.data === undefined) return;
    const ev: SseEvent = { data: this.data };
    if (event !== undefined) ev.event = event;
    if (this.lastId !== undefined) ev.id = this.lastId;
    this.data = undefined;
    out.push(ev);
  }
}
