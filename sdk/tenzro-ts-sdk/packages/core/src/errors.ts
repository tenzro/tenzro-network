/**
 * An error the node reports in its `{"error":{message,type,code}}` shape, as
 * an HTTP body or as a frame inside a stream.
 */
export class ApiError extends Error {
  constructor(
    message: string,
    /** Error class, such as `invalid_request_error` or `server_error`. */
    public readonly type: string,
    /** Machine-readable code, such as `model_not_found`. */
    public readonly code: string | null,
  ) {
    super(message);
    this.name = "ApiError";
  }

  /** The error an `{"error":{..}}` body carries, if it carries one. */
  static fromBody(body: unknown): ApiError | undefined {
    const e = (body as { error?: unknown } | null)?.error;
    if (typeof e !== "object" || e === null) return undefined;
    const o = e as { message?: unknown; type?: unknown; code?: unknown };
    return new ApiError(
      typeof o.message === "string" ? o.message : "",
      typeof o.type === "string" ? o.type : "",
      typeof o.code === "string" ? o.code : null,
    );
  }

  /** The wire shape: `{message, type, code}`. */
  toJSON(): { message: string; type: string; code: string | null } {
    return { message: this.message, type: this.type, code: this.code };
  }
}
