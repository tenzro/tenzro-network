/**
 * CAIP-25 session store with mandatory user confirmation.
 *
 * A page asks for scopes; it never grants them. Every `session.create`
 * waits on a {@link ScopeConfirmer} — the wallet's confirmation UI — and
 * the session holds only what the user approved, narrowed against what the
 * page asked for, so a confirmer cannot widen a request either. With no
 * approval there is no session, and with no session the provider serves no
 * RPC for that origin: {@link SessionStore.authorize} is the gate every
 * page-originated call passes through.
 */

import {
  CAIP25CreateSessionParams,
  CAIP25CreateSessionResult,
  CAIP25Scope,
  CAIP25Scopes,
  RPC_ERROR_CODES,
} from "./types";

/**
 * Shows the user what `origin` asked for and resolves with the scopes the
 * user approved, or `null` when the user declined or closed the prompt.
 */
export type ScopeConfirmer = (
  origin: string,
  requested: CAIP25Scopes,
) => Promise<CAIP25Scopes | null>;

export interface SessionRecord {
  readonly sessionId: string;
  readonly origin: string;
  readonly scopes: CAIP25Scopes;
  readonly createdAt: number;
}

export interface ProviderError {
  readonly code: number;
  readonly message: string;
}

function intersect(
  requested: readonly string[] | undefined,
  approved: readonly string[] | undefined,
): string[] | undefined {
  if (requested === undefined || approved === undefined) return undefined;
  const allowed = new Set(approved);
  return requested.filter((item) => allowed.has(item));
}

/**
 * The scopes a session may hold: each scope and each method, notification,
 * account and chain must appear in both the request and the approval.
 */
export function narrowScopes(
  requested: CAIP25Scopes,
  approved: CAIP25Scopes,
): CAIP25Scopes {
  const granted: Record<string, CAIP25Scope> = {};
  for (const [key, want] of Object.entries(requested)) {
    const ok = approved[key];
    if (!ok) continue;
    const scope: CAIP25Scope = {
      methods: intersect(want.methods, ok.methods) ?? [],
      notifications: intersect(want.notifications, ok.notifications) ?? [],
      ...(want.accounts !== undefined
        ? { accounts: intersect(want.accounts, ok.accounts) ?? [] }
        : {}),
      ...(want.chains !== undefined
        ? { chains: intersect(want.chains, ok.chains) ?? [] }
        : {}),
    };
    granted[key] = scope;
  }
  return granted;
}

function newSessionId(): string {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  let out = "";
  for (const b of buf) out += b.toString(16).padStart(2, "0");
  return out;
}

export class SessionStore {
  private readonly sessions = new Map<string, SessionRecord>();

  constructor(private readonly confirm: ScopeConfirmer) {}

  /**
   * Ask the user to approve `params.scopes` for `origin`. Throws a
   * `USER_REJECTED` provider error when the user declines or approves
   * nothing; otherwise records and returns the narrowed session.
   */
  async create(
    origin: string,
    params: CAIP25CreateSessionParams,
  ): Promise<CAIP25CreateSessionResult> {
    const approved = await this.confirm(origin, params.scopes);
    if (!approved) {
      throw { code: RPC_ERROR_CODES.USER_REJECTED, message: "the user declined the session request" };
    }
    const scopes = narrowScopes(params.scopes, approved);
    if (Object.keys(scopes).length === 0) {
      throw { code: RPC_ERROR_CODES.USER_REJECTED, message: "the user approved none of the requested scopes" };
    }
    const record: SessionRecord = {
      sessionId: newSessionId(),
      origin,
      scopes,
      createdAt: Date.now(),
    };
    this.sessions.set(origin, record);
    return {
      sessionId: record.sessionId,
      scopes,
      sessionProperties: params.sessionProperties,
    };
  }

  revoke(origin: string): void {
    this.sessions.delete(origin);
  }

  describe(origin: string): SessionRecord | undefined {
    return this.sessions.get(origin);
  }

  /**
   * Whether `origin` may call `method` in `scope`. Returns `null` when it
   * may, or the `UNAUTHORIZED` error to relay to the page.
   */
  authorize(origin: string, scope: string | null, method: string): ProviderError | null {
    const session = this.sessions.get(origin);
    if (!session) {
      return {
        code: RPC_ERROR_CODES.UNAUTHORIZED,
        message: "no session for this origin; request one with wallet_createSession first",
      };
    }
    if (scope === null) {
      return {
        code: RPC_ERROR_CODES.UNAUTHORIZED,
        message: "unscoped calls are not served; name the CAIP-2 scope the session granted",
      };
    }
    const granted = session.scopes[scope];
    if (!granted) {
      return { code: RPC_ERROR_CODES.UNAUTHORIZED, message: `scope "${scope}" was not granted to this origin` };
    }
    if (!granted.methods.includes(method)) {
      return {
        code: RPC_ERROR_CODES.UNAUTHORIZED,
        message: `method "${method}" was not granted in scope "${scope}"`,
      };
    }
    return null;
  }
}
