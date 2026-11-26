import type { RpcClient } from "@tenzro/core";
import type { ChainEvent, CompletenessProof, EventProof } from './event-proof';

// ── Types ──

/** A page of the chain's events, as `tenzro_subscribe` and `tenzro_queryEvents` return it. */
export interface EventPage {
  /** Each entry holds `event`, and `proof` when proofs were asked for. */
  events: { event: ChainEvent; proof?: EventProof }[];
  /** The proof that the page left nothing out, when asked for. */
  completeness?: CompletenessProof;
  /** On a page read forward, the cursor to resume after (`height:tx_index:event_index`). */
  cursor?: string | null;
  /** On a newest-first page, the cursor that reads the older page; `null` once the oldest held height was read. */
  before_cursor?: string | null;
  /** The highest height whose events the node holds. */
  tip: number | null;
  /** On the newest page of `tenzro_queryEvents`, for a caller that may read the node's conditions: their changes, newest first. */
  node_events?: NodeEvent[];
}

/** A condition on the node opening, clearing or being answered: the node's own account of itself, with no proof. */
export interface NodeEvent {
  /** The event's sequence on the node's event stream. */
  sequence: number;
  kind: 'condition_opened' | 'condition_cleared' | 'condition_answered';
  summary: string;
  /** When the node saw it, RFC 3339 in UTC. */
  at: string;
  /** The node's height when it saw it. */
  block: number;
  /** The condition's id. */
  condition: string;
  severity: 'info' | 'warning' | 'critical';
}

/** An event filter: `event_types` ('log' | 'transaction_included'), `addresses` (20-byte hex), positional `topics`, `from_block`, `to_block`. */
export type EventFilter = Record<string, unknown>;

// ── Client ──

/**
 * Client for the chain's events: follow them from a cursor, query ranges
 * with proofs. Verify proofs with `verifyEventProof`.
 */
export class EventsClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * The next events `filter` selects after `fromCursor` (from the tip when
   * omitted), waiting up to `waitMs` for new blocks. Pass the returned
   * cursor back: a reader that restarts resumes with no gap and no repeat.
   * With `proofs`, each event carries the proof `verifyEventProof` checks.
   */
  async subscribe(filter: EventFilter, fromCursor?: string, waitMs = 0, proofs = false): Promise<EventPage> {
    return this.rpc.call<EventPage>('tenzro_subscribe', {
      filter,
      wait_ms: waitMs,
      proofs,
      ...(fromCursor ? { from_cursor: fromCursor } : {}),
    });
  }

  /**
   * A page of the events `filter` selects after `fromCursor` (from the
   * oldest held height when omitted), each with its proof. With
   * `completeness`, also the proof that the page left nothing out (check it
   * with `verifyCompleteness`), every proof anchored at `anchorIndex` or at
   * the latest certified checkpoint.
   */
  async query(
    filter: EventFilter,
    fromCursor?: string,
    toCursor?: string,
    limit = 100,
    completeness = false,
    anchorIndex?: number,
  ): Promise<EventPage> {
    return this.rpc.call<EventPage>('tenzro_queryEvents', {
      filter,
      limit,
      ...(fromCursor ? { from_cursor: fromCursor } : { from_height: 0 }),
      ...(toCursor ? { to_cursor: toCursor } : {}),
      ...(completeness ? { completeness: true } : {}),
      ...(anchorIndex !== undefined ? { anchor_index: anchorIndex } : {}),
    });
  }

  /**
   * The newest events `filter` selects before `beforeCursor` (from the tip
   * when omitted), newest first, each with its proof anchored at
   * `anchorIndex` or at the latest certified checkpoint. Pass the page's
   * `before_cursor` back for the older page; it is `null` once the oldest
   * height the node holds was read.
   */
  async newest(
    filter: EventFilter,
    beforeCursor?: string,
    limit = 100,
    anchorIndex?: number,
  ): Promise<EventPage> {
    return this.rpc.call<EventPage>('tenzro_queryEvents', {
      filter,
      limit,
      ...(beforeCursor ? { before_cursor: beforeCursor } : {}),
      ...(anchorIndex !== undefined ? { anchor_index: anchorIndex } : {}),
    });
  }

  /** The proof of the event at `cursor`, anchored at `anchorIndex` when given. */
  async proof(cursor: string, anchorIndex?: number): Promise<EventProof> {
    const out = await this.rpc.call<{ proof: EventProof }>('tenzro_getEventProof', {
      cursor,
      ...(anchorIndex !== undefined ? { anchor_index: anchorIndex } : {}),
    });
    return out.proof;
  }


  /** `tenzro_eventStatus`. */
  eventStatus<T = unknown>(params: { sequence?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_eventStatus", params);
  }

  /** `tenzro_verifyEventProof`. */
  verifyEventProof<T = unknown>(params: Record<string, unknown> = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_verifyEventProof", params);
  }

}
