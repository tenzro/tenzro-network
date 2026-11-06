import type { RpcClient } from "@tenzro/core";

// ── Types ──

/** TEE hardware information. */
export interface TeeInfo {
  /** Whether TEE hardware is available */
  available: boolean;
  /** The vendor detected on this node, when one is (`IntelTdx`, `AmdSevSnp`, ...) */
  vendor: string | null;
  /** Every vendor this node can attest with */
  available_vendors: string[];
}

/** One measurement register of a report. */
export interface MeasurementRegister {
  /** Register name (`MRTD`, `RTMR0`..`RTMR3`, `MEASUREMENT`, `PCR0`..) */
  register: string;
  /** Hash algorithm */
  algorithm: string;
  /** Hex register value */
  value_hex: string;
}

/** TEE attestation report. */
export interface AttestationResult {
  /** Vendor of the report */
  vendor: string;
  /** Hex report data the hardware signed */
  user_data_hex: string;
  /** Hex launch measurement (TDX MRTD, SEV-SNP MEASUREMENT) */
  measurement_hex: string;
  /** Every measurement register the evidence carries */
  measurements: MeasurementRegister[];
  /** Hex of the JSON report, as `verifyAttestation` takes it */
  report_hex: string;
  /** Milliseconds since the epoch the report was made at */
  timestamp: number;
}

/** TEE attestation verification result. */
export interface TeeVerifyResult {
  /** Whether the attestation is valid */
  valid: boolean;
  /** Why it is not, when `valid` is false */
  error?: string;
  /** Vendor of the verified report */
  vendor?: string;
  /** Hex launch measurement of the verified report */
  measurement_hex?: string;
  /** Hex per-platform identifier of the verified report */
  platform_id_hex?: string;
  /** The vendor's TCB verdict */
  tcb_status?: string;
  /** The facility the report was bound to, if a claim was presented */
  facility?: string | null;
  /** Every measurement register of the verified report */
  measurements?: MeasurementRegister[];
}

/** A single-use nonce for one attestation verification. */
export interface AttestationChallenge {
  /** Hex nonce, `0x`-prefixed */
  nonce: string;
  /** Seconds the nonce stays redeemable */
  expires_in_secs: number;
}

/** Optional inputs to {@link TeeClient.verifyAttestation}. */
export interface VerifyAttestationOptions {
  /** Hex of extra data the report commits to after the nonce */
  boundData?: string;
  /** A signed facility claim (JSON) the report is bound to */
  facility?: unknown;
}

/** A TEE provider entry as stored on the network. */
export interface TeeProvider {
  /** Registry id (e.g. `tee:<address>`). */
  id: string;
  /** Stored provider info blob (vendor, capabilities, endpoint, etc.). */
  info: unknown;
}

/** Result of `listTeeProviders` — network providers plus local detection. */
export interface TeeProviderList {
  /** TEE providers registered on the network. */
  providers: TeeProvider[];
  /** Number of registered providers. */
  total: number;
  /** Whether this node has locally-detected TEE hardware. */
  local_tee_available: boolean;
  /** Locally-detected TEE vendor, when present. */
  local_vendor: string | null;
}

// ── Client ──

/**
 * Client for Trusted Execution Environment operations.
 *
 * Supports Intel TDX, AMD SEV-SNP, AWS Nitro, and NVIDIA GPU TEE providers.
 */
export class TeeClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * Detect available TEE hardware on the node.
   */
  async detectTee(): Promise<TeeInfo> {
    return this.rpc.call<TeeInfo>('tenzro_detectTee');
  }

  /**
   * Generate a TEE attestation report and its measurement registers.
   * @param userData - Optional hex data the report commits to (64 zero bytes when omitted)
   */
  async getAttestation(userData?: string): Promise<AttestationResult> {
    return this.rpc.call<AttestationResult>('tenzro_getTeeAttestation', userData === undefined ? {} : { user_data: userData });
  }

  /**
   * Request a single-use nonce for one attestation verification. The attester
   * asks its TEE for a report over `nonce || boundData` and submits it with
   * {@link TeeClient.verifyAttestation} before `expires_in_secs` elapse.
   */
  async attestationChallenge(): Promise<AttestationChallenge> {
    return this.rpc.call<AttestationChallenge>('tenzro_teeAttestationChallenge', {});
  }

  /**
   * Verify a TEE attestation report against a nonce this node issued. The
   * report must be vendor-signed, chain to a pinned vendor root, and carry
   * `nonce || boundData` (packed for its vendor) as its signed user data.
   * The nonce is consumed.
   * @param reportHex - Hex of the JSON `AttestationReport`
   * @param nonce - Hex nonce from {@link TeeClient.attestationChallenge}
   */
  async verifyAttestation(
    reportHex: string,
    nonce: string,
    options: VerifyAttestationOptions = {},
  ): Promise<TeeVerifyResult> {
    const params: Record<string, unknown> = { report_hex: reportHex, nonce };
    if (options.boundData !== undefined) params.bound_data = options.boundData;
    if (options.facility !== undefined) params.facility = options.facility;
    return this.rpc.call<TeeVerifyResult>('tenzro_verifyTeeAttestation', params);
  }

  /**
   * List TEE providers on the network, plus this node's local TEE detection.
   */
  async listTeeProviders(): Promise<TeeProviderList> {
    return this.rpc.call<TeeProviderList>('tenzro_listTeeProviders');
  }
}
