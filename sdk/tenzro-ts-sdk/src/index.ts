/**
 * Tenzro Network SDK: the core and every capability package in one import.
 *
 * Each capability is its own package over `@tenzro/core`, for applications
 * that want only part of the SDK: `@tenzro/payments`, `@tenzro/settlement`,
 * `@tenzro/agents`, `@tenzro/bridge`, `@tenzro/inference` and `@tenzro/chain`.
 * This package re-exports all of them and adds {@link TenzroClient}, which
 * reaches every capability from one node connection.
 */
export { TenzroClient } from "./client";
export * from "@tenzro/core";
export * from "@tenzro/payments";
export * from "@tenzro/settlement";
export * from "@tenzro/agents";
export * from "@tenzro/bridge";
export * from "@tenzro/inference";
export * from "@tenzro/chain";
export { DEFAULT_NETWORK, FailoverTransport, connectToNetwork, discoverEndpoints } from "./network";
export type { CheckedEndpoint, NetworkOptions } from "./network";
