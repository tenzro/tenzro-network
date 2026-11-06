/**
 * NFTs: the network's NFT factory precompile at `0x…1006`, which keeps
 * ERC-721 and ERC-1155 collections in consensus state.
 *
 * Writes are EVM calls inside a `ContractCall` transaction signed by the
 * account that acts: the collection's creator creates, mints and registers
 * pointers, a token's owner transfers it, and anyone fulfils a random mint
 * two blocks after its request. `nftTransaction` builds that transaction
 * for `TypedTxClient`. Reads are `eth_call`s through `NftClient`. Every
 * calldata builder and decoder here is offline.
 */
import { createHash } from "node:crypto";
import type { RpcClient, TypedTransaction } from "@tenzro/core";
import { abiDecode, encodeWithSelector, eventTopic } from "./abi";

/** The NFT factory precompile's address. */
export const NFT_FACTORY_ADDRESS = "0x0000000000000000000000000000000000001006";

/** The factory's function selectors (fixed values, not all the hash of their signature). */
export const NFT_SELECTORS = {
  createCollection: "0xe9c3ab8b",
  getCollection: "0xf5c1f76e",
  mint: "0x40c10f19",
  mintBatch: "0xb48ab8b6",
  transferNft: "0x26a75453",
  ownerOf: "0x6352211e",
  balanceOf: "0x00fdd58e",
  tokenUri: "0x0e89341c",
  registerEvmPointer: "0x1a6d2e4f",
  registerSvmPointer: "0x2b7ce500",
  mintMulti: "0x731133e9",
  balanceOfMulti: "0x4e1273f4",
  mintRandom: "0xd3622f7b",
  fulfillRandom: "0xdd68a4e3",
} as const;

/** topic 0 of `NftTransfer(bytes32 indexed collection, address indexed from, address indexed to, uint256 tokenId)`. */
export const NFT_TRANSFER_TOPIC = eventTopic("NftTransfer(bytes32,address,address,uint256)");

export type NftStandard = "erc721" | "erc1155";
const STANDARD_CODE: Record<NftStandard, number> = { erc721: 0, erc1155: 1 };

/** Longest name, symbol or token URI the factory accepts, in bytes. */
export const NFT_MAX_TEXT = 512;
/** Most tokens one `mintBatch` mints. */
export const NFT_MAX_BATCH = 256;
/** Largest token id or amount the factory stores (`u128`). */
export const NFT_MAX_ID = (1n << 128n) - 1n;

function hexOf(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
function bytesOf(h: string, len: number, what: string): Uint8Array {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  if (s.length !== len * 2 || !/^[0-9a-fA-F]*$/.test(s)) throw new Error(`${what} must be ${len} bytes of hex`);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}
const id32 = (id: string) => "0x" + hexOf(bytesOf(id, 32, "collection id"));
const addr = (a: string, what = "address") => "0x" + hexOf(bytesOf(a, 20, what));
function recipient(a: string): string {
  const x = addr(a, "recipient");
  if (/^0x0{40}$/.test(x)) throw new Error("the recipient may not be the zero address");
  return x;
}
function tokenId(v: bigint | number | string, what = "token id"): bigint {
  const n = BigInt(v);
  if (n < 0n || n > NFT_MAX_ID) throw new Error(`${what} must fit 128 bits`);
  return n;
}
function text(s: string, what: string): string {
  if (new TextEncoder().encode(s).length > NFT_MAX_TEXT) throw new Error(`${what} is longer than ${NFT_MAX_TEXT} bytes`);
  return s;
}
const call = (sel: string, types: string[], values: (string | bigint | number | string[] | bigint[])[]) =>
  encodeWithSelector(sel, types, values);

/** Calldata for each factory function. */
export const nftCalldata = {
  createCollection(name: string, symbol: string, standard: NftStandard = "erc721"): Uint8Array {
    if (name === "") throw new Error("a collection needs a name");
    return call(NFT_SELECTORS.createCollection, ["string", "string", "uint8"], [
      text(name, "name"),
      text(symbol, "symbol"),
      STANDARD_CODE[standard],
    ]);
  },
  getCollection(collectionId: string): Uint8Array {
    return call(NFT_SELECTORS.getCollection, ["bytes32"], [id32(collectionId)]);
  },
  mint(collectionId: string, to: string, token: bigint | number | string, uri = ""): Uint8Array {
    return call(NFT_SELECTORS.mint, ["bytes32", "address", "uint256", "string"], [
      id32(collectionId),
      recipient(to),
      tokenId(token),
      text(uri, "token URI"),
    ]);
  },
  mintBatch(collectionId: string, to: string, tokens: (bigint | number | string)[], uris: string[] = []): Uint8Array {
    if (tokens.length === 0 || tokens.length > NFT_MAX_BATCH) throw new Error(`a batch holds 1 to ${NFT_MAX_BATCH} tokens`);
    if (uris.length > tokens.length) throw new Error("more URIs than tokens");
    return call(NFT_SELECTORS.mintBatch, ["bytes32", "address", "uint256[]", "string[]"], [
      id32(collectionId),
      recipient(to),
      tokens.map((t) => tokenId(t)),
      uris.map((u) => text(u, "token URI")),
    ]);
  },
  transfer(collectionId: string, to: string, token: bigint | number | string): Uint8Array {
    return call(NFT_SELECTORS.transferNft, ["bytes32", "address", "uint256"], [id32(collectionId), recipient(to), tokenId(token)]);
  },
  ownerOf(collectionId: string, token: bigint | number | string): Uint8Array {
    return call(NFT_SELECTORS.ownerOf, ["bytes32", "uint256"], [id32(collectionId), tokenId(token)]);
  },
  balanceOf(collectionId: string, owner: string): Uint8Array {
    return call(NFT_SELECTORS.balanceOf, ["bytes32", "address"], [id32(collectionId), addr(owner, "owner")]);
  },
  tokenUri(collectionId: string, token: bigint | number | string): Uint8Array {
    return call(NFT_SELECTORS.tokenUri, ["bytes32", "uint256"], [id32(collectionId), tokenId(token)]);
  },
  registerEvmPointer(collectionId: string, evmContract: string): Uint8Array {
    return call(NFT_SELECTORS.registerEvmPointer, ["bytes32", "address"], [id32(collectionId), addr(evmContract, "EVM contract")]);
  },
  registerSvmPointer(collectionId: string, svmMint: string): Uint8Array {
    return call(NFT_SELECTORS.registerSvmPointer, ["bytes32", "bytes32"], [id32(collectionId), "0x" + hexOf(bytesOf(svmMint, 32, "SVM mint"))]);
  },
  mintMulti(collectionId: string, to: string, token: bigint | number | string, amount: bigint | number | string): Uint8Array {
    const n = tokenId(amount, "amount");
    if (n === 0n) throw new Error("amount must be positive");
    return call(NFT_SELECTORS.mintMulti, ["bytes32", "address", "uint256", "uint256"], [id32(collectionId), recipient(to), tokenId(token), n]);
  },
  balanceOfMulti(collectionId: string, owner: string, token: bigint | number | string): Uint8Array {
    return call(NFT_SELECTORS.balanceOfMulti, ["bytes32", "address", "uint256"], [id32(collectionId), addr(owner, "owner"), tokenId(token)]);
  },
  mintRandom(collectionId: string, to: string, idSpace: bigint | number | string): Uint8Array {
    const n = tokenId(idSpace, "id space");
    if (n === 0n) throw new Error("id space must be positive");
    return call(NFT_SELECTORS.mintRandom, ["bytes32", "address", "uint256"], [id32(collectionId), recipient(to), n]);
  },
  fulfillRandom(requestId: string): Uint8Array {
    return call(NFT_SELECTORS.fulfillRandom, ["bytes32"], ["0x" + hexOf(bytesOf(requestId, 32, "request id"))]);
  },
};

/** A collection as `getCollection` returns it. */
export interface NftCollection {
  name: string;
  symbol: string;
  creator: string;
  totalSupply: bigint;
  standard: NftStandard;
}

const raw = (d: Uint8Array | string) => (typeof d === "string" ? bytesOf(d, (d.length - (d.startsWith("0x") ? 2 : 0)) / 2, "return data") : d);

/** Decoders for the factory's return data. */
export const nftDecode = {
  /** `createCollection` and `mintRandom` return a raw 32-byte id. */
  id(data: Uint8Array | string): string {
    const b = raw(data);
    if (b.length !== 32) throw new Error("expected a 32-byte id");
    return "0x" + hexOf(b);
  },
  collection(data: Uint8Array | string): NftCollection {
    const [name, symbol, creator, totalSupply, standard] = abiDecode(["string", "string", "address", "uint256", "uint8"], raw(data));
    const s = Number(standard);
    if (s !== 0 && s !== 1) throw new Error(`unknown NFT standard ${s}`);
    return {
      name: name as string,
      symbol: symbol as string,
      creator: creator as string,
      totalSupply: totalSupply as bigint,
      standard: s === 0 ? "erc721" : "erc1155",
    };
  },
  /** `ownerOf`. */
  address(data: Uint8Array | string): string {
    return abiDecode(["address"], raw(data))[0] as string;
  },
  /** `balanceOf`, `balanceOfMulti`, `mintBatch` (tokens minted) and `fulfillRandom` (the token id drawn). */
  uint(data: Uint8Array | string): bigint {
    return abiDecode(["uint256"], raw(data))[0] as bigint;
  },
  /** `tokenUri`. */
  string(data: Uint8Array | string): string {
    return abiDecode(["string"], raw(data))[0] as string;
  },
  /** `mint`, `transferNft`, `mintMulti` and the pointer registrations. */
  bool(data: Uint8Array | string): boolean {
    return abiDecode(["bool"], raw(data))[0] as boolean;
  },
};

/** A minted or moved token, from an `NftTransfer` log (`from` is the zero address for a mint). */
export interface NftTransfer {
  collectionId: string;
  from: string;
  to: string;
  tokenId: bigint;
}

/** Decode an `NftTransfer` log; `undefined` for any other log. */
export function decodeNftTransfer(log: { address?: string; topics: string[]; data: string }): NftTransfer | undefined {
  if (log.address !== undefined && log.address.toLowerCase() !== NFT_FACTORY_ADDRESS) return undefined;
  if (log.topics.length !== 4 || log.topics[0]!.toLowerCase() !== NFT_TRANSFER_TOPIC) return undefined;
  const word = (t: string) => abiDecode(["address"], t)[0] as string;
  return {
    collectionId: id32(log.topics[1]!).toLowerCase(),
    from: word(log.topics[2]!),
    to: word(log.topics[3]!),
    tokenId: nftDecode.uint(log.data),
  };
}

/** The id `createCollection` gives the `nonce`-th collection of `creator`: SHA-256(creator ‖ nonce as 8 bytes little-endian). */
export function nftCollectionId(creator: string, nonce: bigint | number): string {
  const n = BigInt(nonce);
  if (n < 0n || n >= 1n << 64n) throw new Error("nonce must fit 64 bits");
  const le = new Uint8Array(8);
  for (let i = 0; i < 8; i++) le[i] = Number((n >> BigInt(8 * i)) & 0xffn);
  return "0x" + createHash("sha256").update(bytesOf(creator, 20, "creator")).update(le).digest("hex");
}

/** One EVM call of the factory, as a `ContractCall` transaction carries it. */
export function nftCall(calldata: Uint8Array): { vm: "evm"; to: number[]; value: number; data: number[] } {
  return { vm: "evm", to: Array.from(bytesOf(NFT_FACTORY_ADDRESS, 20, "factory")), value: 0, data: Array.from(calldata) };
}

/**
 * A `ContractCall` transaction running the factory calls in order, all or
 * nothing, for `TypedTxClient.send`. The signer's account is `msg.sender`.
 */
export function nftTransaction(...calldata: Uint8Array[]): TypedTransaction {
  if (calldata.length === 0) throw new Error("a transaction needs at least one call");
  return { kind: "ContractCall", fields: { calls: calldata.map(nftCall) } };
}

/** Reads from the factory through `eth_call`. */
export class NftClient {
  constructor(private readonly rpc: RpcClient) {}

  private async read(data: Uint8Array): Promise<string> {
    return this.rpc.call<string>("eth_call", [{ to: NFT_FACTORY_ADDRESS, data: "0x" + hexOf(data) }, "latest"]);
  }

  async collection(collectionId: string): Promise<NftCollection> {
    return nftDecode.collection(await this.read(nftCalldata.getCollection(collectionId)));
  }
  async ownerOf(collectionId: string, token: bigint | number | string): Promise<string> {
    return nftDecode.address(await this.read(nftCalldata.ownerOf(collectionId, token)));
  }
  async balanceOf(collectionId: string, owner: string): Promise<bigint> {
    return nftDecode.uint(await this.read(nftCalldata.balanceOf(collectionId, owner)));
  }
  async balanceOfMulti(collectionId: string, owner: string, token: bigint | number | string): Promise<bigint> {
    return nftDecode.uint(await this.read(nftCalldata.balanceOfMulti(collectionId, owner, token)));
  }
  async tokenUri(collectionId: string, token: bigint | number | string): Promise<string> {
    return nftDecode.string(await this.read(nftCalldata.tokenUri(collectionId, token)));
  }
}
