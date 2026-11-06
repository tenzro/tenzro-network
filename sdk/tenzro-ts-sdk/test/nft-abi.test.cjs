// ABI encoding against the Solidity specification's examples, and the NFT
// factory calldata and return decoding against sdk/fixtures/nft, the vectors
// the VM test runs through the precompile and the other SDKs check too.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const FIXTURES = path.join(__dirname, "..", "..", "fixtures");
const ABI = JSON.parse(fs.readFileSync(path.join(FIXTURES, "abi", "vectors.json"), "utf8"));
const NFT = JSON.parse(fs.readFileSync(path.join(FIXTURES, "nft", "vectors.json"), "utf8"));
const hex = (b) => "0x" + Buffer.from(b).toString("hex");
const norm = (v) => (typeof v === "bigint" ? v.toString() : Array.isArray(v) ? v.map(norm) : v);
const args = (a) => a.map((x) => (typeof x === "string" && /^\d+$/.test(x) ? BigInt(x) : Array.isArray(x) ? args(x) : x));

test("the specification's calls encode and decode exactly", () => {
  for (const c of ABI.cases) {
    assert.equal(hex(sdk.functionSelector(c.signature)), c.selector, c.signature);
    assert.equal(hex(sdk.encodeFunctionCall(c.signature, c.values)), c.calldata, c.signature);
    const { types } = sdk.parseSignature(c.signature);
    const d = sdk.decodeFunctionCall(types, c.calldata);
    assert.equal(d.selector, c.selector);
    assert.deepEqual(norm(d.args), c.values, c.signature);
  }
});

test("signed integers, tuples and fixed arrays round-trip; uint is uint256", () => {
  const types = ["int8", "int256", "(address,bool,string)", "uint16[2]", "(uint8,bytes)[]"];
  const values = [-1n, -(2n ** 200n), ["0x" + "11".repeat(20), true, "x"], [1n, 65535n], [[7n, "0x"], [8n, "0xabcd"]]];
  assert.deepEqual(sdk.abiDecode(types, sdk.abiEncode(types, values)), values);
  assert.equal(sdk.parseSignature("transfer(address, uint)").canonical, "transfer(address,uint256)");
  assert.equal(hex(sdk.functionSelector("transfer(address,uint256)")), "0xa9059cbb");
  assert.equal(sdk.eventTopic("Transfer(address,address,uint256)"), "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
});

test("out-of-range values and malformed data are refused", () => {
  assert.throws(() => sdk.abiEncode(["uint8"], [256n]), /out of range/);
  assert.throws(() => sdk.abiEncode(["int8"], [-129n]), /out of range/);
  assert.throws(() => sdk.abiEncode(["address"], ["0x1234"]), /20 bytes/);
  assert.throws(() => sdk.abiEncode(["bytes2"], ["0x010203"]), /2 bytes/);
  assert.throws(() => sdk.abiEncode(["uint256"], [2 ** 60]), /safe integer/);
  assert.throws(() => sdk.abiDecode(["bool"], "0x" + "00".repeat(31) + "02"), /neither 0 nor 1/);
  assert.throws(() => sdk.abiDecode(["address"], "0x" + "ff".repeat(32)), /high bytes/);
  assert.throws(() => sdk.abiDecode(["uint256"], "0x" + "00".repeat(31)), /ends before/);
  assert.throws(() => sdk.abiDecode(["string"], "0x" + "00".repeat(31) + "20" + "00".repeat(31) + "ff"), /beyond|runs past/);
  assert.throws(() => sdk.abiDecode(["uint8"], "0x" + "00".repeat(30) + "0100"), /out of range/);
});

const DECODE = {
  createCollection: (d) => sdk.nftDecode.id(d),
  mint: (d) => sdk.nftDecode.bool(d),
  mintBatch: (d) => sdk.nftDecode.uint(d).toString(),
  transfer: (d) => sdk.nftDecode.bool(d),
  registerEvmPointer: (d) => sdk.nftDecode.bool(d),
  mintMulti: (d) => sdk.nftDecode.bool(d),
  ownerOf: (d) => sdk.nftDecode.address(d),
  balanceOf: (d) => sdk.nftDecode.uint(d).toString(),
  balanceOfMulti: (d) => sdk.nftDecode.uint(d).toString(),
  tokenUri: (d) => sdk.nftDecode.string(d),
  getCollection: (d) => {
    const c = sdk.nftDecode.collection(d);
    return { ...c, totalSupply: c.totalSupply.toString() };
  },
};

test("NFT factory calldata, return data and transfer logs match the vectors", () => {
  assert.equal(sdk.NFT_FACTORY_ADDRESS, NFT.factory);
  assert.equal(sdk.NFT_TRANSFER_TOPIC, NFT.transfer_topic);
  assert.deepEqual({ ...sdk.NFT_SELECTORS }, NFT.selectors);
  for (const c of NFT.collection_ids) assert.equal(sdk.nftCollectionId(c.creator, c.nonce), c.id);
  for (const s of NFT.steps) {
    assert.equal(hex(sdk.nftCalldata[s.call](...args(s.args))), s.calldata, `${s.call} ${JSON.stringify(s.args)}`);
    if (s.output !== null && "decoded" in s) assert.deepEqual(DECODE[s.call](s.output), s.decoded, s.call);
    for (const log of s.logs ?? []) {
      const t = sdk.decodeNftTransfer({ address: NFT.factory, ...log });
      assert.ok(t, "a transfer log decodes");
      assert.equal(t.collectionId, log.topics[1]);
      assert.equal(t.tokenId, BigInt(log.data));
    }
  }
  const id1 = NFT.collection_ids[0].id;
  const someone = NFT.accounts.bob;
  assert.equal(hex(sdk.nftCalldata.mintRandom(id1, someone, 100n)), NFT.random.mint_random);
  assert.equal(hex(sdk.nftCalldata.fulfillRandom("0x" + "ee".repeat(32))), NFT.random.fulfill_random);
  assert.equal(hex(sdk.nftCalldata.registerSvmPointer(NFT.collection_ids[1].id, "0x" + "5a".repeat(32))), NFT.random.register_svm_pointer);
  assert.equal(sdk.decodeNftTransfer({ topics: ["0x" + "00".repeat(32)], data: "0x" }), undefined);
});

test("NFT inputs the factory would refuse are refused before signing", () => {
  const id = NFT.collection_ids[0].id;
  const zero = "0x" + "00".repeat(20);
  assert.throws(() => sdk.nftCalldata.mint(id, zero, 1n), /zero address/);
  assert.throws(() => sdk.nftCalldata.mint(id, NFT.accounts.bob, 2n ** 128n), /128 bits/);
  assert.throws(() => sdk.nftCalldata.mint(id, NFT.accounts.bob, 1n, "x".repeat(513)), /512 bytes/);
  assert.throws(() => sdk.nftCalldata.mintBatch(id, NFT.accounts.bob, []), /1 to 256/);
  assert.throws(() => sdk.nftCalldata.createCollection("", "X"), /needs a name/);
  assert.throws(() => sdk.nftCalldata.mintMulti(id, NFT.accounts.bob, 1n, 0n), /positive/);
  assert.throws(() => sdk.nftCalldata.ownerOf("0x12", 1n), /32 bytes/);
});

test("NFT writes are one all-or-nothing ContractCall transaction; reads go through eth_call", async () => {
  const id = NFT.collection_ids[0].id;
  const tx = sdk.nftTransaction(sdk.nftCalldata.mint(id, NFT.accounts.bob, 1n), sdk.nftCalldata.transfer(id, NFT.accounts.alice, 1n));
  assert.equal(tx.kind, "ContractCall");
  assert.equal(tx.fields.calls.length, 2);
  assert.deepEqual(tx.fields.calls[0].to, [...Array(18).fill(0), 0x10, 0x06]);
  assert.equal(tx.fields.calls[0].vm, "evm");
  assert.equal(tx.fields.calls[0].value, 0);
  assert.deepEqual(sdk.txType(tx), { ContractCall: tx.fields });
  const seen = [];
  const out = NFT.steps.find((s) => s.call === "getCollection").output;
  const rpc = { call: async (method, params) => (seen.push([method, params]), out) };
  const c = await new sdk.NftClient(rpc).collection(id);
  assert.equal(c.name, "Tenzro Cats");
  assert.deepEqual(seen[0], ["eth_call", [{ to: NFT.factory, data: hex(sdk.nftCalldata.getCollection(id)) }, "latest"]]);
});
