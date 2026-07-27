"""4-tier keyword routing for natural language messages to handler skills."""

import re


def route_message(text: str) -> str:
    """Route a natural language message to the appropriate handler skill.

    Routing uses four priority tiers:
      Tier 1 - Multi-word compound phrases (highest priority)
      Tier 2 - Token sub-commands
      Tier 3 - Single-keyword domain routes
      Tier 4 - Generic / fallback (lowest priority)
    """
    t = text.lower()

    # ------------------------------------------------------------------
    # Tier 1: Multi-word compound phrases (highest priority)
    # ------------------------------------------------------------------
    # Approval phrases are checked ahead of "auth" and "treasury" so the
    # out-of-band signoff loop wins over the token flows; the narrower
    # "approval gate" (workflow) and "approve withdrawal" (treasury)
    # phrases stay with their own skills because none of these match them.
    if any(k in t for k in [
        "pending approval", "pending approvals", "approval request",
        "approval record", "decide approval", "approve request",
        "deny request", "reject request", "approval id", "deny reason",
    ]):
        return "approval"
    # "onboard delegated" / "onboard autonomous" carry the onboarding verb, so
    # the bare identity-class nouns stay out: a sentence about an autonomous
    # agent is far more often about spawning or hiring one than about issuing
    # it an access token.
    if any(k in t for k in [
        "refresh token", "refresh access token", "refresh my token",
        "link wallet for auth", "link my wallet", "link wallet to auth",
        "onboard human", "onboard delegated", "onboard autonomous",
        "dpop", "access token", "auth token",
    ]):
        return "auth"
    if any(k in t for k in ["join", "micronode", "onboard", "participate"]):
        return "join"
    # "template" is qualified by "agent" so a DAML template listing is not
    # mistaken for a marketplace browse.
    if (
        "agent template" in t
        or "agent marketplace" in t
        or ("rate" in t and "template" in t)
        or ("spawn" in t and "template" in t)
    ):
        return "agent_marketplace"
    # A training run is addressed by an id that reads like a task id, so the
    # training vocabulary is claimed ahead of the marketplace route.
    if any(k in t for k in [
        "tenzro train", "training run", "training receipt", "sync round",
    ]):
        return "operability"
    if (
        "task marketplace" in t
        or ("task" in t and "marketplace" in t)
        or (
            "task" in t
            and any(k in t for k in [
                "post ", "list ", "open ", "cancel", "status",
                "quote", "assign", "complete",
            ])
        )
    ):
        return "task_marketplace"
    if any(k in t for k in [
        "spawn", "child agent", "sub-agent", "subagent", "agent task",
    ]):
        return "agent_spawning"
    # Claimed after spawning so "spawn an agent with coding capabilities" keeps
    # its route, and ahead of the Tier 2 "attestation" catch-all that otherwise
    # sends every attestation phrase to the TEE surface.
    if any(k in t for k in [
        "capability registry", "capability attestation", "registered capabilities",
        "list capabilities", "list all capabilities", "attestations issued for",
        "attestations for the", "best agent for", "tee-backed agent",
    ]):
        return "capability_registry"
    if any(k in t for k in ["swarm", "orchestrat"]):
        return "swarm_orchestration"
    # Regulated-asset controls claim the kill switch only when the subject is
    # a token; the bare phrase stays with the agent lifecycle below. Freezing
    # is claimed only when an account is named, because ERC-7943 freezes a
    # (token, account) pair while the compliance route freezes an address.
    if any(k in t for k in [
        "urwa", "erc-7943", "erc7943", "frozen token", "frozen tokens",
        "frozen amount", "regulated asset",
    ]) or (
        any(k in t for k in ["kill-switch", "kill switch", "killswitch"])
        and "token" in t
    ) or ("freeze" in t and "account" in t):
        return "urwa"
    if any(k in t for k in [
        "kill-switch", "kill switch", "killswitch",
        "pause agent", "quarantine agent", "terminate agent",
        "agent lifecycle", "lifecycle receipt",
    ]):
        return "lifecycle"
    # Ahead of the Tier 2 "token" catch-all so phrases like "register token
    # pointer discriminator" reach the SVM program reference rather than the
    # token listing.
    if any(k in t for k in [
        "svm program", "svm-native program", "program id", "discriminator",
        "cross-vm program", "cross vm program",
    ]):
        return "svm_cross_vm_info"

    # ------------------------------------------------------------------
    # Tier 2: Token sub-commands
    #
    # Compound phrases naming another domain are matched first, because the
    # catch-all below claims every remaining mention of the word "token".
    # ------------------------------------------------------------------
    if any(k in t for k in [
        "native token transfer", "ntt manager", "ntt transceiver",
        "wormhole ntt", "wormhole-ntt",
    ]):
        return "wormhole-ntt"
    # Bridge authorization, rate limits and the audit trail are the ERC-7802
    # control surface, not a bridge transfer, so they are claimed ahead of the
    # broad bridge route in Tier 3.
    if any(k in t for k in [
        "crosschain token", "cross-chain token", "erc-7802", "erc7802",
    ]) or (
        "bridge" in t
        and any(k in t for k in [
            "authorize", "authorization", "revoke", "rate limit", "audit trail",
        ])
    ):
        return "crosschain"
    if any(k in t for k in [
        "cct pool", "cct pools", "chainlink cross-chain token",
        "lockrelease pool", "burnmint pool",
    ]):
        return "cct"
    # SPT precedes the token block because every natural phrasing of a shared
    # payment token contains the word "token" and would be claimed by it.
    if any(k in t for k in [
        "shared payment token", "sharedpaymenttoken", "shared-payment-token",
        "stripe spt", "stripe-spt", "granted token", "granted_token",
        "issued token", "spt_grant",
    ]) or ("spt" in t and "stripe" in t):
        return "stripe-spt"

    # ------------------------------------------------------------------
    # Tier 2b: Crypto / TEE / Custody / ZK compound phrases
    # ------------------------------------------------------------------
    if any(k in t for k in ["key exchange", "x25519", "diffie-hellman"]):
        return "crypto"
    if any(k in t for k in [
        "passkey", "webauthn", "smart account", "social recovery",
        "guardian", "recovery ceremony", "hardware signer",
        "passkey policy", "enroll passkey",
    ]):
        return "passkey-wallet"
    if any(k in t for k in ["mpc wallet", "keystore", "session key", "spending limit", "custody", "key share", "key rotation"]):
        return "custody"
    if any(k in t for k in ["zk proof", "zero knowledge", "zk circuit", "plonky3", "stark"]):
        return "zk"
    if any(k in t for k in ["tee enclave", "tee attestation", "tee provider", "seal data", "unseal data", "trusted execution"]):
        return "tee"

    # ------------------------------------------------------------------
    # Tier 2c: AP2 mandate, ERC-8004, Wormhole, CCT compound phrases
    # ------------------------------------------------------------------
    if any(k in t for k in [
        "ap2 mandate", "verify mandate", "validate mandate", "intent vdc", "cart vdc",
        "payment vdc", "mandate pair", "ap2 session", "ap2 protocol", "ap2 intent",
        "ap2 cart", "ap2 payment", "list mandates", "list mandate", "ap2 mandates",
    ]):
        return "ap2-payments"
    if any(k in t for k in [
        "erc-8004", "erc8004", "agent id", "agentid", "agent_id",
        "trustless agent", "reputation feedback", "request validation",
        "submit validation",
    ]):
        return "erc8004"
    if any(k in t for k in ["wormhole", "vaa"]):
        return "wormhole"
    if any(k in t for k in [
        "capital intent", "capital allocation", "reserve attestation",
        "attested mint", "tokenized asset", "1:1 backed", "regulated capital",
        "solver bid", "intent_id", "execute leg", "current reserve",
    ]):
        return "capital"
    # Netting precedes the workflow route because a netting batch collapses
    # obligations, and "obligation" is a workflow keyword.
    if any(k in t for k in [
        "dvp", "delivery versus payment", "delivery-versus-payment",
        "netting", "net obligations", "saga leg", "atomic settlement",
    ]):
        return "dvp-netting"
    if any(k in t for k in [
        "workflow", "compensate step", "verify step", "obligation",
        "approval gate", "fee route", "privacy domain",
    ]):
        return "workflow"
    if any(k in t for k in [
        "did envelope", "did-envelope", "verify envelope", "signed envelope",
    ]):
        return "verification"

    # ------------------------------------------------------------------
    # Tier 2d: EVM primitives + cross-chain reach + CAIP discovery
    # ------------------------------------------------------------------
    if any(k in t for k in [
        "eip-7702", "eip7702", "7702 delegation", "set eoa code", "eoa code",
        "designator", "pectra delegation", "delegate_address",
        "delegate address", "0xef0100", "ef0100",
    ]):
        return "eip7702"
    # A permit carrying a digest, a nonce, a witness or a signature is a
    # Permit2 operation whatever else the sentence names.
    if any(k in t for k in [
        "permit2", "signaturetransfer", "signature transfer",
    ]) or (
        "permit" in t
        and any(k in t for k in ["digest", "consume", "nonce", "witness", "sign"])
    ) or ("nonce" in t and "consumed" in t):
        return "permit2"
    if any(k in t for k in [
        "secure-mint", "secure mint", "reserve attestation", "por feed",
        "proof of reserve", "1:1 backing", "tokenized rwa", "xstock",
        "tokenized equity", "tokenized treasury", "circulating",
    ]) or ("asset_id" in t and any(k in t for k in ["mint", "burn"])):
        return "secure-mint"
    if any(k in t for k in [
        "treasury withdrawal", "treasury multisig", "pending withdrawal",
        "approve withdrawal", "execute withdrawal", "add withdrawer",
        "remove withdrawer", "withdrawal threshold",
    ]):
        return "treasury"
    if any(k in t for k in [
        "stable-asset", "stable asset", "stable unit", "stablecoin issuance",
        "issue stable", "mint stable", "redeem stable", "stable-unit",
        "unit_token",
    ]):
        return "stable-asset"
    if any(k in t for k in [
        "hyperlane", "tenzro-ism", "hyperlane mailbox", "sovereign ism",
        "interchain gas", "destination_domain", "destination domain",
    ]):
        return "hyperlane"
    if any(k in t for k in [
        "axelar", "gmp", "call contract", "axelar gas service",
        "cosmos chain", "stellar reach", "xrpl reach",
    ]):
        return "axelar"
    if any(k in t for k in [
        "babylon", "finality provider", "bitcoin staking", "btc staking",
        "eots", "extractable one-time signature",
    ]):
        return "babylon"
    if any(k in t for k in [
        "caip", "caip-2", "caip-10", "caip-19", "chain-agnostic",
        "slip-44", "slip44 coin", "asset namespace", "casa",
    ]):
        return "caip"
    if any(k in t for k in [
        "asset price", "price oracle", "spot price", "usd price",
        "price feed", "get price", "oracle price", "price of",
    ]):
        return "oracle"

    # ------------------------------------------------------------------
    # Tier 2e: Operability inspection, storage market, compute rental,
    # MoE sharding, local discovery
    #
    # Operability phrases must precede the MoE route ("sealed-shard
    # manifest" contains "shard") and the broad Tier 3 routes. MoE and
    # local-discovery phrases must precede the broad Tier 3 "model" and
    # "network" routes because both share keywords.
    # ------------------------------------------------------------------
    # A supply snapshot is the burn dial's read, not an operability read, so
    # "snapshot" is qualified rather than matched bare.
    if any(k in t for k in [
        "tenzro train", "training run", "training receipt", "sealed receipt",
        "sealed manifest", "sealed-shard manifest", "sla probe", "sla fault",
        "sla param", "liveness probe", "outstanding probe",
        "state-sync", "router metrics", "hedges",
    ]) or ("snapshot" in t and "supply" not in t):
        return "operability"
    # Media-gen phrases must precede the MoE route: a split denoising
    # schedule is described in terms of its high-noise and low-noise
    # "expert" halves, which would otherwise match the MoE route.
    if any(k in t for k in [
        "media gen", "media-gen", "generative-media", "generative media",
        "text2image", "image2image", "text-to-image", "image-to-image",
        "text2video", "image2video", "text-to-video", "image-to-video",
        "generate image", "generate video",
        "diffusers catalog", "pixel-step", "pixel step", "render job",
        "render", "denoise step", "denoising step",
        "latent handoff", "high-noise", "low-noise",
    ]):
        return "media-gen"
    if any(k in t for k in [
        "expert", "moe", "shard map", "shard", "expert-shard",
        "dispatch plan", "plan dispatch", "replication policy",
    ]):
        return "moe"
    # Bare "cluster" is deliberately absent: a database placement hint and an
    # expert-cluster index both carry the word without being a peer query.
    if any(k in t for k in [
        "local peers", "local peer", "local cluster", "lan cluster",
        "local segment", "cluster placement", "discover peers", "mdns",
        "reachability", "connectivity tier",
        "node profile", "hardware profile",
    ]):
        return "discovery"
    # App hosting must precede the broad Tier 3 routes: "sealing key"
    # contains "seal" (tee), "function deploy" contains "deploy"
    # (contract), and static-site publishing overlaps "model"/"deploy".
    if any(k in t for k in [
        "hosting", "publish site", "static site", "static export",
        "site alias", "site placement", "custom domain", "claim domain",
        "verify domain", "apps.tenzro.xyz", "wasi:http", "wasi http",
        "wasm function", "function deploy", "deploy function",
        "microvm", "micro vm", "firecracker", "machine deploy",
        "deploy machine", "machine status", "sealing key",
        "placement lease", "serving lease", "pin site",
    ]):
        return "hosting"
    if any(k in t for k in [
        "database", "managed database", "database engine", "database partition",
        "database query", "database connection", "create database",
        "drop database", "rescale database", "list databases",
    ]):
        return "database"
    if any(k in t for k in [
        "storage", "store object", "storage deal", "store ",
        "por challenge", "charge epoch", "retrievability", "byte-epoch",
        "byte epoch", "on deal ",
    ]):
        return "storage"
    if any(k in t for k in [
        "compute rental", "compute provider", "book rental",
        "settle epoch", "rent compute", "rental", "compute pricing",
    ]) or re.search(r"\brent\b", t):
        return "compute"

    # ------------------------------------------------------------------
    # Tier 2f: Reasoning tiers, settlement rails, cross-chain intents,
    # travel-rule envelopes and the per-modality inference runtimes.
    #
    # These sit below the storage / compute / hosting phrases so
    # "settle epoch" stays with the compute rental it belongs to, and above
    # Tier 3 because the modality routes share the words "model" and
    # "inference" with the chat route, and "ccip" with the bridge route.
    # ------------------------------------------------------------------
    if any(k in t for k in [
        "cortex", "reasoning tier", "-tier reasoning", "reason over",
        "deep reasoning", "institutional reasoning", "remote worker",
    ]):
        return "cortex"
    # A travel-rule envelope is hashed so a settlement receipt can point at
    # it, so the phrase carries both vocabularies and is claimed here first.
    if any(k in t for k in [
        "ivms", "ivms101", "ivms-101", "travel rule", "travel-rule",
    ]):
        return "ivms101"
    if any(k in t for k in [
        "settlement", "settle payment", "payment channel", "micropayment",
        "channel balance", "prepaid", "escrow", "settlement receipt",
        "unpaid settlement",
    ]):
        return "settlement"
    if any(k in t for k in [
        "bond", "insurance", "insurance claim", "insurance pool",
        "file claim",
    ]):
        return "bond-insurance"
    # Quoting an adapter fee denominated in TNZO precedes the CCIP route,
    # which otherwise claims every sentence naming the adapter.
    if any(k in t for k in [
        "in tnzo", "fee in tnzo", "sponsorship pool", "sponsorship-pool",
        "gas sponsorship", "quote bridge fee",
    ]):
        return "bridge-fee-in-tnzo"
    if "ccip" in t:
        return "ccip"
    # A permit carrying a 7683 witness is a Permit2 operation; the witness is
    # the payload, not the subject.
    if any(k in t for k in [
        "erc-7683", "erc7683", "7683", "cross-chain intent",
        "cross-chain order", "record fill", "fill record", "order fill",
        "origin_chain", "origin settler",
    ]) and "permit" not in t:
        return "erc7683"
    if any(k in t for k in [
        "attested clock", "attested-clock", "attested timestamp",
        "attestedtimestamp", "hardware-signed timestamp", "wall clock",
        "wall_ms", "current time", "grace deadline", "monotonic",
    ]):
        return "attested-clock"
    if any(k in t for k in [
        "signed agent card", "agent card", "agentcard",
        "canonical card hash",
    ]):
        return "signed-agent-card"
    if any(k in t for k in [
        "agent memory", "memories", "grant memory", "archive memory",
        "memory record", "remember this",
    ]) or ("recall" in t and "memor" in t):
        return "agent-memory"
    if any(k in t for k in [
        "adaptive burn", "adaptive-burn", "burn rate", "burn-rate",
        "supply metric", "supply-metric", "burn recommendation",
    ]):
        return "adaptive-burn"
    if any(k in t for k in [
        "seed agent", "seedagent", "treasury earmark", "earmark",
        "network activity", "seed charter",
    ]):
        return "seed-agent"
    if any(k in t for k in [
        "forecast", "time series", "timeseries", "timesfm",
        "predict horizon",
    ]):
        return "forecast"
    # A quoted noun after "segment" is a text prompt, which is what
    # distinguishes the open-vocabulary segmenter from the point/box one.
    if any(k in t for k in [
        "text segmentation", "text-promptable", "open-vocabulary",
        "open vocabulary", "segment by text", "sam 3", "sam3",
    ]) or ("segment" in t and ("'" in t or '"' in t)):
        return "text-segmentation"
    # Bare "segment" is deliberately absent: a network segment is a
    # discovery query, not an image one.
    if any(k in t for k in [
        "segmentation", "segment image", "segment the image", "sam 2",
        "sam2", "mask prompt",
    ]) or ("segment" in t and any(k in t for k in ["image", "mask", "pixel"])):
        return "segmentation"
    if any(k in t for k in [
        "embed video", "video embed", "video embedding", "video clip",
        "frame_stride", "video catalog", "video model",
    ]):
        return "video-embed"
    if any(k in t for k in [
        "embed image", "image embed", "image embedding", "vision embed",
        "image-text similarity", "image text similarity", "clip embed",
        "zero-shot classify", "classify image", "siglip", "dinov3",
        "vision catalog", "vision model",
    ]):
        return "vision-embed"
    if any(k in t for k in [
        "embed text", "text embed", "text embedding", "embedding",
        "bge-m3", "arctic embed",
    ]):
        return "text-embed"
    # Bare "detect" is deliberately absent: "detect tee hardware" is a
    # hardware query that belongs to the tee route in Tier 3.
    if any(k in t for k in [
        "detection", "detect object", "bounding box", "rf-detr", "d-fine",
    ]) or ("detect" in t and "image" in t):
        return "detection"
    if any(k in t for k in [
        "transcribe", "transcription", "speech to text", "speech-to-text",
        "asr", "whisper", "moonshine", "parakeet", "canary-1b",
        "audio catalog", "audio model",
    ]):
        return "audio-transcribe"

    # x402 is a payment rail whatever else the sentence names; a seller DID or
    # a payer DID in the metadata does not make the request an identity one.
    if "x402" in t:
        return "payment"
    # Registering as a provider is a staking operation — the phrasing names the
    # modality being served ("model provider"), which would otherwise route to
    # inference.
    if "register" in t and "provider" in t:
        return "staking"

    # ------------------------------------------------------------------
    # Tier 2g: Compliance, Canton and the event stream.
    #
    # All three precede the token catch-all and the Tier 3 single keywords:
    # a compliance freeze and a country restriction both name a token, a
    # Canton read names a balance, a contract and a transaction, and an event
    # query names a contract.
    # ------------------------------------------------------------------
    if any(k in t for k in [
        "compliance", "kyc", "t-rex", "erc-3643", "whitelist",
        "accreditation", "accredited", "country restriction", "trusted issuer",
        "freeze", "unfreeze", "recover token",
    ]):
        return "compliance"
    if any(k in t for k in ["canton", "daml", "upload dar"]):
        return "canton"
    if any(k in t for k in [
        "event", "subscribe", "webhook", "listen", "stream pending",
        "in real time",
    ]):
        return "events"

    # ------------------------------------------------------------------
    # Tier 2h: Token sub-commands.
    #
    # The catch-all claims every remaining mention of the word "token", so it
    # sits below every domain compound above — a compliance freeze, a
    # cross-chain mint authorization and a capital intent over tokenized
    # treasuries all name a token without being token-registry operations.
    # It stays above Tier 3 so "token balance" outranks the bare wallet route.
    #
    # "wrap tnzo" is the natural phrasing and carries no literal "token", so the
    # gate admits it explicitly rather than leaving wrap_tnzo unreachable.
    # ------------------------------------------------------------------
    if (
        "token" in t
        or ("wrap" in t and "tnzo" in t)
        or ("tnzo" in t and any(k in t for k in ["evm", "svm", "all vms"]))
    ):
        if any(k in t for k in ["create", "mint"]):
            return "create_token"
        if any(k in t for k in ["info", "details", "lookup"]):
            return "token_info"
        if "balance" in t:
            return "token_balance"
        if "cross" in t and "vm" in t:
            return "cross_vm_transfer"
        if "wrap" in t and "tnzo" in t:
            return "wrap_tnzo"
        return "token"

    # ------------------------------------------------------------------
    # Tier 3: Single-keyword domain routes
    # ------------------------------------------------------------------
    if any(k in t for k in ["sign", "encrypt", "decrypt", "keccak"]):
        return "crypto"
    if any(k in t for k in ["tee", "enclave", "attestation", "seal"]):
        return "tee"
    if any(k in t for k in ["deploy", "contract", "bytecode"]):
        return "contract"
    if any(k in t for k in ["nft", "collection", "mint nft"]):
        return "nft"
    if any(k in t for k in ["debridge", "dln", "same chain swap"]):
        return "debridge"
    if any(k in t for k in ["bridge", "cross-chain", "layerzero"]):
        return "bridge"
    if any(k in t for k in ["erc-7802", "crosschain token"]):
        return "crosschain"
    # Validator-lifecycle: registry reads + key rotation. Must precede the
    # identity rule because "candidate" contains "did", and the staking rule
    # because both match "validator".
    if any(
        k in t
        for k in [
            "rotate key", "rotate-key", "rotate the key",
            "list validator", "list active validator",
            "active validator", "list candidate", "list jailed",
            "validator state", "validator registry",
        ]
    ) or ("rotate" in t and "validator" in t) or (
        "registry" in t and "validator" in t
    ):
        return "validator-lifecycle"
    if any(k in t for k in ["identity", "did", "register identity", "resolve", "username"]):
        return "identity"
    if any(k in t for k in ["balance", "wallet", "send", "transfer"]):
        return "wallet"
    if "faucet" in t:
        return "faucet"
    if any(k in t for k in [
        "model", "inference", "ai ", "chat", "route by intent",
    ]):
        return "inference"
    if any(k in t for k in ["stake", "staking", "unstake", "validator"]):
        return "staking"
    if any(k in t for k in ["provider", "serving", "earnings"]):
        return "provider"
    if "ap2" in t:
        return "ap2-payments"
    if any(k in t for k in ["payment", "challenge", "mpp", "x402"]):
        return "payment"
    if any(k in t for k in ["verify", "proof", "attestation", "zk"]):
        return "verification"
    if any(k in t for k in [
        "block", "height", "transaction", "block range", "sync from",
        "catch up", "catch-up",
        "fee market", "gas price", "gasprice", "priority tip",
        "fee history", "1559", "eip-1559", "eip1559",
    ]):
        return "block"

    # ------------------------------------------------------------------
    # Tier 4: Most generic (lowest priority)
    # ------------------------------------------------------------------
    if any(k in t for k in ["peer", "network"]):
        return "network"
    if any(k in t for k in ["status", "health", "node"]):
        return "status"

    return "help"
