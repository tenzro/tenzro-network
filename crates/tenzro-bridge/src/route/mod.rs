//! The route framework: one set of rules for every bridge route.
//!
//! A route moves TNZO between Tenzro and one external chain over one
//! transport (see [`BridgeRoute`]). Each chain family implements
//! [`RouteAdapter`]: it decodes the messages that chain emits and builds the
//! messages it accepts. Everything that keeps a route safe is enforced here,
//! by the framework, and never left to an adapter:
//!
//! - **Governed routes.** Only a route installed by governance carries
//!   traffic, and it is re-checked against the route rules on every use.
//! - **Circuit breaker.** A paused route admits and sends nothing. A
//!   disabled route winds down: it sends nothing new and credits no new
//!   deposit, while value already sent out over it can still come back and
//!   messages already sent to Tenzro are still admitted, so nothing in flight
//!   is stranded ([`BridgeRouteMode`]).
//! - **Strict canonical decoding.** The delivery envelope and the adapter's
//!   message are read through a [`canonical::Reader`]; a truncated payload,
//!   a non-canonical field or a single trailing byte rejects the delivery.
//!   Outbound messages are decoded back and must match what was built.
//! - **Domain-separated, replay-protected attestations.** The committee (and
//!   the independent blessing committee where the transport has one) signs
//!   [`attestation_digest`], which binds this chain's id, the route, the
//!   nonce and an expiry. A used nonce is refused for good.
//! - **Light-client proofs.** A route that names a light client admits
//!   nothing without a proof that the installed verifier of that kind
//!   accepts against the light-client state started from the route's
//!   governed anchor ([`ethereum_light_client`] for Ethereum, [`tendermint`]
//!   for Cosmos chains, [`bitcoin`], [`sui`], [`aptos`] and [`stellar`]).
//!   A Solana route, which has none, admits only with an attested record
//!   of the source transaction's success signed by verifiers independent in
//!   operator and RPC provider ([`solana::check_execution`]).
//! - **Caps and rate limits.** Per mint and per epoch, the tighter of the
//!   route's and the network's; the network's are lower for a route without
//!   a light client ([`NetworkMintLimits`]). On a CCIP route also the lane's
//!   token buckets in each direction ([`lane`]), the limits the external
//!   chain's token pool applies. A transfer passes all of them or none.
//! - **The supply invariant.** For every route, the representation on the
//!   external chain is never more than the TNZO locked on Tenzro for it.
//!   Every outbound transfer locks before it authorises a remote mint;
//!   every inbound transfer is refused unless the route has at least that
//!   much outstanding. A deposit route counts the other way round: the
//!   asset held under its deposit script on the external chain against the
//!   representation credited on Tenzro; a withdrawal burns the
//!   representation and spends exactly that much from the descriptor's
//!   tracked outputs ([`bitcoin_spend`]).

pub mod aptos;
pub mod attestation;
pub mod beacon_body;
pub mod bitcoin;
pub mod bitcoin_spend;
pub mod canonical;
pub mod ethereum_light_client;
pub mod evm;
pub mod ibc;
pub mod ibc_core;
pub mod lane;
pub mod light_client;
pub mod move_event;
pub mod receipt_proof;
pub mod reserve;
pub mod solana;
pub mod state;
pub mod stellar;
pub mod sui;
pub mod tendermint;
pub mod ton;
pub mod ton_cell;
pub mod ton_light_client;

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
pub use tenzro_types::bridge_route::{
    AssetLane, AssetTransfer, BridgeRoute, BridgeRouteAdapter, BridgeRouteError, BridgeRouteMode,
    CarriedAsset, CcipLane, CcipLaneVersion, ChainFamily, IbcRoute, IbcVersion, LaneRateLimit,
    LightClientAnchor, LightClientKind, MintRateLimit, NetworkMintLimits, NetworkOutflowLimits,
    OutflowCap, TNZO_UNIT, VerifierMember, VerifierQuorum, bridge_route_storage_key, deposit_unit,
};

use crate::error::{BridgeError, Result};
use attestation::{Delivery, attestation_digest, verify_committee};
use canonical::Reader;
use lane::LaneDirection;
use light_client::{LightClientHead, LightClientVerifier};
use state::{EpochUsage, RouteState, SupplyRecord};

/// Longest an attestation may remain usable after it is signed.
pub const MAX_ATTESTATION_VALIDITY_MS: i64 = 60 * 60 * 1000;

/// A transfer message in family-neutral form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMessage {
    /// The transport's message id; adapters verify it on decode.
    pub message_id: [u8; 32],
    /// The sending chain's identifier on the transport.
    pub source_selector: u64,
    /// The receiving chain's identifier on the transport.
    pub dest_selector: u64,
    /// Per-route sequence number; the attestation nonce must equal it.
    pub sequence: u64,
    /// The sender on the sending chain, as that chain encodes it.
    pub sender: Vec<u8>,
    /// The recipient on the receiving chain, as that chain encodes it.
    pub receiver: Vec<u8>,
    /// The token pool on the sending chain, left-padded to 32 bytes.
    pub token_pool: [u8; 32],
    /// The token on the receiving chain, left-padded to 32 bytes.
    pub token: [u8; 32],
    /// Amount in the smallest unit.
    pub amount: u128,
}

/// What one chain family implements. Adapters only translate formats: every
/// rule in the module docs is applied by [`RouteFramework`] around them.
pub trait RouteAdapter: Send + Sync {
    /// The transport this adapter speaks.
    fn transport(&self) -> BridgeRouteAdapter;

    /// The chain family this adapter reads and writes.
    fn family(&self) -> ChainFamily;

    /// Decode one message the external chain emitted towards Tenzro and
    /// check its message id. The framework owns `r` and refuses the delivery
    /// if any byte is left after this returns.
    fn decode_inbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage>;

    /// Build the message the external chain accepts for `msg`.
    fn encode_outbound(&self, route: &BridgeRoute, msg: &RouteMessage) -> Result<Vec<u8>>;

    /// Read back what [`RouteAdapter::encode_outbound`] wrote.
    fn decode_outbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage>;

    /// The message id of an outbound message.
    fn outbound_message_id(&self, route: &BridgeRoute, msg: &RouteMessage) -> Result<[u8; 32]>;

    /// How many of the external chain's blocks (slots, ledgers, checkpoints)
    /// a message's block is buried under before it is final there. Committee
    /// members attest only final messages; relayers read it from the route
    /// listing.
    fn finality_depth(&self, route: &BridgeRoute) -> Result<u64>;
}

/// An inbound transfer every rule admitted.
#[derive(Debug, Clone)]
pub struct AdmittedTransfer {
    /// The route it arrived on.
    pub route: BridgeRoute,
    /// The decoded message.
    pub message: RouteMessage,
    /// The route's mint usage this epoch, after this transfer.
    pub usage: EpochUsage,
    /// The route's supply record, after this transfer (the carried asset's
    /// when it carried one).
    pub supply: SupplyRecord,
    /// The listed asset it carried; `None` for TNZO.
    pub asset: Option<CarriedAsset>,
}

/// An issuer's own transfer protocol, plugged into the framework for the
/// carried assets that name it ([`AssetTransfer::BurnAndMint`]). The route's
/// committee still attests every delivery; the hook adds the issuer's own
/// evidence of the burn and builds the issuer's mint instruction.
pub trait IssuerTransferHook: Send + Sync {
    /// The protocol name carried assets refer to.
    fn protocol(&self) -> &str;
    /// Check the issuer's evidence, carried in the delivery body, that
    /// `message.amount` was burned on the external chain for Tenzro.
    fn verify_burn(
        &self,
        route: &BridgeRoute,
        asset: &CarriedAsset,
        message: &RouteMessage,
        body: &[u8],
    ) -> Result<()>;
    /// The issuer-protocol instruction that mints `message.amount` to
    /// `message.receiver` on the external chain.
    fn mint_instruction(
        &self,
        route: &BridgeRoute,
        asset: &CarriedAsset,
        message: &RouteMessage,
    ) -> Result<Vec<u8>>;
}

/// A request to move TNZO, or a carried asset's representation, from Tenzro
/// to an external chain.
#[derive(Debug, Clone)]
pub struct OutboundTransfer {
    /// The Tenzro account that gave up the TNZO.
    pub sender: Vec<u8>,
    /// The recipient on the external chain, as that chain encodes it.
    pub recipient: Vec<u8>,
    /// Amount in the smallest unit.
    pub amount: u128,
    /// The carried asset's symbol; `None` for TNZO.
    pub asset: Option<String>,
}

/// An outbound message ready for the transport.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    /// The route it leaves on.
    pub route: BridgeRoute,
    /// The message as built.
    pub message: RouteMessage,
    /// Its encoding for the external chain.
    pub bytes: Vec<u8>,
    /// The route's supply record, after this transfer (the carried asset's
    /// when it carries one).
    pub supply: SupplyRecord,
    /// The listed asset it carries; `None` for TNZO.
    pub asset: Option<CarriedAsset>,
}

/// Domain tag of an outbound data message.
pub const ROUTE_MESSAGE_DOMAIN: &[u8] = b"tenzro/bridge/route-message";

/// An outbound data message queued on a route: a record Tenzro publishes to
/// the external chain (a settlement mirror, for example). It moves no TNZO.
#[derive(Debug, Clone)]
pub struct OutboundData {
    /// The route it leaves on.
    pub route: BridgeRoute,
    /// Its sequence in the route's data-message space.
    pub sequence: u64,
    /// Keccak-256 of `bytes`.
    pub message_id: [u8; 32],
    /// [`ROUTE_MESSAGE_DOMAIN`], the local and remote selectors, the
    /// sequence (all u64 big-endian) and the length-prefixed body.
    pub bytes: Vec<u8>,
}

/// Which way traffic moves, for the route-mode check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Traffic {
    /// A delivery from the external chain.
    Inbound,
    /// A transfer or message leaving Tenzro.
    Outbound,
    /// A carried asset's representation going back to its vault: a disabled
    /// route still lets it out, so no holder is stranded while it winds down.
    Redeem,
}

fn refuse(msg: impl Into<String>) -> BridgeError {
    BridgeError::TransferFailed(msg.into())
}

/// The unit a transfer leaving over `route` is counted in against the
/// network outflow caps: the carried asset's symbol, a deposit route's
/// native asset, or TNZO.
pub fn exit_unit(route: &BridgeRoute, asset: Option<&CarriedAsset>) -> Result<String> {
    if let Some(a) = asset {
        return Ok(a.symbol.clone());
    }
    if route.adapter != BridgeRouteAdapter::Deposit {
        return Ok(TNZO_UNIT.to_string());
    }
    deposit_unit(route.family)
        .map(str::to_string)
        .ok_or_else(|| refuse("the route's family has no deposit asset"))
}

/// The framework. See the module docs.
pub struct RouteFramework {
    adapters: HashMap<(BridgeRouteAdapter, ChainFamily), Arc<dyn RouteAdapter>>,
    light_clients: HashMap<LightClientKind, Arc<dyn LightClientVerifier>>,
    issuer_hooks: HashMap<String, Arc<dyn IssuerTransferHook>>,
    /// Serialises every read-check-write of route state in the process.
    lock: Mutex<()>,
}

impl Default for RouteFramework {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteFramework {
    /// The framework with every family's adapter.
    pub fn new() -> Self {
        let mut f = Self {
            adapters: HashMap::new(),
            light_clients: HashMap::new(),
            issuer_hooks: HashMap::new(),
            lock: Mutex::new(()),
        };
        f.register(Arc::new(evm::EvmCcipAdapter::new()));
        f.register(Arc::new(solana::SolanaCcipAdapter));
        f.register(Arc::new(ibc::IbcAdapter));
        f.register(Arc::new(bitcoin::BitcoinAdapter));
        f.register(Arc::new(sui::SuiAdapter));
        f.register(Arc::new(aptos::AptosAdapter));
        f.register(Arc::new(stellar::StellarAdapter));
        f.register(Arc::new(ton::TonAdapter));
        f
    }

    fn register(&mut self, adapter: Arc<dyn RouteAdapter>) {
        self.adapters
            .insert((adapter.transport(), adapter.family()), adapter);
    }

    /// Install a light-client verifier. Routes that name its kind start
    /// admitting deliveries whose proof it accepts.
    pub fn with_light_client(mut self, verifier: Arc<dyn LightClientVerifier>) -> Self {
        self.light_clients.insert(verifier.kind(), verifier);
        self
    }

    /// Install an issuer transfer hook. Carried assets that name its
    /// protocol start carrying traffic.
    pub fn with_issuer_hook(mut self, hook: Arc<dyn IssuerTransferHook>) -> Self {
        self.issuer_hooks.insert(hook.protocol().to_string(), hook);
        self
    }

    fn issuer_hook(&self, asset: &CarriedAsset) -> Result<Option<&Arc<dyn IssuerTransferHook>>> {
        match &asset.transfer {
            AssetTransfer::LockAndMint => Ok(None),
            AssetTransfer::BurnAndMint { protocol, .. } => {
                self.issuer_hooks.get(protocol).map(Some).ok_or_else(|| {
                    refuse(format!(
                        "no issuer transfer hook '{protocol}' is installed for {}",
                        asset.symbol
                    ))
                })
            }
        }
    }

    /// Install every light client this crate implements.
    pub fn with_all_light_clients(self) -> Self {
        self.with_light_client(Arc::new(ethereum_light_client::EthereumLightClient::new()))
            .with_light_client(Arc::new(tendermint::TendermintLightClient))
            .with_light_client(Arc::new(bitcoin::BitcoinLightClient))
            .with_light_client(Arc::new(sui::SuiLightClient))
            .with_light_client(Arc::new(aptos::AptosLightClient))
            .with_light_client(Arc::new(ton_light_client::TonLightClient))
            .with_light_client(Arc::new(stellar::StellarLightClient))
    }

    fn light_client<'a>(
        &'a self,
        route: &'a BridgeRoute,
    ) -> Result<(&'a Arc<dyn LightClientVerifier>, &'a LightClientAnchor)> {
        let anchor = route
            .light_client
            .as_ref()
            .ok_or_else(|| refuse(format!("route {} has no light client", route.storage_key())))?;
        let verifier = self.light_clients.get(&anchor.kind()).ok_or_else(|| {
            refuse(format!(
                "route {} requires a light-client proof and no verifier of its kind is installed",
                route.storage_key()
            ))
        })?;
        Ok((verifier, anchor))
    }

    /// Move the light client of the route `{adapter, chain}` forward with an
    /// update the external chain signed (or its bootstrap from the route's
    /// anchor). Anyone may submit one: the update carries its own proof, and
    /// a paused route's light client still follows its chain.
    pub fn advance_light_client(
        &self,
        state: &mut dyn RouteState,
        adapter: BridgeRouteAdapter,
        chain: &str,
        update: &[u8],
    ) -> Result<LightClientHead> {
        let _guard = self.lock.lock();
        let chain = chain.to_ascii_lowercase();
        let route = state.route(adapter, &chain).ok_or_else(|| {
            refuse(format!(
                "no governed {} route for '{chain}'",
                adapter.as_str()
            ))
        })?;
        route.validate().map_err(|e| {
            refuse(format!(
                "route {} breaks the route rules ({e})",
                route.storage_key()
            ))
        })?;
        let (verifier, anchor) = self.light_client(&route)?;
        verifier.advance(state, &route, anchor, update)
    }

    /// The route's finality depth (see [`RouteAdapter::finality_depth`]).
    pub fn finality_depth(&self, route: &BridgeRoute) -> Result<u64> {
        self.adapter(route)?.finality_depth(route)
    }

    /// Where the route's light client stands, if it has one and it has been
    /// bootstrapped.
    /// A Bitcoin payment proven by the light client of the live Bitcoin route
    /// `(adapter, chain)`.
    pub fn prove_bitcoin_payment(
        &self,
        state: &dyn RouteState,
        adapter: BridgeRouteAdapter,
        chain: &str,
        proof: &[u8],
    ) -> Result<bitcoin::ProvenPayment> {
        let route = self.live_route(state, adapter, chain, Traffic::Inbound)?;
        if route.family != ChainFamily::Bitcoin {
            return Err(refuse(format!(
                "route {} is not a Bitcoin route",
                route.storage_key()
            )));
        }
        let (_, anchor) = self.light_client(&route)?;
        bitcoin::prove_payment(state, &route, anchor, proof)
    }

    pub fn light_client_head(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
    ) -> Option<LightClientHead> {
        let (verifier, anchor) = self.light_client(route).ok()?;
        verifier.head(state, route, anchor)
    }

    fn adapter(&self, route: &BridgeRoute) -> Result<&Arc<dyn RouteAdapter>> {
        self.adapters
            .get(&(route.adapter, route.family))
            .ok_or_else(|| {
                refuse(format!(
                    "no {} adapter for {} chains",
                    route.adapter.as_str(),
                    route.family.as_str()
                ))
            })
    }

    /// Load a route and apply the checks every use shares: installed, still
    /// valid, and its mode lets `traffic` through.
    fn live_route(
        &self,
        state: &dyn RouteState,
        adapter: BridgeRouteAdapter,
        chain: &str,
        traffic: Traffic,
    ) -> Result<BridgeRoute> {
        let chain = chain.to_ascii_lowercase();
        let route = state
            .route(adapter, &chain)
            .filter(|r| r.adapter == adapter && r.source_chain == chain)
            .ok_or_else(|| {
                refuse(format!(
                    "no governed {} route for '{chain}'; traffic refused",
                    adapter.as_str()
                ))
            })?;
        route.validate().map_err(|e| {
            refuse(format!(
                "route {} breaks the route rules ({e}); traffic refused",
                route.storage_key()
            ))
        })?;
        match state.stopped(&route) {
            None => {}
            Some((BridgeRouteMode::Disabled, _))
                if (traffic == Traffic::Inbound
                    && route.adapter != BridgeRouteAdapter::Deposit)
                    || traffic == Traffic::Redeem => {}
            Some((mode, reason)) => {
                return Err(refuse(format!(
                    "route {} is {} ({reason}); governance must open it",
                    route.storage_key(),
                    mode.as_str()
                )));
            }
        }
        Ok(route)
    }

    /// Decode a delivery for `route` and apply every envelope rule: it names
    /// this chain, has not expired and expires within
    /// [`MAX_ATTESTATION_VALIDITY_MS`], carries the committee quorum (and the
    /// blessing quorum where the route has one) over [`attestation_digest`],
    /// and carries a light-client proof exactly when the route requires one.
    /// Prove what the route `(adapter, chain)`'s settlement lock recorded: a
    /// plan leg's lock, or the lock's reconciliation checkpoint. On a route
    /// with a light client, `evidence` is the family's proof of the lock's
    /// event and the result is proven; on a route without one it is a
    /// committee-attested delivery whose body is the record's canonical
    /// encoding, its nonce consumed once, and the result is attested.
    /// Returns the record, whether it was proven, and a digest of the
    /// evidence.
    pub fn prove_lock(
        &self,
        state: &mut dyn RouteState,
        adapter: BridgeRouteAdapter,
        chain: &str,
        evidence: &[u8],
    ) -> Result<(receipt_proof::LockRecord, bool, [u8; 32])> {
        use sha2::Digest;
        let digest: [u8; 32] = sha2::Sha256::digest(evidence).into();
        let route = self.live_route(state, adapter, chain, Traffic::Inbound)?;
        let lock = route.settlement_lock.ok_or_else(|| {
            refuse(format!(
                "route {} has no settlement lock",
                route.storage_key()
            ))
        })?;
        if route.light_client.is_some() {
            let (verifier, anchor) = self.light_client(&route)?;
            let record = verifier.proven_lock_record(state, &route, anchor, &lock, evidence)?;
            return Ok((record, true, digest));
        }
        let (_, body) = self.admit_message(state, adapter, chain, evidence)?;
        Ok((receipt_proof::LockRecord::decode(&body)?, false, digest))
    }

    fn verified_delivery(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        delivery: &[u8],
    ) -> Result<Delivery> {
        let d = Delivery::decode(delivery)?;
        if d.dest_chain_id != state.local_chain_id() {
            return Err(refuse(format!(
                "attestation names chain {} but this chain is {}",
                d.dest_chain_id,
                state.local_chain_id()
            )));
        }
        let now = state.now_ms();
        if d.expiry_ms <= now {
            return Err(refuse("attestation has expired"));
        }
        if d.expiry_ms - now > MAX_ATTESTATION_VALIDITY_MS {
            return Err(refuse(format!(
                "attestation expiry is more than {MAX_ATTESTATION_VALIDITY_MS} ms ahead"
            )));
        }

        let digest = attestation_digest(route, &d);
        verify_committee(
            &route.verifiers,
            "verifiers",
            &digest,
            &d.committee,
            &d.committee_pq,
        )?;
        match &route.blessing {
            Some(blessing) => {
                verify_committee(blessing, "blessing", &digest, &d.blessing, &d.blessing_pq)?
            }
            None if !d.blessing.is_empty() || !d.blessing_pq.is_empty() => {
                return Err(refuse(
                    "blessing signatures on a route without a blessing committee",
                ));
            }
            None => {}
        }

        if route.light_client.is_some() {
            let (verifier, anchor) = self.light_client(route)?;
            verifier.verify(
                state,
                route,
                anchor,
                &attestation::body_hash(&d.body),
                &d.proof,
            )?;
        } else if route.family == ChainFamily::Solana {
            solana::check_execution(route, &digest, &d)?;
        } else if !d.proof.is_empty() {
            return Err(refuse("a proof on a route that takes none"));
        }
        Ok(d)
    }

    /// Admit one attested data message on the route `(adapter, chain)` for
    /// the native consumer acting on it: a delivery whose body is not a
    /// transfer but a statement the route's committee attests the external
    /// chain made (an agent account report, a settlement lock). Every
    /// envelope rule applies; the nonce is consumed in its own namespace, so
    /// a message never uses up a transfer's sequence. A delivery
    /// already published by [`Self::publish_message`] is still admitted here,
    /// once, so publishing a copy first takes nothing from its consumer.
    /// Nothing is minted and no supply moves. Returns the route and the body,
    /// which the caller decodes strictly.
    pub fn admit_message(
        &self,
        state: &mut dyn RouteState,
        adapter: BridgeRouteAdapter,
        chain: &str,
        delivery: &[u8],
    ) -> Result<(BridgeRoute, Vec<u8>)> {
        let _guard = self.lock.lock();
        let route = self.live_route(state, adapter, chain, Traffic::Inbound)?;
        let d = self.verified_delivery(state, &route, delivery)?;
        let nonce_key = state::message_nonce_key(&route, d.nonce);
        match state.get(&nonce_key) {
            None => {}
            Some(v) if v == state::published_message(&d.body) => {}
            Some(_) => {
                return Err(BridgeError::ReplayAttack(format!(
                    "message nonce {} on route {} was already used",
                    d.nonce,
                    route.storage_key()
                )));
            }
        }
        state.apply(vec![(nonce_key, state::CONSUMED_MESSAGE.to_vec())])?;
        Ok((route, d.body))
    }

    /// Publish one attested data message on the route `(adapter, chain)`
    /// without acting on it: the envelope rules of [`Self::admit_message`]
    /// apply and the nonce records the body's hash, so each delivery is
    /// published once and a native consumer may still admit it once.
    pub fn publish_message(
        &self,
        state: &mut dyn RouteState,
        adapter: BridgeRouteAdapter,
        chain: &str,
        delivery: &[u8],
    ) -> Result<(BridgeRoute, Vec<u8>)> {
        let _guard = self.lock.lock();
        let route = self.live_route(state, adapter, chain, Traffic::Inbound)?;
        let d = self.verified_delivery(state, &route, delivery)?;
        let nonce_key = state::message_nonce_key(&route, d.nonce);
        if state.get(&nonce_key).is_some() {
            return Err(BridgeError::ReplayAttack(format!(
                "message nonce {} on route {} was already used",
                d.nonce,
                route.storage_key()
            )));
        }
        state.apply(vec![(nonce_key, state::published_message(&d.body))])?;
        Ok((route, d.body))
    }

    /// Apply a relayer's IBC message on the IBC route to `chain`: a classic
    /// handshake step, or the acknowledgement or timeout of a packet Tenzro
    /// sent ([`ibc_core::handle`]). Taken while the route is disabled, so
    /// packets in flight still settle.
    pub fn handle_ibc(
        &self,
        state: &mut dyn RouteState,
        chain: &str,
        msg: &tenzro_types::bridge_transfer::IbcMsg,
    ) -> Result<(BridgeRoute, ibc_core::IbcOutcome)> {
        let _guard = self.lock.lock();
        let route = self.live_route(state, BridgeRouteAdapter::Ibc, chain, Traffic::Inbound)?;
        let outcome = ibc_core::handle(state, &route, msg)?;
        Ok((route, outcome))
    }

    /// Admit one inbound delivery on the route `(adapter, chain)`, or refuse
    /// it. On success the nonce, the epoch usage and the supply record are
    /// written in one [`RouteState::apply`].
    pub fn admit_inbound(
        &self,
        state: &mut dyn RouteState,
        adapter: BridgeRouteAdapter,
        chain: &str,
        delivery: &[u8],
    ) -> Result<AdmittedTransfer> {
        let _guard = self.lock.lock();
        let route = self.live_route(state, adapter, chain, Traffic::Inbound)?;
        let family = self.adapter(&route)?;
        let d = self.verified_delivery(state, &route, delivery)?;

        let mut r = Reader::new(&d.body);
        let message = family.decode_inbound(&route, &mut r)?;
        r.finish()?;

        if message.source_selector != route.source_chain_id
            || message.dest_selector != route.local_selector
        {
            return Err(refuse(format!(
                "message travels {} -> {} but the route is {} -> {}",
                message.source_selector,
                message.dest_selector,
                route.source_chain_id,
                route.local_selector
            )));
        }
        let asset = if message.token_pool == route.peer {
            if message.token != route.local_endpoint {
                return Err(refuse(
                    "message is not addressed to the route's Tenzro endpoint",
                ));
            }
            None
        } else {
            let asset = route
                .asset_by_pool(&message.token_pool)
                .ok_or_else(|| refuse("message was not sent by the route's token pool"))?
                .clone();
            if message.token != asset.representation_id() {
                return Err(refuse(format!(
                    "message is not addressed to the {} representation",
                    asset.symbol
                )));
            }
            if !asset.enabled {
                return Err(refuse(format!(
                    "{} is not enabled on route {}",
                    asset.symbol,
                    route.storage_key()
                )));
            }
            if let Some((mode, reason)) = state.stopped(&route) {
                return Err(refuse(format!(
                    "route {} is {} ({reason}); it credits no new {}",
                    route.storage_key(),
                    mode.as_str(),
                    asset.symbol
                )));
            }
            if let Some(hook) = self.issuer_hook(&asset)? {
                hook.verify_burn(&route, &asset, &message, &d.body)?;
            }
            Some(asset)
        };
        if message.sequence != d.nonce {
            return Err(refuse(format!(
                "attestation nonce {} does not match message sequence {}",
                d.nonce, message.sequence
            )));
        }
        if message.amount == 0 {
            return Err(refuse("a transfer must carry a positive amount"));
        }

        let nonce_key = state::nonce_key(&route, d.nonce);
        if state.get(&nonce_key).is_some() {
            return Err(BridgeError::ReplayAttack(format!(
                "nonce {} on route {} was already used",
                d.nonce,
                route.storage_key()
            )));
        }

        let (usage_key, usage_value, usage, lane, supply_key, supply) = if let Some(asset) = &asset
        {
            // A carried asset's record counts the token held in the route's
            // vault against the representation issued here, so a delivery
            // raises both, up to the vault's cap.
            let (k, v, usage) = state::consume_asset_epoch(state, &route, asset, message.amount)?;
            let lane = lane::consume_asset_lane(
                state,
                &route,
                asset,
                LaneDirection::Inbound,
                message.amount,
            )?;
            let supply = state::read_asset_supply(state, &route, asset)
                .lock_and_mint(message.amount, &route)?;
            if supply.locked > asset.max_outstanding {
                return Err(refuse(format!(
                    "{} would back {} {} on route {}, above its cap of {}",
                    asset.symbol,
                    supply.locked,
                    asset.symbol,
                    route.storage_key(),
                    asset.max_outstanding
                )));
            }
            (
                k,
                v,
                usage,
                lane,
                state::asset_supply_key(&route, asset),
                supply,
            )
        } else {
            let network = state.network_limit(&route).ok_or_else(|| {
                refuse("no network-wide bridge mint limits are set; no route may mint")
            })?;
            let (k, v, usage) = state::consume_epoch(state, &route, network, message.amount)?;
            let lane = lane::consume_lane(state, &route, LaneDirection::Inbound, message.amount)?;
            // A deposit route's record counts the asset held under the
            // deposit script on the external chain against the representation
            // credited here, so a deposit raises both; every other route
            // releases TNZO locked when it went out.
            let record = state::read_supply(state, &route);
            let supply = if route.adapter == BridgeRouteAdapter::Deposit {
                record.lock_and_mint(message.amount, &route)?
            } else {
                record.release(message.amount, &route)?
            };
            (k, v, usage, lane, state::supply_key(&route), supply)
        };

        let mut writes = vec![
            (nonce_key, vec![1]),
            (usage_key, usage_value),
            (supply_key, supply.encode()),
        ];
        writes.extend(lane);
        if route.adapter == BridgeRouteAdapter::Ibc {
            ibc_core::check_open(state, &route)?;
            writes.extend(ibc_core::received_writes(&route, message.sequence)?);
        }
        if let (BridgeRouteAdapter::Deposit, Some(anchor)) = (route.adapter, &route.light_client) {
            let mut utxos = bitcoin::read_utxos(state, &route)?;
            utxos.push(bitcoin::deposit_utxo(&route, &d.body)?);
            writes.push((
                bitcoin::utxo_set_key(&route, anchor),
                bitcoin_spend::encode_utxos(&utxos),
            ));
        }
        state.apply(writes)?;
        Ok(AdmittedTransfer {
            route,
            message,
            usage,
            supply,
            asset,
        })
    }

    /// The one route serving `chain`. An outbound transfer names only the
    /// destination chain, so a chain served by more than one route is
    /// refused rather than guessed.
    pub fn route_for_chain(&self, state: &dyn RouteState, chain: &str) -> Result<BridgeRoute> {
        let mut found = BridgeRouteAdapter::ALL
            .into_iter()
            .filter(|a| state.route(*a, &chain.to_ascii_lowercase()).is_some());
        match (found.next(), found.next()) {
            (Some(adapter), None) => self.live_route(state, adapter, chain, Traffic::Outbound),
            (None, _) => Err(refuse(format!("no governed route serves '{chain}'"))),
            (Some(_), Some(_)) => Err(refuse(format!(
                "more than one route serves '{chain}'; governance must keep one"
            ))),
        }
    }

    /// Check that `amount` may leave towards `chain` without writing anything:
    /// the route exists, is live, the amount is within its per-mint cap and
    /// the lane's outbound bucket holds it.
    pub fn check_outbound(&self, state: &dyn RouteState, chain: &str, amount: u128) -> Result<()> {
        let route = self.route_for_chain(state, chain)?;
        let network = state.network_limit(&route).ok_or_else(|| {
            refuse("no network-wide bridge mint limits are set; no route may mint")
        })?;
        let cap = route.mint_limit.tightest(network).per_mint;
        if amount == 0 || amount > cap {
            return Err(refuse(format!(
                "amount {amount} is outside the {} route's per-mint cap of {cap}",
                route.storage_key()
            )));
        }
        lane::consume_lane(state, &route, LaneDirection::Outbound, amount)?;
        state::consume_outflow(state, &exit_unit(&route, None)?, amount)?;
        Ok(())
    }

    /// Lock `transfer.amount` for the route serving `chain` and build the
    /// message that authorises the same amount on the external chain. The
    /// caller has already taken the TNZO out of the sender's balance.
    pub fn send_outbound(
        &self,
        state: &mut dyn RouteState,
        chain: &str,
        transfer: &OutboundTransfer,
    ) -> Result<OutboundMessage> {
        let _guard = self.lock.lock();
        if let Some(symbol) = &transfer.asset {
            return self.redeem(state, chain, symbol, transfer);
        }
        self.check_outbound(state, chain, transfer.amount)?;
        let route = self.route_for_chain(state, chain)?;
        let family = self.adapter(&route)?;
        let mut limits: Vec<(String, Vec<u8>)> =
            lane::consume_lane(state, &route, LaneDirection::Outbound, transfer.amount)?
                .into_iter()
                .collect();
        limits.push(state::consume_outflow(
            state,
            &exit_unit(&route, None)?,
            transfer.amount,
        )?);

        let seq_key = state::sequence_key(&route);
        let sequence = state::read_u64(state, &seq_key)
            .checked_add(1)
            .ok_or_else(|| refuse("outbound sequence exhausted"))?;
        if route.adapter == BridgeRouteAdapter::Deposit {
            return Self::withdraw(state, route, sequence, transfer, limits);
        }
        let mut writes = Vec::new();
        let (message, bytes) = if route.adapter == BridgeRouteAdapter::Ibc {
            let (message, bytes, commit) =
                ibc_core::send_packet(state, &route, sequence, transfer)?;
            writes.push(commit);
            (message, bytes)
        } else {
            let mut message = RouteMessage {
                message_id: [0u8; 32],
                source_selector: route.local_selector,
                dest_selector: route.source_chain_id,
                sequence,
                sender: transfer.sender.clone(),
                receiver: transfer.recipient.clone(),
                token_pool: route.local_endpoint,
                token: route.remote_token,
                amount: transfer.amount,
            };
            message.message_id = family.outbound_message_id(&route, &message)?;
            let bytes = family.encode_outbound(&route, &message)?;
            let mut r = Reader::new(&bytes);
            let back = family.decode_outbound(&route, &mut r)?;
            r.finish()?;
            if back != message {
                return Err(refuse("outbound message does not read back as built"));
            }
            (message, bytes)
        };

        let supply = state::read_supply(state, &route).lock_and_mint(transfer.amount, &route)?;
        writes.extend([
            (seq_key, sequence.to_be_bytes().to_vec()),
            (state::supply_key(&route), supply.encode()),
            (state::outbound_key(&route, sequence), bytes.clone()),
        ]);
        writes.extend(limits);
        state.apply(writes)?;
        Ok(OutboundMessage {
            route,
            message,
            bytes,
            supply,
            asset: None,
        })
    }

    /// The one route serving `chain` that carries `symbol`.
    pub fn route_for_asset(
        &self,
        state: &dyn RouteState,
        chain: &str,
        symbol: &str,
    ) -> Result<(BridgeRoute, CarriedAsset)> {
        let mut found = BridgeRouteAdapter::ALL.into_iter().filter(|a| {
            state
                .route(*a, &chain.to_ascii_lowercase())
                .is_some_and(|r| r.asset(symbol).is_some())
        });
        let adapter = match (found.next(), found.next()) {
            (Some(adapter), None) => adapter,
            (None, _) => {
                return Err(refuse(format!(
                    "no governed route carries {symbol} to '{chain}'"
                )));
            }
            (Some(_), Some(_)) => {
                return Err(refuse(format!(
                    "more than one route carries {symbol} to '{chain}'; governance must keep one"
                )));
            }
        };
        let route = self.live_route(state, adapter, chain, Traffic::Redeem)?;
        let asset = route
            .asset(symbol)
            .cloned()
            .ok_or_else(|| refuse(format!("no governed route carries {symbol} to '{chain}'")))?;
        if !asset.enabled {
            return Err(refuse(format!(
                "{symbol} is not enabled on route {}",
                route.storage_key()
            )));
        }
        Ok((route, asset))
    }

    /// Check that `amount` of the carried asset `symbol` may go back to its
    /// vault on `chain`, without writing anything.
    pub fn check_redeem(
        &self,
        state: &dyn RouteState,
        chain: &str,
        symbol: &str,
        amount: u128,
    ) -> Result<()> {
        let (route, asset) = self.route_for_asset(state, chain, symbol)?;
        if amount == 0 || amount > asset.mint_limit.per_mint {
            return Err(refuse(format!(
                "amount {amount} is outside the {} {symbol} per-transfer cap of {}",
                route.storage_key(),
                asset.mint_limit.per_mint
            )));
        }
        state::read_asset_supply(state, &route, &asset).release(amount, &route)?;
        lane::consume_asset_lane(state, &route, &asset, LaneDirection::Outbound, amount)?;
        state::consume_outflow(state, &exit_unit(&route, Some(&asset))?, amount)?;
        Ok(())
    }

    /// Send a carried asset's representation back: the caller has already
    /// burned it; the vault on the external chain releases the same amount
    /// to the recipient (or, for burn-and-mint, the issuer mints it there).
    /// Refused beyond what the route's vault backs.
    fn redeem(
        &self,
        state: &mut dyn RouteState,
        chain: &str,
        symbol: &str,
        transfer: &OutboundTransfer,
    ) -> Result<OutboundMessage> {
        self.check_redeem(state, chain, symbol, transfer.amount)?;
        let (route, asset) = self.route_for_asset(state, chain, symbol)?;
        let family = self.adapter(&route)?;
        let seq_key = state::sequence_key(&route);
        let sequence = state::read_u64(state, &seq_key)
            .checked_add(1)
            .ok_or_else(|| refuse("outbound sequence exhausted"))?;
        let mut message = RouteMessage {
            message_id: [0u8; 32],
            source_selector: route.local_selector,
            dest_selector: route.source_chain_id,
            sequence,
            sender: transfer.sender.clone(),
            receiver: transfer.recipient.clone(),
            token_pool: asset.representation_id(),
            token: asset.remote_token,
            amount: transfer.amount,
        };
        message.message_id = family.outbound_message_id(&route, &message)?;
        let bytes = match self.issuer_hook(&asset)? {
            Some(hook) => hook.mint_instruction(&route, &asset, &message)?,
            None => {
                let bytes = family.encode_outbound(&route, &message)?;
                let mut r = Reader::new(&bytes);
                let back = family.decode_outbound(&route, &mut r)?;
                r.finish()?;
                if back != message {
                    return Err(refuse("outbound message does not read back as built"));
                }
                bytes
            }
        };
        let supply =
            state::read_asset_supply(state, &route, &asset).release(transfer.amount, &route)?;
        let lane = lane::consume_asset_lane(
            state,
            &route,
            &asset,
            LaneDirection::Outbound,
            transfer.amount,
        )?;
        let outflow =
            state::consume_outflow(state, &exit_unit(&route, Some(&asset))?, transfer.amount)?;
        let mut writes = vec![
            (seq_key, sequence.to_be_bytes().to_vec()),
            (state::asset_supply_key(&route, &asset), supply.encode()),
            (state::outbound_key(&route, sequence), bytes.clone()),
            outflow,
        ];
        writes.extend(lane);
        state.apply(writes)?;
        Ok(OutboundMessage {
            route,
            message,
            bytes,
            supply,
            asset: Some(asset),
        })
    }

    /// Withdraw from a deposit route: plan the transaction that spends the
    /// amount from the descriptor's oldest outputs, burn the representation
    /// against it, and store the withdrawal for its signers. The outputs it
    /// spends leave the tracked set and its change joins it at once, since
    /// the transaction id is fixed before anyone signs.
    fn withdraw(
        state: &mut dyn RouteState,
        route: BridgeRoute,
        sequence: u64,
        transfer: &OutboundTransfer,
        limits: Vec<(String, Vec<u8>)>,
    ) -> Result<OutboundMessage> {
        let (desc, fee_rate) = bitcoin::route_descriptor(&route)?;
        let anchor = route
            .light_client
            .clone()
            .ok_or_else(|| refuse("a deposit route needs its anchor"))?;
        let amount = u64::try_from(transfer.amount)
            .map_err(|_| refuse("a withdrawal amount fits 64 bits"))?;
        let utxos = bitcoin::read_utxos(state, &route)?;
        let (withdrawal, remaining) =
            bitcoin_spend::plan_withdrawal(&desc, &utxos, &transfer.recipient, amount, fee_rate)?;
        let supply = state::read_supply(state, &route).release(transfer.amount, &route)?;
        let bytes = withdrawal.encode();
        let message = RouteMessage {
            message_id: withdrawal.txid(),
            source_selector: route.local_selector,
            dest_selector: route.source_chain_id,
            sequence,
            sender: transfer.sender.clone(),
            receiver: transfer.recipient.clone(),
            token_pool: route.local_endpoint,
            token: route.remote_token,
            amount: transfer.amount,
        };
        let mut writes = vec![
            (state::sequence_key(&route), sequence.to_be_bytes().to_vec()),
            (state::supply_key(&route), supply.encode()),
            (state::outbound_key(&route, sequence), bytes.clone()),
            (
                bitcoin::utxo_set_key(&route, &anchor),
                bitcoin_spend::encode_utxos(&remaining),
            ),
        ];
        writes.extend(limits);
        state.apply(writes)?;
        Ok(OutboundMessage {
            route,
            message,
            bytes,
            supply,
            asset: None,
        })
    }

    /// Queue `body` for the external chain on the route serving `chain`.
    /// The route must be live; the message takes the next sequence in the
    /// route's data-message space and is stored for relayers.
    pub fn send_message(
        &self,
        state: &mut dyn RouteState,
        chain: &str,
        body: &[u8],
    ) -> Result<OutboundData> {
        let _guard = self.lock.lock();
        let route = self.route_for_chain(state, chain)?;
        if body.is_empty() || body.len() > attestation::MAX_BODY_LEN {
            return Err(refuse(format!(
                "a message body must be 1 to {} bytes",
                attestation::MAX_BODY_LEN
            )));
        }
        let seq_key = state::message_sequence_key(&route);
        let sequence = state::read_u64(state, &seq_key)
            .checked_add(1)
            .ok_or_else(|| refuse("message sequence exhausted"))?;
        let mut w = canonical::Writer::new();
        w.raw(ROUTE_MESSAGE_DOMAIN)
            .u64_be(route.local_selector)
            .u64_be(route.source_chain_id)
            .u64_be(sequence)
            .be_bytes(body);
        let bytes = w.into_bytes();
        let message_id = attestation::body_hash(&bytes);
        state.apply(vec![
            (seq_key, sequence.to_be_bytes().to_vec()),
            (state::outbound_message_key(&route, sequence), bytes.clone()),
        ])?;
        Ok(OutboundData {
            route,
            sequence,
            message_id,
            bytes,
        })
    }
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod family_tests;
#[cfg(test)]
mod ibc_tests;

#[cfg(test)]
mod ccip_contracts;
