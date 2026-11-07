# Node networking: ports, firewalls, NAT and relays

This guide is for anyone running a Tenzro node at home, in an office, on a
laptop or on a server. It says which ports the node uses, what to do about
the firewall on Windows, macOS and Linux, how the node gets through NAT, what
relays are, and how to read `tenzro-node doctor`.

The short version: **a node needs no inbound port, no firewall rule and no
administrator rights.** It works from any network that allows outbound
HTTPS. It keeps outbound connections to relays (HTTPS on TCP 443) and to its
peers; direct paths open by hole punching, which host and router firewalls
let through because each side sends first. Inbound reachability (a port the
router maps, or a firewall rule) is an optional improvement: it lets peers
open a direct path first. Validators should have it; other nodes benefit.

## Ports

| Port | Protocol | Direction | What for | Needed? |
|---|---|---|---|---|
| `9001` | UDP | outbound; inbound optional | The node's QUIC endpoint: consensus, blocks, blobs, discovery | Outbound: yes. Inbound: no (optional, for direct paths peers open first) |
| `443` | TCP | outbound | Relays (HTTPS) | Yes, unless every peer is reachable directly |
| `8545` | TCP | loopback only | JSON-RPC and the admin page | Never open it to the network |

Firewall rules per role and the settings for a public RPC are in
[operations/HARDENED-PROFILE.md](operations/HARDENED-PROFILE.md).

Change the UDP port with `[iroh] bind_addr` in the node config. The node
binds it on IPv4 (`0.0.0.0`) and IPv6 (`[::]`) at once.

## Firewalls

No rule is needed on any system. A host firewall that refuses unsolicited
inbound traffic (Windows Defender Firewall and the macOS application
firewall by default) still lets in the replies to traffic the node sent,
which is all hole punching needs. Do not answer the Windows "allow access"
prompt for the node with Allow unless you want inbound reachability; the
node works either way.

To let peers open direct paths to the node first, opt in once:

### Windows

Open PowerShell with **Run as administrator** and run:

```powershell
tenzro-node doctor --allow-inbound
```

It adds one inbound rule, `TenzroNode-UDP`, for the `tenzro-node.exe` you ran
and its UDP port only, on the Private and Public profiles, and removes any
block rules a dismissed prompt left for that same binary (block rules win
over allow rules). A domain-joined machine's rules belong to its
administrator, so the Domain profile is left alone. Without administrator
rights it changes nothing and says so.

To check or remove it by hand:

```powershell
Get-NetFirewallRule -Name TenzroNode-UDP | Get-NetFirewallPortFilter
Remove-NetFirewallRule -Name TenzroNode-UDP
```

The rule names the binary's full path: after moving the binary, run it again.

### macOS

```bash
sudo tenzro-node doctor --allow-inbound
```

It adds the binary to the application firewall and allows it
(`socketfilterfw --add` and `--unblockapp`). With **Block all incoming
connections** turned on in System Settings > Network > Firewall > Options,
only paths the node opened work, which is enough.

### Linux

The node does not change Linux firewalls. To allow inbound, open the node's
UDP port:

```bash
sudo ufw allow 9001/udp
# or
sudo firewall-cmd --permanent --add-port=9001/udp && sudo firewall-cmd --reload
```

### Corporate networks and proxies

Where outbound web traffic must go through an HTTP proxy, set it in the node
config (`[iroh] proxy = "http://proxy.corp:3128"`) or in the `HTTPS_PROXY`
environment variable: the node reaches its relays through it with HTTP
CONNECT on TCP 443. Where UDP is blocked, everything goes through relays.

The node checks relays' HTTPS certificates against the certificate store of
the operating system (the system keychain on macOS, the Windows certificate
store, the system CA bundle on Linux, which `SSL_CERT_FILE` overrides). A
network whose proxy inspects TLS by re-signing it with its own CA therefore
works on a machine that trusts that CA, as managed machines on such networks
do.

Where a network passes only web traffic, UDP to port 443 included, the node
still reaches edge relays directly: they serve their peer relay on UDP 443
(see Relays).

## NAT

Most home, mobile and office networks put the node behind NAT: the router
shares one public address among many machines. The node gets through it
five ways, tried together:

1. **Port mapping (optional).** The node asks the router to forward its UDP
   port, using whichever of UPnP IGD, PCP (RFC 6887) or NAT-PMP (RFC 6886)
   the router answers. Many home routers do; most carrier and office
   networks do not. Turn it off with `[iroh] port_mapping = false`.
2. **Hole punching.** Peers that reach the node over a direct path tell it
   the address they see it at. When two different machines report the same
   address, the node offers it to other peers, and both sides send packets
   to each other at the same time so each NAT lets the other in. This works
   when the NAT keeps the same public port for every peer
   (endpoint-independent mapping, RFC 4787), which is what most home routers
   do.
3. **Birthday punching.** Behind a symmetric NAT (a different public port
   for every peer), the node punches a direct path to a peer behind an
   endpoint-independent NAT by the birthday method: it opens 256 sockets
   towards the peer, so its NAT opens 256 mappings, and the peer sends 1,024
   probes to random ports at the node's public IP; one lands on a mapping
   with probability about 98%, and that pair of sockets becomes the path.
   Each attempt is asked for over an ordinary connection first, runs at
   most five seconds, and is not repeated for the same peer within ten
   minutes. Two symmetric NATs facing each other cannot be crossed this
   way.
4. **Peer relays.** When the NATs on both sides cannot be punched through
   (two symmetric NATs, or a failed attempt), both nodes go through a
   peer relay: a staked edge operator's node that both reach directly over
   UDP. Each keeps an ordinary connection to it, opened outbound, and it
   passes their packets along as QUIC datagrams, still end-to-end encrypted.
   A node keeps connections to the two peer relays with the lowest
   round-trip time among the relays it admitted, counting only those it
   reaches directly, and names them in its signed endpoint record. A peer
   relay forwards at most 4 MiB/s from any one node and holds at most 4,096
   nodes.
5. **Relays.** When nothing else works, traffic goes through a relay over
   HTTPS, end-to-end encrypted. The relay sees only ciphertext.

What to expect on common networks:

| Network | What happens |
|---|---|
| Home router | Port mapping or hole punching: direct paths to most peers |
| Carrier-grade NAT (many mobile and fibre providers) | Hole punching when the carrier NAT is endpoint-independent, else relays |
| Symmetric NAT (each peer sees a different port) | Direct paths to peers with a public or mapped address, birthday-punched paths to peers behind endpoint-independent NATs, peer relays over UDP between two symmetric NATs |
| IPv6 | Direct paths to IPv6 peers; usually no NAT at all |
| IPv6 only | Direct to IPv6 peers; IPv4-only peers through relays that answer on IPv6 |
| Mobile hotspot | Usually carrier-grade NAT: as above |
| Office network that blocks UDP | Everything through relays over HTTPS on TCP 443 |
| Captive portal (hotel, airport) | Relays fail until you sign in to the portal; the node detects it and keeps trying |

To get direct paths behind a symmetric NAT, turn on UPnP, NAT-PMP or PCP on
the router, or forward UDP `9001` to the node's machine.

### How the peer relay path is built

The peer relay path is iroh's custom transport, implemented in one module of
the node (`crates/tenzro-iroh/src/paths.rs`). iroh 1.3 opens paths only to
the addresses hole punching finds and to the relay, so the node carries a
vendored copy of iroh 1.3.0 that also opens a custom-transport path on every
connection to a peer as soon as the path is named (`vendor/iroh`, one change
in `socket/remote_map/remote_state.rs`). When iroh opens such paths itself,
or ships its own peer relay or MASQUE transport, the vendored copy is dropped
and that one module is replaced by iroh's, with nothing else changing.

## Relays

A relay forwards encrypted QUIC between two nodes that cannot reach each
other directly. Any operator can run one. The relay is part of the **edge**
role:

1. Start the node with `--relay-listen 127.0.0.1:3340 --relay-url https://relay.example.org/`.
   The relay listener binds loopback only. A node serving the relay role
   binds its UDP endpoint on port 443 instead of 9001, so nodes on networks
   that pass only web traffic reach its peer relay. Binding a port below
   1024 needs the right to: on Linux the capability `CAP_NET_BIND_SERVICE`
   (`AmbientCapabilities=CAP_NET_BIND_SERVICE` in the systemd unit) or
   `sysctl net.ipv4.ip_unprivileged_port_start=443`. Open UDP 443 inbound
   on the host and any firewall in front of it; a port forward from 443 to
   another port does not work, because peers learn the port the node bound.
   A host that runs several relays, such as a test cluster, gives each its
   own port with `--relay-udp-port`.
2. Put your own TLS proxy (on TCP 443) in front of it, forwarding the
   paths `/relay` (with WebSocket upgrade), `/identity`, `/ping` and
   `/generate_204` to `127.0.0.1:3340`.
3. Bond the edge role (governed `stake.edge_tnzo`, 10,000 TNZO at genesis) and publish the same URL on
   chain: `tenzro stake bond --role edge --amount 10000`, then
   `tenzro stake endpoint --role edge --url https://relay.example.org/`.

An edge operator's node is also a peer relay (see NAT above) on its UDP
port. Validators probe each staked relay on the same SLA schedule every
bonded role is held to: the relay must serve its operator's current signed
record at `<url>/identity`, announcing exactly that URL, and the operator's
node must forward a peer relay datagram. An epoch that two thirds
of the bonded stake attests unavailable costs the edge bond the governed SLA
penalty (`sla.unavailable.penalty_gwei`), paid into the insurance pool, the
same as any other role. A stake with no published URL answers no probe.

Every node also checks each staked relay every five minutes the same way,
and times it, to choose among them. `tenzro stake relays`
(`tenzro_listRelays`) shows the staked relays with the last frozen SLA
verdict and the answering node's latest check.

Nodes find relays three ways, none of them run by a single party:

- the boot list (`--boot-nodes did:tenzro:machine:<id>@https://<relay>/`) and
  the genesis validators' relays;
- staked edge operators: at start, a node reads `tenzro_listRoleEndpoints`
  `{ "role": "edge" }` from its own chain state and admits each URL (up to 8,
  most bonded first) whose operator's signed record, served at
  `<url>/identity`, announces exactly that URL;
- relays it met on the network before, remembered in
  `{data_dir}/iroh/known-relays.json`.

A relay is never trusted for content: it is admitted only by its operator's
signature, and it carries only end-to-end encrypted packets.

Relays speak HTTPS on TCP 443, so a node on a network that blocks UDP still
reaches the whole network through them.

## Connection limits

The endpoint bounds how many connections it holds and what each may carry.
Every value is in the `[iroh.connection]` table and the defaults apply to
any value the table omits:

```toml
[iroh.connection]
max_connections = 1024                    # all protocols except consensus
max_connections_per_peer = 8              # one endpoint id, same protocols
max_consensus_connections = 512           # the consensus protocol, own pool
max_consensus_connections_per_peer = 4
idle_timeout_secs = 30                    # no traffic: connection closed
max_concurrent_bidi_streams = 100         # per connection
max_concurrent_uni_streams = 100          # per connection
receive_window_bytes = 33554432           # per connection, all streams
```

- **Two pools.** Connections on `tenzro/consensus` count in their own pool, so
  a flood of connections on any other protocol cannot take the places of
  established consensus links, and the reverse. A connection is counted from
  the moment its protocol accepts it until it closes; an excess one is closed
  with application error code 4. A connection already established is never
  closed to make room for a new one.
- **Before the handshake.** Once both pools together are full, a new attempt
  is refused before its handshake, so a flood past the bound costs no TLS
  work. The per-peer bound keys on the peer's endpoint id, which a flooder can
  mint freely; the overall bounds are what hold against many ids.
- **Idle and streams.** Each connection sends a keep-alive well inside the
  idle timeout. A peer cannot open more streams than the two stream bounds,
  and cannot have more than `receive_window_bytes` in flight to the node on
  one connection. The stream and idle values equal the QUIC defaults the node
  ran under before they were made explicit; the receive window was unbounded.
- **Streams per surface** are bounded separately, by the `[iroh.admission]`
  table: streams served at once overall and per peer, and the read and write
  timeouts.
- **What stays at the library default.** The number of handshakes in flight
  (65,536) and the bytes buffered for them are set by the QUIC library when
  the router installs the endpoint's server configuration and are not
  configurable from the node.

## Validators

Validators exchange consensus messages with every other validator, so give
each one a direct address: a host with a public IP, a port forward of UDP
`9001`, or a router with UPnP, NAT-PMP or PCP turned on. A validator behind a
NAT that hole punching cannot get through still works, through relays, with
higher latency. `tenzro-node doctor` says so when it sees it.

## No overlay network in the trust path

Nodes reach each other only over Tenzro's own transport: QUIC with TLS 1.3
and the X25519MLKEM768 post-quantum hybrid key exchange, authenticated by
each node's own key, directly or through relays. Nothing a node, the
installer or the operations scripts in this repository do depends on a VPN
or private overlay network, or on SSH carried over one.

Between Tenzro endpoints the key exchange is the hybrid only: a peer offering a classical share alone, on a fresh or a resumed session, is refused. Relay HTTPS, relay records and address lookup keep X25519 as a fallback for TLS terminators without the hybrid. Beside iroh's Ed25519 endpoint key, each node makes an ML-DSA-65 endpoint key every boot, bound to its endpoint record by the machine's hardware ML-DSA key; on every connection each side signs the TLS exporter with it, and nodes keep pins of each identity's hardware ML-DSA key across restarts, refusing a later record without the binding or bound by another key.

An operator may still run such a network for their own administrative
access, or forward a port over it for convenience. That stays outside the
deploy path and outside the trust path: the node neither knows nor relies on
it, and a peer reached over it is checked exactly like any other peer. The
scheduled security checks fail if a deploy, installer or operations script
in this repository starts to depend on one.

## `tenzro-node doctor`

Run it on the node's machine, while the node runs:

```text
$ tenzro-node doctor
  IPv4             yes (192.168.1.20)
  IPv6             yes (2001:db8:1::20)
  port mapping     the router offers UPnP, NAT-PMP
  firewall         Windows Defender Firewall: an allow rule lets peers reach the node (UDP 9001)
  reachable        directly, through a port the router mapped
  NAT              endpoint-independent: every peer sees the same address and port
  peers see        198.51.100.7:9001 (by 3fa1c2d4e5b6), 198.51.100.7:9001 (by 9c0d1e2f3a4b)
  mapped port      198.51.100.7:9001
  relay            https://relay.example.org/ (connected)
  UDP port         9001 on 0.0.0.0:9001, [::]:9001

Nothing to fix.
```

| Line | Meaning |
|---|---|
| IPv4 / IPv6 | Whether this machine has a route to the internet on each. |
| port mapping | Which port mapping protocols the router answers. "none" is normal on carrier and office networks. |
| firewall | What the host firewall does with the node's port. |
| reachable | How peers reach the node: at a public address, through a mapped port, after hole punching, or through relays. |
| NAT | The NAT in front of the machine, from what peers report. "not known yet" until two peers reached the node over UDP. |
| peers see | The addresses peers saw the node at. |
| relay | The relays the node is connected to. |

When something is wrong, the report ends with **To fix:** and the steps, for
example:

- *Optional: the host firewall lets peers in only on paths this node
  opened.* Run the `tenzro-node doctor --allow-inbound` command it names if
  you want peers to open paths first.
- *No relay is connected.* Outbound HTTPS (TCP 443) is blocked, or no relay
  is known: name one with `--boot-nodes`.
- *The NAT gives each peer a different port.* Turn on UPnP, NAT-PMP or PCP on
  the router, or forward UDP 9001.
- *No peer has reached this node over UDP yet.* The network may block UDP;
  the node keeps working through relays.

`tenzro-node doctor --json` prints the same report as JSON. From anywhere,
`tenzro iroh connectivity --rpc <url>` (`tenzro_getConnectivity`) shows how a
node is reached without its addresses. The node's part
comes from its loopback admin page (`GET /access/connectivity`), which
answers only on the node's own machine, to a caller holding the admin page
ticket in the node's data directory: the report names the node's network
addresses, which the network itself never publishes.
