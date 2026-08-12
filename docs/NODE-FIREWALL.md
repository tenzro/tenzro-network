# Node firewall (defense-in-depth) — Part D of the access-hardening plan

Goal: at the network layer, allow inbound only the two intended surfaces —
libp2p p2p (`9000/tcp`+`9000/udp`) and the iroh overlay (`9001/udp`) — plus
management (SSH / tailscale). Everything else (the HTTP RPC `8545`, Web `8080`,
MCP sidecars `3001-3008`, and any future stray bind) is refused off-box. This
is the backstop behind the fail-closed binds (Part A moves those to loopback);
the firewall guarantees it even if a future code path forgets.

Run on EACH node (spark/admin1/server1/server2) with sudo. **Apply with console
access available** — a firewall mistake can lock out SSH.

## ufw (simplest)
```bash
# 1. Preserve management BEFORE enabling (do not lock yourself out):
sudo ufw allow in on tailscale0            # tailnet management (SSH over tailscale, admin)
sudo ufw allow 22/tcp                       # plain SSH, if used

# 2. The two intended network surfaces (all interfaces):
sudo ufw allow 9000/tcp                      # libp2p p2p
sudo ufw allow 9000/udp                      # libp2p quic
sudo ufw allow 9001/udp                      # iroh overlay (tenzro/*)

# 3. Default deny inbound, allow outbound (node must dial peers/relays):
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 4. Enable:
sudo ufw --force enable
sudo ufw status verbose
```
After this: `8545`, `8080`, `3001-3008` are unreachable off-box (they are
loopback-bound after Part A anyway; this is the belt-and-suspenders). p2p + iroh
stay open; tailnet management stays open; loopback services are only reachable
on-box.

## Why tailscale0 is allowed
Management (this session's SSH, operator admin) rides the tailnet. Allowing
`tailscale0` keeps management working. It does NOT re-expose the sidecars: after
Part A they bind `127.0.0.1`, which is not reachable via `tailscale0` (that
interface carries the `100.x` address, not loopback). So tailnet peers see only
`9000`/`9001` and SSH — nothing else.

## Retire the tsbridge
Once Part A binds RPC to loopback and tenzro-code uses the overlay, the
tailnet RPC bridge is obsolete and is an exposure. Stop and disable it:
```bash
pkill -f tsbridge.py            # or: systemctl --user stop tsbridge (if unit)
# remove any autostart entry for ~/alva/tsbridge.py
```
Confirm nothing off-box still needs raw HTTP RPC before removing.

## Verify
From another machine (off-box):
```bash
nc -z -w3 <node-tailscale-ip> 9000 && echo "9000 open (expected)"
nc -z -w3 <node-tailscale-ip> 8545 && echo "8545 OPEN (BAD)" || echo "8545 closed (good)"
nc -z -w3 <node-tailscale-ip> 3005 && echo "3005 OPEN (BAD)" || echo "3005 closed (good)"
```

## Note — Minima
`spark` also runs a separate Minima node (`minima.jar`, `9001/tcp`, RPC enabled
with a password). It is NOT Tenzro. The rules above do not open `9001/tcp`
(only `9001/udp` for iroh), so Minima's RPC becomes loopback-only off-box unless
you explicitly allow it. Decide whether Minima should be reachable and add a
rule if so.
