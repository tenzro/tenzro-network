//! Performance measurements, run on demand:
//!
//! ```text
//! cargo test --release -p tenzro-iroh --lib measure:: -- --ignored --nocapture --test-threads 1
//! ```
//!
//! Each prints `MEASURE` lines with its numbers. They assert only that the
//! work completed, never a speed: a number is recorded before anything is
//! tuned against it.

#![expect(
    clippy::disallowed_methods,
    reason = "the measurements are tests that bound every wait themselves"
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use iroh::address_lookup::memory::MemoryLookup;
use tenzro_types::tenzro_uri::TenzroUri;

use crate::discovery::DiscoveryStore;
use crate::resolver::{IrohBackedResolver, IrohResolver};

const MIB: usize = 1024 * 1024;

async fn node(lookup: &MemoryLookup) -> Arc<IrohBackedResolver> {
    IrohBackedResolver::bind_for_test(lookup, Arc::new(DiscoveryStore::new()))
        .await
        .unwrap()
}

/// Seconds of CPU this process has used, user and system, where the OS
/// reports it (Linux, from `/proc/self/stat` in clock ticks of 1/100 s).
fn cpu_seconds() -> Option<f64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // Fields after the command name, which is in parentheses.
    let rest = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let utime: f64 = fields.get(11)?.parse().ok()?;
    let stime: f64 = fields.get(12)?.parse().ok()?;
    Some((utime + stime) / 100.0)
}

/// Whether UDP segmentation offload (GSO) and receive offload (GRO) are
/// active for the sockets QUIC opens here: the segments per call the socket
/// layer reports, 1 meaning off.
#[test]
#[ignore = "measurement: scripts/netlab/measure.sh runs it with --ignored"]
fn udp_offload() {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let state = noq_udp::UdpSocketState::new((&sock).into()).unwrap();
    println!(
        "MEASURE udp_offload os={} gso_segments={} gro_segments={}",
        std::env::consts::OS,
        state.max_gso_segments(),
        state.gro_segments()
    );
}

/// Rate of one blob fetched from one provider over loopback, with the CPU
/// both ends spent on it (one process holds both).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement: scripts/netlab/measure.sh runs it with --ignored"]
async fn blob_transfer_rate() {
    let lookup = MemoryLookup::new();
    let provider = node(&lookup).await;
    let fetcher = node(&lookup).await;
    for size_mib in [16usize, 128] {
        let blob = Bytes::from(
            (0..size_mib * MIB)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<u8>>(),
        );
        let hash = match provider.publish_bytes(blob.clone()).await.unwrap() {
            TenzroUri::Blob { hash, .. } => hash,
            other => panic!("{other}"),
        };
        let uri = TenzroUri::Blob {
            hash,
            provider_hint: Some(provider.endpoint().id().to_string()),
        };
        let cpu = cpu_seconds();
        let started = Instant::now();
        let got = fetcher.fetch_bytes(&uri).await.unwrap();
        let took = started.elapsed();
        let cpu = cpu.zip(cpu_seconds()).map(|(a, b)| b - a);
        assert_eq!(got.len(), blob.len());
        println!(
            "MEASURE blob_transfer size_mib={size_mib} secs={:.3} mib_per_s={:.1} cpu_secs={}",
            took.as_secs_f64(),
            size_mib as f64 / took.as_secs_f64(),
            cpu.map_or("n/a".into(), |c| format!("{c:.2}"))
        );
    }
}

/// One blob fetched while 1, 2 or 4 nodes hold it, one provider at a time
/// (`SplitStrategy::None`, what the node's fetch uses) and split across them
/// (`SplitStrategy::Split`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement: scripts/netlab/measure.sh runs it with --ignored"]
async fn multi_provider_download() {
    use iroh_blobs::api::downloader::{DownloadOptions, Downloader, SplitStrategy};

    let lookup = MemoryLookup::new();
    let size_mib = 64usize;
    let blob = Bytes::from(
        (0..size_mib * MIB)
            .map(|i| (i % 241) as u8)
            .collect::<Vec<u8>>(),
    );
    let hash = iroh_blobs::Hash::new(&blob);
    let mut holders = Vec::new();
    for _ in 0..4 {
        let p = node(&lookup).await;
        p.publish_bytes(blob.clone()).await.unwrap();
        holders.push(p);
    }
    let providers: Vec<_> = holders.iter().map(|p| p.endpoint().id()).collect();
    for name in ["one_at_a_time", "split"] {
        for count in [1usize, 2, 4] {
            let strategy = if name == "split" {
                SplitStrategy::Split
            } else {
                SplitStrategy::None
            };
            let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .bind()
                .await
                .unwrap();
            endpoint.address_lookup().unwrap().add(lookup.clone());
            let store = iroh_blobs::store::mem::MemStore::new();
            let downloader = Downloader::new(&store, &endpoint);
            let started = Instant::now();
            tokio::time::timeout(
                Duration::from_secs(300),
                downloader.download_with_opts(DownloadOptions::new(
                    hash,
                    providers[..count].to_vec(),
                    strategy,
                )),
            )
            .await
            .expect("fetched in time")
            .unwrap();
            let took = started.elapsed();
            assert_eq!(
                store.blobs().get_bytes(hash).await.unwrap().len(),
                blob.len()
            );
            println!(
                "MEASURE multi_provider strategy={name} providers={count} size_mib={size_mib} secs={:.3} mib_per_s={:.1}",
                took.as_secs_f64(),
                size_mib as f64 / took.as_secs_f64()
            );
            endpoint.close().await;
        }
    }
}

/// How many real-time streams one relay carries: `pairs` pairs of endpoints
/// that reach each other only through one relay (at its default limits),
/// each side sending a 200-byte datagram 50 times a second for 10 s and
/// echoing what it receives. Per load it prints the share of datagrams
/// echoed back and the round-trip time at the median, p99 and worst. Every
/// endpoint runs in this one process, so the relay competes with its clients
/// for the CPU: a lower bound for a relay on a machine of its own.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement: scripts/netlab/measure.sh runs it with --ignored"]
async fn relay_capacity() {
    use crate::connection_limits::ConnectionLimits;
    use crate::identity_transport::{base_builder_with, with_relay_urls};
    use crate::relay::{RelayLimits, RelayServer};

    const ALPN: &[u8] = b"tenzro/measure/realtime";
    let relay = RelayServer::spawn(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(DiscoveryStore::new()),
        "did:tenzro:machine:measure".into(),
        RelayLimits::default(),
        crate::relay::RelayAdmission::default(),
    )
    .await
    .unwrap();
    let url: url::Url = format!("http://{}/", relay.local_addr()).parse().unwrap();
    let endpoint = |url: url::Url| async move {
        let limits = ConnectionLimits::default();
        let e = with_relay_urls(base_builder_with(&limits, true), &[url], None)
            .clear_ip_transports()
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(20), e.online())
            .await
            .expect("reaches the relay");
        e
    };

    for pairs in [10usize, 50, 100, 200] {
        let mut conns = Vec::new();
        let mut endpoints = Vec::new();
        for _ in 0..pairs {
            let (a, b) = (endpoint(url.clone()).await, endpoint(url.clone()).await);
            let accept = {
                let b = b.clone();
                tokio::spawn(async move { b.accept().await.unwrap().await.unwrap() })
            };
            let addr = iroh::EndpointAddr::new(b.id()).with_relay_url(url.clone().into());
            let ca = a.connect(addr, ALPN).await.unwrap();
            let cb = accept.await.unwrap();
            conns.push((ca, cb));
            endpoints.push((a, b));
        }
        let sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let rtts: Arc<parking_lot::Mutex<Vec<Duration>>> = Arc::default();
        let origin = Instant::now();
        let mut tasks = Vec::new();
        for (ca, cb) in &conns {
            for (me, peer) in [(ca.clone(), cb.clone()), (cb.clone(), ca.clone())] {
                // The peer echoes; this side sends and times the echoes.
                tasks.push(tokio::spawn(async move {
                    while let Ok(d) = peer.read_datagram().await {
                        if d.first() == Some(&0) {
                            let mut back = d.to_vec();
                            back[0] = 1;
                            peer.send_datagram(back.into()).ok();
                        }
                    }
                }));
                let (sent, rtts) = (sent.clone(), rtts.clone());
                let me_read = me.clone();
                tasks.push(tokio::spawn(async move {
                    while let Ok(d) = me_read.read_datagram().await {
                        if d.first() == Some(&1) && d.len() >= 9 {
                            let at = u64::from_le_bytes(d[1..9].try_into().unwrap());
                            let now = origin.elapsed().as_micros() as u64;
                            rtts.lock()
                                .push(Duration::from_micros(now.saturating_sub(at)));
                        }
                    }
                }));
                tasks.push(tokio::spawn(async move {
                    let mut tick = tokio::time::interval(Duration::from_millis(20));
                    for _ in 0..500 {
                        tick.tick().await;
                        let mut d = vec![0u8; 200];
                        d[1..9]
                            .copy_from_slice(&(origin.elapsed().as_micros() as u64).to_le_bytes());
                        if me.send_datagram(d.into()).is_ok() {
                            sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }));
            }
        }
        tokio::time::sleep(Duration::from_secs(12)).await;
        let mut rtts = rtts.lock().clone();
        rtts.sort();
        let sent = sent.load(std::sync::atomic::Ordering::Relaxed);
        let at = |q: f64| {
            rtts.get(((rtts.len() as f64 * q) as usize).min(rtts.len().saturating_sub(1)))
                .copied()
                .unwrap_or_default()
        };
        println!(
            "MEASURE relay_capacity pairs={pairs} clients={} streams={} sent={sent} echoed_share={:.4} \
             rtt_median_ms={:.2} rtt_p99_ms={:.2} rtt_worst_ms={:.2} relay_connections={}",
            2 * pairs,
            2 * pairs,
            rtts.len() as f64 / sent.max(1) as f64,
            at(0.5).as_secs_f64() * 1e3,
            at(0.99).as_secs_f64() * 1e3,
            rtts.last().copied().unwrap_or_default().as_secs_f64() * 1e3,
            relay.load().connections
        );
        for t in tasks {
            t.abort();
        }
        for (a, b) in endpoints {
            a.close().await;
            b.close().await;
        }
    }
}

/// One side of the lossy-path lab (`scripts/netlab/lossy-path.sh`), not a
/// unit test: the lab runs it in two network namespaces joined by a link it
/// shapes with netem, and reads the lines it prints.
///
/// `MEASURE_ROLE=serve` binds UDP `MEASURE_PORT` with the key of
/// `MEASURE_SEED`, sends zeros on every stream opened to it and echoes every
/// datagram. `MEASURE_ROLE=fetch` dials the serving side at `MEASURE_PEER`
/// (`ip:port`, seed `MEASURE_SEED`) and for `MEASURE_SECS` sends a 200-byte
/// datagram 50 times a second, timing the echoes; with `MEASURE_BULK=1` it
/// also reads one stream as fast as it can. `MEASURE_CC` is `bbr3` (what
/// nodes run) or `cubic`. It prints the goodput, the datagrams echoed, the
/// round-trip times and the longest gap between echoes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs as one node inside the lossy-path lab: scripts/netlab/lossy-path.sh starts it with --ignored"]
async fn lossy_path_lab_node() {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};

    const ALPN: &[u8] = b"tenzro/measure/lossy";
    let var = |k: &str| std::env::var(k).unwrap_or_default();
    let seed: u8 = var("MEASURE_SEED").parse().unwrap_or(1);
    let key = iroh::SecretKey::from_bytes(&[seed; 32]);
    let cc = var("MEASURE_CC");
    let limits = crate::connection_limits::ConnectionLimits::default();
    let transport = if cc == "cubic" {
        iroh::endpoint::QuicTransportConfig::builder()
            .congestion_controller_factory(Arc::new(noq_proto::congestion::CubicConfig::default()))
            .max_idle_timeout(Some(
                iroh::endpoint::IdleTimeout::try_from(Duration::from_secs(
                    limits.idle_timeout_secs,
                ))
                .unwrap(),
            ))
            .default_path_keep_alive_interval(Duration::from_secs(4))
            .receive_window(iroh::endpoint::VarInt::from_u32(
                limits.receive_window_bytes,
            ))
            .build()
    } else {
        limits.transport_config(true)
    };
    let builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .transport_config(transport)
        .alpns(vec![ALPN.to_vec()]);

    if var("MEASURE_ROLE") == "serve" {
        let port: u16 = var("MEASURE_PORT").parse().expect("MEASURE_PORT");
        let ep = builder
            .secret_key(key)
            .bind_addr(SocketAddr::from(([0, 0, 0, 0], port)))
            .unwrap()
            .bind()
            .await
            .unwrap();
        println!("READY {}", ep.id());
        while let Some(incoming) = ep.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let echo = conn.clone();
                tokio::spawn(async move {
                    while let Ok(d) = echo.read_datagram().await {
                        echo.send_datagram(d).ok();
                    }
                });
                while let Ok((mut send, _recv)) = conn.accept_bi().await {
                    tokio::spawn(async move {
                        let chunk = vec![0u8; 64 * 1024];
                        while send.write_all(&chunk).await.is_ok() {}
                    });
                }
            });
        }
        return;
    }

    let secs: u64 = var("MEASURE_SECS").parse().unwrap_or(30);
    let peer: SocketAddr = var("MEASURE_PEER").parse().expect("MEASURE_PEER");
    let ep = builder.bind().await.unwrap();
    let addr = iroh::EndpointAddr::new(key.public()).with_addrs([iroh::TransportAddr::Ip(peer)]);
    let conn = tokio::time::timeout(Duration::from_secs(30), ep.connect(addr, ALPN))
        .await
        .expect("dial in time")
        .expect("dial");
    let origin = Instant::now();
    let until = origin + Duration::from_secs(secs);
    let received = Arc::new(AtomicU64::new(0));
    if var("MEASURE_BULK") == "1" {
        let (conn, received) = (conn.clone(), received.clone());
        tokio::spawn(async move {
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(b"go").await.ok();
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(Some(n)) = recv.read(&mut buf).await {
                received.fetch_add(n as u64, Ordering::Relaxed);
            }
        });
    }
    let echoes: Arc<parking_lot::Mutex<Vec<(Instant, Duration)>>> = Arc::default();
    {
        let (conn, echoes) = (conn.clone(), echoes.clone());
        tokio::spawn(async move {
            while let Ok(d) = conn.read_datagram().await {
                if d.len() >= 8 {
                    let at = u64::from_le_bytes(d[0..8].try_into().unwrap());
                    let now = Instant::now();
                    let rtt = Duration::from_micros(
                        (now - origin).as_micros() as u64
                            - at.min((now - origin).as_micros() as u64),
                    );
                    echoes.lock().push((now, rtt));
                }
            }
        });
    }
    let mut sent = 0u64;
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    let bulk_start = received.load(Ordering::Relaxed);
    while Instant::now() < until {
        tick.tick().await;
        let mut d = vec![0u8; 200];
        d[0..8].copy_from_slice(&(origin.elapsed().as_micros() as u64).to_le_bytes());
        if conn.send_datagram(d.into()).is_ok() {
            sent += 1;
        }
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let bulk = received.load(Ordering::Relaxed) - bulk_start;
    let echoes = echoes.lock().clone();
    let mut rtts: Vec<Duration> = echoes.iter().map(|(_, r)| *r).collect();
    rtts.sort();
    let mut gap = echoes.first().map_or(Duration::ZERO, |(t, _)| *t - origin);
    for w in echoes.windows(2) {
        gap = gap.max(w[1].0 - w[0].0);
    }
    let at = |q: f64| {
        rtts.get(((rtts.len() as f64 * q) as usize).min(rtts.len().saturating_sub(1)))
            .copied()
            .unwrap_or_default()
    };
    println!(
        "MEASURE lossy_path cc={} secs={secs} goodput_mbit={:.2} datagrams_sent={sent} echoed={} \
         loss={:.4} rtt_median_ms={:.1} rtt_p99_ms={:.1} longest_gap_ms={:.0}",
        if cc == "cubic" { "cubic" } else { "bbr3" },
        bulk as f64 * 8.0 / secs as f64 / 1e6,
        echoes.len(),
        1.0 - echoes.len() as f64 / sent.max(1) as f64,
        at(0.5).as_secs_f64() * 1e3,
        at(0.99).as_secs_f64() * 1e3,
        gap.as_secs_f64() * 1e3
    );
    conn.close(0u32.into(), b"done");
    ep.close().await;
}

/// A real-time stream through a relay restart: two endpoints exchange a
/// 200-byte datagram 50 times a second each way for `MEASURE_SECS` (60 by
/// default) while their relay is stopped halfway and started again on the
/// same port two seconds later. Run once with the relay as the only path and
/// once with a direct path beside it; each prints the datagrams echoed and
/// the longest gap between echoes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement: scripts/netlab/measure.sh runs it with --ignored"]
async fn realtime_through_a_relay_restart() {
    use crate::connection_limits::ConnectionLimits;
    use crate::identity_transport::{base_builder_with, with_relay_urls};
    use crate::relay::{RelayLimits, RelayServer};

    const ALPN: &[u8] = b"tenzro/measure/restart";
    let secs: u64 = std::env::var("MEASURE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let spawn_relay = |addr: std::net::SocketAddr| async move {
        RelayServer::spawn(
            addr,
            Arc::new(DiscoveryStore::new()),
            "did:tenzro:machine:measure".into(),
            RelayLimits::default(),
            crate::relay::RelayAdmission::default(),
        )
        .await
        .unwrap()
    };
    let limits = ConnectionLimits::default();
    for relay_only in [true, false] {
        let relay = spawn_relay("127.0.0.1:0".parse().unwrap()).await;
        let relay_addr = relay.local_addr();
        let url: url::Url = format!("http://{relay_addr}/").parse().unwrap();
        let endpoint = || async {
            let relays = std::slice::from_ref(&url);
            let mut b = with_relay_urls(base_builder_with(&limits, true), relays, None)
                .alpns(vec![ALPN.to_vec()]);
            if relay_only {
                b = b.clear_ip_transports();
            }
            let e = b.bind().await.unwrap();
            tokio::time::timeout(Duration::from_secs(20), e.online())
                .await
                .expect("reaches the relay");
            e
        };
        let (a, b) = (endpoint().await, endpoint().await);
        let accept = {
            let b = b.clone();
            tokio::spawn(async move { b.accept().await.unwrap().await.unwrap() })
        };
        let conn = a.connect(b.addr(), ALPN).await.unwrap();
        let echo = accept.await.unwrap();
        let echoer = tokio::spawn(async move {
            while let Ok(d) = echo.read_datagram().await {
                echo.send_datagram(d).ok();
            }
        });
        let arrivals: Arc<parking_lot::Mutex<Vec<Instant>>> = Arc::default();
        let reader = {
            let (conn, arrivals) = (conn.clone(), arrivals.clone());
            tokio::spawn(async move {
                while conn.read_datagram().await.is_ok() {
                    arrivals.lock().push(Instant::now());
                }
            })
        };
        let start = Instant::now();
        // The restart runs beside the sender, which keeps sending through it.
        let restart = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(secs / 2)).await;
            drop(relay);
            tokio::time::sleep(Duration::from_secs(2)).await;
            spawn_relay(relay_addr).await
        });
        let mut sent = 0u64;
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        while start.elapsed() < Duration::from_secs(secs) {
            tick.tick().await;
            if conn.send_datagram(vec![0u8; 200].into()).is_ok() {
                sent += 1;
            }
        }
        let restarted = restart.is_finished();
        let relay = restart.await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        let arrivals = arrivals.lock().clone();
        let mut gap = arrivals.first().map_or(Duration::ZERO, |t| *t - start);
        for w in arrivals.windows(2) {
            gap = gap.max(w[1] - w[0]);
        }
        println!(
            "MEASURE relay_restart paths={} secs={secs} restarted={restarted} sent={sent} echoed={} \
             loss={:.4} longest_gap_ms={:.0}",
            if relay_only {
                "relay_only"
            } else {
                "relay_and_direct"
            },
            arrivals.len(),
            1.0 - arrivals.len() as f64 / sent.max(1) as f64,
            gap.as_secs_f64() * 1e3
        );
        reader.abort();
        echoer.abort();
        conn.close(0u32.into(), b"done");
        a.close().await;
        b.close().await;
        drop(relay);
    }
}
