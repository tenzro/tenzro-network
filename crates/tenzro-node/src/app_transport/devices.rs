//! The devices signed in to this node's app transport, and who may reach
//! them.
//!
//! A device is reachable by nobody until it says who may open streams to it:
//! identities it names, or anyone opening with an application label it
//! names. An open that the target does not admit is answered exactly as an
//! open to an identity with no device here, so a sender learns nothing about
//! who is signed in. Each sender is held to a number of opens a minute, and
//! each device to a number of streams waiting for its answer.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

/// The window opens are counted over.
const OPEN_WINDOW: Duration = Duration::from_secs(60);

/// What bounds the devices and the streams offered to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceLimits {
    /// Most devices signed in at once.
    pub max_sessions: usize,
    /// Most streams one identity may open in a minute.
    pub opens_per_minute: u32,
    /// Most streams that may wait for one device's answer at once.
    pub pending_per_device: u32,
    /// Most devices of one identity signed in at once.
    pub sessions_per_identity: usize,
}

/// Why an open did not reach a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreached {
    /// The sender opened too many streams this minute.
    TooManyOpens,
    /// No device of the target takes this stream: none is signed in, or
    /// none admits this sender.
    NoDevice,
    /// The device has as many streams waiting for its answer as it may.
    Busy,
}

impl std::fmt::Display for Unreached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Unreached::TooManyOpens => "too many streams opened this minute; slow down",
            Unreached::NoDevice => "no device of that identity takes this stream",
            Unreached::Busy => "that device has too many streams waiting for its answer",
        })
    }
}

/// A stream one device asks to open to another identity's device.
#[derive(Debug, Clone)]
pub struct Opening<'a> {
    /// The identity that opens the stream.
    pub from: &'a str,
    /// The device it opens it from.
    pub from_device: &'a str,
    /// The identity it opens it to.
    pub to: &'a str,
    /// The device of that identity it wants, if it names one.
    pub device: Option<&'a str>,
    /// The node that carried the stream here, when it is not this one.
    pub via: Option<String>,
    /// The application label it opens with.
    pub app: &'a str,
}

/// A stream offered to a device, with the way to answer it. `S` is the
/// stream the device's session hands back once the device accepts.
#[derive(Debug)]
pub struct Offer<S> {
    /// The identity that opened the stream.
    pub from: String,
    /// The device it opened it from.
    pub from_device: String,
    /// The node that carried it here, when it is not this one.
    pub via: Option<String>,
    /// The application label it was opened with.
    pub app: String,
    /// Where the device's session sends the accepted stream. Dropped without
    /// an answer, the opener is told the device declined.
    pub answer: oneshot::Sender<S>,
    _waiting: Waiting,
}

/// One stream waiting for a device's answer, counted until dropped.
#[derive(Debug)]
struct Waiting(Arc<AtomicU32>);

impl Drop for Waiting {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Device<S> {
    id: String,
    session: u64,
    from: HashSet<String>,
    apps: HashSet<String>,
    waiting: Arc<AtomicU32>,
    offers: mpsc::Sender<Offer<S>>,
}

impl<S> Device<S> {
    fn admits(&self, sender: &str, app: &str) -> bool {
        self.from.contains(sender) || self.apps.contains(app)
    }
}

struct Inner<S> {
    next_session: u64,
    sessions: usize,
    by_did: HashMap<String, Vec<Device<S>>>,
    opens: HashMap<String, (Instant, u32)>,
}

/// The devices signed in now.
pub struct Devices<S> {
    limits: DeviceLimits,
    inner: Mutex<Inner<S>>,
}

/// A device's place among the signed-in devices, given up when dropped.
pub struct SignedIn<S> {
    devices: Arc<Devices<S>>,
    did: String,
    session: u64,
}

impl<S> Drop for SignedIn<S> {
    fn drop(&mut self) {
        let mut inner = self.devices.inner.lock();
        if let Some(list) = inner.by_did.get_mut(&self.did) {
            let before = list.len();
            list.retain(|d| d.session != self.session);
            let gone = before - list.len();
            if list.is_empty() {
                inner.by_did.remove(&self.did);
            }
            inner.sessions -= gone;
        }
    }
}

impl<S> SignedIn<S> {
    /// Sets who may open streams to this device from now on: the identities
    /// in `from`, and anyone opening with a label in `apps`.
    pub fn listen(&self, from: Vec<String>, apps: Vec<String>) {
        let mut inner = self.devices.inner.lock();
        if let Some(device) = inner
            .by_did
            .get_mut(&self.did)
            .and_then(|list| list.iter_mut().find(|d| d.session == self.session))
        {
            device.from = from.into_iter().collect();
            device.apps = apps.into_iter().collect();
        }
    }
}

impl<S> Devices<S> {
    /// No device signed in, bounded by `limits`.
    pub fn new(limits: DeviceLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            inner: Mutex::new(Inner {
                next_session: 0,
                sessions: 0,
                by_did: HashMap::new(),
                opens: HashMap::new(),
            }),
        })
    }

    /// How many devices are signed in.
    pub fn sessions(&self) -> usize {
        self.inner.lock().sessions
    }

    /// Signs in `device` of `did`. Streams offered to it arrive on the
    /// returned receiver. A device that signs in again replaces its earlier
    /// session. Refused when the node holds as many sessions as it may.
    pub fn sign_in(
        self: &Arc<Self>,
        did: &str,
        device: &str,
    ) -> Result<(SignedIn<S>, mpsc::Receiver<Offer<S>>), String> {
        let (offers, receiver) = mpsc::channel(self.limits.pending_per_device.max(1) as usize);
        let mut inner = self.inner.lock();
        let replaced = inner
            .by_did
            .get(did)
            .is_some_and(|list| list.iter().any(|d| d.id == device));
        if !replaced && inner.sessions >= self.limits.max_sessions {
            return Err(format!(
                "this node holds its {} sessions; try again later",
                self.limits.max_sessions
            ));
        }
        let of_did = inner.by_did.get(did).map_or(0, Vec::len);
        if !replaced && of_did >= self.limits.sessions_per_identity {
            return Err(format!(
                "{did} already has {of_did} devices signed in here, as many as one identity may"
            ));
        }
        let session = inner.next_session;
        inner.next_session += 1;
        let list = inner.by_did.entry(did.to_string()).or_default();
        list.retain(|d| d.id != device);
        list.push(Device {
            id: device.to_string(),
            session,
            from: HashSet::new(),
            apps: HashSet::new(),
            waiting: Arc::new(AtomicU32::new(0)),
            offers,
        });
        if !replaced {
            inner.sessions += 1;
        }
        Ok((
            SignedIn {
                devices: self.clone(),
                did: did.to_string(),
                session,
            },
            receiver,
        ))
    }

    /// Counts a stream `from` opens to a device signed in to another node,
    /// under the same limit as one it opens to a device here.
    pub fn count_open(&self, from: &str, now: Instant) -> Result<(), Unreached> {
        let mut inner = self.inner.lock();
        Self::count_open_in(&mut inner, self.limits.opens_per_minute, from, now)
    }

    fn count_open_in(
        inner: &mut Inner<S>,
        per_minute: u32,
        from: &str,
        now: Instant,
    ) -> Result<(), Unreached> {
        let opens = inner.opens.entry(from.to_string()).or_insert((now, 0));
        if now.duration_since(opens.0) >= OPEN_WINDOW {
            *opens = (now, 0);
        }
        if opens.1 >= per_minute {
            return Err(Unreached::TooManyOpens);
        }
        opens.1 += 1;
        inner
            .opens
            .retain(|_, (since, _)| now.duration_since(*since) < OPEN_WINDOW);
        Ok(())
    }

    /// Offers the stream `open` asks for to a device of its target: the one
    /// named, or the first that admits the sender. On success the device's
    /// session holds the offer, and the accepted stream arrives on the
    /// returned receiver together with the device's id.
    pub fn offer(
        &self,
        open: Opening<'_>,
        now: Instant,
    ) -> Result<(String, oneshot::Receiver<S>), Unreached> {
        let Opening {
            from,
            from_device,
            to,
            device,
            via,
            app,
        } = open;
        let mut inner = self.inner.lock();
        Self::count_open_in(&mut inner, self.limits.opens_per_minute, from, now)?;

        let target = inner
            .by_did
            .get(to)
            .and_then(|list| {
                list.iter()
                    .find(|d| device.is_none_or(|id| d.id == id) && d.admits(from, app))
            })
            .ok_or(Unreached::NoDevice)?;
        if target.waiting.fetch_add(1, Ordering::AcqRel) >= self.limits.pending_per_device {
            target.waiting.fetch_sub(1, Ordering::AcqRel);
            return Err(Unreached::Busy);
        }
        let waiting = Waiting(target.waiting.clone());
        let (answer, accepted) = oneshot::channel();
        target
            .offers
            .try_send(Offer {
                from: from.to_string(),
                from_device: from_device.to_string(),
                via,
                app: app.to_string(),
                answer,
                _waiting: waiting,
            })
            .map_err(|_| Unreached::Busy)?;
        Ok((target.id.clone(), accepted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "did:tenzro:human:a";
    const B: &str = "did:tenzro:human:b";
    const C: &str = "did:tenzro:human:c";

    fn devices(opens_per_minute: u32, pending_per_device: u32) -> Arc<Devices<u8>> {
        Devices::new(DeviceLimits {
            max_sessions: 2,
            opens_per_minute,
            pending_per_device,
            sessions_per_identity: 2,
        })
    }

    fn offer(
        devices: &Devices<u8>,
        from: &str,
        to: &str,
        app: &str,
        now: Instant,
    ) -> Result<(String, oneshot::Receiver<u8>), Unreached> {
        named(devices, from, to, None, app, now)
    }

    fn named(
        devices: &Devices<u8>,
        from: &str,
        to: &str,
        device: Option<&str>,
        app: &str,
        now: Instant,
    ) -> Result<(String, oneshot::Receiver<u8>), Unreached> {
        devices.offer(
            Opening {
                from,
                from_device: "phone",
                to,
                device,
                via: None,
                app,
            },
            now,
        )
    }

    #[test]
    fn an_identity_signs_in_no_more_devices_than_it_may() {
        let devices = Devices::<u8>::new(DeviceLimits {
            max_sessions: 8,
            opens_per_minute: 10,
            pending_per_device: 4,
            sessions_per_identity: 2,
        });
        let _one = devices.sign_in(A, "one").unwrap();
        let _two = devices.sign_in(A, "two").unwrap();
        assert!(devices.sign_in(A, "three").is_err());
        // Signing a device in again replaces it rather than adding one.
        assert!(devices.sign_in(A, "two").is_ok());
        assert!(devices.sign_in(B, "one").is_ok());
    }

    #[test]
    fn opens_through_another_node_share_the_per_minute_limit() {
        let devices = devices(2, 4);
        let now = Instant::now();
        assert_eq!(devices.count_open(A, now), Ok(()));
        assert_eq!(devices.count_open(A, now), Ok(()));
        assert_eq!(devices.count_open(A, now), Err(Unreached::TooManyOpens));
        assert_eq!(devices.count_open(B, now), Ok(()));
        assert_eq!(devices.count_open(A, now + OPEN_WINDOW), Ok(()));
    }

    #[test]
    fn a_device_is_reached_by_nobody_until_it_says_who_may() {
        let devices = devices(100, 4);
        let now = Instant::now();
        let (b, mut offers) = devices.sign_in(B, "laptop").unwrap();
        assert_eq!(
            offer(&devices, A, B, "messenger", now).unwrap_err(),
            Unreached::NoDevice
        );
        assert!(offers.try_recv().is_err());

        b.listen(vec![A.to_string()], Vec::new());
        let (device, _accepted) = offer(&devices, A, B, "messenger", now).unwrap();
        assert_eq!(device, "laptop");
        let got = offers.try_recv().unwrap();
        assert_eq!((got.from.as_str(), got.app.as_str()), (A, "messenger"));
    }

    #[test]
    fn an_unlisted_sender_never_reaches_the_target_and_cannot_tell_it_is_there() {
        let devices = devices(100, 4);
        let now = Instant::now();
        let (b, mut offers) = devices.sign_in(B, "laptop").unwrap();
        b.listen(vec![A.to_string()], vec!["files".to_string()]);

        let unlisted = offer(&devices, C, B, "messenger", now).unwrap_err();
        let absent = offer(&devices, C, "did:tenzro:human:nobody", "messenger", now).unwrap_err();
        assert_eq!(unlisted, absent);
        assert!(offers.try_recv().is_err());

        // The label it listens for lets any sender through.
        assert!(offer(&devices, C, B, "files", now).is_ok());
        assert_eq!(offers.try_recv().unwrap().from, C);

        // A later `listen` replaces the earlier one.
        b.listen(Vec::new(), Vec::new());
        assert_eq!(
            offer(&devices, A, B, "files", now).unwrap_err(),
            Unreached::NoDevice
        );
    }

    #[test]
    fn a_named_device_is_the_only_one_offered_the_stream() {
        let devices = devices(100, 4);
        let now = Instant::now();
        let (laptop, mut at_laptop) = devices.sign_in(B, "laptop").unwrap();
        let (phone, mut at_phone) = devices.sign_in(B, "phone").unwrap();
        laptop.listen(vec![A.to_string()], Vec::new());
        phone.listen(vec![A.to_string()], Vec::new());
        let (device, _accepted) = named(&devices, A, B, Some("phone"), "messenger", now).unwrap();
        assert_eq!(device, "phone");
        assert!(at_laptop.try_recv().is_err());
        assert!(at_phone.try_recv().is_ok());
        assert_eq!(
            named(&devices, A, B, Some("tablet"), "messenger", now).unwrap_err(),
            Unreached::NoDevice
        );
    }

    #[test]
    fn only_so_many_streams_wait_for_one_device() {
        let devices = devices(100, 2);
        let now = Instant::now();
        let (b, mut offers) = devices.sign_in(B, "laptop").unwrap();
        b.listen(vec![A.to_string()], Vec::new());
        let _first = offer(&devices, A, B, "messenger", now).unwrap();
        let _second = offer(&devices, A, B, "messenger", now).unwrap();
        assert_eq!(
            offer(&devices, A, B, "messenger", now).unwrap_err(),
            Unreached::Busy
        );

        // An answered offer makes room for another.
        drop(offers.try_recv().unwrap());
        assert!(offer(&devices, A, B, "messenger", now).is_ok());
    }

    #[test]
    fn a_sender_opens_only_so_many_streams_a_minute() {
        let devices = devices(2, 100);
        let now = Instant::now();
        let (b, _offers) = devices.sign_in(B, "laptop").unwrap();
        b.listen(vec![A.to_string(), C.to_string()], Vec::new());
        assert!(offer(&devices, A, B, "messenger", now).is_ok());
        // An open that reaches nobody counts as well.
        assert_eq!(
            offer(&devices, A, "did:tenzro:human:nobody", "messenger", now).unwrap_err(),
            Unreached::NoDevice
        );
        assert_eq!(
            offer(&devices, A, B, "messenger", now).unwrap_err(),
            Unreached::TooManyOpens
        );
        assert!(offer(&devices, C, B, "messenger", now).is_ok());
        assert!(offer(&devices, A, B, "messenger", now + OPEN_WINDOW).is_ok());
    }

    #[test]
    fn sessions_are_bounded_and_a_dropped_one_frees_its_place() {
        let devices = devices(100, 4);
        let (a, _a_offers) = devices.sign_in(A, "phone").unwrap();
        let (_b, _b_offers) = devices.sign_in(B, "laptop").unwrap();
        assert!(devices.sign_in(C, "phone").is_err());
        assert_eq!(devices.sessions(), 2);
        drop(a);
        assert_eq!(devices.sessions(), 1);
        assert!(devices.sign_in(C, "phone").is_ok());
    }

    #[test]
    fn a_device_that_signs_in_again_replaces_its_earlier_session() {
        let devices = devices(100, 4);
        let now = Instant::now();
        let (old, mut old_offers) = devices.sign_in(B, "laptop").unwrap();
        old.listen(vec![A.to_string()], Vec::new());
        let (new, mut new_offers) = devices.sign_in(B, "laptop").unwrap();
        assert_eq!(devices.sessions(), 1);
        // The new session starts reachable by nobody.
        assert_eq!(
            offer(&devices, A, B, "messenger", now).unwrap_err(),
            Unreached::NoDevice
        );
        new.listen(vec![A.to_string()], Vec::new());
        assert!(offer(&devices, A, B, "messenger", now + OPEN_WINDOW).is_ok());
        assert!(new_offers.try_recv().is_ok());
        assert!(old_offers.try_recv().is_err());
        // The old session ending does not take the new one down.
        drop(old);
        assert_eq!(devices.sessions(), 1);
    }
}
