//! Every TPM command this process sends goes through one executor.
//!
//! - One dedicated thread does all TPM I/O, so the process never has two TPM
//!   commands in flight and no async worker ever blocks on the chip.
//! - Each call has a deadline ([`Limits::call_timeout`], 10 s unless
//!   configured). A caller whose command has not answered by then gets an
//!   error; the command it queued is skipped if it has not started. While the
//!   thread is stuck on a command older than the deadline, new calls fail at
//!   once instead of queueing behind it.
//! - Signing and quoting are rate-limited by token buckets, so a burst of
//!   requests cannot monopolise a chip other processes share. A call that
//!   cannot get a token before its deadline fails.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::{DeviceKeyError, Result};

/// The executor's limits, set once per process with [`configure`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    /// The longest one TPM command may take before its caller gets an error.
    pub call_timeout: Duration,
    /// Sustained `TPM2_Sign` commands per second (the burst is the same).
    pub signs_per_second: u32,
    /// Sustained `TPM2_Quote` and `TPM2_Certify` commands per second.
    pub quotes_per_second: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            call_timeout: Duration::from_secs(10),
            signs_per_second: 30,
            quotes_per_second: 2,
        }
    }
}

static LIMITS: OnceLock<Limits> = OnceLock::new();

/// Set this process's TPM limits. Must run before the first TPM command;
/// refused afterwards, or when a value is zero.
pub fn configure(limits: Limits) -> Result<()> {
    if limits.call_timeout.is_zero()
        || limits.signs_per_second == 0
        || limits.quotes_per_second == 0
    {
        return Err(DeviceKeyError::Tpm(
            "TPM limits must be non-zero: a call timeout, signs per second and quotes per second"
                .into(),
        ));
    }
    let set = LIMITS.get_or_init(|| limits);
    if *set != limits {
        return Err(DeviceKeyError::Tpm(format!(
            "TPM limits already in use ({set:?}); set them before the first TPM command"
        )));
    }
    Ok(())
}

/// The process-wide executor.
pub(crate) fn global() -> &'static Executor {
    static EXEC: OnceLock<Executor> = OnceLock::new();
    EXEC.get_or_init(|| Executor::new(*LIMITS.get_or_init(Limits::default)))
}

/// Which rate limit a command counts against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Sign,
    Quote,
    Other,
}

impl Class {
    pub(crate) fn of(command: &[u8]) -> Self {
        use crate::tpm_wire::{
            TPM2_CC_CERTIFY, TPM2_CC_QUOTE, TPM2_CC_SIGN, TPM2_CC_SIGN_SEQUENCE_COMPLETE,
            command_code,
        };
        match command_code(command) {
            Some(TPM2_CC_SIGN | TPM2_CC_SIGN_SEQUENCE_COMPLETE) => Self::Sign,
            Some(TPM2_CC_QUOTE | TPM2_CC_CERTIFY) => Self::Quote,
            _ => Self::Other,
        }
    }
}

struct Bucket {
    per_second: f64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(per_second: u32) -> Self {
        Self {
            per_second: f64::from(per_second),
            tokens: f64::from(per_second),
            last: Instant::now(),
        }
    }

    /// Take a token, returning how long to wait for it. The token is taken
    /// even when it is still owed, so waiters are served in order.
    fn take(&mut self, now: Instant) -> Duration {
        let burst = self.per_second.max(1.0);
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.per_second)
            .min(burst);
        self.last = now;
        self.tokens -= 1.0;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.per_second)
        }
    }

    fn give_back(&mut self) {
        self.tokens += 1.0;
    }
}

type Job = Box<dyn FnOnce() + Send>;

/// The serializing TPM executor: one thread, a deadline per call, and rate
/// limits for signing and quoting.
pub(crate) struct Executor {
    jobs: mpsc::Sender<Job>,
    /// When the command the thread is running started; `None` when idle.
    busy_since: Arc<Mutex<Option<Instant>>>,
    timeout: Duration,
    signs: Mutex<Bucket>,
    quotes: Mutex<Bucket>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Executor {
    pub(crate) fn new(limits: Limits) -> Self {
        let (jobs, queue) = mpsc::channel::<Job>();
        let busy_since = Arc::new(Mutex::new(None));
        let busy = busy_since.clone();
        std::thread::Builder::new()
            .name("tpm".into())
            .spawn(move || {
                while let Ok(job) = queue.recv() {
                    *lock(&busy) = Some(Instant::now());
                    // A panicking command must not take TPM access down with it.
                    let _ = std::panic::catch_unwind(AssertUnwindSafe(job));
                    *lock(&busy) = None;
                }
            })
            .expect("spawn the TPM thread");
        Self {
            jobs,
            busy_since,
            timeout: limits.call_timeout,
            signs: Mutex::new(Bucket::new(limits.signs_per_second)),
            quotes: Mutex::new(Bucket::new(limits.quotes_per_second)),
        }
    }

    /// Run `job` on the TPM thread and wait for it until the call deadline.
    pub(crate) fn run<R: Send + 'static>(
        &self,
        what: &str,
        class: Class,
        job: impl FnOnce() -> Result<R> + Send + 'static,
    ) -> Result<R> {
        let start = Instant::now();
        let deadline = start + self.timeout;
        if let Some(since) = *lock(&self.busy_since) {
            let stuck = since.elapsed();
            if stuck >= self.timeout {
                return Err(DeviceKeyError::Tpm(format!(
                    "{what}: the TPM has not answered a command for {}s; refusing new commands until it does",
                    stuck.as_secs()
                )));
            }
        }
        self.admit(what, class, start, deadline)?;

        let (reply, answer) = mpsc::sync_channel::<Result<R>>(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let skip = cancelled.clone();
        self.jobs
            .send(Box::new(move || {
                if !skip.load(Ordering::Acquire) {
                    let _ = reply.send(job());
                }
            }))
            .map_err(|_| DeviceKeyError::Tpm(format!("{what}: the TPM thread has stopped")))?;
        match answer.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(r) => r,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                cancelled.store(true, Ordering::Release);
                tracing::warn!(
                    command = what,
                    timeout_secs = self.timeout.as_secs_f64(),
                    "TPM command timed out"
                );
                Err(DeviceKeyError::Tpm(format!(
                    "{what}: the TPM did not answer within {}s",
                    self.timeout.as_secs_f64()
                )))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(DeviceKeyError::Tpm(format!(
                "{what}: the TPM command panicked"
            ))),
        }
    }

    /// Queue `job` without waiting for it: releasing a descriptor or a
    /// transient object, which nobody waits on and which must not block the
    /// caller when the chip is slow.
    pub(crate) fn detach(&self, job: impl FnOnce() + Send + 'static) {
        let _ = self.jobs.send(Box::new(job));
    }

    fn admit(&self, what: &str, class: Class, now: Instant, deadline: Instant) -> Result<()> {
        let bucket = match class {
            Class::Sign => &self.signs,
            Class::Quote => &self.quotes,
            Class::Other => return Ok(()),
        };
        let wait = lock(bucket).take(now);
        if wait.is_zero() {
            return Ok(());
        }
        if now + wait >= deadline {
            lock(bucket).give_back();
            return Err(DeviceKeyError::Tpm(format!(
                "{what}: TPM {} rate limit reached; retry later",
                if class == Class::Sign {
                    "signing"
                } else {
                    "quote"
                }
            )));
        }
        std::thread::sleep(wait);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn limits(timeout_ms: u64) -> Limits {
        Limits {
            call_timeout: Duration::from_millis(timeout_ms),
            signs_per_second: 1000,
            quotes_per_second: 1000,
        }
    }

    #[test]
    fn a_hung_call_times_out_and_later_calls_fail_fast_until_it_returns() {
        let exec = Executor::new(limits(200));
        let (release, hung) = mpsc::channel::<()>();
        let started = Instant::now();
        let err = exec
            .run("hang", Class::Other, move || {
                let _ = hung.recv();
                Ok(())
            })
            .unwrap_err();
        let waited = started.elapsed();
        assert!(err.to_string().contains("did not answer"), "{err}");
        assert!(
            waited >= Duration::from_millis(200) && waited < Duration::from_secs(2),
            "{waited:?}"
        );

        // The thread is still stuck: a new call fails at once rather than
        // queueing behind it, once the stuck command is older than the deadline.
        std::thread::sleep(Duration::from_millis(20));
        let t = Instant::now();
        let ran = Arc::new(AtomicBool::new(false));
        let r = ran.clone();
        let err = exec
            .run("next", Class::Other, move || {
                r.store(true, Ordering::SeqCst);
                Ok(())
            })
            .unwrap_err();
        assert!(err.to_string().contains("has not answered"), "{err}");
        assert!(t.elapsed() < Duration::from_millis(100));

        // Once the chip answers, the executor serves again.
        release.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(exec.run("after", Class::Other, || Ok(7)).unwrap(), 7);
        assert!(!ran.load(Ordering::SeqCst), "a refused call never runs");
    }

    #[test]
    fn a_call_that_timed_out_while_queued_is_skipped() {
        let exec = Arc::new(Executor::new(limits(150)));
        let (release, hung) = mpsc::channel::<()>();
        let e = exec.clone();
        let first = std::thread::spawn(move || {
            e.run("slow", Class::Other, move || {
                let _ = hung.recv();
                Ok(())
            })
        });
        std::thread::sleep(Duration::from_millis(20));
        let ran = Arc::new(AtomicBool::new(false));
        let r = ran.clone();
        assert!(
            exec.run("queued", Class::Other, move || {
                r.store(true, Ordering::SeqCst);
                Ok(())
            })
            .is_err()
        );
        release.send(()).unwrap();
        assert!(first.join().unwrap().is_err());
        std::thread::sleep(Duration::from_millis(50));
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[test]
    fn commands_never_overlap() {
        let exec = Arc::new(Executor::new(limits(5_000)));
        let inside = Arc::new(AtomicUsize::new(0));
        let overlapped = Arc::new(AtomicBool::new(false));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (exec, inside, overlapped) = (exec.clone(), inside.clone(), overlapped.clone());
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        let (inside, overlapped) = (inside.clone(), overlapped.clone());
                        exec.run("op", Class::Other, move || {
                            if inside.fetch_add(1, Ordering::SeqCst) != 0 {
                                overlapped.store(true, Ordering::SeqCst);
                            }
                            std::thread::sleep(Duration::from_micros(200));
                            inside.fetch_sub(1, Ordering::SeqCst);
                            Ok(())
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert!(!overlapped.load(Ordering::SeqCst));
    }

    #[test]
    fn signing_is_rate_limited() {
        let exec = Executor::new(Limits {
            call_timeout: Duration::from_millis(300),
            signs_per_second: 2,
            quotes_per_second: 1000,
        });
        let sign = crate::tpm_wire::sign_command(0x8000_0000, &[0u8; 32]);
        assert_eq!(Class::of(&sign), Class::Sign);
        // The burst of two passes; the third would wait 500 ms, past the
        // 300 ms deadline, so it is refused without reaching the chip.
        for _ in 0..2 {
            exec.run("sign", Class::Sign, || Ok(())).unwrap();
        }
        let err = exec.run("sign", Class::Sign, || Ok(())).unwrap_err();
        assert!(err.to_string().contains("rate limit"), "{err}");
        // Other commands are not held back by the signing limit.
        exec.run("read", Class::Other, || Ok(())).unwrap();
    }

    #[test]
    fn a_panicking_command_does_not_stop_the_thread() {
        let exec = Executor::new(limits(1_000));
        assert!(
            exec.run::<()>("boom", Class::Other, || panic!("boom"))
                .is_err()
        );
        assert_eq!(exec.run("ok", Class::Other, || Ok(1)).unwrap(), 1);
    }

    #[test]
    fn zero_limits_are_refused() {
        assert!(
            configure(Limits {
                call_timeout: Duration::ZERO,
                ..Limits::default()
            })
            .is_err()
        );
    }
}
