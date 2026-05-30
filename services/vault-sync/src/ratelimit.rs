//! A tiny token-bucket rate limiter for vault-sync's unauthenticated surface (the
//! enrol-challenge endpoint), so an attacker cannot cheaply mine enrolment salts/params or
//! probe account existence. One shared bucket is enough: a vault-sync instance serves a
//! single person's devices, and a TLS-terminating reverse proxy does per-IP limiting in
//! front — this is the in-process backstop.

use std::sync::Mutex;
use std::time::Instant;

/// Sustained rate (tokens/sec) and burst depth for the unauthenticated challenge endpoint.
pub const DEFAULT_CHALLENGE_RATE_PER_SEC: f64 = 5.0;
pub const DEFAULT_CHALLENGE_BURST: f64 = 20.0;

/// A single shared token bucket. `tokens` refills at `rate_per_sec`, capped at `burst`.
pub struct RateBucket {
    inner: Mutex<Inner>,
    rate_per_sec: f64,
    burst: f64,
}

struct Inner {
    tokens: f64,
    last: Instant,
}

impl RateBucket {
    /// A bucket that starts full (a burst's worth), so normal use never waits.
    #[must_use]
    pub fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                tokens: burst,
                last: Instant::now(),
            }),
            rate_per_sec,
            burst,
        }
    }

    /// Consume one token; `true` if allowed, `false` if the bucket is empty.
    pub fn allow(&self) -> bool {
        let now = Instant::now();
        let mut i = self.inner.lock().expect("ratelimit lock");
        let elapsed = now.duration_since(i.last).as_secs_f64();
        i.last = now;
        i.tokens = (i.tokens + elapsed * self.rate_per_sec).min(self.burst);
        if i.tokens >= 1.0 {
            i.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Default for RateBucket {
    fn default() -> Self {
        Self::new(DEFAULT_CHALLENGE_RATE_PER_SEC, DEFAULT_CHALLENGE_BURST)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_burst_then_throttles() {
        let b = RateBucket::new(0.0, 3.0); // no refill, burst of 3
        assert!(b.allow());
        assert!(b.allow());
        assert!(b.allow());
        assert!(!b.allow()); // empty
    }
}
