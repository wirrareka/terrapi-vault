//! A token-bucket rate limiter for vesta-sync's unauthenticated surface (the
//! enrol-challenge / account / enrol endpoints), so an attacker cannot cheaply
//! mine enrolment salts/params or probe account existence.
//!
//! The bucket is **keyed by vault id**: abuse of one vault's endpoint must not
//! drain the allowance of any other vault (a single global bucket let an
//! attacker hammering *any* vault deny challenges to *all* of them — fine for a
//! single-person instance, but a cross-tenant DoS the moment one host serves
//! more than one vault). A TLS-terminating reverse proxy still does per-IP
//! limiting in front; this is the in-process, per-vault backstop.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Sustained rate (tokens/sec) and burst depth for the unauthenticated endpoints.
pub const DEFAULT_CHALLENGE_RATE_PER_SEC: f64 = 5.0;
pub const DEFAULT_CHALLENGE_BURST: f64 = 20.0;
/// Max distinct vault ids tracked at once. Bounds the limiter's own memory: an
/// attacker spraying random vault ids can create at most this many buckets
/// before the idle-sweep + cap kick in (so the map cannot itself become a DoS).
pub const DEFAULT_MAX_KEYS: usize = 4096;

struct Inner {
    tokens: f64,
    last: Instant,
}

/// A per-key token bucket. Each key's `tokens` refills at `rate_per_sec`, capped
/// at `burst`. The key set is bounded by `max_keys`: when a new key would exceed
/// the cap, idle (fully-refilled) buckets are swept first; if the map is still
/// full of *active* buckets, the new request is denied (fail-closed under memory
/// pressure — keys already present keep working, and the proxy IP-limit is the
/// outer defense).
pub struct KeyedRateBucket {
    inner: Mutex<HashMap<String, Inner>>,
    rate_per_sec: f64,
    burst: f64,
    max_keys: usize,
}

impl KeyedRateBucket {
    #[must_use]
    pub fn new(rate_per_sec: f64, burst: f64, max_keys: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            rate_per_sec,
            burst,
            max_keys,
        }
    }

    /// Consume one token for `key`; `true` if allowed, `false` if throttled.
    /// A previously-unseen key starts full (a burst's worth), so normal use
    /// never waits.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().expect("ratelimit lock");

        // Keep the map bounded before inserting a brand-new key.
        if !map.contains_key(key) && map.len() >= self.max_keys {
            // Drop buckets that have refilled to full — equivalent to absent, so
            // evicting them loses nothing.
            let rate = self.rate_per_sec;
            let burst = self.burst;
            map.retain(|_, i| {
                let refilled = i.tokens + now.duration_since(i.last).as_secs_f64() * rate;
                refilled < burst
            });
            // Still full of active buckets → deny rather than grow unboundedly.
            if map.len() >= self.max_keys {
                return false;
            }
        }

        let i = map.entry(key.to_owned()).or_insert(Inner {
            tokens: self.burst,
            last: now,
        });
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

impl Default for KeyedRateBucket {
    fn default() -> Self {
        Self::new(
            DEFAULT_CHALLENGE_RATE_PER_SEC,
            DEFAULT_CHALLENGE_BURST,
            DEFAULT_MAX_KEYS,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_burst_then_throttles_per_key() {
        let b = KeyedRateBucket::new(0.0, 3.0, 16); // no refill, burst of 3
        assert!(b.allow("vault-a"));
        assert!(b.allow("vault-a"));
        assert!(b.allow("vault-a"));
        assert!(!b.allow("vault-a")); // a's bucket empty
    }

    #[test]
    fn keys_are_independent() {
        let b = KeyedRateBucket::new(0.0, 2.0, 16);
        // Drain vault-a completely.
        assert!(b.allow("vault-a"));
        assert!(b.allow("vault-a"));
        assert!(!b.allow("vault-a"));
        // vault-b is untouched — the cross-vault DoS is gone.
        assert!(b.allow("vault-b"));
        assert!(b.allow("vault-b"));
    }

    #[test]
    fn key_set_is_bounded_and_denies_when_full_of_active_buckets() {
        let b = KeyedRateBucket::new(0.0, 1.0, 2); // no refill, cap 2 keys
        assert!(b.allow("a")); // a active (now empty, not full)
        assert!(b.allow("b")); // b active (now empty)
                               // A third NEW key can't be added (map full of active buckets) → denied.
        assert!(!b.allow("c"));
        // Existing keys are unaffected by the cap.
        assert!(!b.allow("a")); // still throttled on its own merits, not evicted
    }
}
