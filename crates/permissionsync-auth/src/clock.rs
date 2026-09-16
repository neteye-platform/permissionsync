//! The narrow internal time source consulted by verification: a monotonic
//! tick for cache aging, and wall-clock unix seconds for claim temporal
//! validity. Kept behind a trait so tests can substitute deterministic time.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub(crate) trait Clock: Send + Sync {
    fn tick(&self) -> Instant;
    fn unix_seconds(&self) -> Option<f64>;
}

pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn tick(&self) -> Instant {
        Instant::now()
    }
    fn unix_seconds(&self) -> Option<f64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|value| value.as_secs_f64())
    }
}
