use std::time::Instant;

/// Returns the current high-resolution timestamp.
#[inline]
pub fn now() -> Instant {
    Instant::now()
}

/// Returns elapsed time in microseconds since `start`.
#[inline]
pub fn elapsed_us(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1_000_000.0
}

/// Returns elapsed time in milliseconds since `start`.
#[inline]
pub fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1_000.0
}
