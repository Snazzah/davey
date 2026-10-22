use std::time::Duration;
#[cfg(not(test))]
use std::time::Instant;

/// A monotonic clock shared between a decryptor and its cipher managers.
/// In tests, time is frozen and only moves when advanced manually.
pub struct Clock {
  #[cfg(not(test))]
  start: Instant,
  #[cfg(test)]
  now: std::sync::Mutex<Duration>,
}

impl Clock {
  pub fn new() -> Self {
    Self {
      #[cfg(not(test))]
      start: Instant::now(),
      #[cfg(test)]
      now: std::sync::Mutex::new(Duration::ZERO),
    }
  }

  /// The time elapsed since the clock was created.
  pub fn elapsed(&self) -> Duration {
    #[cfg(not(test))]
    return self.start.elapsed();

    #[cfg(test)]
    *self.now.lock().unwrap()
  }

  #[cfg(test)]
  pub fn advance(&self, duration: Duration) {
    *self.now.lock().unwrap() += duration;
  }
}
