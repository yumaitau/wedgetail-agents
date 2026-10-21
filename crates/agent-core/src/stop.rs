use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// A shared stop flag that threads can sleep on.
#[derive(Debug, Clone, Default)]
pub struct Stop(Arc<(Mutex<bool>, Condvar)>);

impl Stop {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stop(&self) {
        let (flag, cv) = &*self.0;
        *flag.lock().unwrap_or_else(PoisonError::into_inner) = true;
        cv.notify_all();
    }

    pub fn is_stopped(&self) -> bool {
        *self.0.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sleep for `d` or until stopped. Returns true if stopped.
    pub fn wait(&self, d: Duration) -> bool {
        let (flag, cv) = &*self.0;
        let deadline = Instant::now() + d;
        let mut stopped = flag.lock().unwrap_or_else(PoisonError::into_inner);
        while !*stopped {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            stopped = cv
                .wait_timeout(stopped, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        *stopped
    }
}
