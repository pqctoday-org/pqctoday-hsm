use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Health {
    Ready,
    Degraded,
    Disabled,
}

pub struct Runtime {
    health: Health,
    failures: AtomicU64,
}

impl Runtime {
    pub fn new(disabled: bool) -> Self {
        Self {
            health: if disabled {
                Health::Disabled
            } else {
                Health::Ready
            },
            failures: AtomicU64::new(0),
        }
    }

    pub fn health(&self) -> Health {
        self.health
    }

    pub fn failure_count(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Use hardware while it is healthy. Any hardware failure degrades the
    /// runtime and retries this operation once through the software closure.
    pub fn execute<T, E>(
        &mut self,
        hardware: impl FnOnce() -> Result<T, E>,
        software: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        if self.health == Health::Ready {
            match hardware() {
                Ok(value) => return Ok(value),
                Err(_) => {
                    self.failures.fetch_add(1, Ordering::Relaxed);
                    self.health = Health::Degraded;
                }
            }
        }
        software()
    }

    /// A successful known-answer self-test is the only way to restore a
    /// degraded runtime. An operator-disabled runtime stays disabled.
    pub fn self_test<E>(&mut self, test: impl FnOnce() -> Result<(), E>) -> Result<(), E> {
        let result = test();
        if self.health != Health::Disabled {
            self.health = if result.is_ok() {
                Health::Ready
            } else {
                Health::Degraded
            };
        }
        result
    }
}
