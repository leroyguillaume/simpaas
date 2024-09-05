use chrono::{DateTime, FixedOffset, Utc};

// Traits

#[cfg_attr(test, mockall::automock)]
pub trait Clock: Send + Sync {
    fn utc(&self) -> DateTime<FixedOffset>;
}

// DefaultClock

pub struct DefaultClock;

impl Clock for DefaultClock {
    fn utc(&self) -> DateTime<FixedOffset> {
        Utc::now().into()
    }
}
