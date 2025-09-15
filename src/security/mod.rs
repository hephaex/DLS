pub mod zero_trust;
pub mod threat_detection;
pub mod legacy;

pub use zero_trust::*;
pub use threat_detection::*;
pub use legacy::{SecurityManager, NetworkSegment};