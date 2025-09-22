pub mod zero_trust;
pub mod threat_detection;
pub mod legacy;

// Zero Trust components
pub use zero_trust::{ZeroTrustManager, ZeroTrustConfig, TrustScore, TrustFactor,
                     TrustSession, SecurityContext, ThreatIndicator as ZeroTrustThreatIndicator};

// Threat Detection components
pub use threat_detection::{ThreatDetectionEngine, ThreatDetectionConfig,
                          ThreatIndicator as ThreatDetectionIndicator};
pub use legacy::{SecurityManager, NetworkSegment};