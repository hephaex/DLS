pub mod legacy;
pub mod threat_detection;
pub mod zero_trust;

// Zero Trust components
pub use zero_trust::{
    SecurityContext, ThreatIndicator as ZeroTrustThreatIndicator, TrustFactor, TrustScore,
    TrustSession, ZeroTrustConfig, ZeroTrustManager,
};

// Threat Detection components
pub use legacy::{NetworkSegment, SecurityManager};
pub use threat_detection::{
    ThreatDetectionConfig, ThreatDetectionEngine, ThreatIndicator as ThreatDetectionIndicator,
};
