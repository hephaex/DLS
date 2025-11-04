// Enterprise Features & Governance Module
// Comprehensive enterprise-grade features for CLAUDE DLS platform

pub mod audit;
pub mod authentication;
pub mod authorization;
pub mod compliance;
pub mod enterprise_analytics;
pub mod governance;
pub mod licensing;
pub mod marketplace;

pub use audit::{AuditManager, ComplianceAuditor, SecurityAuditEngine};
pub use authentication::{AuthenticationProvider, EnterpriseAuthenticationManager, SSOManager};
pub use authorization::{AccessControlManager, AuthorizationEngine, PolicyEngine};
pub use compliance::{AuditTrailManager, ComplianceManager, RegulatoryFramework};
pub use enterprise_analytics::{BusinessIntelligence, EnterpriseAnalyticsEngine, ReportingEngine};
pub use governance::{ComplianceEngine, GovernanceFramework, PolicyManager};
pub use licensing::{LicenseValidator, LicensingManager, UsageTracker};
pub use marketplace::{ExtensionManager, MarketplaceManager, PluginRegistry};
