// Enterprise Features & Governance Module
// Comprehensive enterprise-grade features for CLAUDE DLS platform

pub mod authentication;
pub mod authorization;
pub mod governance;
pub mod compliance;
pub mod marketplace;
pub mod licensing;
pub mod enterprise_analytics;
pub mod audit;

pub use authentication::{EnterpriseAuthenticationManager, AuthenticationProvider, SSOManager};
pub use authorization::{AuthorizationEngine, PolicyEngine, AccessControlManager};
pub use governance::{GovernanceFramework, PolicyManager, ComplianceEngine};
pub use compliance::{ComplianceManager, RegulatoryFramework, AuditTrailManager};
pub use marketplace::{MarketplaceManager, PluginRegistry, ExtensionManager};
pub use licensing::{LicensingManager, LicenseValidator, UsageTracker};
pub use enterprise_analytics::{EnterpriseAnalyticsEngine, BusinessIntelligence, ReportingEngine};
pub use audit::{AuditManager, SecurityAuditEngine, ComplianceAuditor};