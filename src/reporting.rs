use crate::error::Result;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReportType {
    ComplianceAudit,
    SecurityAssessment,
    PerformanceAnalysis,
    UsageStatistics,
    IncidentReport,
    SystemHealth,
    AccessControl,
    DataRetention,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReportFormat {
    PDF,
    HTML,
    CSV,
    JSON,
    XML,
    Excel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceFramework {
    SOX,      // Sarbanes-Oxley
    HIPAA,    // Health Insurance Portability and Accountability Act
    GDPR,     // General Data Protection Regulation
    SOC2,     // Service Organization Control 2
    ISO27001, // Information Security Management
    PciDss,   // Payment Card Industry Data Security Standard
    FISMA,    // Federal Information Security Management Act
    NIST,     // National Institute of Standards and Technology
    CIS,      // Center for Internet Security
    COBIT,    // Control Objectives for Information Technologies
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReportStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRequirement {
    pub id: String,
    pub framework: ComplianceFramework,
    pub control_id: String,
    pub title: String,
    pub description: String,
    pub implementation_status: ComplianceStatus,
    pub evidence_required: Vec<String>,
    pub responsible_party: String,
    pub due_date: Option<DateTime<Utc>>,
    pub last_assessment: Option<DateTime<Utc>>,
    pub risk_level: RiskLevel,
    pub remediation_plan: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceStatus {
    NotImplemented,
    InProgress,
    Implemented,
    NonCompliant,
    PartiallyCompliant,
    FullyCompliant,
    Exempt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrail {
    pub id: Uuid,
    pub event_type: AuditEventType,
    pub user_id: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub resource_id: Option<String>,
    pub action: String,
    pub details: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
    pub outcome: AuditOutcome,
    pub risk_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditEventType {
    Authentication,
    Authorization,
    DataAccess,
    DataModification,
    SystemAccess,
    ConfigurationChange,
    SecurityEvent,
    ComplianceEvent,
    AdminAction,
    UserAction,
    SystemEvent,
    NetworkEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditOutcome {
    Success,
    Failure,
    Warning,
    Information,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: Uuid,
    pub report_type: ReportType,
    pub title: String,
    pub description: String,
    pub created_by: String,
    pub tenant_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub generated_at: Option<DateTime<Utc>>,
    pub status: ReportStatus,
    pub format: ReportFormat,
    pub parameters: ReportParameters,
    pub data: serde_json::Value,
    pub file_path: Option<String>,
    pub size_bytes: Option<u64>,
    pub retention_until: DateTime<Utc>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportParameters {
    pub date_range: Option<DateRange>,
    pub tenant_filter: Option<Vec<Uuid>>,
    pub user_filter: Option<Vec<String>>,
    pub resource_filter: Option<Vec<String>>,
    pub compliance_framework: Option<ComplianceFramework>,
    pub risk_level_filter: Option<Vec<RiskLevel>>,
    pub custom_filters: HashMap<String, serde_json::Value>,
    pub include_raw_data: bool,
    pub include_charts: bool,
    pub include_recommendations: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework: ComplianceFramework,
    pub assessment_date: DateTime<Utc>,
    pub overall_score: f64,
    pub total_controls: usize,
    pub compliant_controls: usize,
    pub non_compliant_controls: usize,
    pub partially_compliant_controls: usize,
    pub requirements: Vec<ComplianceRequirement>,
    pub findings: Vec<ComplianceFinding>,
    pub recommendations: Vec<ComplianceRecommendation>,
    pub executive_summary: String,
    pub next_assessment_date: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    pub id: Uuid,
    pub severity: RiskLevel,
    pub control_id: String,
    pub finding_type: FindingType,
    pub title: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub remediation: String,
    pub due_date: DateTime<Utc>,
    pub status: FindingStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingType {
    Gap,
    Weakness,
    NonCompliance,
    Improvement,
    Observation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingStatus {
    Open,
    InRemediation,
    Resolved,
    Accepted,
    Mitigated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRecommendation {
    pub id: Uuid,
    pub priority: RiskLevel,
    pub title: String,
    pub description: String,
    pub implementation_steps: Vec<String>,
    pub estimated_effort: String,
    pub cost_estimate: Option<f64>,
    pub timeline: String,
    pub responsible_party: String,
}

#[derive(Debug, Clone)]
pub struct ReportingConfig {
    pub storage_path: String,
    pub max_report_age_days: u64,
    pub max_storage_size_gb: u64,
    pub auto_cleanup_enabled: bool,
    pub encryption_enabled: bool,
    pub compress_reports: bool,
    pub audit_trail_retention_days: u64,
    pub default_report_format: ReportFormat,
    pub concurrent_report_limit: usize,
    pub compliance_frameworks: Vec<ComplianceFramework>,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            storage_path: "./reports".to_string(),
            max_report_age_days: 2555, // 7 years for compliance
            max_storage_size_gb: 100,
            auto_cleanup_enabled: true,
            encryption_enabled: true,
            compress_reports: true,
            audit_trail_retention_days: 2555,
            default_report_format: ReportFormat::PDF,
            concurrent_report_limit: 10,
            compliance_frameworks: vec![
                ComplianceFramework::SOX,
                ComplianceFramework::SOC2,
                ComplianceFramework::ISO27001,
            ],
        }
    }
}

#[derive(Debug)]
pub struct ReportingEngine {
    config: ReportingConfig,
    reports: Arc<DashMap<Uuid, Report>>,
    audit_trails: Arc<RwLock<Vec<AuditTrail>>>,
    compliance_requirements: Arc<DashMap<String, ComplianceRequirement>>,
    active_generators: Arc<DashMap<Uuid, tokio::task::JoinHandle<Result<()>>>>,
    templates: Arc<DashMap<String, ReportTemplate>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub report_type: ReportType,
    pub default_parameters: ReportParameters,
    pub template_content: String,
    pub required_permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ReportingEngine {
    pub fn new(config: ReportingConfig) -> Self {
        Self {
            config,
            reports: Arc::new(DashMap::new()),
            audit_trails: Arc::new(RwLock::new(Vec::new())),
            compliance_requirements: Arc::new(DashMap::new()),
            active_generators: Arc::new(DashMap::new()),
            templates: Arc::new(DashMap::new()),
        }
    }

    pub async fn start(&self) -> Result<()> {
        // Create storage directory if it doesn't exist
        fs::create_dir_all(&self.config.storage_path).await?;

        // Load existing reports
        self.load_existing_reports().await?;

        // Load compliance requirements
        self.load_compliance_requirements().await?;

        // Load report templates
        self.load_report_templates().await?;

        // Start cleanup task
        if self.config.auto_cleanup_enabled {
            self.start_cleanup_task().await;
        }

        Ok(())
    }

    // Getter methods for testing
    pub fn reports(&self) -> &Arc<DashMap<Uuid, Report>> {
        &self.reports
    }

    pub fn compliance_requirements(&self) -> &Arc<DashMap<String, ComplianceRequirement>> {
        &self.compliance_requirements
    }

    pub fn audit_trails(&self) -> &Arc<RwLock<Vec<AuditTrail>>> {
        &self.audit_trails
    }

    pub fn templates(&self) -> &Arc<DashMap<String, ReportTemplate>> {
        &self.templates
    }

    pub fn active_generators(&self) -> &Arc<DashMap<Uuid, tokio::task::JoinHandle<Result<()>>>> {
        &self.active_generators
    }

    pub async fn load_compliance_requirements_public(&self) -> Result<()> {
        self.load_compliance_requirements().await
    }

    pub async fn load_report_templates_public(&self) -> Result<()> {
        self.load_report_templates().await
    }

    async fn load_existing_reports(&self) -> Result<()> {
        // Implementation would load reports from storage
        // For now, this is a placeholder
        Ok(())
    }

    async fn load_compliance_requirements(&self) -> Result<()> {
        // Load compliance requirements for various frameworks
        self.load_sox_requirements().await?;
        self.load_soc2_requirements().await?;
        self.load_iso27001_requirements().await?;
        self.load_gdpr_requirements().await?;
        Ok(())
    }

    async fn load_sox_requirements(&self) -> Result<()> {
        let requirements = vec![
            ComplianceRequirement {
                id: "SOX-302".to_string(),
                framework: ComplianceFramework::SOX,
                control_id: "302".to_string(),
                title: "Corporate Responsibility for Financial Reports".to_string(),
                description:
                    "Principal executive and financial officers must certify financial reports"
                        .to_string(),
                implementation_status: ComplianceStatus::NotImplemented,
                evidence_required: vec![
                    "Officer certifications".to_string(),
                    "Internal control assessments".to_string(),
                ],
                responsible_party: "CFO/CEO".to_string(),
                due_date: None,
                last_assessment: None,
                risk_level: RiskLevel::High,
                remediation_plan: None,
            },
            ComplianceRequirement {
                id: "SOX-404".to_string(),
                framework: ComplianceFramework::SOX,
                control_id: "404".to_string(),
                title: "Management Assessment of Internal Controls".to_string(),
                description: "Annual assessment of internal control over financial reporting"
                    .to_string(),
                implementation_status: ComplianceStatus::NotImplemented,
                evidence_required: vec![
                    "Internal control documentation".to_string(),
                    "Testing evidence".to_string(),
                    "Management assessment report".to_string(),
                ],
                responsible_party: "Internal Audit".to_string(),
                due_date: None,
                last_assessment: None,
                risk_level: RiskLevel::Critical,
                remediation_plan: None,
            },
        ];

        for req in requirements {
            self.compliance_requirements.insert(req.id.clone(), req);
        }
        Ok(())
    }

    async fn load_soc2_requirements(&self) -> Result<()> {
        let requirements = vec![
            ComplianceRequirement {
                id: "SOC2-CC1.0".to_string(),
                framework: ComplianceFramework::SOC2,
                control_id: "CC1.0".to_string(),
                title: "Control Environment".to_string(),
                description: "The entity demonstrates a commitment to integrity and ethical values"
                    .to_string(),
                implementation_status: ComplianceStatus::NotImplemented,
                evidence_required: vec![
                    "Code of conduct".to_string(),
                    "Ethics training records".to_string(),
                    "Policy documentation".to_string(),
                ],
                responsible_party: "CISO".to_string(),
                due_date: None,
                last_assessment: None,
                risk_level: RiskLevel::High,
                remediation_plan: None,
            },
            ComplianceRequirement {
                id: "SOC2-CC6.0".to_string(),
                framework: ComplianceFramework::SOC2,
                control_id: "CC6.0".to_string(),
                title: "Logical and Physical Access Controls".to_string(),
                description: "The entity implements logical and physical access controls"
                    .to_string(),
                implementation_status: ComplianceStatus::NotImplemented,
                evidence_required: vec![
                    "Access control matrices".to_string(),
                    "User access reviews".to_string(),
                    "Physical security assessments".to_string(),
                ],
                responsible_party: "IT Security".to_string(),
                due_date: None,
                last_assessment: None,
                risk_level: RiskLevel::Critical,
                remediation_plan: None,
            },
        ];

        for req in requirements {
            self.compliance_requirements.insert(req.id.clone(), req);
        }
        Ok(())
    }

    async fn load_iso27001_requirements(&self) -> Result<()> {
        let requirements = vec![
            ComplianceRequirement {
                id: "ISO27001-A.5.1".to_string(),
                framework: ComplianceFramework::ISO27001,
                control_id: "A.5.1".to_string(),
                title: "Information Security Policies".to_string(),
                description: "A set of policies for information security shall be defined"
                    .to_string(),
                implementation_status: ComplianceStatus::NotImplemented,
                evidence_required: vec![
                    "Information security policy".to_string(),
                    "Policy approval records".to_string(),
                    "Communication records".to_string(),
                ],
                responsible_party: "CISO".to_string(),
                due_date: None,
                last_assessment: None,
                risk_level: RiskLevel::High,
                remediation_plan: None,
            },
            ComplianceRequirement {
                id: "ISO27001-A.8.1".to_string(),
                framework: ComplianceFramework::ISO27001,
                control_id: "A.8.1".to_string(),
                title: "Responsibility for Assets".to_string(),
                description: "Assets shall be identified and responsibility for protection defined"
                    .to_string(),
                implementation_status: ComplianceStatus::NotImplemented,
                evidence_required: vec![
                    "Asset inventory".to_string(),
                    "Asset ownership records".to_string(),
                    "Asset classification".to_string(),
                ],
                responsible_party: "IT Asset Management".to_string(),
                due_date: None,
                last_assessment: None,
                risk_level: RiskLevel::Medium,
                remediation_plan: None,
            },
        ];

        for req in requirements {
            self.compliance_requirements.insert(req.id.clone(), req);
        }
        Ok(())
    }

    async fn load_gdpr_requirements(&self) -> Result<()> {
        let requirements = vec![
            ComplianceRequirement {
                id: "GDPR-Art.32".to_string(),
                framework: ComplianceFramework::GDPR,
                control_id: "Article 32".to_string(),
                title: "Security of Processing".to_string(),
                description: "Appropriate technical and organizational measures for data security"
                    .to_string(),
                implementation_status: ComplianceStatus::NotImplemented,
                evidence_required: vec![
                    "Security measures documentation".to_string(),
                    "Encryption implementation".to_string(),
                    "Access control procedures".to_string(),
                ],
                responsible_party: "Data Protection Officer".to_string(),
                due_date: None,
                last_assessment: None,
                risk_level: RiskLevel::Critical,
                remediation_plan: None,
            },
            ComplianceRequirement {
                id: "GDPR-Art.33".to_string(),
                framework: ComplianceFramework::GDPR,
                control_id: "Article 33".to_string(),
                title: "Notification of Data Breach".to_string(),
                description: "Data breach notification to supervisory authority within 72 hours"
                    .to_string(),
                implementation_status: ComplianceStatus::NotImplemented,
                evidence_required: vec![
                    "Breach response procedures".to_string(),
                    "Notification templates".to_string(),
                    "Contact information".to_string(),
                ],
                responsible_party: "Data Protection Officer".to_string(),
                due_date: None,
                last_assessment: None,
                risk_level: RiskLevel::Critical,
                remediation_plan: None,
            },
        ];

        for req in requirements {
            self.compliance_requirements.insert(req.id.clone(), req);
        }
        Ok(())
    }

    async fn load_report_templates(&self) -> Result<()> {
        // Load predefined report templates
        let templates = vec![
            ReportTemplate {
                id: "compliance_audit".to_string(),
                name: "Compliance Audit Report".to_string(),
                description: "Comprehensive compliance assessment report".to_string(),
                report_type: ReportType::ComplianceAudit,
                default_parameters: ReportParameters {
                    date_range: Some(DateRange {
                        start: Utc::now() - Duration::days(90),
                        end: Utc::now(),
                    }),
                    tenant_filter: None,
                    user_filter: None,
                    resource_filter: None,
                    compliance_framework: Some(ComplianceFramework::SOC2),
                    risk_level_filter: None,
                    custom_filters: HashMap::new(),
                    include_raw_data: false,
                    include_charts: true,
                    include_recommendations: true,
                },
                template_content: "<!-- Compliance audit template placeholder -->".to_string(),
                required_permissions: vec!["compliance.read".to_string()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            ReportTemplate {
                id: "security_assessment".to_string(),
                name: "Security Assessment Report".to_string(),
                description: "Comprehensive security posture assessment".to_string(),
                report_type: ReportType::SecurityAssessment,
                default_parameters: ReportParameters {
                    date_range: Some(DateRange {
                        start: Utc::now() - Duration::days(30),
                        end: Utc::now(),
                    }),
                    tenant_filter: None,
                    user_filter: None,
                    resource_filter: None,
                    compliance_framework: None,
                    risk_level_filter: Some(vec![RiskLevel::High, RiskLevel::Critical]),
                    custom_filters: HashMap::new(),
                    include_raw_data: true,
                    include_charts: true,
                    include_recommendations: true,
                },
                template_content: "<!-- Security assessment template placeholder -->".to_string(),
                required_permissions: vec!["security.read".to_string()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ];

        for template in templates {
            self.templates.insert(template.id.clone(), template);
        }
        Ok(())
    }

    async fn start_cleanup_task(&self) {
        let config = self.config.clone();
        let reports = Arc::clone(&self.reports);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::hours(24).to_std().unwrap());

            loop {
                interval.tick().await;

                // Clean up expired reports
                let cutoff_date = Utc::now() - Duration::days(config.max_report_age_days as i64);
                let mut to_remove = Vec::new();

                for entry in reports.iter() {
                    let report = entry.value();
                    if report.retention_until < cutoff_date {
                        to_remove.push(*entry.key());
                    }
                }

                for report_id in to_remove {
                    if let Some((_, report)) = reports.remove(&report_id) {
                        if let Some(file_path) = report.file_path {
                            let _ = fs::remove_file(&file_path).await;
                        }
                    }
                }
            }
        });
    }

    pub async fn create_report(&self, mut report: Report) -> Result<Uuid> {
        report.id = Uuid::new_v4();
        report.created_at = Utc::now();
        report.updated_at = Utc::now();
        report.status = ReportStatus::Pending;

        let report_id = report.id;
        self.reports.insert(report_id, report);

        Ok(report_id)
    }

    pub async fn generate_report(&self, report_id: Uuid) -> Result<()> {
        // Check if already generating
        if self.active_generators.contains_key(&report_id) {
            return Err(crate::error::DlsError::ReportGenerationInProgress);
        }

        let reports = Arc::clone(&self.reports);
        let config = self.config.clone();
        let audit_trails = Arc::clone(&self.audit_trails);
        let compliance_requirements = Arc::clone(&self.compliance_requirements);

        let handle = tokio::spawn(async move {
            if let Some(mut report) = reports.get_mut(&report_id) {
                report.status = ReportStatus::InProgress;
                report.updated_at = Utc::now();

                let result = match report.report_type {
                    ReportType::ComplianceAudit => {
                        Self::generate_compliance_report(
                            &report,
                            &config,
                            &compliance_requirements,
                        )
                        .await
                    }
                    ReportType::SecurityAssessment => {
                        Self::generate_security_report(&report, &config, &audit_trails).await
                    }
                    ReportType::PerformanceAnalysis => {
                        Self::generate_performance_report(&report, &config).await
                    }
                    ReportType::UsageStatistics => {
                        Self::generate_usage_report(&report, &config, &audit_trails).await
                    }
                    ReportType::IncidentReport => {
                        Self::generate_incident_report(&report, &config, &audit_trails).await
                    }
                    ReportType::SystemHealth => {
                        Self::generate_health_report(&report, &config).await
                    }
                    ReportType::AccessControl => {
                        Self::generate_access_report(&report, &config, &audit_trails).await
                    }
                    ReportType::DataRetention => {
                        Self::generate_retention_report(&report, &config).await
                    }
                    ReportType::Custom(_) => Self::generate_custom_report(&report, &config).await,
                };

                match result {
                    Ok(file_path) => {
                        report.status = ReportStatus::Completed;
                        report.generated_at = Some(Utc::now());
                        report.file_path = Some(file_path);
                        report.updated_at = Utc::now();
                    }
                    Err(_) => {
                        report.status = ReportStatus::Failed;
                        report.updated_at = Utc::now();
                    }
                }
            }

            Ok(())
        });

        self.active_generators.insert(report_id, handle);
        Ok(())
    }

    async fn generate_compliance_report(
        report: &Report,
        config: &ReportingConfig,
        compliance_requirements: &Arc<DashMap<String, ComplianceRequirement>>,
    ) -> Result<String> {
        let framework = report
            .parameters
            .compliance_framework
            .as_ref()
            .unwrap_or(&ComplianceFramework::SOC2);

        // Collect relevant requirements
        let requirements: Vec<ComplianceRequirement> = compliance_requirements
            .iter()
            .filter(|req| &req.value().framework == framework)
            .map(|req| req.value().clone())
            .collect();

        let total_controls = requirements.len();
        let compliant_controls = requirements
            .iter()
            .filter(|req| req.implementation_status == ComplianceStatus::FullyCompliant)
            .count();
        let non_compliant_controls = requirements
            .iter()
            .filter(|req| req.implementation_status == ComplianceStatus::NonCompliant)
            .count();
        let partially_compliant_controls = requirements
            .iter()
            .filter(|req| req.implementation_status == ComplianceStatus::PartiallyCompliant)
            .count();

        let overall_score = if total_controls > 0 {
            (compliant_controls as f64 + partially_compliant_controls as f64 * 0.5)
                / total_controls as f64
                * 100.0
        } else {
            0.0
        };

        let compliance_report = ComplianceReport {
            framework: framework.clone(),
            assessment_date: Utc::now(),
            overall_score,
            total_controls,
            compliant_controls,
            non_compliant_controls,
            partially_compliant_controls,
            requirements,
            findings: Vec::new(), // Would be populated with actual findings
            recommendations: Vec::new(), // Would be populated with recommendations
            executive_summary: format!(
                "Compliance assessment for {framework:?} framework shows {overall_score:.1}% overall compliance with {total_controls} total controls assessed."
            ),
            next_assessment_date: Utc::now() + Duration::days(90),
        };

        // Generate report file
        let file_path = format!(
            "{}/compliance_{}_{}.{}",
            config.storage_path,
            format!("{framework:?}").to_lowercase(),
            report.id,
            match report.format {
                ReportFormat::PDF => "pdf",
                ReportFormat::HTML => "html",
                ReportFormat::JSON => "json",
                _ => "txt",
            }
        );

        let report_content = match report.format {
            ReportFormat::JSON => serde_json::to_string_pretty(&compliance_report)?,
            ReportFormat::HTML => Self::generate_html_compliance_report(&compliance_report)?,
            _ => Self::generate_text_compliance_report(&compliance_report)?,
        };

        let mut file = fs::File::create(&file_path).await?;
        file.write_all(report_content.as_bytes()).await?;

        Ok(file_path)
    }

    pub fn generate_html_compliance_report(report: &ComplianceReport) -> Result<String> {
        let html = format!(
            r#"
<!DOCTYPE html>
<html>
<head>
    <title>Compliance Report - {:?}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .score {{ font-size: 24px; font-weight: bold; color: {}; }}
        .metrics {{ display: flex; gap: 20px; margin: 20px 0; }}
        .metric {{ background: #f9f9f9; padding: 10px; border-radius: 5px; flex: 1; }}
        .requirements {{ margin: 20px 0; }}
        .requirement {{ background: white; border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .status-compliant {{ border-left: 4px solid #4CAF50; }}
        .status-partial {{ border-left: 4px solid #FF9800; }}
        .status-noncompliant {{ border-left: 4px solid #F44336; }}
        .status-not-implemented {{ border-left: 4px solid #9E9E9E; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Compliance Assessment Report</h1>
        <h2>Framework: {:?}</h2>
        <p>Assessment Date: {}</p>
        <div class="score">Overall Score: {:.1}%</div>
    </div>
    
    <div class="metrics">
        <div class="metric">
            <h3>Total Controls</h3>
            <div style="font-size: 20px; font-weight: bold;">{}</div>
        </div>
        <div class="metric">
            <h3>Compliant</h3>
            <div style="font-size: 20px; font-weight: bold; color: #4CAF50;">{}</div>
        </div>
        <div class="metric">
            <h3>Partially Compliant</h3>
            <div style="font-size: 20px; font-weight: bold; color: #FF9800;">{}</div>
        </div>
        <div class="metric">
            <h3>Non-Compliant</h3>
            <div style="font-size: 20px; font-weight: bold; color: #F44336;">{}</div>
        </div>
    </div>
    
    <h2>Executive Summary</h2>
    <p>{}</p>
    
    <h2>Requirements Assessment</h2>
    <div class="requirements">
        {}
    </div>
    
    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
        <p>Next Assessment Date: {}</p>
        <p>Generated: {}</p>
    </div>
</body>
</html>
"#,
            report.framework,
            if report.overall_score >= 80.0 {
                "#4CAF50"
            } else if report.overall_score >= 60.0 {
                "#FF9800"
            } else {
                "#F44336"
            },
            report.framework,
            report.assessment_date.format("%Y-%m-%d %H:%M:%S UTC"),
            report.overall_score,
            report.total_controls,
            report.compliant_controls,
            report.partially_compliant_controls,
            report.non_compliant_controls,
            report.executive_summary,
            report
                .requirements
                .iter()
                .map(|req| {
                    let status_class = match req.implementation_status {
                        ComplianceStatus::FullyCompliant => "status-compliant",
                        ComplianceStatus::PartiallyCompliant => "status-partial",
                        ComplianceStatus::NonCompliant => "status-noncompliant",
                        _ => "status-not-implemented",
                    };
                    format!(
                        r#"
                <div class="requirement {}">
                    <h4>{} - {}</h4>
                    <p><strong>Status:</strong> {:?}</p>
                    <p><strong>Risk Level:</strong> {:?}</p>
                    <p>{}</p>
                    <p><strong>Responsible Party:</strong> {}</p>
                    <p><strong>Evidence Required:</strong> {}</p>
                </div>
                "#,
                        status_class,
                        req.control_id,
                        req.title,
                        req.implementation_status,
                        req.risk_level,
                        req.description,
                        req.responsible_party,
                        req.evidence_required.join(", ")
                    )
                })
                .collect::<Vec<String>>()
                .join(""),
            report.next_assessment_date.format("%Y-%m-%d"),
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        );
        Ok(html)
    }

    pub fn generate_text_compliance_report(report: &ComplianceReport) -> Result<String> {
        let mut content = String::new();
        content.push_str("COMPLIANCE ASSESSMENT REPORT\n");
        content.push_str(&format!("Framework: {:?}\n", report.framework));
        content.push_str(&format!(
            "Assessment Date: {}\n",
            report.assessment_date.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        content.push_str(&format!("Overall Score: {:.1}%\n\n", report.overall_score));

        content.push_str("SUMMARY\n");
        content.push_str(&format!("Total Controls: {}\n", report.total_controls));
        content.push_str(&format!("Compliant: {}\n", report.compliant_controls));
        content.push_str(&format!(
            "Partially Compliant: {}\n",
            report.partially_compliant_controls
        ));
        content.push_str(&format!(
            "Non-Compliant: {}\n\n",
            report.non_compliant_controls
        ));

        content.push_str(&format!(
            "EXECUTIVE SUMMARY\n{}\n\n",
            report.executive_summary
        ));

        content.push_str("REQUIREMENTS\n");
        for req in &report.requirements {
            content.push_str(&format!("- {} - {}\n", req.control_id, req.title));
            content.push_str(&format!("  Status: {:?}\n", req.implementation_status));
            content.push_str(&format!("  Risk Level: {:?}\n", req.risk_level));
            content.push_str(&format!("  Responsible: {}\n", req.responsible_party));
            content.push_str(&format!("  Description: {}\n\n", req.description));
        }

        content.push_str(&format!(
            "Next Assessment: {}\n",
            report.next_assessment_date.format("%Y-%m-%d")
        ));

        Ok(content)
    }

    async fn generate_security_report(
        _report: &Report,
        config: &ReportingConfig,
        _audit_trails: &Arc<RwLock<Vec<AuditTrail>>>,
    ) -> Result<String> {
        let file_path = format!("{}/security_report_placeholder.txt", config.storage_path);
        let mut file = fs::File::create(&file_path).await?;
        file.write_all(b"Security assessment report - Implementation pending")
            .await?;
        Ok(file_path)
    }

    async fn generate_performance_report(
        _report: &Report,
        config: &ReportingConfig,
    ) -> Result<String> {
        let file_path = format!("{}/performance_report_placeholder.txt", config.storage_path);
        let mut file = fs::File::create(&file_path).await?;
        file.write_all(b"Performance analysis report - Implementation pending")
            .await?;
        Ok(file_path)
    }

    async fn generate_usage_report(
        _report: &Report,
        config: &ReportingConfig,
        _audit_trails: &Arc<RwLock<Vec<AuditTrail>>>,
    ) -> Result<String> {
        let file_path = format!("{}/usage_report_placeholder.txt", config.storage_path);
        let mut file = fs::File::create(&file_path).await?;
        file.write_all(b"Usage statistics report - Implementation pending")
            .await?;
        Ok(file_path)
    }

    async fn generate_incident_report(
        _report: &Report,
        config: &ReportingConfig,
        _audit_trails: &Arc<RwLock<Vec<AuditTrail>>>,
    ) -> Result<String> {
        let file_path = format!("{}/incident_report_placeholder.txt", config.storage_path);
        let mut file = fs::File::create(&file_path).await?;
        file.write_all(b"Incident report - Implementation pending")
            .await?;
        Ok(file_path)
    }

    async fn generate_health_report(_report: &Report, config: &ReportingConfig) -> Result<String> {
        let file_path = format!("{}/health_report_placeholder.txt", config.storage_path);
        let mut file = fs::File::create(&file_path).await?;
        file.write_all(b"System health report - Implementation pending")
            .await?;
        Ok(file_path)
    }

    async fn generate_access_report(
        _report: &Report,
        config: &ReportingConfig,
        _audit_trails: &Arc<RwLock<Vec<AuditTrail>>>,
    ) -> Result<String> {
        let file_path = format!("{}/access_report_placeholder.txt", config.storage_path);
        let mut file = fs::File::create(&file_path).await?;
        file.write_all(b"Access control report - Implementation pending")
            .await?;
        Ok(file_path)
    }

    async fn generate_retention_report(
        _report: &Report,
        config: &ReportingConfig,
    ) -> Result<String> {
        let file_path = format!("{}/retention_report_placeholder.txt", config.storage_path);
        let mut file = fs::File::create(&file_path).await?;
        file.write_all(b"Data retention report - Implementation pending")
            .await?;
        Ok(file_path)
    }

    async fn generate_custom_report(_report: &Report, config: &ReportingConfig) -> Result<String> {
        let file_path = format!("{}/custom_report_placeholder.txt", config.storage_path);
        let mut file = fs::File::create(&file_path).await?;
        file.write_all(b"Custom report - Implementation pending")
            .await?;
        Ok(file_path)
    }

    pub async fn get_report(&self, report_id: Uuid) -> Option<Report> {
        self.reports.get(&report_id).map(|r| r.value().clone())
    }

    pub async fn list_reports(&self, tenant_id: Option<Uuid>) -> Vec<Report> {
        self.reports
            .iter()
            .filter(|entry| tenant_id.is_none() || entry.value().tenant_id == tenant_id)
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub async fn delete_report(&self, report_id: Uuid) -> Result<()> {
        if let Some((_, report)) = self.reports.remove(&report_id) {
            if let Some(file_path) = report.file_path {
                fs::remove_file(&file_path).await?;
            }
        }
        Ok(())
    }

    pub async fn record_audit_event(&self, mut audit_event: AuditTrail) -> Result<()> {
        audit_event.id = Uuid::new_v4();
        audit_event.timestamp = Utc::now();

        let mut trails = self.audit_trails.write();
        trails.push(audit_event);

        // Keep audit trail size manageable
        if trails.len() > 100000 {
            trails.drain(0..10000);
        }

        Ok(())
    }

    pub async fn get_audit_trails(
        &self,
        date_range: Option<DateRange>,
        tenant_id: Option<Uuid>,
        event_types: Option<Vec<AuditEventType>>,
    ) -> Vec<AuditTrail> {
        let trails = self.audit_trails.read();
        trails
            .iter()
            .filter(|trail| {
                if let Some(range) = &date_range {
                    if trail.timestamp < range.start || trail.timestamp > range.end {
                        return false;
                    }
                }

                if let Some(tenant) = tenant_id {
                    if trail.tenant_id != Some(tenant) {
                        return false;
                    }
                }

                if let Some(types) = &event_types {
                    if !types.contains(&trail.event_type) {
                        return false;
                    }
                }

                true
            })
            .cloned()
            .collect()
    }

    pub async fn get_compliance_status(&self, framework: ComplianceFramework) -> ComplianceReport {
        let requirements: Vec<ComplianceRequirement> = self
            .compliance_requirements
            .iter()
            .filter(|req| req.value().framework == framework)
            .map(|req| req.value().clone())
            .collect();

        let total_controls = requirements.len();
        let compliant_controls = requirements
            .iter()
            .filter(|req| req.implementation_status == ComplianceStatus::FullyCompliant)
            .count();
        let non_compliant_controls = requirements
            .iter()
            .filter(|req| req.implementation_status == ComplianceStatus::NonCompliant)
            .count();
        let partially_compliant_controls = requirements
            .iter()
            .filter(|req| req.implementation_status == ComplianceStatus::PartiallyCompliant)
            .count();

        let overall_score = if total_controls > 0 {
            (compliant_controls as f64 + partially_compliant_controls as f64 * 0.5)
                / total_controls as f64
                * 100.0
        } else {
            0.0
        };

        ComplianceReport {
            framework,
            assessment_date: Utc::now(),
            overall_score,
            total_controls,
            compliant_controls,
            non_compliant_controls,
            partially_compliant_controls,
            requirements,
            findings: Vec::new(),
            recommendations: Vec::new(),
            executive_summary: format!(
                "Current compliance status shows {overall_score:.1}% overall compliance with {total_controls} controls assessed."
            ),
            next_assessment_date: Utc::now() + Duration::days(90),
        }
    }

    pub async fn update_compliance_requirement(
        &self,
        requirement: ComplianceRequirement,
    ) -> Result<()> {
        self.compliance_requirements
            .insert(requirement.id.clone(), requirement);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_reporting_engine_creation() {
        let config = ReportingConfig::default();
        let engine = ReportingEngine::new(config);
        assert!(engine.reports.is_empty());
    }

    #[tokio::test]
    async fn test_create_report() {
        let config = ReportingConfig::default();
        let engine = ReportingEngine::new(config);

        let report = Report {
            id: Uuid::new_v4(),
            report_type: ReportType::ComplianceAudit,
            title: "Test Report".to_string(),
            description: "Test Description".to_string(),
            created_by: "test_user".to_string(),
            tenant_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            generated_at: None,
            status: ReportStatus::Pending,
            format: ReportFormat::JSON,
            parameters: ReportParameters {
                date_range: None,
                tenant_filter: None,
                user_filter: None,
                resource_filter: None,
                compliance_framework: Some(ComplianceFramework::SOC2),
                risk_level_filter: None,
                custom_filters: HashMap::new(),
                include_raw_data: false,
                include_charts: false,
                include_recommendations: false,
            },
            data: serde_json::Value::Null,
            file_path: None,
            size_bytes: None,
            retention_until: Utc::now() + Duration::days(365),
            tags: vec!["test".to_string()],
        };

        let report_id = engine.create_report(report).await.unwrap();
        assert!(engine.reports.contains_key(&report_id));
    }

    #[tokio::test]
    async fn test_compliance_requirements() {
        let config = ReportingConfig::default();
        let engine = ReportingEngine::new(config);
        engine.load_compliance_requirements().await.unwrap();

        assert!(!engine.compliance_requirements.is_empty());
        assert!(engine.compliance_requirements.contains_key("SOX-302"));
        assert!(engine.compliance_requirements.contains_key("SOC2-CC1.0"));
        assert!(engine
            .compliance_requirements
            .contains_key("ISO27001-A.5.1"));
        assert!(engine.compliance_requirements.contains_key("GDPR-Art.32"));
    }

    #[tokio::test]
    async fn test_audit_trail_recording() {
        let config = ReportingConfig::default();
        let engine = ReportingEngine::new(config);

        let audit_event = AuditTrail {
            id: Uuid::new_v4(),
            event_type: AuditEventType::Authentication,
            user_id: Some("test_user".to_string()),
            tenant_id: None,
            resource_id: None,
            action: "login".to_string(),
            details: serde_json::json!({"success": true}),
            timestamp: Utc::now(),
            source_ip: Some("127.0.0.1".to_string()),
            user_agent: Some("test_agent".to_string()),
            session_id: Some("session_123".to_string()),
            outcome: AuditOutcome::Success,
            risk_score: Some(0.1),
        };

        engine.record_audit_event(audit_event).await.unwrap();

        let trails = engine.audit_trails.read();
        assert_eq!(trails.len(), 1);
        assert_eq!(trails[0].action, "login");
    }

    #[tokio::test]
    async fn test_compliance_status() {
        let config = ReportingConfig::default();
        let engine = ReportingEngine::new(config);
        engine.load_compliance_requirements().await.unwrap();

        let status = engine
            .get_compliance_status(ComplianceFramework::SOC2)
            .await;
        assert_eq!(status.framework, ComplianceFramework::SOC2);
        assert!(status.total_controls > 0);
    }

    #[tokio::test]
    async fn test_generate_html_compliance_report() {
        let report = ComplianceReport {
            framework: ComplianceFramework::SOC2,
            assessment_date: Utc::now(),
            overall_score: 75.5,
            total_controls: 10,
            compliant_controls: 7,
            non_compliant_controls: 2,
            partially_compliant_controls: 1,
            requirements: vec![],
            findings: vec![],
            recommendations: vec![],
            executive_summary: "Test summary".to_string(),
            next_assessment_date: Utc::now() + Duration::days(90),
        };

        let html = ReportingEngine::generate_html_compliance_report(&report).unwrap();
        assert!(html.contains("Compliance Assessment Report"));
        assert!(html.contains("75.5%"));
        assert!(html.contains("SOC2"));
    }

    #[tokio::test]
    async fn test_report_templates() {
        let config = ReportingConfig::default();
        let engine = ReportingEngine::new(config);
        engine.load_report_templates().await.unwrap();

        assert!(!engine.templates.is_empty());
        assert!(engine.templates.contains_key("compliance_audit"));
        assert!(engine.templates.contains_key("security_assessment"));
    }
}
