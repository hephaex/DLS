use chrono::{Duration, Utc};
use dls_server::error::Result;
use dls_server::reporting::*;
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::test]
async fn test_reporting_engine_creation() {
    let config = ReportingConfig::default();
    let engine = ReportingEngine::new(config);

    // Verify engine is created with empty collections
    assert!(engine.reports().is_empty());
    assert!(engine.audit_trails().read().is_empty());
    assert!(engine.compliance_requirements().is_empty());
    assert!(engine.active_generators().is_empty());
    assert!(engine.templates().is_empty());
}

#[tokio::test]
async fn test_create_and_retrieve_report() {
    let config = ReportingConfig::default();
    let engine = ReportingEngine::new(config);

    let report = Report {
        id: Uuid::new_v4(),
        report_type: ReportType::ComplianceAudit,
        title: "Test Compliance Report".to_string(),
        description: "Testing compliance report creation".to_string(),
        created_by: "test_user".to_string(),
        tenant_id: Some(Uuid::new_v4()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        generated_at: None,
        status: ReportStatus::Pending,
        format: ReportFormat::JSON,
        parameters: ReportParameters {
            date_range: Some(DateRange {
                start: Utc::now() - Duration::days(30),
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
        data: serde_json::Value::Null,
        file_path: None,
        size_bytes: None,
        retention_until: Utc::now() + Duration::days(365),
        tags: vec!["test".to_string(), "compliance".to_string()],
    };

    // Create report
    let report_id = engine.create_report(report.clone()).await.unwrap();

    // Verify report was created and can be retrieved
    let retrieved_report = engine.get_report(report_id).await.unwrap();
    assert_eq!(retrieved_report.title, "Test Compliance Report");
    assert_eq!(retrieved_report.report_type, ReportType::ComplianceAudit);
    assert_eq!(retrieved_report.status, ReportStatus::Pending);
}

#[tokio::test]
async fn test_list_reports_with_tenant_filter() {
    let config = ReportingConfig::default();
    let engine = ReportingEngine::new(config);

    let tenant1 = Uuid::new_v4();
    let tenant2 = Uuid::new_v4();

    // Create reports for different tenants
    for i in 0..3 {
        let report = Report {
            id: Uuid::new_v4(),
            report_type: ReportType::UsageStatistics,
            title: format!("Report {} for Tenant 1", i + 1),
            description: "Test report".to_string(),
            created_by: "test_user".to_string(),
            tenant_id: Some(tenant1),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            generated_at: None,
            status: ReportStatus::Pending,
            format: ReportFormat::CSV,
            parameters: ReportParameters {
                date_range: None,
                tenant_filter: None,
                user_filter: None,
                resource_filter: None,
                compliance_framework: None,
                risk_level_filter: None,
                custom_filters: HashMap::new(),
                include_raw_data: false,
                include_charts: false,
                include_recommendations: false,
            },
            data: serde_json::Value::Null,
            file_path: None,
            size_bytes: None,
            retention_until: Utc::now() + Duration::days(90),
            tags: vec!["usage".to_string()],
        };
        engine.create_report(report).await.unwrap();
    }

    for i in 0..2 {
        let report = Report {
            id: Uuid::new_v4(),
            report_type: ReportType::SecurityAssessment,
            title: format!("Security Report {} for Tenant 2", i + 1),
            description: "Test security report".to_string(),
            created_by: "security_user".to_string(),
            tenant_id: Some(tenant2),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            generated_at: None,
            status: ReportStatus::Pending,
            format: ReportFormat::PDF,
            parameters: ReportParameters {
                date_range: None,
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
            data: serde_json::Value::Null,
            file_path: None,
            size_bytes: None,
            retention_until: Utc::now() + Duration::days(180),
            tags: vec!["security".to_string()],
        };
        engine.create_report(report).await.unwrap();
    }

    // List all reports
    let all_reports = engine.list_reports(None).await;
    assert_eq!(all_reports.len(), 5);

    // List reports for tenant1
    let tenant1_reports = engine.list_reports(Some(tenant1)).await;
    assert_eq!(tenant1_reports.len(), 3);
    assert!(tenant1_reports.iter().all(|r| r.tenant_id == Some(tenant1)));

    // List reports for tenant2
    let tenant2_reports = engine.list_reports(Some(tenant2)).await;
    assert_eq!(tenant2_reports.len(), 2);
    assert!(tenant2_reports.iter().all(|r| r.tenant_id == Some(tenant2)));
}

#[tokio::test]
async fn test_compliance_requirements_loading() {
    let config = ReportingConfig::default();
    let engine = ReportingEngine::new(config);

    // Load compliance requirements
    engine.load_compliance_requirements_public().await.unwrap();

    // Verify different framework requirements are loaded
    assert!(engine.compliance_requirements().contains_key("SOX-302"));
    assert!(engine.compliance_requirements().contains_key("SOX-404"));
    assert!(engine.compliance_requirements().contains_key("SOC2-CC1.0"));
    assert!(engine.compliance_requirements().contains_key("SOC2-CC6.0"));
    assert!(engine
        .compliance_requirements()
        .contains_key("ISO27001-A.5.1"));
    assert!(engine
        .compliance_requirements()
        .contains_key("ISO27001-A.8.1"));
    assert!(engine.compliance_requirements().contains_key("GDPR-Art.32"));
    assert!(engine.compliance_requirements().contains_key("GDPR-Art.33"));

    // Verify requirement details
    let sox_302 = engine.compliance_requirements().get("SOX-302").unwrap();
    assert_eq!(sox_302.framework, ComplianceFramework::SOX);
    assert_eq!(sox_302.control_id, "302");
    assert_eq!(sox_302.risk_level, RiskLevel::High);

    let gdpr_32 = engine.compliance_requirements().get("GDPR-Art.32").unwrap();
    assert_eq!(gdpr_32.framework, ComplianceFramework::GDPR);
    assert_eq!(gdpr_32.risk_level, RiskLevel::Critical);
}

#[tokio::test]
async fn test_compliance_status_calculation() {
    let config = ReportingConfig::default();
    let engine = ReportingEngine::new(config);

    // Load requirements and update some statuses
    engine.load_compliance_requirements_public().await.unwrap();

    // Update some requirements to compliant status
    let mut soc2_cc1 = engine
        .compliance_requirements()
        .get("SOC2-CC1.0")
        .unwrap()
        .clone();
    soc2_cc1.implementation_status = ComplianceStatus::FullyCompliant;
    engine
        .update_compliance_requirement(soc2_cc1)
        .await
        .unwrap();

    let mut soc2_cc6 = engine
        .compliance_requirements()
        .get("SOC2-CC6.0")
        .unwrap()
        .clone();
    soc2_cc6.implementation_status = ComplianceStatus::PartiallyCompliant;
    engine
        .update_compliance_requirement(soc2_cc6)
        .await
        .unwrap();

    // Get compliance status
    let status = engine
        .get_compliance_status(ComplianceFramework::SOC2)
        .await;

    assert_eq!(status.framework, ComplianceFramework::SOC2);
    assert_eq!(status.total_controls, 2);
    assert_eq!(status.compliant_controls, 1);
    assert_eq!(status.partially_compliant_controls, 1);
    assert_eq!(status.non_compliant_controls, 0);
    assert_eq!(status.overall_score, 75.0); // (1 + 0.5) / 2 * 100
}

#[tokio::test]
async fn test_audit_trail_recording() {
    let config = ReportingConfig::default();
    let engine = ReportingEngine::new(config);

    // Record audit events
    for i in 0..5 {
        let audit_event = AuditTrail {
            id: Uuid::new_v4(),
            event_type: match i % 3 {
                0 => AuditEventType::Authentication,
                1 => AuditEventType::DataAccess,
                _ => AuditEventType::SecurityEvent,
            },
            user_id: Some(format!("user_{}", i)),
            tenant_id: Some(Uuid::new_v4()),
            resource_id: Some(format!("resource_{}", i)),
            action: format!("action_{}", i),
            details: serde_json::json!({"test": true, "index": i}),
            timestamp: Utc::now() - Duration::minutes(i as i64),
            source_ip: Some("192.168.1.100".to_string()),
            user_agent: Some("TestAgent/1.0".to_string()),
            session_id: Some(format!("session_{}", i)),
            outcome: if i % 2 == 0 {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failure
            },
            risk_score: Some(i as f64 * 0.2),
        };

        engine.record_audit_event(audit_event).await.unwrap();
    }

    // Verify events were recorded
    let trails = engine.audit_trails().read();
    assert_eq!(trails.len(), 5);

    // Test filtering by date range
    let date_range = Some(DateRange {
        start: Utc::now() - Duration::minutes(3),
        end: Utc::now(),
    });

    let filtered_trails = engine.get_audit_trails(date_range, None, None).await;
    assert!(filtered_trails.len() <= 4); // Should filter out the oldest event

    // Test filtering by event type
    let event_types = Some(vec![AuditEventType::Authentication]);
    let auth_trails = engine.get_audit_trails(None, None, event_types).await;
    assert!(auth_trails
        .iter()
        .all(|t| t.event_type == AuditEventType::Authentication));
}

#[tokio::test]
async fn test_report_templates_loading() {
    let config = ReportingConfig::default();
    let engine = ReportingEngine::new(config);

    engine.load_report_templates_public().await.unwrap();

    // Verify templates are loaded
    assert!(engine.templates().contains_key("compliance_audit"));
    assert!(engine.templates().contains_key("security_assessment"));

    let compliance_template = engine.templates().get("compliance_audit").unwrap();
    assert_eq!(compliance_template.report_type, ReportType::ComplianceAudit);
    assert!(compliance_template
        .required_permissions
        .contains(&"compliance.read".to_string()));

    let security_template = engine.templates().get("security_assessment").unwrap();
    assert_eq!(
        security_template.report_type,
        ReportType::SecurityAssessment
    );
    assert!(security_template
        .required_permissions
        .contains(&"security.read".to_string()));
}

#[tokio::test]
async fn test_html_compliance_report_generation() {
    let compliance_report = ComplianceReport {
        framework: ComplianceFramework::SOC2,
        assessment_date: Utc::now(),
        overall_score: 85.5,
        total_controls: 10,
        compliant_controls: 8,
        non_compliant_controls: 1,
        partially_compliant_controls: 1,
        requirements: vec![ComplianceRequirement {
            id: "TEST-001".to_string(),
            framework: ComplianceFramework::SOC2,
            control_id: "CC1.0".to_string(),
            title: "Test Control".to_string(),
            description: "This is a test control for verification".to_string(),
            implementation_status: ComplianceStatus::FullyCompliant,
            evidence_required: vec!["Test evidence".to_string()],
            responsible_party: "Test Team".to_string(),
            due_date: None,
            last_assessment: Some(Utc::now() - Duration::days(30)),
            risk_level: RiskLevel::Medium,
            remediation_plan: Some("No remediation needed".to_string()),
        }],
        findings: vec![],
        recommendations: vec![],
        executive_summary: "This is a test compliance report showing excellent results."
            .to_string(),
        next_assessment_date: Utc::now() + Duration::days(90),
    };

    let html_content =
        ReportingEngine::generate_html_compliance_report(&compliance_report).unwrap();

    // Verify HTML structure and content
    assert!(html_content.contains("<!DOCTYPE html>"));
    assert!(html_content.contains("Compliance Assessment Report"));
    assert!(html_content.contains("SOC2"));
    assert!(html_content.contains("85.5%"));
    assert!(html_content.contains("Test Control"));
    assert!(html_content.contains("This is a test compliance report"));
}

#[tokio::test]
async fn test_text_compliance_report_generation() {
    let compliance_report = ComplianceReport {
        framework: ComplianceFramework::ISO27001,
        assessment_date: Utc::now(),
        overall_score: 92.3,
        total_controls: 15,
        compliant_controls: 13,
        non_compliant_controls: 1,
        partially_compliant_controls: 1,
        requirements: vec![ComplianceRequirement {
            id: "TEST-002".to_string(),
            framework: ComplianceFramework::ISO27001,
            control_id: "A.5.1".to_string(),
            title: "Information Security Policies".to_string(),
            description: "Policies must be defined and implemented".to_string(),
            implementation_status: ComplianceStatus::FullyCompliant,
            evidence_required: vec![
                "Policy documents".to_string(),
                "Training records".to_string(),
            ],
            responsible_party: "CISO".to_string(),
            due_date: None,
            last_assessment: Some(Utc::now() - Duration::days(60)),
            risk_level: RiskLevel::High,
            remediation_plan: None,
        }],
        findings: vec![],
        recommendations: vec![],
        executive_summary: "ISO 27001 compliance assessment shows strong performance.".to_string(),
        next_assessment_date: Utc::now() + Duration::days(180),
    };

    let text_content =
        ReportingEngine::generate_text_compliance_report(&compliance_report).unwrap();

    // Verify text structure and content
    assert!(text_content.contains("COMPLIANCE ASSESSMENT REPORT"));
    assert!(text_content.contains("Framework: ISO27001"));
    assert!(text_content.contains("Overall Score: 92.3%"));
    assert!(text_content.contains("Total Controls: 15"));
    assert!(text_content.contains("Compliant: 13"));
    assert!(text_content.contains("Information Security Policies"));
    assert!(text_content.contains("ISO 27001 compliance assessment"));
}

#[tokio::test]
async fn test_report_deletion() {
    let config = ReportingConfig::default();
    let engine = ReportingEngine::new(config);

    // Create a test report
    let report = Report {
        id: Uuid::new_v4(),
        report_type: ReportType::PerformanceAnalysis,
        title: "Test Report for Deletion".to_string(),
        description: "This report will be deleted".to_string(),
        created_by: "test_user".to_string(),
        tenant_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        generated_at: None,
        status: ReportStatus::Pending,
        format: ReportFormat::HTML,
        parameters: ReportParameters {
            date_range: None,
            tenant_filter: None,
            user_filter: None,
            resource_filter: None,
            compliance_framework: None,
            risk_level_filter: None,
            custom_filters: HashMap::new(),
            include_raw_data: false,
            include_charts: false,
            include_recommendations: false,
        },
        data: serde_json::Value::Null,
        file_path: None,
        size_bytes: None,
        retention_until: Utc::now() + Duration::days(30),
        tags: vec!["test".to_string(), "deletion".to_string()],
    };

    let report_id = engine.create_report(report).await.unwrap();

    // Verify report exists
    assert!(engine.get_report(report_id).await.is_some());

    // Delete the report
    engine.delete_report(report_id).await.unwrap();

    // Verify report is deleted
    assert!(engine.get_report(report_id).await.is_none());
}

#[tokio::test]
async fn test_report_type_variants() {
    // Test all report type variants
    let report_types = vec![
        ReportType::ComplianceAudit,
        ReportType::SecurityAssessment,
        ReportType::PerformanceAnalysis,
        ReportType::UsageStatistics,
        ReportType::IncidentReport,
        ReportType::SystemHealth,
        ReportType::AccessControl,
        ReportType::DataRetention,
        ReportType::Custom("CustomReport".to_string()),
    ];

    for report_type in report_types {
        // Verify each report type can be created and serialized
        let json = serde_json::to_string(&report_type).unwrap();
        let deserialized: ReportType = serde_json::from_str(&json).unwrap();
        assert_eq!(report_type, deserialized);
    }
}

#[tokio::test]
async fn test_compliance_framework_variants() {
    // Test all compliance framework variants
    let frameworks = vec![
        ComplianceFramework::SOX,
        ComplianceFramework::HIPAA,
        ComplianceFramework::GDPR,
        ComplianceFramework::SOC2,
        ComplianceFramework::ISO27001,
        ComplianceFramework::PCI_DSS,
        ComplianceFramework::FISMA,
        ComplianceFramework::NIST,
        ComplianceFramework::CIS,
        ComplianceFramework::COBIT,
        ComplianceFramework::Custom("CustomFramework".to_string()),
    ];

    for framework in frameworks {
        // Verify each framework can be created and serialized
        let json = serde_json::to_string(&framework).unwrap();
        let deserialized: ComplianceFramework = serde_json::from_str(&json).unwrap();
        assert_eq!(framework, deserialized);
    }
}

#[tokio::test]
async fn test_risk_level_ordering() {
    // Test risk level ordering for proper priority handling
    let mut risk_levels = vec![
        RiskLevel::Critical,
        RiskLevel::Low,
        RiskLevel::High,
        RiskLevel::Medium,
    ];

    // Risk levels should be orderable for priority sorting
    let json = serde_json::to_string(&risk_levels).unwrap();
    let deserialized: Vec<RiskLevel> = serde_json::from_str(&json).unwrap();
    assert_eq!(risk_levels, deserialized);
}

#[tokio::test]
async fn test_audit_event_serialization() {
    let audit_event = AuditTrail {
        id: Uuid::new_v4(),
        event_type: AuditEventType::DataModification,
        user_id: Some("admin_user".to_string()),
        tenant_id: Some(Uuid::new_v4()),
        resource_id: Some("config_file_123".to_string()),
        action: "modify_configuration".to_string(),
        details: serde_json::json!({
            "file": "/etc/dls/config.yaml",
            "changes": {
                "max_clients": {"old": 100, "new": 150},
                "timeout": {"old": 30, "new": 45}
            },
            "checksum_before": "abc123",
            "checksum_after": "def456"
        }),
        timestamp: Utc::now(),
        source_ip: Some("10.0.1.50".to_string()),
        user_agent: Some("DLS-CLI/2.1.0".to_string()),
        session_id: Some("admin_session_789".to_string()),
        outcome: AuditOutcome::Success,
        risk_score: Some(0.3),
    };

    // Test serialization and deserialization
    let json = serde_json::to_string(&audit_event).unwrap();
    let deserialized: AuditTrail = serde_json::from_str(&json).unwrap();

    assert_eq!(audit_event.event_type, deserialized.event_type);
    assert_eq!(audit_event.action, deserialized.action);
    assert_eq!(audit_event.outcome, deserialized.outcome);
    assert_eq!(audit_event.risk_score, deserialized.risk_score);
}

#[tokio::test]
async fn test_default_reporting_config() {
    let config = ReportingConfig::default();

    // Verify default configuration values
    assert_eq!(config.storage_path, "./reports");
    assert_eq!(config.max_report_age_days, 2555); // 7 years
    assert_eq!(config.max_storage_size_gb, 100);
    assert!(config.auto_cleanup_enabled);
    assert!(config.encryption_enabled);
    assert!(config.compress_reports);
    assert_eq!(config.audit_trail_retention_days, 2555);
    assert_eq!(config.default_report_format, ReportFormat::PDF);
    assert_eq!(config.concurrent_report_limit, 10);

    // Verify default compliance frameworks
    assert!(config
        .compliance_frameworks
        .contains(&ComplianceFramework::SOX));
    assert!(config
        .compliance_frameworks
        .contains(&ComplianceFramework::SOC2));
    assert!(config
        .compliance_frameworks
        .contains(&ComplianceFramework::ISO27001));
}
