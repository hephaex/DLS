use dls_server::disaster_recovery::*;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::test]
async fn test_disaster_recovery_manager_creation() {
    let config = DisasterRecoveryConfig::default();
    let manager = DisasterRecoveryManager::new(config);
    
    // Verify manager is created with empty collections
    assert!(manager.backup_jobs().is_empty());
    assert!(manager.recovery_plans().is_empty());
    assert!(manager.active_backup_jobs().is_empty());
}

#[tokio::test]
async fn test_backup_job_creation_and_retrieval() {
    let config = DisasterRecoveryConfig::default();
    let manager = DisasterRecoveryManager::new(config);
    
    let job = BackupJob {
        id: Uuid::new_v4(),
        name: "Critical System Backup".to_string(),
        backup_type: BackupType::Full,
        source_paths: vec![
            "/etc/dls".to_string(),
            "/var/lib/dls".to_string(),
        ],
        destination: "/backups/system".to_string(),
        schedule: BackupSchedule {
            frequency: ScheduleFrequency::Daily,
            time_of_day: Some(chrono::NaiveTime::from_hms_opt(3, 0, 0).unwrap()),
            days_of_week: None,
            day_of_month: None,
            enabled: true,
            max_concurrent_jobs: 2,
        },
        retention_policy: RetentionPolicy {
            daily_retention_days: 30,
            weekly_retention_weeks: 12,
            monthly_retention_months: 12,
            yearly_retention_years: 7,
            max_backup_size_gb: Some(50),
            auto_cleanup_enabled: true,
        },
        compression_enabled: true,
        encryption_enabled: true,
        verification_enabled: true,
        tenant_id: Some(Uuid::new_v4()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_run: None,
        next_run: Utc::now() + Duration::hours(24),
        status: BackupStatus::Pending,
        priority: 9,
        metadata: {
            let mut metadata = HashMap::new();
            metadata.insert("department".to_string(), "IT".to_string());
            metadata.insert("criticality".to_string(), "high".to_string());
            metadata
        },
    };
    
    // Create backup job
    let job_id = manager.create_backup_job(job.clone()).await.unwrap();
    assert_eq!(job_id, job.id);
    
    // Retrieve and verify backup job
    let retrieved_job = manager.get_backup_job(job_id).await.unwrap();
    assert_eq!(retrieved_job.name, "Critical System Backup");
    assert_eq!(retrieved_job.backup_type, BackupType::Full);
    assert_eq!(retrieved_job.source_paths.len(), 2);
    assert_eq!(retrieved_job.priority, 9);
    assert!(retrieved_job.compression_enabled);
    assert!(retrieved_job.encryption_enabled);
    assert!(retrieved_job.verification_enabled);
}

#[tokio::test]
async fn test_backup_job_listing_with_tenant_filter() {
    let config = DisasterRecoveryConfig::default();
    let manager = DisasterRecoveryManager::new(config);
    
    let tenant1 = Uuid::new_v4();
    let tenant2 = Uuid::new_v4();
    
    // Create backup jobs for different tenants
    for i in 0..3 {
        let job = BackupJob {
            id: Uuid::new_v4(),
            name: format!("Tenant 1 Backup {}", i + 1),
            backup_type: BackupType::Incremental,
            source_paths: vec![format!("/tenant1/data{}", i + 1)],
            destination: format!("/backups/tenant1/data{}", i + 1),
            schedule: BackupSchedule {
                frequency: ScheduleFrequency::Hourly,
                time_of_day: None,
                days_of_week: None,
                day_of_month: None,
                enabled: true,
                max_concurrent_jobs: 1,
            },
            retention_policy: RetentionPolicy {
                daily_retention_days: 7,
                weekly_retention_weeks: 4,
                monthly_retention_months: 3,
                yearly_retention_years: 1,
                max_backup_size_gb: Some(10),
                auto_cleanup_enabled: true,
            },
            compression_enabled: true,
            encryption_enabled: false,
            verification_enabled: true,
            tenant_id: Some(tenant1),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_run: None,
            next_run: Utc::now() + Duration::hours(1),
            status: BackupStatus::Pending,
            priority: 7,
            metadata: HashMap::new(),
        };
        manager.create_backup_job(job).await.unwrap();
    }
    
    for i in 0..2 {
        let job = BackupJob {
            id: Uuid::new_v4(),
            name: format!("Tenant 2 Backup {}", i + 1),
            backup_type: BackupType::Differential,
            source_paths: vec![format!("/tenant2/data{}", i + 1)],
            destination: format!("/backups/tenant2/data{}", i + 1),
            schedule: BackupSchedule {
                frequency: ScheduleFrequency::Daily,
                time_of_day: Some(chrono::NaiveTime::from_hms_opt(1, 0, 0).unwrap()),
                days_of_week: None,
                day_of_month: None,
                enabled: true,
                max_concurrent_jobs: 1,
            },
            retention_policy: RetentionPolicy {
                daily_retention_days: 14,
                weekly_retention_weeks: 6,
                monthly_retention_months: 6,
                yearly_retention_years: 2,
                max_backup_size_gb: Some(25),
                auto_cleanup_enabled: true,
            },
            compression_enabled: false,
            encryption_enabled: true,
            verification_enabled: true,
            tenant_id: Some(tenant2),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_run: None,
            next_run: Utc::now() + Duration::hours(24),
            status: BackupStatus::Pending,
            priority: 6,
            metadata: HashMap::new(),
        };
        manager.create_backup_job(job).await.unwrap();
    }
    
    // Test listing all jobs
    let all_jobs = manager.list_backup_jobs(None).await;
    assert_eq!(all_jobs.len(), 5);
    
    // Test listing tenant1 jobs
    let tenant1_jobs = manager.list_backup_jobs(Some(tenant1)).await;
    assert_eq!(tenant1_jobs.len(), 3);
    assert!(tenant1_jobs.iter().all(|job| job.tenant_id == Some(tenant1)));
    
    // Test listing tenant2 jobs
    let tenant2_jobs = manager.list_backup_jobs(Some(tenant2)).await;
    assert_eq!(tenant2_jobs.len(), 2);
    assert!(tenant2_jobs.iter().all(|job| job.tenant_id == Some(tenant2)));
}

#[tokio::test]
async fn test_disaster_recovery_plan_creation() {
    let config = DisasterRecoveryConfig::default();
    let manager = DisasterRecoveryManager::new(config);
    
    let plan = DisasterRecoveryPlan {
        id: Uuid::new_v4(),
        name: "Complete System Failure Recovery".to_string(),
        description: "Comprehensive recovery plan for total system failure scenarios".to_string(),
        disaster_types: vec![
            DisasterType::HardwareFailure,
            DisasterType::PowerFailure,
            DisasterType::StorageFailure,
        ],
        rpo: RecoveryPointObjective::Quick,
        rto: RecoveryTimeObjective::Critical,
        recovery_steps: vec![
            RecoveryStep {
                step_number: 1,
                title: "Emergency Assessment".to_string(),
                description: "Assess the extent of system failure and determine recovery approach".to_string(),
                commands: vec![
                    "dls-cli system status --detailed".to_string(),
                    "zpool status -v".to_string(),
                    "systemctl status dls-*".to_string(),
                ],
                estimated_duration: Duration::minutes(15),
                required_resources: vec![
                    "Senior System Administrator".to_string(),
                    "Network Operations Center".to_string(),
                ],
                rollback_commands: vec![],
                validation_checks: vec![
                    "Verify system status assessment".to_string(),
                    "Confirm impact scope".to_string(),
                ],
                dependencies: vec![],
            },
            RecoveryStep {
                step_number: 2,
                title: "Activate Backup Systems".to_string(),
                description: "Bring online backup infrastructure and services".to_string(),
                commands: vec![
                    "dls-cli cluster activate-backup".to_string(),
                    "systemctl start dls-backup-services".to_string(),
                    "dls-cli network configure-failover".to_string(),
                ],
                estimated_duration: Duration::minutes(10),
                required_resources: vec![
                    "Cluster Administrator".to_string(),
                    "Network Engineer".to_string(),
                ],
                rollback_commands: vec![
                    "dls-cli cluster deactivate-backup".to_string(),
                    "systemctl stop dls-backup-services".to_string(),
                ],
                validation_checks: vec![
                    "Verify backup systems are online".to_string(),
                    "Test network connectivity".to_string(),
                ],
                dependencies: vec![1],
            },
            RecoveryStep {
                step_number: 3,
                title: "Data Recovery and Restoration".to_string(),
                description: "Restore critical data from latest verified backups".to_string(),
                commands: vec![
                    "dls-backup restore --latest --verify".to_string(),
                    "zfs rollback tank/dls@emergency-restore".to_string(),
                    "dls-cli database restore --point-in-time".to_string(),
                ],
                estimated_duration: Duration::hours(1),
                required_resources: vec![
                    "Database Administrator".to_string(),
                    "Storage Specialist".to_string(),
                ],
                rollback_commands: vec![
                    "dls-backup restore --previous".to_string(),
                ],
                validation_checks: vec![
                    "Verify data integrity checksums".to_string(),
                    "Test critical system functions".to_string(),
                    "Validate tenant data accessibility".to_string(),
                ],
                dependencies: vec![2],
            },
        ],
        dependencies: vec![
            "Backup Infrastructure".to_string(),
            "Emergency Power Systems".to_string(),
            "Network Redundancy".to_string(),
        ],
        notification_contacts: vec![
            ContactInfo {
                name: "Emergency Response Team Lead".to_string(),
                role: "Incident Commander".to_string(),
                email: "emergency@company.com".to_string(),
                phone: Some("+1-555-EMERGENCY".to_string()),
                escalation_level: 1,
                available_24_7: true,
            },
            ContactInfo {
                name: "Chief Technology Officer".to_string(),
                role: "Executive Sponsor".to_string(),
                email: "cto@company.com".to_string(),
                phone: Some("+1-555-CTO-CELL".to_string()),
                escalation_level: 2,
                available_24_7: true,
            },
            ContactInfo {
                name: "Business Continuity Manager".to_string(),
                role: "Business Impact Coordinator".to_string(),
                email: "bcm@company.com".to_string(),
                phone: Some("+1-555-BCM-DESK".to_string()),
                escalation_level: 3,
                available_24_7: false,
            },
        ],
        testing_schedule: TestingSchedule {
            frequency: TestingFrequency::Quarterly,
            next_test_date: Utc::now() + Duration::days(90),
            partial_test_frequency: Some(TestingFrequency::Monthly),
            full_test_frequency: TestingFrequency::SemiAnnually,
            automated_testing_enabled: true,
        },
        last_tested: Some(Utc::now() - Duration::days(85)),
        last_updated: Utc::now(),
        version: 3,
        approved_by: "CTO and COO".to_string(),
        tenant_id: None,
    };
    
    // Create recovery plan
    let plan_id = manager.create_recovery_plan(plan.clone()).await.unwrap();
    assert_eq!(plan_id, plan.id);
    
    // Retrieve and verify recovery plan
    let retrieved_plan = manager.get_recovery_plan(plan_id).await.unwrap();
    assert_eq!(retrieved_plan.name, "Complete System Failure Recovery");
    assert_eq!(retrieved_plan.disaster_types.len(), 3);
    assert_eq!(retrieved_plan.recovery_steps.len(), 3);
    assert_eq!(retrieved_plan.notification_contacts.len(), 3);
    assert_eq!(retrieved_plan.rpo, RecoveryPointObjective::Quick);
    assert_eq!(retrieved_plan.rto, RecoveryTimeObjective::Critical);
    assert_eq!(retrieved_plan.version, 3);
}

#[tokio::test]
async fn test_system_health_monitoring() {
    let config = DisasterRecoveryConfig::default();
    let manager = DisasterRecoveryManager::new(config);
    
    // Get initial system health
    let health = manager.get_system_health().await;
    assert_eq!(health.overall_health, HealthLevel::Unknown);
    assert_eq!(health.recovery_readiness_score, 0.0);
    
    // Test health calculation with good conditions
    let good_health = SystemHealthStatus {
        overall_health: HealthLevel::Good,
        last_backup_success: Some(Utc::now() - Duration::hours(2)),
        storage_health: StorageHealthStatus {
            available_space_gb: 800,
            total_space_gb: 1000,
            iops_performance: 2000,
            backup_storage_health: HealthLevel::Excellent,
            disk_failures: 0,
        },
        network_health: NetworkHealthStatus {
            connectivity_status: HealthLevel::Excellent,
            bandwidth_utilization_percent: 45.0,
            latency_ms: 5,
            packet_loss_percent: 0.0,
        },
        service_health: HashMap::new(),
        backup_queue_length: 1,
        recovery_readiness_score: 0.95,
    };
    
    let overall_health = DisasterRecoveryManager::calculate_overall_health(&good_health);
    assert_eq!(overall_health, HealthLevel::Excellent);
    
    let readiness_score = DisasterRecoveryManager::calculate_recovery_readiness(&good_health);
    assert!(readiness_score > 0.8);
}

#[tokio::test]
async fn test_backup_type_serialization() {
    let backup_types = vec![
        BackupType::Full,
        BackupType::Incremental,
        BackupType::Differential,
        BackupType::Snapshot,
        BackupType::Continuous,
    ];
    
    for backup_type in backup_types {
        let json = serde_json::to_string(&backup_type).unwrap();
        let deserialized: BackupType = serde_json::from_str(&json).unwrap();
        assert_eq!(backup_type, deserialized);
    }
}

#[tokio::test]
async fn test_disaster_type_coverage() {
    let disaster_types = vec![
        DisasterType::HardwareFailure,
        DisasterType::NetworkOutage,
        DisasterType::PowerFailure,
        DisasterType::DataCorruption,
        DisasterType::SecurityBreach,
        DisasterType::NaturalDisaster,
        DisasterType::HumanError,
        DisasterType::SoftwareFailure,
        DisasterType::StorageFailure,
        DisasterType::SystemOverload,
    ];
    
    for disaster_type in disaster_types {
        let json = serde_json::to_string(&disaster_type).unwrap();
        let deserialized: DisasterType = serde_json::from_str(&json).unwrap();
        assert_eq!(disaster_type, deserialized);
    }
}

#[tokio::test]
async fn test_schedule_frequency_variations() {
    let frequencies = vec![
        ScheduleFrequency::Continuous,
        ScheduleFrequency::Hourly,
        ScheduleFrequency::Daily,
        ScheduleFrequency::Weekly,
        ScheduleFrequency::Monthly,
        ScheduleFrequency::Custom("0 2 * * 1-5".to_string()), // Weekdays at 2 AM
    ];
    
    for frequency in frequencies {
        let json = serde_json::to_string(&frequency).unwrap();
        let deserialized: ScheduleFrequency = serde_json::from_str(&json).unwrap();
        assert_eq!(frequency, deserialized);
    }
}

#[tokio::test]
async fn test_backup_execution_workflow() {
    let execution = BackupExecution {
        id: Uuid::new_v4(),
        job_id: Uuid::new_v4(),
        backup_type: BackupType::Full,
        started_at: Utc::now() - Duration::minutes(30),
        completed_at: Some(Utc::now()),
        status: BackupStatus::Completed,
        files_processed: 1250,
        bytes_processed: 2_500_000_000, // 2.5 GB
        bytes_compressed: 1_200_000_000, // 1.2 GB
        files_failed: 3,
        error_messages: vec![
            "Permission denied: /restricted/file1.dat".to_string(),
            "File not found: /temp/missing.log".to_string(),
        ],
        checksum: Some("sha256:abc123def456...".to_string()),
        backup_location: "/backups/system/20240915_143022".to_string(),
        restoration_tested: true,
        verification_status: Some(VerificationStatus::Passed),
    };
    
    // Test serialization
    let json = serde_json::to_string(&execution).unwrap();
    let deserialized: BackupExecution = serde_json::from_str(&json).unwrap();
    
    assert_eq!(execution.files_processed, deserialized.files_processed);
    assert_eq!(execution.bytes_processed, deserialized.bytes_processed);
    assert_eq!(execution.files_failed, deserialized.files_failed);
    assert_eq!(execution.status, deserialized.status);
    assert_eq!(execution.verification_status, deserialized.verification_status);
}

#[tokio::test]
async fn test_recovery_objectives() {
    let rpo_variants = vec![
        RecoveryPointObjective::RealTime,
        RecoveryPointObjective::Immediate,
        RecoveryPointObjective::Quick,
        RecoveryPointObjective::Standard,
        RecoveryPointObjective::Extended,
        RecoveryPointObjective::Daily,
    ];
    
    let rto_variants = vec![
        RecoveryTimeObjective::Instant,
        RecoveryTimeObjective::Critical,
        RecoveryTimeObjective::Important,
        RecoveryTimeObjective::Standard,
        RecoveryTimeObjective::Extended,
        RecoveryTimeObjective::Flexible,
    ];
    
    for rpo in rpo_variants {
        let json = serde_json::to_string(&rpo).unwrap();
        let deserialized: RecoveryPointObjective = serde_json::from_str(&json).unwrap();
        assert_eq!(rpo, deserialized);
    }
    
    for rto in rto_variants {
        let json = serde_json::to_string(&rto).unwrap();
        let deserialized: RecoveryTimeObjective = serde_json::from_str(&json).unwrap();
        assert_eq!(rto, deserialized);
    }
}

#[tokio::test]
async fn test_disaster_event_tracking() {
    let disaster_event = DisasterEvent {
        id: Uuid::new_v4(),
        disaster_type: DisasterType::DataCorruption,
        severity: DisasterSeverity::High,
        started_at: Utc::now() - Duration::hours(3),
        resolved_at: Some(Utc::now() - Duration::minutes(30)),
        affected_systems: vec![
            "Database Server".to_string(),
            "Web Frontend".to_string(),
            "File Storage".to_string(),
        ],
        recovery_plan_id: Some(Uuid::new_v4()),
        recovery_steps_executed: vec![
            RecoveryStepExecution {
                step_number: 1,
                started_at: Utc::now() - Duration::hours(3),
                completed_at: Some(Utc::now() - Duration::hours(2) - Duration::minutes(45)),
                status: ExecutionStatus::Completed,
                executed_by: "emergency.admin@company.com".to_string(),
                output: "System assessment completed. Data corruption confirmed in /var/lib/data".to_string(),
                errors: vec![],
            },
            RecoveryStepExecution {
                step_number: 2,
                started_at: Utc::now() - Duration::hours(2) - Duration::minutes(45),
                completed_at: Some(Utc::now() - Duration::hours(1) - Duration::minutes(30)),
                status: ExecutionStatus::Completed,
                executed_by: "backup.admin@company.com".to_string(),
                output: "Data restoration from backup successful. 99.8% data recovery achieved".to_string(),
                errors: vec!["Minor checksum mismatch in 3 files".to_string()],
            },
        ],
        estimated_downtime: Some(Duration::hours(2)),
        actual_downtime: Some(Duration::hours(2) + Duration::minutes(30)),
        data_loss_estimate: DataLossEstimate {
            estimated_data_loss_mb: 150,
            last_successful_backup: Utc::now() - Duration::hours(4),
            affected_tenants: vec![Uuid::new_v4(), Uuid::new_v4()],
            critical_data_affected: false,
            recovery_confidence: RecoveryConfidence::High,
        },
        lessons_learned: vec![
            "Need more frequent integrity checks".to_string(),
            "Backup verification process should be automated".to_string(),
            "Consider implementing real-time replication".to_string(),
        ],
        post_incident_actions: vec![
            "Implement hourly integrity monitoring".to_string(),
            "Upgrade backup verification tools".to_string(),
            "Review and update recovery procedures".to_string(),
        ],
    };
    
    // Test serialization
    let json = serde_json::to_string(&disaster_event).unwrap();
    let deserialized: DisasterEvent = serde_json::from_str(&json).unwrap();
    
    assert_eq!(disaster_event.disaster_type, deserialized.disaster_type);
    assert_eq!(disaster_event.severity, deserialized.severity);
    assert_eq!(disaster_event.affected_systems.len(), deserialized.affected_systems.len());
    assert_eq!(disaster_event.recovery_steps_executed.len(), deserialized.recovery_steps_executed.len());
    assert_eq!(disaster_event.lessons_learned.len(), deserialized.lessons_learned.len());
}

#[tokio::test]
async fn test_retention_policy_validation() {
    let retention_policy = RetentionPolicy {
        daily_retention_days: 30,
        weekly_retention_weeks: 12,
        monthly_retention_months: 12,
        yearly_retention_years: 7,
        max_backup_size_gb: Some(100),
        auto_cleanup_enabled: true,
    };
    
    // Test serialization
    let json = serde_json::to_string(&retention_policy).unwrap();
    let deserialized: RetentionPolicy = serde_json::from_str(&json).unwrap();
    
    assert_eq!(retention_policy.daily_retention_days, deserialized.daily_retention_days);
    assert_eq!(retention_policy.weekly_retention_weeks, deserialized.weekly_retention_weeks);
    assert_eq!(retention_policy.monthly_retention_months, deserialized.monthly_retention_months);
    assert_eq!(retention_policy.yearly_retention_years, deserialized.yearly_retention_years);
    assert_eq!(retention_policy.max_backup_size_gb, deserialized.max_backup_size_gb);
    assert_eq!(retention_policy.auto_cleanup_enabled, deserialized.auto_cleanup_enabled);
}

#[tokio::test]
async fn test_testing_schedule_frequency() {
    let testing_frequencies = vec![
        TestingFrequency::Weekly,
        TestingFrequency::Monthly,
        TestingFrequency::Quarterly,
        TestingFrequency::SemiAnnually,
        TestingFrequency::Annually,
    ];
    
    for frequency in testing_frequencies {
        let json = serde_json::to_string(&frequency).unwrap();
        let deserialized: TestingFrequency = serde_json::from_str(&json).unwrap();
        assert_eq!(frequency, deserialized);
    }
}

#[tokio::test]
async fn test_health_level_progression() {
    let health_levels = vec![
        HealthLevel::Excellent,
        HealthLevel::Good,
        HealthLevel::Warning,
        HealthLevel::Critical,
        HealthLevel::Unknown,
    ];
    
    for health_level in health_levels {
        let json = serde_json::to_string(&health_level).unwrap();
        let deserialized: HealthLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(health_level, deserialized);
    }
}

#[tokio::test]
async fn test_default_disaster_recovery_config() {
    let config = DisasterRecoveryConfig::default();
    
    assert_eq!(config.backup_storage_path, "./backups");
    assert!(!config.offsite_backup_enabled);
    assert!(config.offsite_backup_locations.is_empty());
    assert_eq!(config.encryption_key_path, "./keys/backup.key");
    assert_eq!(config.max_concurrent_backups, 3);
    assert_eq!(config.backup_bandwidth_limit_mbps, Some(100));
    assert!(config.notification_endpoints.is_empty());
    assert_eq!(config.monitoring_interval_seconds, 60);
    assert!(!config.auto_failover_enabled);
    assert_eq!(config.recovery_test_interval_days, 90);
}

#[tokio::test]
async fn test_contact_info_escalation() {
    let contacts = vec![
        ContactInfo {
            name: "Primary On-Call".to_string(),
            role: "System Administrator".to_string(),
            email: "oncall@company.com".to_string(),
            phone: Some("+1-555-0001".to_string()),
            escalation_level: 1,
            available_24_7: true,
        },
        ContactInfo {
            name: "Secondary Support".to_string(),
            role: "Senior Engineer".to_string(),
            email: "senior@company.com".to_string(),
            phone: Some("+1-555-0002".to_string()),
            escalation_level: 2,
            available_24_7: true,
        },
        ContactInfo {
            name: "Management".to_string(),
            role: "IT Director".to_string(),
            email: "director@company.com".to_string(),
            phone: None,
            escalation_level: 3,
            available_24_7: false,
        },
    ];
    
    // Test that contacts are properly structured for escalation
    assert_eq!(contacts[0].escalation_level, 1);
    assert_eq!(contacts[1].escalation_level, 2);
    assert_eq!(contacts[2].escalation_level, 3);
    
    // Verify 24/7 availability decreases with escalation level
    assert!(contacts[0].available_24_7);
    assert!(contacts[1].available_24_7);
    assert!(!contacts[2].available_24_7);
}

#[tokio::test]
async fn test_next_run_calculation_logic() {
    let base_time = Utc::now();
    
    // Test daily schedule
    let daily_schedule = BackupSchedule {
        frequency: ScheduleFrequency::Daily,
        time_of_day: Some(chrono::NaiveTime::from_hms_opt(2, 30, 0).unwrap()),
        days_of_week: None,
        day_of_month: None,
        enabled: true,
        max_concurrent_jobs: 1,
    };
    
    let next_daily = DisasterRecoveryManager::calculate_next_run(&daily_schedule);
    assert!(next_daily > base_time);
    
    // Test hourly schedule
    let hourly_schedule = BackupSchedule {
        frequency: ScheduleFrequency::Hourly,
        time_of_day: None,
        days_of_week: None,
        day_of_month: None,
        enabled: true,
        max_concurrent_jobs: 1,
    };
    
    let next_hourly = DisasterRecoveryManager::calculate_next_run(&hourly_schedule);
    assert!(next_hourly > base_time);
    assert!(next_hourly < base_time + Duration::hours(2));
    
    // Test continuous schedule
    let continuous_schedule = BackupSchedule {
        frequency: ScheduleFrequency::Continuous,
        time_of_day: None,
        days_of_week: None,
        day_of_month: None,
        enabled: true,
        max_concurrent_jobs: 3,
    };
    
    let next_continuous = DisasterRecoveryManager::calculate_next_run(&continuous_schedule);
    assert!(next_continuous > base_time);
    assert!(next_continuous < base_time + Duration::minutes(2));
}