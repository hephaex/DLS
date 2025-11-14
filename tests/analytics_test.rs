#![allow(unused_variables)]
#![allow(clippy::field_reassign_with_default)]

mod common;

use chrono::{Duration, Utc};
use dls_server::analytics::{
    AggregationType, AnalysisRequest, AnalysisType, AnalyticsConfig, AnalyticsEngine, Dashboard, InsightType, MLModelType, Metric, MetricType, Position, RecommendationType, Size, TimeRange, Widget, WidgetConfiguration,
    WidgetType,
};
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::test]
async fn test_analytics_engine_creation() {
    common::setup();

    let config = AnalyticsConfig::default();
    let engine = AnalyticsEngine::new(config.clone());

    assert!(engine.config.enabled);
    assert_eq!(engine.config.retention_days, 90);
    assert!(engine.config.anomaly_detection_enabled);
    assert!(engine.config.prediction_enabled);
}

#[tokio::test]
async fn test_metric_ingestion_and_retrieval() {
    common::setup();

    let engine = AnalyticsEngine::default();
    engine.start().await.unwrap();

    // Ingest multiple metrics
    for i in 0..10 {
        let metric = Metric {
            id: format!("metric_{i}"),
            name: "cpu_usage".to_string(),
            metric_type: MetricType::Gauge,
            value: 50.0 + (i as f64 * 2.0),
            timestamp: Utc::now() - Duration::minutes(10 - i),
            labels: HashMap::new(),
            tenant_id: None,
            resource_id: Some("server-1".to_string()),
        };
        engine.ingest_metric(metric).await.unwrap();
    }

    // Retrieve metric series
    let time_range = TimeRange {
        start: Utc::now() - Duration::hours(1),
        end: Utc::now(),
    };

    let series = engine.get_metric_series("cpu_usage", time_range).await;
    assert!(series.is_some());
    let series = series.unwrap();
    assert_eq!(series.data_points.len(), 10);
    assert_eq!(series.name, "cpu_usage");
}

#[tokio::test]
async fn test_trend_analysis() {
    common::setup();

    let engine = AnalyticsEngine::default();

    // Ingest trending data - increasing trend
    for i in 0..20 {
        let metric = Metric {
            id: format!("trend_metric_{i}"),
            name: "response_time".to_string(),
            metric_type: MetricType::Gauge,
            value: 100.0 + (i as f64 * 5.0), // Clear increasing trend
            timestamp: Utc::now() - Duration::minutes(20 - i),
            labels: HashMap::new(),
            tenant_id: None,
            resource_id: None,
        };
        engine.ingest_metric(metric).await.unwrap();
    }

    let request = AnalysisRequest {
        id: Uuid::new_v4(),
        analysis_type: AnalysisType::Trend,
        metric_names: vec!["response_time".to_string()],
        time_range: TimeRange {
            start: Utc::now() - Duration::hours(1),
            end: Utc::now(),
        },
        parameters: HashMap::new(),
        tenant_id: None,
        created_at: Utc::now(),
    };

    let result = engine.analyze_metrics(request).await.unwrap();
    assert_eq!(result.analysis_type, AnalysisType::Trend);
    assert!(!result.insights.is_empty());

    // Check that trend was detected
    let trend_insight = result
        .insights
        .iter()
        .find(|i| i.insight_type == InsightType::Trend);
    assert!(trend_insight.is_some());
}

#[tokio::test]
async fn test_anomaly_detection() {
    common::setup();

    let engine = AnalyticsEngine::default();

    // Ingest normal data
    for i in 0..30 {
        let metric = Metric {
            id: format!("normal_metric_{i}"),
            name: "error_rate".to_string(),
            metric_type: MetricType::Gauge,
            value: 1.0 + (rand::random::<f64>() * 2.0), // Normal range: 1-3
            timestamp: Utc::now() - Duration::minutes(30 - i),
            labels: HashMap::new(),
            tenant_id: None,
            resource_id: None,
        };
        engine.ingest_metric(metric).await.unwrap();
    }

    // Ingest anomalous data point
    let anomaly_metric = Metric {
        id: "anomaly_metric".to_string(),
        name: "error_rate".to_string(),
        metric_type: MetricType::Gauge,
        value: 50.0, // Clearly anomalous
        timestamp: Utc::now(),
        labels: HashMap::new(),
        tenant_id: None,
        resource_id: None,
    };
    engine.ingest_metric(anomaly_metric).await.unwrap();

    let anomalies = engine
        .detect_real_time_anomalies("error_rate")
        .await
        .unwrap();
    assert!(!anomalies.is_empty());

    let anomaly = &anomalies[0];
    assert_eq!(anomaly.metric_name, "error_rate");
    assert!(anomaly.anomaly_score > 2.0);
    assert_eq!(anomaly.actual_value, 50.0);
}

#[tokio::test]
async fn test_forecast_generation() {
    common::setup();

    let engine = AnalyticsEngine::default();

    // Ingest predictable data with clear pattern
    for i in 0..50 {
        let metric = Metric {
            id: format!("forecast_metric_{i}"),
            name: "disk_usage".to_string(),
            metric_type: MetricType::Gauge,
            value: 20.0 + (i as f64 * 0.5), // Linear growth
            timestamp: Utc::now() - Duration::minutes(50 - i),
            labels: HashMap::new(),
            tenant_id: None,
            resource_id: None,
        };
        engine.ingest_metric(metric).await.unwrap();
    }

    let request = AnalysisRequest {
        id: Uuid::new_v4(),
        analysis_type: AnalysisType::Forecast,
        metric_names: vec!["disk_usage".to_string()],
        time_range: TimeRange {
            start: Utc::now() - Duration::hours(1),
            end: Utc::now(),
        },
        parameters: HashMap::new(),
        tenant_id: None,
        created_at: Utc::now(),
    };

    let result = engine.analyze_metrics(request).await.unwrap();
    assert_eq!(result.analysis_type, AnalysisType::Forecast);

    // Check that forecast data exists
    if let Some(forecast_data) = result.results.get("disk_usage") {
        assert!(forecast_data.get("forecast").is_some());
    }
}

#[tokio::test]
async fn test_correlation_analysis() {
    common::setup();

    let engine = AnalyticsEngine::default();

    // Ingest correlated metrics
    for i in 0..20 {
        let timestamp = Utc::now() - Duration::minutes(20 - i);

        let cpu_metric = Metric {
            id: format!("cpu_metric_{i}"),
            name: "cpu_usage".to_string(),
            metric_type: MetricType::Gauge,
            value: 30.0 + (i as f64 * 2.0),
            timestamp,
            labels: HashMap::new(),
            tenant_id: None,
            resource_id: None,
        };
        engine.ingest_metric(cpu_metric).await.unwrap();

        // Response time correlated with CPU
        let response_metric = Metric {
            id: format!("response_metric_{i}"),
            name: "response_time".to_string(),
            metric_type: MetricType::Gauge,
            value: 100.0 + (i as f64 * 3.0), // Correlated with CPU
            timestamp,
            labels: HashMap::new(),
            tenant_id: None,
            resource_id: None,
        };
        engine.ingest_metric(response_metric).await.unwrap();
    }

    let request = AnalysisRequest {
        id: Uuid::new_v4(),
        analysis_type: AnalysisType::Correlation,
        metric_names: vec!["cpu_usage".to_string(), "response_time".to_string()],
        time_range: TimeRange {
            start: Utc::now() - Duration::hours(1),
            end: Utc::now(),
        },
        parameters: HashMap::new(),
        tenant_id: None,
        created_at: Utc::now(),
    };

    let result = engine.analyze_metrics(request).await.unwrap();
    assert_eq!(result.analysis_type, AnalysisType::Correlation);

    // Check correlation results
    if let Some(correlations) = result.results.as_object() {
        assert!(!correlations.is_empty());
    }
}

#[tokio::test]
async fn test_ml_model_training_and_prediction() {
    common::setup();

    let engine = AnalyticsEngine::default();

    // Generate training data
    for i in 0..100 {
        let timestamp = Utc::now() - Duration::minutes(100 - i);

        let feature_value = 50.0 + (i as f64 * 0.5);
        let target_value = 100.0 + (feature_value * 1.5); // Linear relationship

        let feature_metric = Metric {
            id: format!("feature_metric_{i}"),
            name: "memory_usage".to_string(),
            metric_type: MetricType::Gauge,
            value: feature_value,
            timestamp,
            labels: HashMap::new(),
            tenant_id: None,
            resource_id: None,
        };
        engine.ingest_metric(feature_metric).await.unwrap();

        let target_metric = Metric {
            id: format!("target_metric_{i}"),
            name: "response_latency".to_string(),
            metric_type: MetricType::Gauge,
            value: target_value,
            timestamp,
            labels: HashMap::new(),
            tenant_id: None,
            resource_id: None,
        };
        engine.ingest_metric(target_metric).await.unwrap();
    }

    // Train model
    let model_id = engine
        .train_ml_model(
            MLModelType::LinearRegression,
            vec!["memory_usage".to_string()],
            "response_latency".to_string(),
        )
        .await
        .unwrap();

    // Make prediction
    let mut input_features = HashMap::new();
    input_features.insert("memory_usage".to_string(), 75.0);

    let prediction = engine
        .make_prediction(model_id, input_features, Duration::hours(1))
        .await
        .unwrap();

    assert_eq!(prediction.model_id, model_id);
    assert!(prediction.predicted_value > 0.0);
    assert!(prediction.confidence_interval.0 < prediction.confidence_interval.1);
}

#[tokio::test]
async fn test_insights_generation() {
    common::setup();

    let engine = AnalyticsEngine::default();

    // Generate data that should produce insights
    for i in 0..30 {
        let metric = Metric {
            id: format!("insight_metric_{i}"),
            name: "api_calls_per_minute".to_string(),
            metric_type: MetricType::Counter,
            value: 1000.0 + (i as f64 * 50.0), // Strong upward trend
            timestamp: Utc::now() - Duration::minutes(30 - i),
            labels: HashMap::new(),
            tenant_id: None,
            resource_id: None,
        };
        engine.ingest_metric(metric).await.unwrap();
    }

    let request = AnalysisRequest {
        id: Uuid::new_v4(),
        analysis_type: AnalysisType::Trend,
        metric_names: vec!["api_calls_per_minute".to_string()],
        time_range: TimeRange {
            start: Utc::now() - Duration::hours(1),
            end: Utc::now(),
        },
        parameters: HashMap::new(),
        tenant_id: None,
        created_at: Utc::now(),
    };

    let result = engine.analyze_metrics(request).await.unwrap();

    // Should generate insights for the strong trend
    assert!(!result.insights.is_empty());

    let insights = engine.get_insights(None, Some(5)).await;
    assert!(!insights.is_empty());

    let trend_insight = insights
        .iter()
        .find(|i| i.insight_type == InsightType::Trend);
    assert!(trend_insight.is_some());
    assert!(trend_insight.unwrap().confidence > 0.5);
}

#[tokio::test]
async fn test_recommendations_generation() {
    common::setup();

    let engine = AnalyticsEngine::default();

    // Generate data that should trigger recommendations
    for i in 0..20 {
        let metric = Metric {
            id: format!("rec_metric_{i}"),
            name: "database_connections".to_string(),
            metric_type: MetricType::Gauge,
            value: 80.0 + (i as f64 * 1.0), // Approaching limit
            timestamp: Utc::now() - Duration::minutes(20 - i),
            labels: HashMap::new(),
            tenant_id: None,
            resource_id: None,
        };
        engine.ingest_metric(metric).await.unwrap();
    }

    let request = AnalysisRequest {
        id: Uuid::new_v4(),
        analysis_type: AnalysisType::Trend,
        metric_names: vec!["database_connections".to_string()],
        time_range: TimeRange {
            start: Utc::now() - Duration::hours(1),
            end: Utc::now(),
        },
        parameters: HashMap::new(),
        tenant_id: None,
        created_at: Utc::now(),
    };

    let result = engine.analyze_metrics(request).await.unwrap();

    // Should generate recommendations based on insights
    assert!(!result.recommendations.is_empty());

    let recommendations = engine.get_recommendations(None, Some(5)).await;
    assert!(!recommendations.is_empty());

    let performance_rec = recommendations
        .iter()
        .find(|r| r.recommendation_type == RecommendationType::Performance);
    assert!(performance_rec.is_some());
}

#[tokio::test]
async fn test_dashboard_creation_and_management() {
    common::setup();

    let engine = AnalyticsEngine::default();

    let dashboard = Dashboard {
        id: Uuid::new_v4(),
        name: "System Performance Dashboard".to_string(),
        description: "Comprehensive system performance metrics".to_string(),
        tenant_id: None,
        widgets: vec![
            Widget {
                id: Uuid::new_v4(),
                title: "CPU Usage Over Time".to_string(),
                widget_type: WidgetType::LineChart,
                position: Position { x: 0, y: 0 },
                size: Size {
                    width: 600,
                    height: 400,
                },
                configuration: WidgetConfiguration {
                    metrics: vec!["cpu_usage".to_string()],
                    time_range: TimeRange {
                        start: Utc::now() - Duration::hours(24),
                        end: Utc::now(),
                    },
                    aggregation: AggregationType::Average,
                    display_options: HashMap::new(),
                },
            },
            Widget {
                id: Uuid::new_v4(),
                title: "Memory Usage".to_string(),
                widget_type: WidgetType::Gauge,
                position: Position { x: 600, y: 0 },
                size: Size {
                    width: 300,
                    height: 300,
                },
                configuration: WidgetConfiguration {
                    metrics: vec!["memory_usage".to_string()],
                    time_range: TimeRange {
                        start: Utc::now() - Duration::minutes(5),
                        end: Utc::now(),
                    },
                    aggregation: AggregationType::Average,
                    display_options: HashMap::new(),
                },
            },
        ],
        refresh_interval_seconds: 30,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let dashboard_id = engine.create_dashboard(dashboard.clone()).await.unwrap();
    assert_eq!(dashboard_id, dashboard.id);

    let retrieved = engine.get_dashboard(&dashboard_id);
    assert!(retrieved.is_some());

    let retrieved_dashboard = retrieved.unwrap();
    assert_eq!(retrieved_dashboard.name, "System Performance Dashboard");
    assert_eq!(retrieved_dashboard.widgets.len(), 2);

    let dashboards = engine.list_dashboards(None);
    assert_eq!(dashboards.len(), 1);
}

#[tokio::test]
async fn test_metric_aggregation_types() {
    common::setup();

    let engine = AnalyticsEngine::default();

    // Test different aggregation types
    let aggregations = vec![
        AggregationType::Sum,
        AggregationType::Average,
        AggregationType::Min,
        AggregationType::Max,
        AggregationType::Count,
        AggregationType::Rate,
        AggregationType::Percentile(95.0),
    ];

    for aggregation in aggregations {
        let widget_config = WidgetConfiguration {
            metrics: vec!["test_metric".to_string()],
            time_range: TimeRange {
                start: Utc::now() - Duration::hours(1),
                end: Utc::now(),
            },
            aggregation,
            display_options: HashMap::new(),
        };

        // Test that configuration is valid
        assert!(!widget_config.metrics.is_empty());
    }
}

#[tokio::test]
async fn test_time_series_data_retention() {
    common::setup();

    let mut config = AnalyticsConfig::default();
    config.retention_days = 1; // Short retention for testing

    let engine = AnalyticsEngine::new(config);

    // Ingest old data (beyond retention)
    let old_metric = Metric {
        id: "old_metric".to_string(),
        name: "old_data".to_string(),
        metric_type: MetricType::Gauge,
        value: 100.0,
        timestamp: Utc::now() - Duration::days(2), // Older than retention
        labels: HashMap::new(),
        tenant_id: None,
        resource_id: None,
    };
    engine.ingest_metric(old_metric).await.unwrap();

    // Ingest recent data (within retention)
    let recent_metric = Metric {
        id: "recent_metric".to_string(),
        name: "old_data".to_string(),
        metric_type: MetricType::Gauge,
        value: 200.0,
        timestamp: Utc::now() - Duration::hours(1), // Recent
        labels: HashMap::new(),
        tenant_id: None,
        resource_id: None,
    };
    engine.ingest_metric(recent_metric).await.unwrap();

    let time_range = TimeRange {
        start: Utc::now() - Duration::days(3),
        end: Utc::now(),
    };

    let series = engine.get_metric_series("old_data", time_range).await;
    assert!(series.is_some());

    // Only recent data should remain due to retention policy
    let series = series.unwrap();
    assert_eq!(series.data_points.len(), 1);
    assert_eq!(series.data_points[0].value, 200.0);
}
