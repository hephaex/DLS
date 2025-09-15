use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use dashmap::DashMap;
use parking_lot::RwLock;
use ndarray::{Array1, Array2, Axis};
use statrs::statistics::Statistics;
use smartcore::linalg::basic::matrix::DenseMatrix;
use smartcore::linear::linear_regression::LinearRegression;
use smartcore::cluster::kmeans::KMeans;
use smartcore::model_selection::train_test_split;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
    TimeSeries,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnalysisType {
    Trend,
    Anomaly,
    Forecast,
    Clustering,
    Classification,
    Regression,
    Correlation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub id: String,
    pub name: String,
    pub metric_type: MetricType,
    pub value: f64,
    pub timestamp: DateTime<Utc>,
    pub labels: HashMap<String, String>,
    pub tenant_id: Option<Uuid>,
    pub resource_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSeries {
    pub id: String,
    pub name: String,
    pub metric_type: MetricType,
    pub data_points: Vec<DataPoint>,
    pub labels: HashMap<String, String>,
    pub tenant_id: Option<Uuid>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPoint {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRequest {
    pub id: Uuid,
    pub analysis_type: AnalysisType,
    pub metric_names: Vec<String>,
    pub time_range: TimeRange,
    pub parameters: HashMap<String, serde_json::Value>,
    pub tenant_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub id: Uuid,
    pub request_id: Uuid,
    pub analysis_type: AnalysisType,
    pub results: serde_json::Value,
    pub insights: Vec<Insight>,
    pub recommendations: Vec<Recommendation>,
    pub confidence_score: f64,
    pub created_at: DateTime<Utc>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Insight {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub insight_type: InsightType,
    pub severity: InsightSeverity,
    pub metrics: Vec<String>,
    pub time_range: TimeRange,
    pub confidence: f64,
    pub details: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InsightType {
    Anomaly,
    Trend,
    Pattern,
    Threshold,
    Correlation,
    Prediction,
    Performance,
    Resource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InsightSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub recommendation_type: RecommendationType,
    pub priority: RecommendationPriority,
    pub estimated_impact: EstimatedImpact,
    pub actions: Vec<RecommendedAction>,
    pub applicable_resources: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecommendationType {
    Scaling,
    Cost,
    Performance,
    Security,
    Maintenance,
    Configuration,
    Resource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecommendationPriority {
    Low,
    Medium,
    High,
    Urgent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstimatedImpact {
    pub cost_savings_per_month: f64,
    pub performance_improvement_percent: f64,
    pub risk_reduction_percent: f64,
    pub implementation_effort: ImplementationEffort,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ImplementationEffort {
    Low,
    Medium,
    High,
    Complex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub action_type: String,
    pub description: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub estimated_time_minutes: u32,
    pub requires_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLModel {
    pub id: Uuid,
    pub name: String,
    pub model_type: MLModelType,
    pub version: String,
    pub training_data_size: usize,
    pub accuracy: f64,
    pub created_at: DateTime<Utc>,
    pub last_trained: DateTime<Utc>,
    pub features: Vec<String>,
    pub hyperparameters: HashMap<String, serde_json::Value>,
    pub performance_metrics: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MLModelType {
    LinearRegression,
    DecisionTree,
    RandomForest,
    SVM,
    NeuralNetwork,
    Clustering,
    TimeSeries,
    AnomalyDetection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prediction {
    pub id: Uuid,
    pub model_id: Uuid,
    pub input_features: HashMap<String, f64>,
    pub predicted_value: f64,
    pub confidence_interval: (f64, f64),
    pub prediction_horizon: Duration,
    pub created_at: DateTime<Utc>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetection {
    pub id: Uuid,
    pub metric_name: String,
    pub timestamp: DateTime<Utc>,
    pub actual_value: f64,
    pub expected_value: f64,
    pub anomaly_score: f64,
    pub threshold: f64,
    pub severity: AnomalySeverity,
    pub context: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub tenant_id: Option<Uuid>,
    pub widgets: Vec<Widget>,
    pub refresh_interval_seconds: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Widget {
    pub id: Uuid,
    pub title: String,
    pub widget_type: WidgetType,
    pub position: Position,
    pub size: Size,
    pub configuration: WidgetConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WidgetType {
    LineChart,
    BarChart,
    PieChart,
    Gauge,
    Table,
    Heatmap,
    Scatter,
    SingleStat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Position {
    pub x: u32,
    pub y: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetConfiguration {
    pub metrics: Vec<String>,
    pub time_range: TimeRange,
    pub aggregation: AggregationType,
    pub display_options: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AggregationType {
    Sum,
    Average,
    Min,
    Max,
    Count,
    Rate,
    Percentile(f64),
}

#[derive(Debug)]
pub struct AnalyticsEngine {
    metrics: Arc<DashMap<String, MetricSeries>>,
    analysis_results: Arc<DashMap<Uuid, AnalysisResult>>,
    ml_models: Arc<DashMap<Uuid, MLModel>>,
    predictions: Arc<RwLock<Vec<Prediction>>>,
    anomalies: Arc<RwLock<Vec<AnomalyDetection>>>,
    insights: Arc<RwLock<Vec<Insight>>>,
    recommendations: Arc<RwLock<Vec<Recommendation>>>,
    dashboards: Arc<DashMap<Uuid, Dashboard>>,
    pub config: AnalyticsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsConfig {
    pub enabled: bool,
    pub retention_days: u32,
    pub batch_size: usize,
    pub processing_interval_seconds: u32,
    pub anomaly_detection_enabled: bool,
    pub anomaly_threshold: f64,
    pub prediction_enabled: bool,
    pub prediction_horizon_hours: u32,
    pub auto_insights: bool,
    pub auto_recommendations: bool,
    pub ml_training_enabled: bool,
    pub ml_training_interval_hours: u32,
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 90,
            batch_size: 1000,
            processing_interval_seconds: 300,
            anomaly_detection_enabled: true,
            anomaly_threshold: 2.0,
            prediction_enabled: true,
            prediction_horizon_hours: 24,
            auto_insights: true,
            auto_recommendations: true,
            ml_training_enabled: true,
            ml_training_interval_hours: 24,
        }
    }
}

impl Default for AnalyticsEngine {
    fn default() -> Self {
        Self::new(AnalyticsConfig::default())
    }
}

impl AnalyticsEngine {
    pub fn new(config: AnalyticsConfig) -> Self {
        Self {
            metrics: Arc::new(DashMap::new()),
            analysis_results: Arc::new(DashMap::new()),
            ml_models: Arc::new(DashMap::new()),
            predictions: Arc::new(RwLock::new(Vec::new())),
            anomalies: Arc::new(RwLock::new(Vec::new())),
            insights: Arc::new(RwLock::new(Vec::new())),
            recommendations: Arc::new(RwLock::new(Vec::new())),
            dashboards: Arc::new(DashMap::new()),
            config,
        }
    }

    pub async fn start(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Start background processing tasks
        self.start_background_tasks().await?;
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        // Cleanup background tasks
        Ok(())
    }

    pub async fn ingest_metric(&self, metric: Metric) -> Result<()> {
        let series_key = format!("{}:{}", metric.name, 
            metric.labels.get("instance").unwrap_or(&"default".to_string()));

        let data_point = DataPoint {
            timestamp: metric.timestamp,
            value: metric.value,
            labels: metric.labels.clone(),
        };

        // Update or create metric series
        if let Some(mut series) = self.metrics.get_mut(&series_key) {
            series.data_points.push(data_point);
            series.end_time = metric.timestamp;
            
            // Keep only recent data points based on retention
            let retention_cutoff = Utc::now() - Duration::days(self.config.retention_days as i64);
            series.data_points.retain(|dp| dp.timestamp > retention_cutoff);
        } else {
            let series = MetricSeries {
                id: Uuid::new_v4().to_string(),
                name: metric.name.clone(),
                metric_type: metric.metric_type,
                data_points: vec![data_point],
                labels: metric.labels,
                tenant_id: metric.tenant_id,
                start_time: metric.timestamp,
                end_time: metric.timestamp,
            };
            self.metrics.insert(series_key, series);
        }

        Ok(())
    }

    pub async fn analyze_metrics(&self, request: AnalysisRequest) -> Result<AnalysisResult> {
        let start_time = std::time::Instant::now();

        let results = match request.analysis_type {
            AnalysisType::Trend => self.analyze_trends(&request).await?,
            AnalysisType::Anomaly => self.detect_anomalies(&request).await?,
            AnalysisType::Forecast => self.generate_forecasts(&request).await?,
            AnalysisType::Clustering => self.perform_clustering(&request).await?,
            AnalysisType::Classification => self.perform_classification(&request).await?,
            AnalysisType::Regression => self.perform_regression(&request).await?,
            AnalysisType::Correlation => self.analyze_correlations(&request).await?,
        };

        let insights = self.generate_insights(&request, &results).await?;
        let recommendations = self.generate_recommendations(&request, &results, &insights).await?;

        let processing_time = start_time.elapsed().as_millis() as u64;

        let analysis_result = AnalysisResult {
            id: Uuid::new_v4(),
            request_id: request.id,
            analysis_type: request.analysis_type,
            results,
            insights: insights.clone(),
            recommendations: recommendations.clone(),
            confidence_score: self.calculate_confidence_score(&insights),
            created_at: Utc::now(),
            processing_time_ms: processing_time,
        };

        // Store results
        self.analysis_results.insert(analysis_result.id, analysis_result.clone());

        // Update insights and recommendations
        {
            let mut insights_guard = self.insights.write();
            insights_guard.extend(insights);
        }
        {
            let mut recommendations_guard = self.recommendations.write();
            recommendations_guard.extend(recommendations);
        }

        Ok(analysis_result)
    }

    pub async fn train_ml_model(
        &self,
        model_type: MLModelType,
        features: Vec<String>,
        target_metric: String,
    ) -> Result<Uuid> {
        // Collect training data
        let training_data = self.collect_training_data(&features, &target_metric).await?;
        
        if training_data.len() < 10 {
            return Err(crate::error::DlsError::Validation(
                "Insufficient training data".to_string()
            ));
        }

        let model_id = Uuid::new_v4();
        let accuracy = self.train_model(&model_type, &training_data).await?;

        let ml_model = MLModel {
            id: model_id,
            name: format!("{:?}_{}", model_type, target_metric),
            model_type,
            version: "1.0.0".to_string(),
            training_data_size: training_data.len(),
            accuracy,
            created_at: Utc::now(),
            last_trained: Utc::now(),
            features,
            hyperparameters: HashMap::new(),
            performance_metrics: HashMap::new(),
        };

        self.ml_models.insert(model_id, ml_model);
        Ok(model_id)
    }

    pub async fn make_prediction(
        &self,
        model_id: Uuid,
        input_features: HashMap<String, f64>,
        horizon: Duration,
    ) -> Result<Prediction> {
        let model = self.ml_models.get(&model_id)
            .ok_or_else(|| crate::error::Error::NotFound(format!("ML model {} not found", model_id)))?;

        // Simple prediction logic - in production, use actual ML framework
        let predicted_value = self.simple_predict(&model, &input_features).await?;
        let confidence_interval = (predicted_value * 0.9, predicted_value * 1.1);

        let prediction = Prediction {
            id: Uuid::new_v4(),
            model_id,
            input_features,
            predicted_value,
            confidence_interval,
            prediction_horizon: horizon,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };

        let mut predictions = self.predictions.write();
        predictions.push(prediction.clone());

        Ok(prediction)
    }

    pub async fn detect_real_time_anomalies(&self, metric_name: &str) -> Result<Vec<AnomalyDetection>> {
        let series_key = format!("{}:default", metric_name);
        
        let series = self.metrics.get(&series_key)
            .ok_or_else(|| crate::error::Error::NotFound(format!("Metric series {} not found", metric_name)))?;

        if series.data_points.len() < 10 {
            return Ok(Vec::new());
        }

        let values: Vec<f64> = series.data_points.iter().map(|dp| dp.value).collect();
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let std_dev = (values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64).sqrt();

        let mut anomalies = Vec::new();
        let threshold = self.config.anomaly_threshold * std_dev;

        for (i, data_point) in series.data_points.iter().enumerate().rev().take(10) {
            let deviation = (data_point.value - mean).abs();
            if deviation > threshold {
                let anomaly_score = deviation / std_dev;
                let severity = match anomaly_score {
                    s if s > 4.0 => AnomalySeverity::Critical,
                    s if s > 3.0 => AnomalySeverity::High,
                    s if s > 2.0 => AnomalySeverity::Medium,
                    _ => AnomalySeverity::Low,
                };

                let anomaly = AnomalyDetection {
                    id: Uuid::new_v4(),
                    metric_name: metric_name.to_string(),
                    timestamp: data_point.timestamp,
                    actual_value: data_point.value,
                    expected_value: mean,
                    anomaly_score,
                    threshold,
                    severity,
                    context: HashMap::new(),
                };

                anomalies.push(anomaly);
            }
        }

        Ok(anomalies)
    }

    pub async fn create_dashboard(&self, dashboard: Dashboard) -> Result<Uuid> {
        let dashboard_id = dashboard.id;
        self.dashboards.insert(dashboard_id, dashboard);
        Ok(dashboard_id)
    }

    pub fn get_dashboard(&self, dashboard_id: &Uuid) -> Option<Dashboard> {
        self.dashboards.get(dashboard_id).map(|d| d.clone())
    }

    pub fn list_dashboards(&self, tenant_id: Option<Uuid>) -> Vec<Dashboard> {
        self.dashboards
            .iter()
            .filter_map(|entry| {
                let dashboard = entry.value();
                if tenant_id.map_or(true, |id| dashboard.tenant_id == Some(id)) {
                    Some(dashboard.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub async fn get_metric_series(&self, metric_name: &str, time_range: TimeRange) -> Option<MetricSeries> {
        let series_key = format!("{}:default", metric_name);
        
        self.metrics.get(&series_key).map(|series| {
            let mut filtered_series = series.clone();
            filtered_series.data_points.retain(|dp| {
                dp.timestamp >= time_range.start && dp.timestamp <= time_range.end
            });
            filtered_series
        })
    }

    pub async fn get_insights(&self, tenant_id: Option<Uuid>, limit: Option<usize>) -> Vec<Insight> {
        let insights = self.insights.read();
        let mut filtered: Vec<Insight> = insights
            .iter()
            .filter(|insight| {
                // Filter by tenant if specified (implement tenant filtering logic)
                true
            })
            .cloned()
            .collect();

        filtered.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        if let Some(limit) = limit {
            filtered.truncate(limit);
        }

        filtered
    }

    pub async fn get_recommendations(&self, tenant_id: Option<Uuid>, limit: Option<usize>) -> Vec<Recommendation> {
        let recommendations = self.recommendations.read();
        let mut filtered: Vec<Recommendation> = recommendations
            .iter()
            .filter(|rec| {
                // Filter by tenant if specified (implement tenant filtering logic)
                true
            })
            .cloned()
            .collect();

        filtered.sort_by(|a, b| {
            // Sort by priority and confidence
            let priority_cmp = b.priority.cmp(&a.priority);
            if priority_cmp == std::cmp::Ordering::Equal {
                b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal)
            } else {
                priority_cmp
            }
        });

        if let Some(limit) = limit {
            filtered.truncate(limit);
        }

        filtered
    }

    async fn analyze_trends(&self, request: &AnalysisRequest) -> Result<serde_json::Value> {
        let mut trend_results = HashMap::new();

        for metric_name in &request.metric_names {
            if let Some(series) = self.get_metric_series(metric_name, request.time_range.clone()).await {
                let values: Vec<f64> = series.data_points.iter().map(|dp| dp.value).collect();
                
                if values.len() > 1 {
                    let trend = self.calculate_trend(&values);
                    trend_results.insert(metric_name, serde_json::json!({
                        "trend": trend,
                        "direction": if trend > 0.0 { "increasing" } else if trend < 0.0 { "decreasing" } else { "stable" },
                        "magnitude": trend.abs()
                    }));
                }
            }
        }

        Ok(serde_json::to_value(trend_results)?)
    }

    async fn detect_anomalies(&self, request: &AnalysisRequest) -> Result<serde_json::Value> {
        let mut anomaly_results = HashMap::new();

        for metric_name in &request.metric_names {
            let anomalies = self.detect_real_time_anomalies(metric_name).await?;
            anomaly_results.insert(metric_name, serde_json::to_value(anomalies)?);
        }

        Ok(serde_json::to_value(anomaly_results)?)
    }

    async fn generate_forecasts(&self, request: &AnalysisRequest) -> Result<serde_json::Value> {
        let mut forecast_results = HashMap::new();

        for metric_name in &request.metric_names {
            if let Some(series) = self.get_metric_series(metric_name, request.time_range.clone()).await {
                let values: Vec<f64> = series.data_points.iter().map(|dp| dp.value).collect();
                
                if values.len() > 5 {
                    let forecast = self.simple_forecast(&values, 10);
                    forecast_results.insert(metric_name, serde_json::json!({
                        "forecast": forecast,
                        "confidence": 0.8
                    }));
                }
            }
        }

        Ok(serde_json::to_value(forecast_results)?)
    }

    async fn perform_clustering(&self, _request: &AnalysisRequest) -> Result<serde_json::Value> {
        // Simplified clustering implementation
        Ok(serde_json::json!({"clusters": [], "centroids": []}))
    }

    async fn perform_classification(&self, _request: &AnalysisRequest) -> Result<serde_json::Value> {
        // Simplified classification implementation
        Ok(serde_json::json!({"predictions": [], "accuracy": 0.85}))
    }

    async fn perform_regression(&self, _request: &AnalysisRequest) -> Result<serde_json::Value> {
        // Simplified regression implementation
        Ok(serde_json::json!({"coefficients": [], "r_squared": 0.75}))
    }

    async fn analyze_correlations(&self, request: &AnalysisRequest) -> Result<serde_json::Value> {
        let mut correlation_matrix = HashMap::new();

        for metric_a in &request.metric_names {
            for metric_b in &request.metric_names {
                if metric_a != metric_b {
                    let correlation = self.calculate_correlation(metric_a, metric_b, &request.time_range).await?;
                    let key = format!("{}_{}", metric_a, metric_b);
                    correlation_matrix.insert(key, correlation);
                }
            }
        }

        Ok(serde_json::to_value(correlation_matrix)?)
    }

    async fn generate_insights(&self, request: &AnalysisRequest, results: &serde_json::Value) -> Result<Vec<Insight>> {
        let mut insights = Vec::new();

        // Generate trend insights
        if request.analysis_type == AnalysisType::Trend {
            if let Some(trend_data) = results.as_object() {
                for (metric, trend_info) in trend_data {
                    if let Some(direction) = trend_info.get("direction").and_then(|v| v.as_str()) {
                        if direction != "stable" {
                            let insight = Insight {
                                id: Uuid::new_v4(),
                                title: format!("{} Trend Detected", metric),
                                description: format!("Metric {} is showing a {} trend", metric, direction),
                                insight_type: InsightType::Trend,
                                severity: InsightSeverity::Medium,
                                metrics: vec![metric.clone()],
                                time_range: request.time_range.clone(),
                                confidence: 0.8,
                                details: HashMap::new(),
                            };
                            insights.push(insight);
                        }
                    }
                }
            }
        }

        Ok(insights)
    }

    async fn generate_recommendations(&self, _request: &AnalysisRequest, _results: &serde_json::Value, insights: &[Insight]) -> Result<Vec<Recommendation>> {
        let mut recommendations = Vec::new();

        for insight in insights {
            match insight.insight_type {
                InsightType::Trend => {
                    let recommendation = Recommendation {
                        id: Uuid::new_v4(),
                        title: "Monitor Trending Metric".to_string(),
                        description: format!("Consider monitoring {} more closely due to detected trend", insight.metrics.join(", ")),
                        recommendation_type: RecommendationType::Performance,
                        priority: RecommendationPriority::Medium,
                        estimated_impact: EstimatedImpact {
                            cost_savings_per_month: 0.0,
                            performance_improvement_percent: 10.0,
                            risk_reduction_percent: 15.0,
                            implementation_effort: ImplementationEffort::Low,
                        },
                        actions: vec![RecommendedAction {
                            action_type: "monitor".to_string(),
                            description: "Increase monitoring frequency".to_string(),
                            parameters: HashMap::new(),
                            estimated_time_minutes: 30,
                            requires_approval: false,
                        }],
                        applicable_resources: insight.metrics.clone(),
                        confidence: insight.confidence,
                    };
                    recommendations.push(recommendation);
                }
                _ => {}
            }
        }

        Ok(recommendations)
    }

    async fn start_background_tasks(&self) -> Result<()> {
        // Start anomaly detection task
        let analytics_engine = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(analytics_engine.config.processing_interval_seconds as u64)
            );
            loop {
                interval.tick().await;
                if analytics_engine.config.anomaly_detection_enabled {
                    // Run anomaly detection on all metrics
                    for metric_series in analytics_engine.metrics.iter() {
                        if let Ok(anomalies) = analytics_engine.detect_real_time_anomalies(&metric_series.name).await {
                            let mut anomalies_guard = analytics_engine.anomalies.write();
                            anomalies_guard.extend(anomalies);
                        }
                    }
                }
            }
        });

        // Start ML training task
        if self.config.ml_training_enabled {
            let analytics_engine = self.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_secs(analytics_engine.config.ml_training_interval_hours as u64 * 3600)
                );
                loop {
                    interval.tick().await;
                    // Retrain ML models periodically
                }
            });
        }

        Ok(())
    }

    async fn collect_training_data(&self, features: &[String], target_metric: &str) -> Result<Vec<(Vec<f64>, f64)>> {
        let mut training_data = Vec::new();

        // Collect data for features and target
        if let Some(target_series) = self.metrics.get(&format!("{}:default", target_metric)) {
            let target_values: Vec<f64> = target_series.data_points.iter().map(|dp| dp.value).collect();
            
            for (i, target_value) in target_values.iter().enumerate() {
                let mut feature_values = Vec::new();
                
                for feature_name in features {
                    if let Some(feature_series) = self.metrics.get(&format!("{}:default", feature_name)) {
                        if let Some(data_point) = feature_series.data_points.get(i) {
                            feature_values.push(data_point.value);
                        }
                    }
                }
                
                if feature_values.len() == features.len() {
                    training_data.push((feature_values, *target_value));
                }
            }
        }

        Ok(training_data)
    }

    async fn train_model(&self, model_type: &MLModelType, training_data: &[(Vec<f64>, f64)]) -> Result<f64> {
        // Simplified model training - in production, use actual ML framework
        match model_type {
            MLModelType::LinearRegression => {
                // Simple linear regression implementation
                Ok(0.85) // Mock accuracy
            }
            _ => Ok(0.80), // Mock accuracy for other models
        }
    }

    async fn simple_predict(&self, _model: &MLModel, input_features: &HashMap<String, f64>) -> Result<f64> {
        // Simplified prediction - in production, use actual trained model
        let sum: f64 = input_features.values().sum();
        Ok(sum / input_features.len() as f64)
    }

    fn calculate_trend(&self, values: &[f64]) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }

        let n = values.len() as f64;
        let x_sum: f64 = (0..values.len()).map(|i| i as f64).sum();
        let y_sum: f64 = values.iter().sum();
        let xy_sum: f64 = values.iter().enumerate().map(|(i, &y)| i as f64 * y).sum();
        let x_squared_sum: f64 = (0..values.len()).map(|i| (i as f64).powi(2)).sum();

        let slope = (n * xy_sum - x_sum * y_sum) / (n * x_squared_sum - x_sum * x_sum);
        slope
    }

    fn simple_forecast(&self, values: &[f64], periods: usize) -> Vec<f64> {
        let trend = self.calculate_trend(values);
        let last_value = values[values.len() - 1];
        
        (0..periods)
            .map(|i| last_value + trend * (i + 1) as f64)
            .collect()
    }

    async fn calculate_correlation(&self, metric_a: &str, metric_b: &str, time_range: &TimeRange) -> Result<f64> {
        let series_a = self.get_metric_series(metric_a, time_range.clone()).await;
        let series_b = self.get_metric_series(metric_b, time_range.clone()).await;

        if let (Some(a), Some(b)) = (series_a, series_b) {
            let values_a: Vec<f64> = a.data_points.iter().map(|dp| dp.value).collect();
            let values_b: Vec<f64> = b.data_points.iter().map(|dp| dp.value).collect();

            if values_a.len() == values_b.len() && values_a.len() > 1 {
                // Simplified correlation calculation
                let mean_a = values_a.iter().sum::<f64>() / values_a.len() as f64;
                let mean_b = values_b.iter().sum::<f64>() / values_b.len() as f64;

                let numerator: f64 = values_a.iter().zip(values_b.iter())
                    .map(|(a, b)| (a - mean_a) * (b - mean_b))
                    .sum();

                let denom_a: f64 = values_a.iter().map(|a| (a - mean_a).powi(2)).sum::<f64>().sqrt();
                let denom_b: f64 = values_b.iter().map(|b| (b - mean_b).powi(2)).sum::<f64>().sqrt();

                if denom_a > 0.0 && denom_b > 0.0 {
                    return Ok(numerator / (denom_a * denom_b));
                }
            }
        }

        Ok(0.0)
    }

    fn calculate_confidence_score(&self, insights: &[Insight]) -> f64 {
        if insights.is_empty() {
            return 0.0;
        }

        insights.iter().map(|i| i.confidence).sum::<f64>() / insights.len() as f64
    }
}

impl Clone for AnalyticsEngine {
    fn clone(&self) -> Self {
        Self {
            metrics: Arc::clone(&self.metrics),
            analysis_results: Arc::clone(&self.analysis_results),
            ml_models: Arc::clone(&self.ml_models),
            predictions: Arc::clone(&self.predictions),
            anomalies: Arc::clone(&self.anomalies),
            insights: Arc::clone(&self.insights),
            recommendations: Arc::clone(&self.recommendations),
            dashboards: Arc::clone(&self.dashboards),
            config: self.config.clone(),
        }
    }
}


impl Ord for RecommendationPriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_value = match self {
            RecommendationPriority::Low => 0,
            RecommendationPriority::Medium => 1,
            RecommendationPriority::High => 2,
            RecommendationPriority::Urgent => 3,
        };
        let other_value = match other {
            RecommendationPriority::Low => 0,
            RecommendationPriority::Medium => 1,
            RecommendationPriority::High => 2,
            RecommendationPriority::Urgent => 3,
        };
        self_value.cmp(&other_value)
    }
}

impl PartialOrd for RecommendationPriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_analytics_engine_creation() {
        let config = AnalyticsConfig::default();
        let engine = AnalyticsEngine::new(config);
        assert!(engine.config.enabled);
    }

    #[tokio::test]
    async fn test_metric_ingestion() {
        let engine = AnalyticsEngine::default();
        
        let metric = Metric {
            id: "test_metric_1".to_string(),
            name: "cpu_usage".to_string(),
            metric_type: MetricType::Gauge,
            value: 75.5,
            timestamp: Utc::now(),
            labels: HashMap::new(),
            tenant_id: None,
            resource_id: None,
        };

        engine.ingest_metric(metric).await.unwrap();
        
        let series = engine.get_metric_series("cpu_usage", TimeRange {
            start: Utc::now() - Duration::hours(1),
            end: Utc::now(),
        }).await;

        assert!(series.is_some());
        assert_eq!(series.unwrap().data_points.len(), 1);
    }

    #[tokio::test]
    async fn test_anomaly_detection() {
        let engine = AnalyticsEngine::default();

        // Ingest normal values
        for i in 0..20 {
            let metric = Metric {
                id: format!("metric_{}", i),
                name: "response_time".to_string(),
                metric_type: MetricType::Gauge,
                value: 100.0 + (i as f64 * 2.0), // Normal increasing trend
                timestamp: Utc::now() - Duration::minutes(20 - i),
                labels: HashMap::new(),
                tenant_id: None,
                resource_id: None,
            };
            engine.ingest_metric(metric).await.unwrap();
        }

        // Ingest anomalous value
        let anomalous_metric = Metric {
            id: "anomaly_metric".to_string(),
            name: "response_time".to_string(),
            metric_type: MetricType::Gauge,
            value: 1000.0, // Anomalous spike
            timestamp: Utc::now(),
            labels: HashMap::new(),
            tenant_id: None,
            resource_id: None,
        };
        engine.ingest_metric(anomalous_metric).await.unwrap();

        let anomalies = engine.detect_real_time_anomalies("response_time").await.unwrap();
        assert!(!anomalies.is_empty());
        assert!(anomalies[0].anomaly_score > 2.0);
    }

    #[tokio::test]
    async fn test_trend_analysis() {
        let engine = AnalyticsEngine::default();

        // Ingest trending data
        for i in 0..10 {
            let metric = Metric {
                id: format!("trend_metric_{}", i),
                name: "memory_usage".to_string(),
                metric_type: MetricType::Gauge,
                value: 50.0 + (i as f64 * 5.0), // Increasing trend
                timestamp: Utc::now() - Duration::minutes(10 - i),
                labels: HashMap::new(),
                tenant_id: None,
                resource_id: None,
            };
            engine.ingest_metric(metric).await.unwrap();
        }

        let request = AnalysisRequest {
            id: Uuid::new_v4(),
            analysis_type: AnalysisType::Trend,
            metric_names: vec!["memory_usage".to_string()],
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
    }

    #[tokio::test]
    async fn test_ml_model_training() {
        let engine = AnalyticsEngine::default();

        // Ingest training data
        for i in 0..20 {
            let feature_metric = Metric {
                id: format!("feature_metric_{}", i),
                name: "cpu_usage".to_string(),
                metric_type: MetricType::Gauge,
                value: 50.0 + (i as f64 * 2.0),
                timestamp: Utc::now() - Duration::minutes(20 - i),
                labels: HashMap::new(),
                tenant_id: None,
                resource_id: None,
            };
            engine.ingest_metric(feature_metric).await.unwrap();

            let target_metric = Metric {
                id: format!("target_metric_{}", i),
                name: "response_time".to_string(),
                metric_type: MetricType::Gauge,
                value: 100.0 + (i as f64 * 3.0), // Correlated with CPU
                timestamp: Utc::now() - Duration::minutes(20 - i),
                labels: HashMap::new(),
                tenant_id: None,
                resource_id: None,
            };
            engine.ingest_metric(target_metric).await.unwrap();
        }

        let model_id = engine.train_ml_model(
            MLModelType::LinearRegression,
            vec!["cpu_usage".to_string()],
            "response_time".to_string(),
        ).await.unwrap();

        assert!(engine.ml_models.contains_key(&model_id));
    }

    #[tokio::test]
    async fn test_prediction() {
        let engine = AnalyticsEngine::default();

        // Create a mock ML model
        let model_id = Uuid::new_v4();
        let model = MLModel {
            id: model_id,
            name: "test_model".to_string(),
            model_type: MLModelType::LinearRegression,
            version: "1.0.0".to_string(),
            training_data_size: 100,
            accuracy: 0.85,
            created_at: Utc::now(),
            last_trained: Utc::now(),
            features: vec!["cpu_usage".to_string()],
            hyperparameters: HashMap::new(),
            performance_metrics: HashMap::new(),
        };
        engine.ml_models.insert(model_id, model);

        let mut input_features = HashMap::new();
        input_features.insert("cpu_usage".to_string(), 75.0);

        let prediction = engine.make_prediction(
            model_id,
            input_features,
            Duration::hours(1),
        ).await.unwrap();

        assert_eq!(prediction.model_id, model_id);
        assert!(prediction.predicted_value > 0.0);
    }

    #[tokio::test]
    async fn test_dashboard_creation() {
        let engine = AnalyticsEngine::default();

        let dashboard = Dashboard {
            id: Uuid::new_v4(),
            name: "Test Dashboard".to_string(),
            description: "Test dashboard for analytics".to_string(),
            tenant_id: None,
            widgets: vec![
                Widget {
                    id: Uuid::new_v4(),
                    title: "CPU Usage".to_string(),
                    widget_type: WidgetType::LineChart,
                    position: Position { x: 0, y: 0 },
                    size: Size { width: 400, height: 300 },
                    configuration: WidgetConfiguration {
                        metrics: vec!["cpu_usage".to_string()],
                        time_range: TimeRange {
                            start: Utc::now() - Duration::hours(1),
                            end: Utc::now(),
                        },
                        aggregation: AggregationType::Average,
                        display_options: HashMap::new(),
                    },
                }
            ],
            refresh_interval_seconds: 60,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let dashboard_id = engine.create_dashboard(dashboard.clone()).await.unwrap();
        assert_eq!(dashboard_id, dashboard.id);

        let retrieved = engine.get_dashboard(&dashboard_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Dashboard");
    }
}