pub mod predictive_analytics;
pub mod anomaly_detection;
pub mod intelligent_ops;
pub mod nlp_interface;

// Export specific types to avoid conflicts
pub use predictive_analytics::{PredictiveAnalyticsEngine, PredictionModel, FailurePrediction, CapacityForecast, PerformanceOptimization};
pub use anomaly_detection::{AnomalyDetectionEngine, AnomalyDetector, AnomalyRecord, BaselineModel};
pub use intelligent_ops::{IntelligentOpsEngine, AutomationRule, IntelligentRecommendation, SafetyCheck};
pub use nlp_interface::{NaturalLanguageProcessor, QueryIntent, QueryResponse, EntityType as NlpEntityType, ResponseType};