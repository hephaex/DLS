pub mod anomaly_detection;
pub mod intelligent_ops;
pub mod nlp_interface;
pub mod predictive_analytics;

// Export specific types to avoid conflicts
pub use anomaly_detection::{
    AnomalyDetectionEngine, AnomalyDetector, AnomalyRecord, BaselineModel,
};
pub use intelligent_ops::{
    AutomationRule, IntelligentOpsEngine, IntelligentRecommendation, SafetyCheck,
};
pub use nlp_interface::{
    EntityType as NlpEntityType, NaturalLanguageProcessor, QueryIntent, QueryResponse, ResponseType,
};
pub use predictive_analytics::{
    CapacityForecast, FailurePrediction, PerformanceOptimization, PredictionModel,
    PredictiveAnalyticsEngine,
};
