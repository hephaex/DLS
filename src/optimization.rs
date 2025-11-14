// Performance optimization utilities for Sprint 4 modules
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Optimized data structure management for reducing memory footprint
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct OptimizedDataManager {
    // Use smaller, more efficient data structures
    pub cache_pools: HashMap<String, Arc<CachePool>>,
    pub memory_pools: HashMap<String, Arc<MemoryPool>>,
    pub connection_pools: HashMap<String, Arc<ConnectionPool>>,
}

#[derive(Debug)]
pub struct CachePool {
    pub pool_id: String,
    pub max_size: usize,
    pub current_size: std::sync::atomic::AtomicUsize,
    pub hit_rate: std::sync::atomic::AtomicU64,
    pub eviction_policy: EvictionPolicy,
}

#[derive(Debug, Clone)]
pub enum EvictionPolicy {
    LRU,
    LFU,
    TTL(Duration),
    Adaptive,
}

#[derive(Debug)]
pub struct MemoryPool {
    pub pool_id: String,
    pub allocated_bytes: std::sync::atomic::AtomicUsize,
    pub peak_usage: std::sync::atomic::AtomicUsize,
    pub allocation_strategy: AllocationStrategy,
}

#[derive(Debug, Clone)]
pub enum AllocationStrategy {
    Eager,
    Lazy,
    Pooled,
    Adaptive,
}

#[derive(Debug)]
pub struct ConnectionPool {
    pub pool_id: String,
    pub max_connections: usize,
    pub active_connections: std::sync::atomic::AtomicUsize,
    pub connection_timeout: Duration,
    pub idle_timeout: Duration,
}

/// Optimized replacements for heavy Arc<DashMap> usage
#[derive(Debug, Clone)]
pub struct LightweightStore<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    inner: Arc<parking_lot::RwLock<HashMap<K, V>>>,
    max_size: Option<usize>,
}

impl<K, V> LightweightStore<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    pub fn new(max_size: Option<usize>) -> Self {
        Self {
            inner: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            max_size,
        }
    }

    pub fn insert(&self, key: K, value: V) -> Option<V> {
        let mut map = self.inner.write();

        // Implement size-based eviction if max_size is set
        if let Some(max) = self.max_size {
            if map.len() >= max {
                // Simple eviction - remove first entry
                if let Some((first_key, _)) = map.iter().next() {
                    let first_key = first_key.clone();
                    map.remove(&first_key);
                }
            }
        }

        map.insert(key, value)
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.inner.read().get(key).cloned()
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        self.inner.write().remove(key)
    }

    pub fn len(&self) -> usize {
        self.inner.read().len()
    }
}

/// Batch processing for reducing synchronization overhead
#[derive(Debug, Clone)]
pub struct BatchProcessor<T> {
    batch_size: usize,
    flush_interval: Duration,
    buffer: Arc<parking_lot::Mutex<Vec<T>>>,
    last_flush: Arc<parking_lot::Mutex<SystemTime>>,
}

impl<T> BatchProcessor<T>
where
    T: Clone + Send + 'static,
{
    pub fn new(batch_size: usize, flush_interval: Duration) -> Self {
        Self {
            batch_size,
            flush_interval,
            buffer: Arc::new(parking_lot::Mutex::new(Vec::with_capacity(batch_size))),
            last_flush: Arc::new(parking_lot::Mutex::new(SystemTime::now())),
        }
    }

    pub async fn add(&self, item: T) -> bool {
        let mut buffer = self.buffer.lock();
        buffer.push(item);

        let should_flush = buffer.len() >= self.batch_size || {
            let last_flush = *self.last_flush.lock();
            SystemTime::now()
                .duration_since(last_flush)
                .unwrap_or_default()
                >= self.flush_interval
        };

        should_flush
    }

    pub fn flush(&self) -> Vec<T> {
        let mut buffer = self.buffer.lock();
        let items = buffer.drain(..).collect();
        *self.last_flush.lock() = SystemTime::now();
        items
    }
}

/// Async-friendly data structures that reduce blocking
#[derive(Debug, Clone)]
pub struct AsyncDataStore<K, V>
where
    K: std::hash::Hash + Eq + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    store: Arc<tokio::sync::RwLock<HashMap<K, V>>>,
    metrics: Arc<tokio::sync::RwLock<StoreMetrics>>,
}

#[derive(Debug, Clone, Default)]
pub struct StoreMetrics {
    pub reads: u64,
    pub writes: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

impl<K, V> Default for AsyncDataStore<K, V>
where
    K: std::hash::Hash + Eq + Clone + Send + Sync,
    V: Clone + Send + Sync,
 {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> AsyncDataStore<K, V>
where
    K: std::hash::Hash + Eq + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    pub fn new() -> Self {
        Self {
            store: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            metrics: Arc::new(tokio::sync::RwLock::new(StoreMetrics::default())),
        }
    }

    pub async fn get(&self, key: &K) -> Option<V> {
        let store = self.store.read().await;
        let result = store.get(key).cloned();

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.reads += 1;
        if result.is_some() {
            metrics.hits += 1;
        } else {
            metrics.misses += 1;
        }

        result
    }

    pub async fn insert(&self, key: K, value: V) -> Option<V> {
        let mut store = self.store.write().await;
        let result = store.insert(key, value);

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.writes += 1;

        result
    }

    pub async fn remove(&self, key: &K) -> Option<V> {
        let mut store = self.store.write().await;
        let result = store.remove(key);

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.writes += 1;
        if result.is_some() {
            metrics.evictions += 1;
        }

        result
    }

    pub async fn get_metrics(&self) -> StoreMetrics {
        self.metrics.read().await.clone()
    }
}

/// Memory-efficient event buffer with circular buffer implementation
#[derive(Debug, Clone)]
pub struct CircularEventBuffer<T>
where
    T: Clone,
{
    buffer: Arc<parking_lot::RwLock<Vec<Option<T>>>>,
    capacity: usize,
    write_index: Arc<std::sync::atomic::AtomicUsize>,
    size: Arc<std::sync::atomic::AtomicUsize>,
}

impl<T> CircularEventBuffer<T>
where
    T: Clone,
{
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Arc::new(parking_lot::RwLock::new(vec![None; capacity])),
            capacity,
            write_index: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            size: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub fn push(&self, item: T) {
        let mut buffer = self.buffer.write();
        let index = self
            .write_index
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            % self.capacity;

        let was_empty = buffer[index].is_none();
        buffer[index] = Some(item);

        if was_empty {
            self.size.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    pub fn read_recent(&self, count: usize) -> Vec<T> {
        let buffer = self.buffer.read();
        let current_size = self.size.load(std::sync::atomic::Ordering::SeqCst);
        let read_count = count.min(current_size);

        let mut result = Vec::with_capacity(read_count);
        let write_pos = self.write_index.load(std::sync::atomic::Ordering::SeqCst);

        for i in 0..read_count {
            let index = (write_pos + self.capacity - read_count + i) % self.capacity;
            if let Some(ref item) = buffer[index] {
                result.push(item.clone());
            }
        }

        result
    }

    pub fn len(&self) -> usize {
        self.size.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Performance monitoring and profiling utilities
#[derive(Debug, Clone)]
pub struct PerformanceProfiler {
    pub measurements: Arc<DashMap<String, PerformanceMeasurement>>,
    pub thresholds: HashMap<String, Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMeasurement {
    pub operation_name: String,
    pub total_time: Duration,
    pub call_count: u64,
    pub average_time: Duration,
    pub min_time: Duration,
    pub max_time: Duration,
    pub last_measured: SystemTime,
}

impl PerformanceProfiler {
    pub fn new() -> Self {
        Self {
            measurements: Arc::new(DashMap::new()),
            thresholds: HashMap::new(),
        }
    }

    pub async fn measure<F, R>(&self, operation_name: &str, operation: F) -> R
    where
        F: std::future::Future<Output = R>,
    {
        let start = std::time::Instant::now();
        let result = operation.await;
        let duration = start.elapsed();

        self.record_measurement(operation_name, duration);
        result
    }

    fn record_measurement(&self, operation_name: &str, duration: Duration) {
        self.measurements
            .entry(operation_name.to_string())
            .and_modify(|measurement| {
                measurement.total_time += duration;
                measurement.call_count += 1;
                measurement.average_time = Duration::from_nanos(
                    measurement.total_time.as_nanos() as u64 / measurement.call_count,
                );
                measurement.min_time = measurement.min_time.min(duration);
                measurement.max_time = measurement.max_time.max(duration);
                measurement.last_measured = SystemTime::now();
            })
            .or_insert(PerformanceMeasurement {
                operation_name: operation_name.to_string(),
                total_time: duration,
                call_count: 1,
                average_time: duration,
                min_time: duration,
                max_time: duration,
                last_measured: SystemTime::now(),
            });
    }

    pub fn get_slow_operations(&self, threshold: Duration) -> Vec<PerformanceMeasurement> {
        self.measurements
            .iter()
            .filter(|entry| entry.average_time > threshold)
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn get_summary(&self) -> PerformanceSummary {
        let measurements: Vec<_> = self
            .measurements
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        let total_operations = measurements.iter().map(|m| m.call_count).sum();
        let total_time: Duration = measurements.iter().map(|m| m.total_time).sum();
        let average_operation_time = if !measurements.is_empty() {
            Duration::from_nanos(total_time.as_nanos() as u64 / measurements.len() as u64)
        } else {
            Duration::ZERO
        };

        PerformanceSummary {
            total_operations,
            total_time,
            average_operation_time,
            operation_count: measurements.len(),
            slowest_operations: measurements
                .into_iter()
                .filter(|m| m.average_time > Duration::from_millis(100))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub total_operations: u64,
    pub total_time: Duration,
    pub average_operation_time: Duration,
    pub operation_count: usize,
    pub slowest_operations: Vec<PerformanceMeasurement>,
}

/// Resource usage monitoring and optimization
#[derive(Debug, Clone)]
pub struct ResourceMonitor {
    pub memory_usage: Arc<std::sync::atomic::AtomicUsize>,
    pub cpu_usage: Arc<parking_lot::RwLock<f64>>,
    pub connection_count: Arc<std::sync::atomic::AtomicUsize>,
    pub active_threads: Arc<std::sync::atomic::AtomicUsize>,
}

impl ResourceMonitor {
    pub fn new() -> Self {
        Self {
            memory_usage: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            cpu_usage: Arc::new(parking_lot::RwLock::new(0.0)),
            connection_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            active_threads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub fn record_memory_allocation(&self, bytes: usize) {
        self.memory_usage
            .fetch_add(bytes, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn record_memory_deallocation(&self, bytes: usize) {
        self.memory_usage
            .fetch_sub(bytes, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn get_memory_usage(&self) -> usize {
        self.memory_usage.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn update_cpu_usage(&self, usage: f64) {
        *self.cpu_usage.write() = usage;
    }

    pub fn get_cpu_usage(&self) -> f64 {
        *self.cpu_usage.read()
    }

    pub fn increment_connections(&self) {
        self.connection_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn decrement_connections(&self) {
        self.connection_count
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn get_connection_count(&self) -> usize {
        self.connection_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn get_resource_summary(&self) -> ResourceSummary {
        ResourceSummary {
            memory_usage_bytes: self.get_memory_usage(),
            cpu_usage_percent: self.get_cpu_usage(),
            active_connections: self.get_connection_count(),
            active_threads: self
                .active_threads
                .load(std::sync::atomic::Ordering::SeqCst),
            timestamp: SystemTime::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSummary {
    pub memory_usage_bytes: usize,
    pub cpu_usage_percent: f64,
    pub active_connections: usize,
    pub active_threads: usize,
    pub timestamp: SystemTime,
}


impl Default for PerformanceProfiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ResourceMonitor {
    fn default() -> Self {
        Self::new()
    }
}
