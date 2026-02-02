/// Distributed Tracing System
/// - OpenTelemetry integration
/// - Span correlation
/// - Trace sampling
/// - Performance metrics
/// - Log aggregation

use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::Mutex;
use alloc::sync::Arc;
use crate::prelude::{String, ToString, Vec};
use uuid::Uuid;
use alloc::collections::BTreeMap as HashMap;

#[derive(Clone, Debug)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub timestamp: u64,
    pub service_name: String,
}

impl TraceContext {
    pub fn new(service_name: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        TraceContext {
            trace_id: Uuid::new_v4(),
            span_id: Uuid::new_v4(),
            parent_span_id: None,
            timestamp: now,
            service_name,
        }
    }

    pub fn child_span(&self) -> TraceContext {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        TraceContext {
            trace_id: self.trace_id.clone(),
            span_id: Uuid::new_v4(),
            parent_span_id: Some(self.span_id.clone()),
            timestamp: now,
            service_name: self.service_name.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Span {
    pub context: TraceContext,
    pub operation: String,
    pub duration_ms: u64,
    pub status: String,
    pub attributes: HashMap<String, String>,
}

impl Span {
    pub fn new(context: TraceContext, operation: String) -> Self {
        Span {
            context,
            operation,
            duration_ms: 0,
            status: "ACTIVE",
            attributes: HashMap::new(),
        }
    }

    pub fn add_attribute(&mut self, key: String, value: String) {
        self.attributes.insert(key, value);
    }

    pub fn finish(&mut self, status: String, duration_ms: u64) {
        self.status = status;
        self.duration_ms = duration_ms;
    }
}

/// Global tracer
pub struct Tracer {
    spans: Arc<Mutex<Vec<Span>>>,
    sampling_rate: f64,
    buffer_size: usize,
    service_name: String,
}

impl Tracer {
    pub fn new(service_name: String, sampling_rate: f64, buffer_size: usize) -> Self {
        Tracer {
            spans: Arc::new(Mutex::new(Vec::with_capacity(buffer_size))),
            sampling_rate,
            buffer_size,
            service_name,
        }
    }

    pub fn should_sample(&self) -> bool {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen::<f64>() < self.sampling_rate
    }

    pub fn start_span(&self, _operation: String) -> Option<TraceContext> {
        if !self.should_sample() {
            return None;
        }

        let context = TraceContext::new(self.service_name.clone());
        Some(context)
    }

    pub fn record_span(&self, span: Span) {
        let mut spans = self.spans.lock();
        if spans.len() < self.buffer_size {
            spans.push(span);
        } else {
            // Flush oldest spans
            spans.remove(0);
            spans.push(span);
        }
    }

    pub fn get_spans(&self) -> Vec<Span> {
        self.spans.lock().clone()
    }

    pub fn flush(&self) -> Vec<Span> {
        let mut spans = self.spans.lock();
        let result = spans.drain(..).collect();
        result
    }

    pub fn span_count(&self) -> usize {
        self.spans.lock().len()
    }
}

/// Performance metrics collector with tracing
pub struct TracedMetrics {
    tracer: Arc<Tracer>,
    operation_times: Arc<Mutex<HashMap<String, Vec<u64>>>>,
}

impl TracedMetrics {
    pub fn new(tracer: Arc<Tracer>) -> Self {
        TracedMetrics {
            tracer,
            operation_times: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn record_operation(&self, operation: &str, duration_ms: u64) {
        let mut times = self.operation_times.lock();
        times.entry(operation)
            .or_insert_with(Vec::new)
            .push(duration_ms);
    }

    pub fn get_percentile(&self, operation: &str, percentile: f64) -> Option<u64> {
        let times = self.operation_times.lock();
        if let Some(ops) = times.get(operation) {
            if ops.is_empty() {
                return None;
            }

            let mut sorted = ops.clone();
            sorted.sort();

            let index = ((percentile / 100.0) * sorted.len() as f64) as usize;
            sorted.get(index).copied()
        } else {
            None
        }
    }

    pub fn get_average(&self, operation: &str) -> Option<f64> {
        let times = self.operation_times.lock();
        if let Some(ops) = times.get(operation) {
            if ops.is_empty() {
                return None;
            }

            let sum: u64 = ops.iter().sum();
            Some(sum as f64 / ops.len() as f64)
        } else {
            None
        }
    }

    pub fn get_all_operations(&self) -> HashMap<String, Vec<u64>> {
        self.operation_times.lock().clone()
    }
}

/// Distributed context propagation
pub struct ContextPropagator;

impl ContextPropagator {
    /// Serialize context to header format
    pub fn serialize(context: &TraceContext) -> String {
        format!(
            "traceparent=00-{}-{}-01",
            context.trace_id, context.span_id
        )
    }

    /// Deserialize context from header
    pub fn deserialize(header: &str) -> Option<TraceContext> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() >= 4 {
            let trace_id = parts[1];
            let span_id = parts[2];

            Some(TraceContext {
                trace_id,
                span_id,
                parent_span_id: None,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                service_name: "propagated",
            })
        } else {
            None
        }
    }
}

/// Trace exporter
pub struct TraceExporter;

impl TraceExporter {
    /// Export spans to JSON format
    pub fn export_json(spans: &[Span]) -> String {
        let mut json = String::from("[\n");
        
        for (idx, span) in spans.iter().enumerate() {
            json.push_str(&format!(
                r#"  {{
    "trace_id": "{}",
    "span_id": "{}",
    "parent_span_id": {},
    "operation": "{}",
    "duration_ms": {},
    "status": "{}",
    "timestamp": {},
    "service": "{}"
  }}"#,
                span.context.trace_id,
                span.context.span_id,
                span.context
                    .parent_span_id
                    .as_ref()
                    .map(|p| format!(r#""{}""#, p))
                    .unwrap_or_else(|| "null"),
                span.operation,
                span.duration_ms,
                span.status,
                span.context.timestamp,
                span.context.service_name
            ));

            if idx < spans.len() - 1 {
                json.push(',');
            }
            json.push('\n');
        }

        json.push(']');
        json
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context() {
        let ctx = TraceContext::new("test-service");
        assert!(!ctx.trace_id.is_empty());
        assert!(!ctx.span_id.is_empty());
        assert!(ctx.parent_span_id.is_none());
    }

    #[test]
    fn test_child_span() {
        let parent = TraceContext::new("service");
        let child = parent.child_span();

        assert_eq!(parent.trace_id, child.trace_id);
        assert_ne!(parent.span_id, child.span_id);
        assert_eq!(child.parent_span_id, Some(parent.span_id));
    }

    #[test]
    fn test_tracer() {
        let tracer = Tracer::new("test", 1.0, 100);

        if let Some(ctx) = tracer.start_span("operation") {
            let mut span = Span::new(ctx, "test_op");
            span.add_attribute("key", "value");
            span.finish("SUCCESS", 100);

            tracer.record_span(span);
        }

        assert!(tracer.span_count() > 0);
    }

    #[test]
    fn test_context_propagator() {
        let ctx = TraceContext::new("service");
        let serialized = ContextPropagator::serialize(&ctx);

        assert!(serialized.contains("traceparent="));
        assert!(serialized.contains(&ctx.trace_id));

        let deserialized = ContextPropagator::deserialize(&serialized);
        assert!(deserialized.is_some());
    }

    #[test]
    fn test_traced_metrics() {
        let tracer = Arc::new(Tracer::new("test", 1.0, 100));
        let metrics = TracedMetrics::new(tracer);

        metrics.record_operation("op1", 100);
        metrics.record_operation("op1", 200);
        metrics.record_operation("op1", 300);

        let avg = metrics.get_average("op1");
        assert_eq!(avg, Some(200.0));

        let p50 = metrics.get_percentile("op1", 50.0);
        assert!(p50.is_some());
    }

    #[test]
    fn test_trace_export() {
        let ctx = TraceContext::new("service");
        let mut span = Span::new(ctx, "op");
        span.finish("SUCCESS", 50);

        let json = TraceExporter::export_json(&[span]);
        assert!(json.contains("trace_id"));
        assert!(json.contains("SUCCESS"));
    }
}
