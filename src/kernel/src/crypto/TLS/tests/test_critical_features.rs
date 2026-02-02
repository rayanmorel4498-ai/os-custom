#[cfg(test)]
mod critical_features_integration {
    extern crate alloc;

    #[test]
    fn test_timeout_rate_limiting_telemetry_integration() {
        use redmi_tls::runtime::{
            TimeoutManager, TimeoutType, RateLimiter, ComponentType, MetricsCollector,
        };

        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║   TIMEOUT + RATE LIMITING + TELEMETRY INTEGRATION        ║");
        println!("╚════════════════════════════════════════════════════════════╝\n");

        println!("1✍️  TIMEOUT MANAGEMENT");
        let timeout_manager = TimeoutManager::new();
        timeout_manager.register_timeout("session_1".to_string(), TimeoutType::Handshake);
        timeout_manager.register_timeout("session_2".to_string(), TimeoutType::Session);
        println!("   ✓ Registered 2 sessions with timeouts");
        println!("   Active sessions: {}", timeout_manager.active_count());

        println!("\n2️⃣  RATE LIMITING BY COMPONENT");
        let rate_limiter = RateLimiter::new();
        
        for component in [
            ComponentType::Kernel,
            ComponentType::IA,
            ComponentType::API,
            ComponentType::HSM,
        ]
        {
            rate_limiter.initialize_component(component);
            let tokens = rate_limiter.get_tokens(component);
            println!("   {:?}: {} tokens", component, tokens);
        }

        println!("\n3️⃣  TELEMETRY METRICS COLLECTION");
        let metrics = MetricsCollector::new();
        metrics.update_active_sessions(2);
        metrics.record_latency(15);
        metrics.record_latency(20);
        metrics.record_message(512);
        metrics.record_encryption();

        let health = metrics.get_health_metrics();
        println!("   Active sessions: {}", health.active_sessions);
        println!("   Avg latency: {} ms", metrics.get_avg_latency());
        
        let throughput = metrics.get_throughput_metrics();
        println!("   Messages/sec: {}", throughput.messages_per_sec);
        println!("   Bytes/sec: {}", throughput.bytes_per_sec);

        println!("\n4️⃣  SIMULATED TRAFFIC FLOW");
        let mut allowed_requests = 0;
        let mut blocked_requests = 0;

        for i in 0..100 {
            let component = match i % 4 {
                0 => ComponentType::Kernel,
                1 => ComponentType::IA,
                2 => ComponentType::API,
                _ => ComponentType::HSM,
            };

            if rate_limiter.is_allowed(component, 1) {
                allowed_requests += 1;
                metrics.record_message(256);
                metrics.record_latency(10 + (i % 5) as u64);
            } else {
                blocked_requests += 1;
                metrics.record_timeout();
            }
        }

        println!("   100 requests: {} allowed, {} throttled", allowed_requests, blocked_requests);
        println!("   Health score: {}/100", metrics.get_health_score());

        println!("\n5️⃣  TIMEOUT HANDLING");
        let retry_candidates = timeout_manager.get_retry_candidates();
        println!("   Sessions needing retry: {}", retry_candidates.len());

        let expired = timeout_manager.cleanup_expired();
        println!("   Expired sessions cleaned: {}", expired.len());

        println!("\n6️⃣  FINAL METRICS SNAPSHOT");
        let snapshot = metrics.create_snapshot();
        println!("   Avg latency: {} ms", snapshot.avg_latency_ms);
        println!("   Throughput: {}/sec", snapshot.throughput_msg_per_sec);
        println!("   Active: {} sessions", snapshot.active_sessions);

        println!("\n✅ INTEGRATION TEST PASSED!\n");
    }

    #[test]
    fn test_timeout_retry_mechanism() {
        use redmi_tls::runtime::{TimeoutManager, TimeoutType};

        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║         TIMEOUT RETRY MECHANISM                          ║");
        println!("╚════════════════════════════════════════════════════════════╝\n");

        let manager = TimeoutManager::new();
        
        manager.register_timeout("sess_retry_1".to_string(), TimeoutType::MessagePending);
        manager.register_timeout("sess_retry_2".to_string(), TimeoutType::Handshake);
        
        println!("1️⃣  Registered 2 sessions");
        println!("   Active: {}", manager.active_count());

        let candidates = manager.get_retry_candidates();
        println!("\n2️⃣  Retry candidates: {}", candidates.len());

        for candidate in candidates {
            manager.increment_retry(&candidate);
            println!("   Incremented retry count for: {}", candidate);
        }

        let expired = manager.cleanup_expired();
        println!("\n3️⃣  Cleanup results:");
        println!("   Expired sessions removed: {}", expired.len());
        println!("   Remaining active: {}", manager.active_count());

        println!("\n✅ RETRY MECHANISM TEST PASSED!\n");
    }

    #[test]
    fn test_rate_limiting_per_component() {
        use redmi_tls::runtime::{RateLimiter, ComponentType};

        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║       RATE LIMITING PER COMPONENT                        ║");
        println!("╚════════════════════════════════════════════════════════════╝\n");

        let limiter = RateLimiter::new();

        println!("1️⃣  COMPONENT RATE LIMITS");
        
        let components = vec![
            ComponentType::Kernel,
            ComponentType::IA,
            ComponentType::API,
            ComponentType::HSM,
        ];

        for component in components {
            limiter.initialize_component(component);
            let tokens = limiter.get_tokens(component);
            println!("   {:?}: {} tokens (burst capacity)", component, tokens);
        }

        let kernel_tokens = limiter.get_tokens(ComponentType::Kernel);
        let hsm_tokens = limiter.get_tokens(ComponentType::HSM);
        assert!(kernel_tokens > hsm_tokens, "Kernel should have more tokens than HSM");
        println!("\n2️⃣  ✓ Kernel has higher limits than HSM");

        println!("\n3️⃣  THROTTLING TEST");
        let mut consumed = 0;
        while limiter.is_allowed(ComponentType::HSM, 1) {
            consumed += 1;
        }
        println!("   HSM allowed {} requests before throttling", consumed);
        println!("   ✓ HSM now throttled: {}", limiter.is_throttled(ComponentType::HSM));

        limiter.reset_component(ComponentType::HSM);
        println!("\n4️⃣  After reset:");
        println!("   Tokens available: {}", limiter.get_tokens(ComponentType::HSM));
        println!("   Throttled: {}", limiter.is_throttled(ComponentType::HSM));

        println!("\n✅ RATE LIMITING TEST PASSED!\n");
    }

    #[test]
    fn test_telemetry_health_monitoring() {
        use redmi_tls::runtime::MetricsCollector;

        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║         TELEMETRY HEALTH MONITORING                      ║");
        println!("╚════════════════════════════════════════════════════════════╝\n");

        let metrics = MetricsCollector::new();

        println!("1️⃣  INITIAL STATE");
        println!("   Health score: {}/100", metrics.get_health_score());

        println!("\n2️⃣  RECORDING ACTIVITY");
        for i in 0..10 {
            metrics.record_latency(5 + (i % 3) as u64);
            metrics.record_message(512);
            metrics.record_encryption();
            metrics.record_decryption();
        }

        metrics.update_active_sessions(5);
        println!("   Recorded 10 operations");
        println!("   Active sessions: 5");

        println!("\n3️⃣  METRICS SNAPSHOT");
        let latency = metrics.get_latency_metrics();
        println!("   Handshake latency: {} ms", latency.handshake_ms);
        println!("   Message processing: {} ms", latency.message_processing_ms);

        let throughput = metrics.get_throughput_metrics();
        println!("   Messages/sec: {}", throughput.messages_per_sec);
        println!("   Bytes/sec: {}", throughput.bytes_per_sec);
        println!("   Encryptions/sec: {}", throughput.encryptions_per_sec);

        let health = metrics.get_health_metrics();
        println!("   Active sessions: {}", health.active_sessions);
        println!("   Failed handshakes: {}", health.failed_handshakes);
        println!("   Timeout errors: {}", health.timeout_errors);

        println!("\n4️⃣  ERROR INJECTION");
        metrics.record_failed_handshake();
        metrics.record_failed_handshake();
        metrics.record_timeout();

        let degraded_score = metrics.get_health_score();
        println!("   Health score after errors: {}/100", degraded_score);
        assert!(degraded_score < 100, "Health should degrade with errors");

        println!("\n✅ HEALTH MONITORING TEST PASSED!\n");
    }
}
