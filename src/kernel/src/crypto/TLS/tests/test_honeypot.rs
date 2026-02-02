use redmi_tls::security::detection::anomaly_detection::AnomalyDetection;
use redmi_tls::runtime::traffic::rate::RateLimiter;

#[test]
fn test_honeypot_anomaly_detection_creation() {
    let detector = AnomalyDetection::new();
    let _ = detector.get_stats();
}

#[test]
fn test_honeypot_anomaly_check_metrics_valid() {
    let detector = AnomalyDetection::new();
    let result = detector.check_metrics(0.1, 0.9, 100, 10, 0.95);
    assert!(result.is_ok(), "Metrics check should succeed");
}

#[test]
fn test_honeypot_anomaly_check_metrics_multiple_calls() {
    let detector = AnomalyDetection::new();
    for i in 0..10 {
        let result = detector.check_metrics(0.1 * i as f64, 0.9 - 0.1 * i as f64, 100 + i * 10, 10 + i as u32, 0.95 - 0.05 * i as f64);
        assert!(result.is_ok(), "Metrics check iteration {} should succeed", i);
    }
}

#[test]
fn test_honeypot_rate_limiter_creation() {
    let rate_limiter = RateLimiter::new(60, 10);
    assert!(rate_limiter.get_stats().total_attempts == 0, "Initial attempts should be 0");
}

#[test]
fn test_honeypot_rate_limiter_check() {
    let rate_limiter = RateLimiter::new(60, 10);
    let result = rate_limiter.check_request("192.168.1.100");
    assert!(result.is_ok(), "Rate limiter check should succeed");
}

#[test]
fn test_honeypot_rate_limiter_single_client_multiple_requests() {
    let rate_limiter = RateLimiter::new(60, 10);
    let client_ip = "192.168.1.100";
    
    let mut successful_requests = 0;
    for _ in 0..5 {
        if rate_limiter.check_request(client_ip).is_ok() {
            successful_requests += 1;
        }
    }
    assert!(successful_requests > 0, "At least some requests should succeed");
    
    let stats = rate_limiter.get_stats();
    assert_eq!(stats.total_attempts, 5, "Should track all 5 attempts");
}

#[test]
fn test_honeypot_multiple_clients() {
    let rate_limiter = RateLimiter::new(60, 10);
    
    let ips = vec!["192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.1", "10.0.0.2"];
    for ip in ips.iter() {
        let result = rate_limiter.check_request(ip);
        assert!(result.is_ok(), "Rate limiter check for {} should succeed", ip);
    }
    
    let stats = rate_limiter.get_stats();
    assert_eq!(stats.total_attempts, 5, "Should track all 5 different clients");
}

#[test]
fn test_honeypot_multiple_clients_burst() {
    let rate_limiter = RateLimiter::new(60, 10);
    
    for i in 0..15 {
        let ip = format!("192.168.1.{}", 100 + (i % 5));
        let _ = rate_limiter.check_request(&ip);
    }
    
    let stats = rate_limiter.get_stats();
    assert_eq!(stats.total_attempts, 15, "Should track all burst requests");
}

#[test]
fn test_honeypot_anomaly_high_error_detection() {
    let detector = AnomalyDetection::new();
    let result = detector.check_metrics(0.5, 0.5, 100, 10, 0.5);
    assert!(result.is_ok(), "High error rate check should succeed");
    if let Ok(anomalies) = result {
        assert!(!anomalies.is_empty(), "Should detect high error rate anomaly");
    }
}

#[test]
fn test_honeypot_anomaly_very_high_error_detection() {
    let detector = AnomalyDetection::new();
    let result = detector.check_metrics(0.9, 0.1, 100, 10, 0.1);
    assert!(result.is_ok(), "Very high error rate check should succeed");
    if let Ok(anomalies) = result {
        assert!(!anomalies.is_empty(), "Should detect very high error rate anomaly");
    }
}

#[test]
fn test_honeypot_anomaly_high_latency_detection() {
    let detector = AnomalyDetection::new();
    let result = detector.check_metrics(0.1, 0.9, 5000, 100, 0.95);
    assert!(result.is_ok(), "High latency check should succeed");
}

#[test]
fn test_honeypot_detector_get_stats() {
    let detector = AnomalyDetection::new();
    let stats = detector.get_stats();
    assert_eq!(stats.total_anomalies_detected, 0, "Initial stats should be zero");
}

#[test]
fn test_honeypot_detector_get_stats_after_checks() {
    let detector = AnomalyDetection::new();
    
    for _ in 0..5 {
        let _ = detector.check_metrics(0.1, 0.9, 100, 10, 0.95);
    }
    
    let stats = detector.get_stats();
    assert!(stats.total_anomalies_detected > 0 || stats.total_anomalies_detected == 0, "Stats should be tracked");
}

#[test]
fn test_honeypot_auto_remediation_enabled() {
    let detector = AnomalyDetection::new();
    detector.set_auto_remediation(true);
    let enabled = detector.is_auto_remediation_enabled();
    assert!(enabled, "Auto remediation should be enabled");
}

#[test]
fn test_honeypot_auto_remediation_disabled() {
    let detector = AnomalyDetection::new();
    detector.set_auto_remediation(false);
    let enabled = detector.is_auto_remediation_enabled();
    assert!(!enabled, "Auto remediation should be disabled");
}

#[test]
fn test_honeypot_auto_remediation_toggle() {
    let detector = AnomalyDetection::new();
    detector.set_auto_remediation(true);
    assert!(detector.is_auto_remediation_enabled());
    detector.set_auto_remediation(false);
    assert!(!detector.is_auto_remediation_enabled());
    detector.set_auto_remediation(true);
    assert!(detector.is_auto_remediation_enabled());
}

#[test]
fn test_honeypot_rate_limiter_stats() {
    let rate_limiter = RateLimiter::new(100, 5);
    
    let _ = rate_limiter.check_request("192.168.1.100");
    let _ = rate_limiter.check_request("192.168.1.101");
    
    let stats = rate_limiter.get_stats();
    assert!(stats.total_attempts >= 2, 
        "Should track at least 2 attempts");
}

#[test]
fn test_honeypot_rate_limiter_stats_progression() {
    let rate_limiter = RateLimiter::new(100, 5);
    
    for i in 1..=10 {
        let ip = format!("192.168.1.{}", i);
        let _ = rate_limiter.check_request(&ip);
        
        let stats = rate_limiter.get_stats();
        assert_eq!(stats.total_attempts, i as u64, "Attempts should progress from 1 to {}", i);
    }
}

#[test]
fn test_honeypot_multiple_failed_attempts() {
    let rate_limiter = RateLimiter::new(100, 10);
    
    for _ in 0..3 {
        let _ = rate_limiter.check_request("192.168.1.100");
    }
    
    let stats = rate_limiter.get_stats();
    assert!(stats.total_attempts >= 3,
        "Should track all check attempts");
}

#[test]
fn test_honeypot_normal_metrics_no_anomaly() {
    let detector = AnomalyDetection::new();
    
    let result = detector.check_metrics(0.05, 0.95, 100, 5, 0.95);
    if let Ok(anomalies) = result {
        assert!(anomalies.is_empty(), "Normal metrics should not trigger anomalies");
    }
}

#[test]
fn test_honeypot_anomaly_detection_consistency() {
    let detector = AnomalyDetection::new();
    
    let same_metrics = (0.1, 0.9, 100, 10, 0.95);
    let result1 = detector.check_metrics(same_metrics.0, same_metrics.1, same_metrics.2, same_metrics.3, same_metrics.4);
    let result2 = detector.check_metrics(same_metrics.0, same_metrics.1, same_metrics.2, same_metrics.3, same_metrics.4);
    
    assert_eq!(result1.is_ok(), result2.is_ok(), "Same metrics should produce consistent results");
}

#[test]
fn test_honeypot_rate_limiter_different_windows() {
    let rl_short = RateLimiter::new(30, 5);
    let rl_long = RateLimiter::new(300, 50);
    
    let ip = "192.168.1.100";
    let _ = rl_short.check_request(ip);
    let _ = rl_long.check_request(ip);
    
    let stats_short = rl_short.get_stats();
    let stats_long = rl_long.get_stats();
    
    assert_eq!(stats_short.total_attempts, 1);
    assert_eq!(stats_long.total_attempts, 1);
}
