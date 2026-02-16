#[cfg(test)]
mod tests {
    extern crate alloc;

    use crate::core::ipc::{DropPolicy, IPC, TimestampPolicy};
    use crate::core::model_cache::{CachedModel, ModelCache, ModelMetadata};
    use crate::core::resource_quota::{PriorityClass, ResourceQuotaManager};
    use crate::time;
    use crate::utils::debug_writer::DebugWriter;
    use alloc::vec;

    fn build_model(model_id: u32, size: usize) -> CachedModel {
        let weights = vec![vec![0.1_f32; size]; 8];
        let params = crate::prelude::BTreeMap::new();
        CachedModel {
            metadata: ModelMetadata {
                model_id,
                version: 1,
                size_bytes: (size as u32) * 8 * 4,
                accuracy: 0.9,
                last_access: 0,
                access_count: 0,
                warm: false,
            },
            weights,
            params,
        }
    }

    #[test]
    #[ignore]
    fn bench_ipc_throughput() {
        let mut ipc = IPC::new();
        ipc.configure_backpressure(4096, 1024, 1024, DropPolicy::RejectNew);
        ipc.register_channel("bench");
        ipc.subscribe(1, "bench");

        let start = time::now_ms();
        let total = 10_000u64;
        for i in 0..total {
            let payload = [i as u8; 8];
            let _ = ipc.send(1, "bench", &payload, 1);
        }
        ipc.route();
        let mut received = 0u64;
        while let Some(msg) = ipc.recv(1) {
            received += 1;
            let _ = ipc.ack(1, msg.id);
        }
        let elapsed_ms = time::now_ms().saturating_sub(start);
        let msg = alloc::format!("IPC throughput: {} msgs in {} ms", received, elapsed_ms);
        DebugWriter::info(&msg);
        assert!(received > 0);
    }

    #[test]
    fn bench_model_cache_churn() {
        let cache = ModelCache::new(32);
        let start = time::now_ms();

        for i in 0..256u32 {
            let model = build_model(i, 256);
            let _ = cache.cache_model(model);
            let _ = cache.get_model(i);
        }

        let elapsed_ms = time::now_ms().saturating_sub(start);
        let msg = alloc::format!("Model cache churn: 256 inserts in {} ms", elapsed_ms);
        DebugWriter::info(&msg);
    }

    #[test]
    fn bench_resource_quota_churn() {
        let mut quota = ResourceQuotaManager::new();
        quota.set_budget("mod", 100, 0, 128, 50);
        let start = time::now_ms();
        for i in 0..50_000u64 {
            quota.record_cpu("mod", 1, i);
            quota.record_latency("mod", 1);
            quota.update_ram_usage("mod", (i % 128) as u32);
            let _ = quota.admission_decision("mod", PriorityClass::Realtime);
        }
        let elapsed_ms = time::now_ms().saturating_sub(start);
        let msg = alloc::format!("Quota churn: 50k iterations in {} ms", elapsed_ms);
        DebugWriter::info(&msg);
    }

    #[test]
    #[ignore]
    fn stress_ipc_security_massive() {
        let mut ipc = IPC::new();
        ipc.configure_security(Some(b"bench-secret-000000"), true);
        ipc.configure_timestamp_policy(TimestampPolicy::Required);
        ipc.configure_time_skew(4);
        ipc.configure_backpressure(20_000, 10_000, 10_000, DropPolicy::DropOldest);
        ipc.register_channel("stress");
        ipc.subscribe(1, "stress");

        let start = time::now_ms();
        let total = 10_000u64;
        for i in 0..total {
            let payload = [i as u8; 32];
            let _ = ipc.send_with_ttl(1, "stress", &payload, 1, 32);
        }
        ipc.route();

        let mut received = 0u64;
        while let Some(msg) = ipc.recv(1) {
            received += 1;
            let _ = ipc.ack(1, msg.id);
        }

        let elapsed_ms = time::now_ms().saturating_sub(start);
        let msg = alloc::format!("IPC secure stress: {} msgs in {} ms", received, elapsed_ms);
        DebugWriter::info(&msg);
        assert!(received > 0);
    }
}

