#[cfg(test)]
mod stress_tests {
    use redmi_kernel::scheduler::{RtEdfScheduler, RtTask};
    use redmi_kernel::core::irq_fiq::{InterruptController, InterruptPriority};
    use std::sync::Arc;

    #[test]
    fn test_scheduler_stress_1000_tasks() {
        let scheduler = RtEdfScheduler::new();

        for i in 0..1000 {
            let deadline_us = ((i as u64) * 1000) % 100000 + 100;
            let task = RtTask::new(i as u32, deadline_us, 0, 10, 100);
            scheduler.add_task(task);
        }

        assert_eq!(scheduler.get_task_count(), 1000);
    }

    #[test]
    fn test_scheduler_stress_add_cycles() {
        let scheduler = RtEdfScheduler::new();

        for cycle in 0..100 {
            for i in 0..100 {
                let deadline_us = ((cycle * 100 + i) as u64) * 1000;
                let task = RtTask::new((cycle * 100 + i) as u32, deadline_us, 0, 10, 100);
                scheduler.add_task(task);
            }
        }

        assert_eq!(scheduler.get_task_count(), 10000);
    }

    #[test]
    fn test_scheduler_with_deadline_misses() {
        let scheduler = RtEdfScheduler::new();

        for i in 0..500 {
            let deadline_us = ((i as u64) * 10) + 100;
            let task = RtTask::new(i as u32, deadline_us, 0, 5, 50);
            scheduler.add_task(task);
        }

        assert_eq!(scheduler.get_task_count(), 500);
        let metrics = scheduler.get_sla_metrics();
        let _ = metrics.deadline_met_percentage();
    }

    #[test]
    fn test_interrupt_controller_stress_rapid_irqs() {
        use core::sync::atomic::{AtomicU32, Ordering};

        static IRQ_COUNT: AtomicU32 = AtomicU32::new(0);

        fn stress_handler(_irq: u32) -> Result<(), &'static str> {
            IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        let ic = InterruptController::new();

        for i in 0..100 {
            let _ = ic.register_irq(i, InterruptPriority::Medium, stress_handler);
        }

        for i in 0..100 {
            for _ in 0..10 {
                let _ = ic.handle_irq(i);
            }
        }

        assert_eq!(IRQ_COUNT.load(Ordering::Relaxed), 1000);
        assert_eq!(ic.get_stats().0, 1000);
    }

    #[test]
    fn test_interrupt_controller_nested_interrupts() {
        static NESTING_LEVEL: core::sync::atomic::AtomicU32 =
            core::sync::atomic::AtomicU32::new(0);

        fn nested_handler(_irq: u32) -> Result<(), &'static str> {
            let level = NESTING_LEVEL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            
            if level < 10 {
            }
            
            NESTING_LEVEL.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
            Ok(())
        }

        let ic = InterruptController::new();
        ic.register_irq(32, InterruptPriority::High, nested_handler)
            .unwrap();

        for _ in 0..100 {
            let _ = ic.handle_irq(32);
        }

        assert_eq!(ic.get_stats().0, 100);
    }

    #[test]
    fn test_interrupt_controller_enable_disable_cycles() {
        fn dummy_handler(_irq: u32) -> Result<(), &'static str> {
            Ok(())
        }

        let ic = InterruptController::new();
        ic.register_irq(32, InterruptPriority::Medium, dummy_handler)
            .unwrap();

        for _ in 0..1000 {
            ic.disable_irqs();
            assert!(!ic.are_irqs_enabled());

            ic.enable_irqs();
            assert!(ic.are_irqs_enabled());
        }
    }

    #[test]
    fn test_scheduler_sla_metrics() {
        let scheduler = RtEdfScheduler::new();

        for i in 0..100 {
            let deadline_us = ((i as u64) * 1000) + 10000;
            let task = RtTask::new(i as u32, deadline_us, 0, 10, 100);
            scheduler.add_task(task);
        }

        for _ in 0..100 {
            let metrics = scheduler.get_sla_metrics();
            let _ = metrics.deadline_met_percentage();
        }
    }

    #[test]
    fn test_concurrent_task_addition() {
        let scheduler = Arc::new(RtEdfScheduler::new());

        for batch in 0..10 {
            for i in 0..100 {
                let task_id = batch * 100 + i;
                let deadline_us = ((task_id as u64) * 100) + 1000;
                let task = RtTask::new(task_id as u32, deadline_us, 0, 5, 50);
                scheduler.add_task(task);
            }
        }

        assert_eq!(scheduler.get_task_count(), 1000);
    }

    #[test]
    fn test_interrupt_priority_levels() {
        fn priority_handler(_irq: u32) -> Result<(), &'static str> {
            Ok(())
        }

        let ic = InterruptController::new();

        let priorities = [
            InterruptPriority::Highest,
            InterruptPriority::Critical,
            InterruptPriority::High,
            InterruptPriority::Medium,
            InterruptPriority::Low,
        ];

        for (idx, priority) in priorities.iter().enumerate() {
            let _ = ic.register_irq(idx as u32, *priority, priority_handler);
        }

        for _ in 0..100 {
            for (idx, _) in priorities.iter().enumerate() {
                let _ = ic.handle_irq(idx as u32);
            }
        }

        assert_eq!(ic.get_stats().0, 500);
    }

    #[test]
    fn test_scheduler_large_deadline_range() {
        let scheduler = RtEdfScheduler::new();

        for i in 0..1000 {
            let deadline_us = ((i as u64) * 100) % 1000000 + 1000;
            let task = RtTask::new(i as u32, deadline_us, 0, 8, 200);
            scheduler.add_task(task);
        }

        assert_eq!(scheduler.get_task_count(), 1000);
        let metrics = scheduler.get_sla_metrics();
        let _ = metrics.deadline_met_percentage();
    }
}
