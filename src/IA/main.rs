fn main() {
    #[cfg(feature = "hw_timer")]
    redmi_ia::time::hal::set_hw_timer_from_platform();
    let core = match redmi_ia::init::init_ia() {
        Ok(core) => core,
        Err(_) => return,
    };
    let mut tick_ms: u64 = redmi_ia::time::now_ms();
    loop {
        core.run_loops(tick_ms);
        let _ = redmi_ia::init::with_resource_quota_mut(|quota| quota.tick(tick_ms));
        tick_ms = tick_ms.wrapping_add(16);
        sleep_until(tick_ms);
    }
}

#[inline(always)]
fn sleep_until(target_ms: u64) {
    loop {
        let now = redmi_ia::time::now_ms();
        if now >= target_ms {
            return;
        }
        let remaining = target_ms.saturating_sub(now);
        let mut iterations = (remaining as u32).saturating_mul(100);
        if iterations < 50 {
            iterations = 50;
        } else if iterations > 5_000 {
            iterations = 5_000;
        }
        for _ in 0..iterations {
            core::hint::spin_loop();
        }
        idle_wait_hint();
    }
}

#[inline(always)]
fn idle_wait_hint() {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        core::arch::asm!("wfi");
    }
}
