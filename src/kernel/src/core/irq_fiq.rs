use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use alloc::vec::Vec;
use parking_lot::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InterruptPriority {
    Highest = 0,
    Critical = 1,
    High = 2,
    Medium = 3,
    Low = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptType {
    IRQ(u32),
    FIQ,
    SGI(u32),
    PPI(u32),
    SPI(u32),
}

pub type IrqHandler = fn(u32) -> Result<(), &'static str>;

#[derive(Debug, Clone, Copy)]
pub struct InterruptContext {
    pub irq_number: u32,
    pub priority: InterruptPriority,
    pub timestamp_us: u64,
    pub nested_count: u32,
}

pub struct InterruptController {
    irq_handlers: Mutex<Vec<Option<(InterruptPriority, IrqHandler)>>>,
    fiq_handler: Mutex<Option<IrqHandler>>,
    masked_irqs: Mutex<Vec<bool>>,
    total_irqs: AtomicU32,
    total_fiqes: AtomicU32,
    nested_interrupts: AtomicU32,
    irq_enabled: AtomicBool,
}

impl InterruptController {
    pub fn new() -> Self {
        InterruptController {
            irq_handlers: Mutex::new(Vec::new()),
            fiq_handler: Mutex::new(None),
            masked_irqs: Mutex::new(Vec::new()),
            total_irqs: AtomicU32::new(0),
            total_fiqes: AtomicU32::new(0),
            nested_interrupts: AtomicU32::new(0),
            irq_enabled: AtomicBool::new(true),
        }
    }

    pub fn register_irq(
        &self,
        irq_number: u32,
        priority: InterruptPriority,
        handler: IrqHandler,
    ) -> Result<(), &'static str> {
        if irq_number >= 256 {
            return Err("IRQ number out of range");
        }

        let mut handlers = self.irq_handlers.lock();
        
        while handlers.len() <= irq_number as usize {
            handlers.push(None);
        }

        if handlers[irq_number as usize].is_some() {
            return Err("IRQ handler already registered");
        }

        handlers[irq_number as usize] = Some((priority, handler));
        Ok(())
    }

    pub fn register_fiq(&self, handler: IrqHandler) -> Result<(), &'static str> {
        let mut fiq = self.fiq_handler.lock();
        if fiq.is_some() {
            return Err("FIQ handler already registered");
        }
        *fiq = Some(handler);
        Ok(())
    }

    pub fn handle_irq(&self, irq_number: u32) -> Result<(), &'static str> {
        if !self.irq_enabled.load(Ordering::Acquire) {
            return Err("IRQs disabled");
        }

        self.total_irqs.fetch_add(1, Ordering::Relaxed);
        self.nested_interrupts.fetch_add(1, Ordering::Relaxed);

        let handlers = self.irq_handlers.lock();
        if (irq_number as usize) < handlers.len() {
            if let Some((priority, handler)) = handlers[irq_number as usize] {
                drop(handlers);
                
                let result = handler(irq_number);
                
                self.nested_interrupts.fetch_sub(1, Ordering::Relaxed);
                return result;
            }
        }

        self.nested_interrupts.fetch_sub(1, Ordering::Relaxed);
        Err("No handler registered")
    }

    pub fn handle_fiq(&self) -> Result<(), &'static str> {
        self.total_fiqes.fetch_add(1, Ordering::Relaxed);

        if let Some(handler) = *self.fiq_handler.lock() {
            handler(240)
        } else {
            Err("No FIQ handler registered")
        }
    }

    pub fn enable_irqs(&self) {
        self.irq_enabled.store(true, Ordering::Release);
    }

    pub fn disable_irqs(&self) {
        self.irq_enabled.store(false, Ordering::Release);
    }

    pub fn are_irqs_enabled(&self) -> bool {
        self.irq_enabled.load(Ordering::Acquire)
    }

    pub fn mask_irq_by_priority(&self, priority: InterruptPriority) -> Result<(), &'static str> {
        let mut masked = self.masked_irqs.lock();
        let idx = priority as usize;
        
        if idx < masked.len() {
            masked[idx] = true;
            Ok(())
        } else {
            Err("Invalid priority level")
        }
    }

    pub fn unmask_irq_by_priority(&self, priority: InterruptPriority) -> Result<(), &'static str> {
        let mut masked = self.masked_irqs.lock();
        let idx = priority as usize;
        
        if idx < masked.len() {
            masked[idx] = false;
            Ok(())
        } else {
            Err("Invalid priority level")
        }
    }

    pub fn get_stats(&self) -> (u32, u32, u32) {
        (
            self.total_irqs.load(Ordering::Relaxed),
            self.total_fiqes.load(Ordering::Relaxed),
            self.nested_interrupts.load(Ordering::Relaxed),
        )
    }

    pub fn nesting_level(&self) -> u32 {
        self.nested_interrupts.load(Ordering::Relaxed)
    }

    pub fn in_critical_section<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let was_enabled = self.are_irqs_enabled();
        self.disable_irqs();
        
        let result = f();
        
        if was_enabled {
            self.enable_irqs();
        }
        result
    }
}

impl Default for InterruptController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_FLAG: AtomicU32 = AtomicU32::new(0);

    fn test_handler(_irq: u32) -> Result<(), &'static str> {
        TEST_FLAG.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    #[test]
    fn test_interrupt_controller_creation() {
        let ic = InterruptController::new();
        assert!(ic.are_irqs_enabled());
        assert_eq!(ic.nesting_level(), 0);
    }

    #[test]
    fn test_irq_registration() {
        let ic = InterruptController::new();
        assert!(ic
            .register_irq(32, InterruptPriority::High, test_handler)
            .is_ok());
        assert!(ic
            .register_irq(32, InterruptPriority::High, test_handler)
            .is_err());
    }

    #[test]
    fn test_irq_handling() {
        let ic = InterruptController::new();
        TEST_FLAG.store(0, Ordering::Relaxed);
        
        ic.register_irq(32, InterruptPriority::High, test_handler)
            .unwrap();
        
        assert!(ic.handle_irq(32).is_ok());
        assert_eq!(TEST_FLAG.load(Ordering::Relaxed), 1);
        assert_eq!(ic.get_stats().0, 1);
    }

    #[test]
    fn test_fiq_registration() {
        let ic = InterruptController::new();
        assert!(ic.register_fiq(test_handler).is_ok());
        assert!(ic.register_fiq(test_handler).is_err());
    }

    #[test]
    fn test_fiq_handling() {
        let ic = InterruptController::new();
        TEST_FLAG.store(0, Ordering::Relaxed);
        
        ic.register_fiq(test_handler).unwrap();
        
        assert!(ic.handle_fiq().is_ok());
        assert_eq!(TEST_FLAG.load(Ordering::Relaxed), 1);
        assert_eq!(ic.get_stats().1, 1);
    }

    #[test]
    fn test_irq_enable_disable() {
        let ic = InterruptController::new();
        assert!(ic.are_irqs_enabled());
        
        ic.disable_irqs();
        assert!(!ic.are_irqs_enabled());
        
        ic.enable_irqs();
        assert!(ic.are_irqs_enabled());
    }

    #[test]
    fn test_critical_section() {
        let ic = InterruptController::new();
        ic.enable_irqs();
        
        ic.in_critical_section(|| {
            assert!(!ic.are_irqs_enabled());
        });
        
        assert!(ic.are_irqs_enabled());
    }

    #[test]
    fn test_nesting_levels() {
        let ic = InterruptController::new();
        ic.register_irq(32, InterruptPriority::High, test_handler)
            .unwrap();
        
        assert_eq!(ic.nesting_level(), 0);
        ic.handle_irq(32).unwrap();
        assert_eq!(ic.nesting_level(), 0);
    }
}
