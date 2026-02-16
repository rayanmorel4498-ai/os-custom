use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};


pub fn block_on<F: Future>(future: F) -> F::Output {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    let mut spins: u32 = 0;
    const SPIN_YIELD_INTERVAL: u32 = 1024;
    const MAX_SPINS: u32 = 5_000_000;
    loop {
        match Pin::new(&mut future).poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => {
                spins = spins.saturating_add(1);
                if spins % SPIN_YIELD_INTERVAL == 0 {
                    core::hint::spin_loop();
                }
                if spins >= MAX_SPINS {
                    panic!("block_on timeout (future never became ready)");
                }
                core::hint::spin_loop();
            }
        }
    }
}
