
use core::sync::atomic::{AtomicUsize, Ordering};

pub type RngCallback = fn(buf: &mut [u8]) -> Result<(), &'static str>;

static RNG_CALLBACK: AtomicUsize = AtomicUsize::new(0);

static mut CHACHA20_STATE: [u32; 16] = [
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
];
static mut CHACHA_COUNTER: u64 = 0;

pub fn init_rng(callback: RngCallback) {
    RNG_CALLBACK.store(callback as usize, Ordering::Release);
}

fn chacha20_block(state: *const [u32; 16]) -> [u32; 16] {
    let mut out = unsafe { *state };
    for _ in 0..10 {
        for i in 0..4 {
            out[i] = out[i].wrapping_add(out[i+4]); 
            out[i+12] = (out[i+12] ^ out[i]).rotate_left(16);
            out[i+8] = out[i+8].wrapping_add(out[i+12]); 
            out[i+4] = (out[i+4] ^ out[i+8]).rotate_left(12);
            out[i] = out[i].wrapping_add(out[i+4]); 
            out[i+12] = (out[i+12] ^ out[i]).rotate_left(8);
            out[i+8] = out[i+8].wrapping_add(out[i+12]); 
            out[i+4] = (out[i+4] ^ out[i+8]).rotate_left(7);
        }
        
        for i in 0..4 {
            let t = (i + i * 4) % 16;
            let u = (t + 5) % 16;
            if t < 16 && u < 16 {
                out[t] = out[t].wrapping_add(out[u]); 
                out[(t + 12) % 16] = (out[(t + 12) % 16] ^ out[t]).rotate_left(16);
            }
        }
    }
    for i in 0..16 {
        out[i] = out[i].wrapping_add(unsafe { (*state)[i] });
    }
    out
}

pub fn kernel_rng_fill(buf: &mut [u8]) -> Result<(), &'static str> {
    let callback_addr = RNG_CALLBACK.load(Ordering::Acquire);
    
    if callback_addr != 0 {
        let callback: RngCallback = unsafe { core::mem::transmute(callback_addr) };
        callback(buf)
    } else {
        unsafe {
            let mut pos = 0;
            while pos < buf.len() {
                CHACHA_COUNTER += 1;
                CHACHA20_STATE[12] = (CHACHA_COUNTER >> 32) as u32;
                CHACHA20_STATE[13] = CHACHA_COUNTER as u32;
                
                let block = chacha20_block(&raw const CHACHA20_STATE);
                let block_bytes = core::mem::transmute::<[u32; 16], [u8; 64]>(block);
                
                let chunk_len = core::cmp::min(64, buf.len() - pos);
                buf[pos..pos + chunk_len].copy_from_slice(&block_bytes[..chunk_len]);
                pos += chunk_len;
            }
        }
        Ok(())
    }
}

pub fn kernel_rng_u32() -> u32 {
    let mut buf = [0u8; 4];
    let _ = kernel_rng_fill(&mut buf);
    u32::from_le_bytes(buf)
}

pub fn kernel_rng_u64() -> u64 {
    let mut buf = [0u8; 8];
    let _ = kernel_rng_fill(&mut buf);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng_fallback() {
        unsafe {
            CHACHA20_STATE = [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ];
            CHACHA_COUNTER = 0;
        }
        let mut buf = [0u8; 16];
        assert!(kernel_rng_fill(&mut buf).is_ok());
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_rng_u32() {
        unsafe {
            CHACHA20_STATE = [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ];
            CHACHA_COUNTER = 0;
        }
        let val1 = kernel_rng_u32();
        let val2 = kernel_rng_u32();
        assert_ne!(val1, val2);
    }
}
