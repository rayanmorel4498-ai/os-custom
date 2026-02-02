use core::ptr::{read_volatile, write_volatile};
pub type RegAddr = usize;
#[inline(always)]
pub unsafe fn read32(addr: RegAddr) -> u32 {
    read_volatile(addr as *const u32)
}
#[inline(always)]
pub unsafe fn write32(addr: RegAddr, value: u32) {
    write_volatile(addr as *mut u32, value);
}
#[inline(always)]
pub unsafe fn set_bits(addr: RegAddr, mask: u32) {
    let val = read32(addr);
    write32(addr, val | mask);
}
#[inline(always)]
pub unsafe fn clear_bits(addr: RegAddr, mask: u32) {
    let val = read32(addr);
    write32(addr, val & !mask);
}
#[inline(always)]
pub unsafe fn write_field(addr: RegAddr, mask: u32, shift: u8, value: u32) {
    let mut val = read32(addr);
    val &= !mask;
    val |= (value << shift) & mask;
    write32(addr, val);
}
#[inline(always)]
pub unsafe fn read_field(addr: RegAddr, mask: u32, shift: u8) -> u32 {
    (read32(addr) & mask) >> shift
}
