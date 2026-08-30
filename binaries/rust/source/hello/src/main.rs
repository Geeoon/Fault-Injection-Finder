#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn main() -> u32 {
    stubs::_write(b"Hello world!");
    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    stubs::_exit(0xFF);
}
