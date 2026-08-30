#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[allow(unreachable_code)]
#[no_mangle]
pub extern "C" fn main() -> u32 {
    // prevents gcc from optimizing away everything after the loop
    loop {
        let mut input: [u8; 8] = [0; 8];
        stubs::_read(&mut input);
        stubs::_write(&input);
    }
    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    stubs::_exit(0xFF);
}
