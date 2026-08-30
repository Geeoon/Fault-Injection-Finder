#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[allow(unreachable_code)]
#[no_mangle]
pub extern "C" fn main() -> u32 {
    const PASSWORD: [u8; 11] = *b"password123";
    let mut input: [u8; 11] = [0; 11];
    loop {
        stubs::_read(&mut input[0..11]);
        if PASSWORD == input {
            break;
        };
    }
    stubs::_write(b"access granted.");
    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    stubs::_exit(0xFF);
}
