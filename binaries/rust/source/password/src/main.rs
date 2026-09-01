#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[allow(unreachable_code)]
#[no_mangle]
pub extern "C" fn main() -> u32 {
    // NOTE: the length of our input actually makes a difference in whether the PC is fully or partially controllable
    // with 11 bytes, we were only able to control the bottom 4 bytes and the top were held 0.  With 16, we get total control
    const PASSWORD: [u8; 16] = *b"password12345678";
    let mut input: [u8; 16] = [0; 16];
    loop {
        stubs::_read(&mut input[0..16]);
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
