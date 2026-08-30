#![no_std]

#[no_mangle]
#[inline(never)]
pub fn pwned() {
    loop {
        stubs::_write(b"pwned!");
    }
}
