// I have never programmed in Rust before, so I'm sorry for this mess.

// EXIT_ADDR    0x3000000
// RW_ADDR      0x3001000
// FAULT_ADDR   0x3002000
// TRIGGER_ADDR 0x3003000
#![no_std]

#[no_mangle]
pub fn _successful_fault() {
    const FAULT_ADDR: *mut i32 = 0x3002000 as *mut i32;
    // write 0 to FAULT_ADDR
    unsafe {
        core::ptr::write_volatile(FAULT_ADDR, 0);
    }
}

#[no_mangle]
pub fn _trigger() {
    const TRIGGER_ADDR: *mut i32 = 0x3003000 as *mut i32;
    // write 0 to TRIGGER_ADDR
    unsafe {
        core::ptr::write_volatile(TRIGGER_ADDR, 0);
    }
}

// unicorn hooks
#[no_mangle]
pub extern "C" fn _exit(status: i32) -> ! {
    const EXIT_ADDR: *mut i32 = 0x3000000 as *mut i32;
    // write status to EXIT_ADDR
    unsafe {
        core::ptr::write_volatile(EXIT_ADDR, status);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub fn _read(buf: &mut [u8]) {
    const RW_ADDR: *const u8 = 0x3001000 as *const u8;
    // write to RW_ADDR from buf[i]
    for item in buf.iter_mut() {
        unsafe {
            *item = core::ptr::read_volatile(RW_ADDR);
        }
    }
}

#[no_mangle]
pub fn _write(buf: &[u8]) {
    // read from RW_ADDR and store in buf[i]
    const RW_ADDR: *mut u8 = 0x3001000 as *mut u8;
    for b in buf {
        unsafe {
            core::ptr::write_volatile(RW_ADDR, *b);
        }
    }
}

#[no_mangle]
pub fn led_blip() {
    _trigger();
}
